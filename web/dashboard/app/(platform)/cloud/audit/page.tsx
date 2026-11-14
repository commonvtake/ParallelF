import type { Metadata } from "next";
import Link from "next/link";

import { ApiError } from "@/components/api-error";
import { CloudNav } from "@/components/cloud/cloud-nav";
import { Card, PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { AuditPage as AuditPageData, AuditVerification } from "@/lib/api/types";
import { formatTimestamp } from "@/lib/format";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Audit · Cloud" };

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const before = (await searchParams).before;
  const cursor = typeof before === "string" && /^\d+$/.test(before) ? before : undefined;
  const session = await requireSession();
  const [page, verification] = await Promise.all([
    gatewayGet<AuditPageData>(session, `/api/v1/cloud/audit?limit=50${cursor ? `&before=${cursor}` : ""}`),
    gatewayGet<AuditVerification>(session, "/api/v1/cloud/audit/verify"),
  ]);
  redirectIfUnauthorized(session, page, verification);

  return (
    <>
      <PageHeader
        title="Cloud"
        summary="Every change to cloud resources, in a hash-chained, append-only log."
      />
      <CloudNav current="/cloud/audit" />
      <div className="space-y-6">
        <Card title="Integrity">
          {verification.ok ? (
            <div data-testid="audit-verification" className="flex flex-wrap items-center gap-3 text-sm">
              {verification.data.valid ? (
                <StatusBadge tone="ok">Chain intact</StatusBadge>
              ) : (
                <StatusBadge tone="down">Chain broken</StatusBadge>
              )}
              <span className="text-slate-600">
                {verification.data.entries} entries verified {formatTimestamp(verification.data.checked_at)}
                {verification.data.valid
                  ? ""
                  : `; first invalid entry: #${verification.data.first_invalid_seq}`}
              </span>
            </div>
          ) : (
            <ApiError
              what="the audit verification"
              status={verification.status}
              problem={verification.problem}
            />
          )}
          <p className="mt-2 text-xs text-slate-500">
            Each entry stores the SHA-256 of its predecessor. Rewriting or removing any entry breaks every
            hash after it; the database also refuses updates and deletes.
          </p>
        </Card>

        <Card title="Entries">
          {!page.ok ? (
            <ApiError what="the audit log" status={page.status} problem={page.problem} />
          ) : page.data.items.length === 0 ? (
            <p className="text-sm text-slate-600">No entries.</p>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <caption className="sr-only">Audit log, newest first</caption>
                  <thead className="text-xs text-slate-500 uppercase">
                    <tr>
                      <th scope="col" className="py-2 pr-4 font-medium">
                        #
                      </th>
                      <th scope="col" className="py-2 pr-4 font-medium">
                        Time
                      </th>
                      <th scope="col" className="py-2 pr-4 font-medium">
                        Actor
                      </th>
                      <th scope="col" className="py-2 pr-4 font-medium">
                        Action
                      </th>
                      <th scope="col" className="py-2 pr-4 font-medium">
                        Resource
                      </th>
                      <th scope="col" className="py-2 font-medium">
                        Details
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {page.data.items.map((e) => (
                      <tr key={e.seq}>
                        <td className="py-2 pr-4 text-slate-500 tabular-nums">{e.seq}</td>
                        <td className="py-2 pr-4 whitespace-nowrap text-slate-600">
                          {formatTimestamp(e.at)}
                        </td>
                        <td className="py-2 pr-4 text-slate-900">
                          {e.actor_name || e.actor_id}
                          <span className="block text-xs text-slate-500">{e.actor_type}</span>
                        </td>
                        <td className="py-2 pr-4 font-mono text-xs">{e.action}</td>
                        <td className="py-2 pr-4 text-slate-600">
                          {e.resource_type === "workload" ? (
                            <Link href={`/cloud/workloads/${e.resource_id}`} className="underline">
                              workload
                            </Link>
                          ) : (
                            e.resource_type
                          )}
                          <span className="block font-mono text-xs text-slate-500">
                            {e.resource_id.slice(0, 8)}
                          </span>
                        </td>
                        <td className="py-2 font-mono text-xs text-slate-600">
                          {Object.entries(e.details)
                            .map(([k, v]) => `${k}=${v}`)
                            .join(" ")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {page.data.next_before ? (
                <p className="mt-3 text-sm">
                  <Link href={`/cloud/audit?before=${page.data.next_before}`} className="underline">
                    Older entries
                  </Link>
                </p>
              ) : null}
            </>
          )}
        </Card>
      </div>
    </>
  );
}
