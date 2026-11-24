import Link from "next/link";

import { ApiError } from "@/components/api-error";
import { Card } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import type { ApiResult } from "@/lib/api/gateway";
import type { AuditPage, AuditVerification } from "@/lib/api/types";
import { formatTimestamp } from "@/lib/format";

/**
 * A service's hash-chained audit trail: the integrity check and a page of
 * entries, newest first. `linkFor` turns a resource into a link when the
 * dashboard has a page for it.
 */
export function AuditLog({
  page,
  verification,
  basePath,
  linkFor,
}: {
  page: ApiResult<AuditPage>;
  verification: ApiResult<AuditVerification>;
  basePath: string;
  linkFor?: (resourceType: string, resourceId: string) => string | undefined;
}) {
  return (
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
          Each entry stores the SHA-256 of its predecessor. Rewriting or removing any entry breaks every hash
          after it; the database also refuses updates and deletes.
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
                  {page.data.items.map((e) => {
                    const href = linkFor?.(e.resource_type, e.resource_id);
                    return (
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
                          {href ? (
                            <Link href={href} className="underline">
                              {e.resource_type}
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
                    );
                  })}
                </tbody>
              </table>
            </div>
            {page.data.next_before ? (
              <p className="mt-3 text-sm">
                <Link href={`${basePath}?before=${page.data.next_before}`} className="underline">
                  Older entries
                </Link>
              </p>
            ) : null}
          </>
        )}
      </Card>
    </div>
  );
}

/** The `before` cursor from a page's search parameters, if valid. */
export function auditCursor(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" && /^\d+$/.test(value) ? value : undefined;
}
