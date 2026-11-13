import type { Metadata } from "next";
import Link from "next/link";

import { ApiError } from "@/components/api-error";
import { Card, PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Component, SystemStatus } from "@/lib/api/types";
import { formatTimestamp } from "@/lib/format";
import { SECTIONS } from "@/lib/nav";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Overview" };

const KIND_LABELS: Record<Component["kind"], string> = {
  service: "Service",
  dependency: "Dependency",
  "identity-provider": "Identity provider",
};

function ComponentsTable({ report }: { report: SystemStatus }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Platform components and their current status</caption>
        <thead className="text-xs text-slate-500 uppercase">
          <tr>
            <th scope="col" className="py-2 pr-4 font-medium">
              Component
            </th>
            <th scope="col" className="py-2 pr-4 font-medium">
              Type
            </th>
            <th scope="col" className="py-2 pr-4 font-medium">
              Status
            </th>
            <th scope="col" className="py-2 pr-4 text-right font-medium">
              Response time
            </th>
            <th scope="col" className="py-2 font-medium">
              Version
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {report.components.map((component) => (
            <tr key={`${component.reported_by ?? ""}/${component.name}`} data-testid={`component-${component.name}`}>
              <th scope="row" className="py-2 pr-4 font-medium text-slate-900">
                {component.name}
                {component.reported_by ? (
                  <span className="ml-2 font-normal text-slate-500">via {component.reported_by}</span>
                ) : null}
              </th>
              <td className="py-2 pr-4 text-slate-600">{KIND_LABELS[component.kind]}</td>
              <td className="py-2 pr-4">
                <StatusBadge tone={component.status === "ok" ? "ok" : "down"}>
                  {component.status === "ok" ? "Operational" : "Unavailable"}
                </StatusBadge>
              </td>
              <td className="py-2 pr-4 text-right text-slate-600 tabular-nums">
                {component.latency_ms === undefined ? "—" : `${component.latency_ms.toFixed(1)} ms`}
              </td>
              <td className="py-2 font-mono text-xs text-slate-600">{component.version ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default async function OverviewPage() {
  const session = await requireSession();
  const status = await gatewayGet<SystemStatus>(session, "/api/v1/system/status");
  redirectIfUnauthorized(session, status);

  return (
    <>
      <PageHeader title="Overview" summary="Live health of the platform's services and dependencies." />
      <div className="space-y-6">
        <Card title="Platform status">
          {status.ok ? (
            <>
              <div className="mb-4 flex flex-wrap items-center gap-3">
                <StatusBadge tone={status.data.status === "ok" ? "ok" : "warn"}>
                  {status.data.status === "ok" ? "All components operational" : "Degraded"}
                </StatusBadge>
                <span className="text-xs text-slate-500">Checked {formatTimestamp(status.data.checked_at)}</span>
              </div>
              <ComponentsTable report={status.data} />
            </>
          ) : (
            <ApiError what="the platform status" status={status.status} problem={status.problem} />
          )}
        </Card>

        <Card title="Sections">
          <ul className="grid gap-3 sm:grid-cols-2">
            {SECTIONS.filter((section) => section.href !== "/").map((section) => (
              <li key={section.href}>
                <Link
                  href={section.href}
                  className="flex h-full flex-col gap-2 rounded-md border border-slate-200 p-4 hover:border-slate-400"
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-slate-900">{section.label}</span>
                    <StatusBadge tone={section.status === "available" ? "ok" : "neutral"}>
                      {section.status === "available" ? "Available" : "Not implemented yet"}
                    </StatusBadge>
                  </span>
                  <span className="text-sm text-slate-600">{section.summary}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  );
}
