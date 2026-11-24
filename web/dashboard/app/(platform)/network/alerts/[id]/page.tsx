import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { ApiError } from "@/components/api-error";
import { AlertActions } from "@/components/network/alert-actions";
import { Card, PageHeader } from "@/components/page-header";
import { NETWORK_TABS, SectionTabs } from "@/components/section-tabs";
import { StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, NetworkAlertDetail } from "@/lib/api/types";
import { stateLabel } from "@/lib/cloud";
import { formatTimestamp } from "@/lib/format";
import { alertStatusTone, detectorLabel, partyLabel, severityTone } from "@/lib/netguard";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Alert · Network Monitoring" };

export default async function AlertPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const session = await requireSession();
  const [me, alert] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<NetworkAlertDetail>(session, `/api/v1/network/alerts/${encodeURIComponent(id)}`),
  ]);
  redirectIfUnauthorized(session, me, alert);
  if (!alert.ok && alert.status === 404) notFound();
  const canTriage = me.ok && me.data.permissions.includes("network.alerts.triage");

  return (
    <>
      <PageHeader
        title="Network Monitoring"
        summary="One alert: what fired, who was involved and the telemetry behind it."
      />
      <SectionTabs label="Network Monitoring" tabs={NETWORK_TABS} current="/network" />
      {!alert.ok ? (
        <ApiError what="the alert" status={alert.status} problem={alert.problem} />
      ) : (
        <div className="space-y-6">
          <Card title={alert.data.title}>
            <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-xs text-slate-500">Detector</dt>
                <dd>
                  {detectorLabel(alert.data.detector)}{" "}
                  <span className="font-mono text-xs">{alert.data.rule_id}</span>
                </dd>
              </div>
              <div>
                <dt className="text-xs text-slate-500">State</dt>
                <dd className="flex flex-wrap gap-1">
                  <StatusBadge tone={severityTone(alert.data.severity)}>
                    {stateLabel(alert.data.severity)}
                  </StatusBadge>
                  <StatusBadge tone={alertStatusTone(alert.data.status)}>
                    {stateLabel(alert.data.status)}
                  </StatusBadge>
                </dd>
              </div>
              <div>
                <dt className="text-xs text-slate-500">Source</dt>
                <dd data-testid="alert-source">{partyLabel(alert.data.attribution.source)}</dd>
              </div>
              <div>
                <dt className="text-xs text-slate-500">Destination</dt>
                <dd>{partyLabel(alert.data.attribution.destination)}</dd>
              </div>
              <div>
                <dt className="text-xs text-slate-500">Seen</dt>
                <dd>
                  {alert.data.count}× between {formatTimestamp(alert.data.first_seen_at)} and{" "}
                  {formatTimestamp(alert.data.last_seen_at)}
                </dd>
              </div>
              {alert.data.status_by ? (
                <div>
                  <dt className="text-xs text-slate-500">Last decision</dt>
                  <dd>
                    {alert.data.status_by}
                    {alert.data.status_reason ? `: ${alert.data.status_reason}` : ""}
                  </dd>
                </div>
              ) : null}
            </dl>
            {Object.keys(alert.data.details).length > 0 ? (
              <dl className="mt-4 grid gap-1 font-mono text-xs text-slate-600">
                {Object.entries(alert.data.details).map(([k, v]) => (
                  <div key={k}>
                    <dt className="inline text-slate-500">{k}: </dt>
                    <dd className="inline break-all">{v}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </Card>

          {canTriage ? (
            <Card title="Triage">
              <AlertActions alert={alert.data} />
            </Card>
          ) : alert.data.incident_id ? (
            <p className="text-sm">
              Part of <Link href={`/network/incidents/${alert.data.incident_id}`}>an incident</Link>.
            </p>
          ) : null}

          <Card title={`Telemetry (${alert.data.events.length})`}>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <caption className="sr-only">Events behind the alert</caption>
                <thead className="text-slate-500 uppercase">
                  <tr>
                    <th scope="col" className="py-1 pr-3 font-medium">
                      #
                    </th>
                    <th scope="col" className="py-1 pr-3 font-medium">
                      Time
                    </th>
                    <th scope="col" className="py-1 pr-3 font-medium">
                      Kind
                    </th>
                    <th scope="col" className="py-1 pr-3 font-medium">
                      Flow
                    </th>
                    <th scope="col" className="py-1 font-medium">
                      Raw line SHA-256
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {alert.data.events.map((e) => (
                    <tr key={e.id}>
                      <td className="py-1 pr-3">{e.id}</td>
                      <td className="py-1 pr-3">{formatTimestamp(e.ts)}</td>
                      <td className="py-1 pr-3">{e.kind}</td>
                      <td className="py-1 pr-3">
                        {e.src_ip}
                        {e.src_port ? `:${e.src_port}` : ""} → {e.dst_ip}
                        {e.dst_port ? `:${e.dst_port}` : ""} {e.proto}
                      </td>
                      <td className="py-1 break-all text-slate-500">{e.raw_sha256.slice(0, 16)}…</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
