import type { Metadata } from "next";
import Link from "next/link";

import { ApiError } from "@/components/api-error";
import { AutoRefresh } from "@/components/cloud/auto-refresh";
import { Card, PageHeader } from "@/components/page-header";
import { NETWORK_TABS, SectionTabs } from "@/components/section-tabs";
import { StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { NetworkAlert, NetworkAlertList, NetworkOverview, NetworkSensorList } from "@/lib/api/types";
import { stateLabel } from "@/lib/cloud";
import { formatTimestamp } from "@/lib/format";
import { SECTIONS } from "@/lib/nav";
import { alertStatusTone, detectorLabel, partyLabel, SEVERITIES, severityTone } from "@/lib/netguard";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Network Monitoring" };

const summary = SECTIONS.find((section) => section.href === "/network")?.summary ?? "";
const STATUSES = ["open", "acknowledged", "suppressed", "closed"] as const;

function Stat({ label, value, testId }: { label: string; value: number; testId: string }) {
  return (
    <div data-testid={testId} className="rounded-md border border-slate-200 p-3">
      <span className="block text-2xl font-semibold tabular-nums">{value}</span>
      <span className="text-xs text-slate-600">{label}</span>
    </div>
  );
}

function AlertsTable({ alerts }: { alerts: readonly NetworkAlert[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Alerts</caption>
        <thead className="text-xs text-slate-500 uppercase">
          <tr>
            <th scope="col" className="py-2 pr-4 font-medium">
              Alert
            </th>
            <th scope="col" className="py-2 pr-4 font-medium">
              Severity
            </th>
            <th scope="col" className="py-2 pr-4 font-medium">
              Source
            </th>
            <th scope="col" className="py-2 pr-4 text-right font-medium">
              Seen
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {alerts.map((a) => (
            <tr key={a.id} data-testid={`alert-${a.id}`} className="align-top">
              <th scope="row" className="py-3 pr-4 font-medium text-slate-900">
                <Link href={`/network/alerts/${a.id}`} className="hover:underline">
                  {a.title}
                </Link>
                <span className="block text-xs font-normal text-slate-500">
                  {detectorLabel(a.detector)} · {a.rule_id}
                </span>
              </th>
              <td className="py-3 pr-4">
                <span className="flex flex-wrap gap-1">
                  <StatusBadge tone={severityTone(a.severity)}>{stateLabel(a.severity)}</StatusBadge>
                  <StatusBadge tone={alertStatusTone(a.status)}>{stateLabel(a.status)}</StatusBadge>
                </span>
              </td>
              <td className="py-3 pr-4 text-xs text-slate-600">{partyLabel(a.attribution.source)}</td>
              <td className="py-3 pr-4 text-right text-xs text-slate-600 tabular-nums">
                {a.count}× · {formatTimestamp(a.last_seen_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default async function NetworkPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const status = STATUSES.find((s) => s === params.status) ?? "open";
  const severity = SEVERITIES.find((s) => s === params.severity) ?? "";
  const session = await requireSession();
  const [overview, sensors, alerts] = await Promise.all([
    gatewayGet<NetworkOverview>(session, "/api/v1/network/overview"),
    gatewayGet<NetworkSensorList>(session, "/api/v1/network/sensors"),
    gatewayGet<NetworkAlertList>(
      session,
      `/api/v1/network/alerts?limit=100&status=${status}${severity ? `&severity=${severity}` : ""}`,
    ),
  ]);
  redirectIfUnauthorized(session, overview, sensors, alerts);

  return (
    <>
      <PageHeader title="Network Monitoring" summary={summary} />
      <SectionTabs label="Network Monitoring" tabs={NETWORK_TABS} current="/network" />
      <AutoRefresh active intervalMs={10_000} />
      <div className="space-y-6">
        {overview.ok ? (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat
              testId="stat-open-alerts"
              label="Open alerts"
              value={Object.values(overview.data.open_alerts_by_severity).reduce((a, b) => a + b, 0)}
            />
            <Stat testId="stat-incidents" label="Open incidents" value={overview.data.open_incidents} />
            <Stat testId="stat-events" label="Events (24 h)" value={overview.data.events_24h} />
            <Stat
              testId="stat-unattributed"
              label="Unattributed assets"
              value={overview.data.unattributed_assets}
            />
          </div>
        ) : (
          <ApiError what="the overview" status={overview.status} problem={overview.problem} />
        )}

        <Card title="Sensors">
          {!sensors.ok ? (
            <ApiError what="sensors" status={sensors.status} problem={sensors.problem} />
          ) : sensors.data.items.length === 0 ? (
            <p data-testid="no-sensor" className="text-sm text-slate-600">
              No sensor has registered. On the host that carries ParallelF&apos;s networks run{" "}
              <code className="font-mono">make ng-sensor-setup</code> and{" "}
              <code className="font-mono">make ng-sensor-install</code> (see docs/netguard.md).
            </p>
          ) : (
            <ul className="space-y-3">
              {sensors.data.items.map((s) => (
                <li key={s.id} data-testid={`sensor-${s.name}`} className="text-sm">
                  <span className="flex flex-wrap items-center gap-2 font-medium text-slate-900">
                    {s.name}
                    <StatusBadge tone={s.status === "reporting" ? "ok" : "down"}>
                      {stateLabel(s.status)}
                    </StatusBadge>
                  </span>
                  <span className="mt-1 block text-xs text-slate-600">
                    {s.engine} on{" "}
                    <span className="font-mono">{s.interfaces.join(", ") || "no interface yet"}</span> ·{" "}
                    {s.events_total.toLocaleString("en-US")} events · last report{" "}
                    {formatTimestamp(s.last_seen_at)}
                  </span>
                  {s.engine_error ? (
                    <span className="block text-xs text-rose-700">Engine: {s.engine_error}</span>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Alerts">
          <nav aria-label="Alert status" className="mb-3 flex flex-wrap gap-2 text-sm">
            {STATUSES.map((s) => (
              <Link
                key={s}
                href={`/network?status=${s}${severity ? `&severity=${severity}` : ""}`}
                aria-current={s === status ? "page" : undefined}
                className={
                  s === status ? "font-medium text-slate-900 underline" : "text-slate-600 hover:underline"
                }
              >
                {stateLabel(s)}
              </Link>
            ))}
          </nav>
          {!alerts.ok ? (
            <ApiError what="alerts" status={alerts.status} problem={alerts.problem} />
          ) : alerts.data.items.length === 0 ? (
            <p className="text-sm text-slate-600">No {status} alerts.</p>
          ) : (
            <AlertsTable alerts={alerts.data.items} />
          )}
          <p className="mt-3 text-xs text-slate-500">
            Suricata watches only ParallelF&apos;s own interfaces (the VPN tunnel and Cloud bridges). Repeats
            of an alert increase its count instead of opening new ones.
          </p>
        </Card>
      </div>
    </>
  );
}
