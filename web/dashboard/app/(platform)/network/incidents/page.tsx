import type { Metadata } from "next";
import Link from "next/link";

import { ApiError } from "@/components/api-error";
import { IncidentCreate } from "@/components/network/incident-create";
import { Card, PageHeader } from "@/components/page-header";
import { NETWORK_TABS, SectionTabs } from "@/components/section-tabs";
import { StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, NetworkIncidentList } from "@/lib/api/types";
import { stateLabel } from "@/lib/cloud";
import { formatTimestamp } from "@/lib/format";
import { incidentStatusTone, severityTone } from "@/lib/netguard";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Incidents · Network Monitoring" };

export default async function IncidentsPage() {
  const session = await requireSession();
  const [me, incidents] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<NetworkIncidentList>(session, "/api/v1/network/incidents"),
  ]);
  redirectIfUnauthorized(session, me, incidents);
  const canTriage = me.ok && me.data.permissions.includes("network.alerts.triage");

  return (
    <>
      <PageHeader
        title="Network Monitoring"
        summary="Incidents group alerts, a timeline and append-only evidence with recorded digests."
      />
      <SectionTabs label="Network Monitoring" tabs={NETWORK_TABS} current="/network/incidents" />
      <div className="space-y-6">
        <Card title="Incidents">
          {!incidents.ok ? (
            <ApiError what="incidents" status={incidents.status} problem={incidents.problem} />
          ) : incidents.data.items.length === 0 ? (
            <p className="text-sm text-slate-600">No incidents.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {incidents.data.items.map((i) => (
                <li key={i.id} data-testid={`incident-${i.id}`} className="py-3 text-sm">
                  <span className="flex flex-wrap items-center gap-2">
                    <Link
                      href={`/network/incidents/${i.id}`}
                      className="font-medium text-slate-900 hover:underline"
                    >
                      {i.title}
                    </Link>
                    <StatusBadge tone={severityTone(i.severity)}>{stateLabel(i.severity)}</StatusBadge>
                    <StatusBadge tone={incidentStatusTone(i.status)}>{stateLabel(i.status)}</StatusBadge>
                  </span>
                  <span className="block text-xs text-slate-500">
                    {i.alert_count} alerts · opened by {i.created_by} {formatTimestamp(i.created_at)} ·
                    updated {formatTimestamp(i.updated_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
        {canTriage ? (
          <Card title="Open an incident">
            <IncidentCreate />
          </Card>
        ) : null}
      </div>
    </>
  );
}
