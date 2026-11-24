import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { ApiError } from "@/components/api-error";
import { IncidentActions } from "@/components/network/incident-actions";
import { Card, PageHeader } from "@/components/page-header";
import { NETWORK_TABS, SectionTabs } from "@/components/section-tabs";
import { StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, NetworkEvidenceVerification, NetworkIncidentDetail } from "@/lib/api/types";
import { stateLabel } from "@/lib/cloud";
import { formatTimestamp } from "@/lib/format";
import { incidentStatusTone, partyLabel, severityTone } from "@/lib/netguard";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Incident · Network Monitoring" };

export default async function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const path = `/api/v1/network/incidents/${encodeURIComponent(id)}`;
  const session = await requireSession();
  const [me, incident, verification] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<NetworkIncidentDetail>(session, path),
    gatewayGet<NetworkEvidenceVerification>(session, `${path}/verify-evidence`),
  ]);
  redirectIfUnauthorized(session, me, incident, verification);
  if (!incident.ok && incident.status === 404) notFound();
  const canTriage = me.ok && me.data.permissions.includes("network.alerts.triage");

  return (
    <>
      <PageHeader title="Network Monitoring" summary="An incident: its alerts, timeline and evidence." />
      <SectionTabs label="Network Monitoring" tabs={NETWORK_TABS} current="/network/incidents" />
      {!incident.ok ? (
        <ApiError what="the incident" status={incident.status} problem={incident.problem} />
      ) : (
        <div className="space-y-6">
          <Card title={incident.data.title}>
            <p className="flex flex-wrap items-center gap-2 text-sm">
              <StatusBadge tone={severityTone(incident.data.severity)}>{stateLabel(incident.data.severity)}</StatusBadge>
              <StatusBadge tone={incidentStatusTone(incident.data.status)}>
                {stateLabel(incident.data.status)}
              </StatusBadge>
              <span className="text-slate-600">
                opened by {incident.data.created_by} {formatTimestamp(incident.data.created_at)}
              </span>
            </p>
            {incident.data.summary ? <p className="mt-3 text-sm text-slate-700">{incident.data.summary}</p> : null}
          </Card>

          <Card title={`Alerts (${incident.data.alerts.length})`}>
            {incident.data.alerts.length === 0 ? (
              <p className="text-sm text-slate-600">No alerts linked. Open an alert to add it to an incident.</p>
            ) : (
              <ul className="space-y-2 text-sm">
                {incident.data.alerts.map((a) => (
                  <li key={a.id}>
                    <Link href={`/network/alerts/${a.id}`} className="font-medium hover:underline">
                      {a.title}
                    </Link>
                    <span className="block text-xs text-slate-500">
                      {partyLabel(a.attribution.source)} · {a.count}× · {stateLabel(a.status)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Evidence">
            {verification.ok ? (
              <p data-testid="evidence-verification" className="mb-3 flex items-center gap-2 text-sm">
                <StatusBadge tone={verification.data.valid ? "ok" : "down"}>
                  {verification.data.valid ? "Digests verified" : "Digest mismatch"}
                </StatusBadge>
                <span className="text-slate-600">{verification.data.checked} items checked just now</span>
              </p>
            ) : null}
            {incident.data.evidence.length === 0 ? (
              <p className="text-sm text-slate-600">No evidence yet.</p>
            ) : (
              <ul className="space-y-2 text-sm">
                {incident.data.evidence.map((e) => (
                  <li key={e.id} data-testid={`evidence-${e.name}`}>
                    <a
                      href={`/bff/api/network/incidents/${incident.data.id}/evidence/${e.id}`}
                      className="font-medium hover:underline"
                    >
                      {e.name}
                    </a>{" "}
                    <span className="text-xs text-slate-500">
                      {e.kind} · {e.size} bytes · added by {e.added_by} {formatTimestamp(e.added_at)}
                    </span>
                    <span className="block font-mono text-xs break-all text-slate-500">sha256 {e.sha256}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Timeline">
            <ol className="space-y-2 text-sm">
              {incident.data.timeline.map((t) => (
                <li key={t.id} className="border-l-2 border-slate-200 pl-3">
                  <span className="text-xs text-slate-500">
                    {formatTimestamp(t.ts)} · {t.actor} · {t.kind.replace("_", " ")}
                  </span>
                  <span className="block whitespace-pre-wrap text-slate-800">{t.body}</span>
                </li>
              ))}
            </ol>
          </Card>

          {canTriage ? (
            <Card title="Work on this incident">
              <IncidentActions incident={incident.data} />
            </Card>
          ) : null}
        </div>
      )}
    </>
  );
}
