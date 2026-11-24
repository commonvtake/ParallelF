import type { Metadata } from "next";

import { ApiError } from "@/components/api-error";
import { ConfirmDelete } from "@/components/cloud/confirm-delete";
import { ScopeForm } from "@/components/network/scope-form";
import { Card, PageHeader } from "@/components/page-header";
import { NETWORK_TABS, SectionTabs } from "@/components/section-tabs";
import { type BadgeTone, StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, NetworkScope, NetworkScopeList } from "@/lib/api/types";
import { stateLabel } from "@/lib/cloud";
import { formatTimestamp } from "@/lib/format";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Discovery scopes · Network Monitoring" };

const TONES: Record<NetworkScope["status"], BadgeTone> = {
  active: "ok",
  expired: "neutral",
  revoked: "down",
};

export default async function ScopesPage() {
  const session = await requireSession();
  const [me, scopes] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<NetworkScopeList>(session, "/api/v1/network/scopes"),
  ]);
  redirectIfUnauthorized(session, me, scopes);
  const canManage = me.ok && me.data.permissions.includes("network.scopes.manage");

  return (
    <>
      <PageHeader
        title="Network Monitoring"
        summary="Active discovery runs only inside a signed scope: ParallelF's own networks, ICMP echo and TCP connect, rate-limited, time-boxed."
      />
      <SectionTabs label="Network Monitoring" tabs={NETWORK_TABS} current="/network/scopes" />
      <div className="space-y-6">
        <Card title="Scopes">
          {!scopes.ok ? (
            <ApiError what="scopes" status={scopes.status} problem={scopes.problem} />
          ) : scopes.data.items.length === 0 ? (
            <p className="text-sm text-slate-600">No discovery scope has been issued.</p>
          ) : (
            <ul className="divide-y divide-slate-100">
              {scopes.data.items.map((s) => (
                <li
                  key={s.id}
                  data-testid={`scope-${s.name}`}
                  className="flex flex-wrap items-start justify-between gap-3 py-3"
                >
                  <div className="text-sm">
                    <span className="flex flex-wrap items-center gap-2 font-medium text-slate-900">
                      {s.name}
                      <StatusBadge tone={TONES[s.status]}>{stateLabel(s.status)}</StatusBadge>
                    </span>
                    <span className="block font-mono text-xs text-slate-600">
                      {s.cidrs.join(", ")} · {s.techniques.join(" + ")}
                      {s.ports.length > 0 ? ` ports ${s.ports.join(", ")}` : ""} · {s.rate_pps}/s
                    </span>
                    <span className="block text-xs text-slate-500">
                      issued by {s.created_by} {formatTimestamp(s.issued_at)}, valid until{" "}
                      {formatTimestamp(s.valid_until)}
                    </span>
                    <span className="block text-xs text-slate-600">
                      Authorization: {s.authorization_note}
                    </span>
                  </div>
                  {canManage && s.status === "active" ? (
                    <ConfirmDelete noun="scope" verb="Revoke" name={s.name} path={`network/scopes/${s.id}`} />
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Card>
        {canManage ? (
          <Card title="Issue a scope">
            <ScopeForm />
          </Card>
        ) : (
          <p className="text-sm text-slate-600">Only owners and admins can issue discovery scopes.</p>
        )}
      </div>
    </>
  );
}
