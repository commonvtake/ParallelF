import type { Metadata } from "next";
import Link from "next/link";

import { ApiError } from "@/components/api-error";
import { AutoRefresh } from "@/components/cloud/auto-refresh";
import { Card, PageHeader } from "@/components/page-header";
import { SectionTabs, VPN_TABS } from "@/components/section-tabs";
import { type BadgeTone, StatusBadge } from "@/components/status-badge";
import { DeviceActions } from "@/components/vpn/device-actions";
import { EnrolForm } from "@/components/vpn/enrol-form";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, VPNDevice, VPNDeviceList, VPNGatewayList } from "@/lib/api/types";
import { stateLabel } from "@/lib/cloud";
import { formatTimestamp } from "@/lib/format";
import { SECTIONS } from "@/lib/nav";
import { requireSession } from "@/lib/session/session";
import { formatBytes, nowMs, remaining } from "@/lib/vpn";

export const metadata: Metadata = { title: "VPN" };

const summary = SECTIONS.find((section) => section.href === "/vpn")?.summary ?? "";

const STATE_TONES: Record<VPNDevice["state"], BadgeTone> = {
  PENDING: "warn",
  ENROLLED: "neutral",
  REVOKED: "down",
  EXPIRED: "neutral",
};

const CONNECTION_TONES: Record<VPNDevice["connection"], BadgeTone> = {
  online: "ok",
  idle: "warn",
  offline: "neutral",
};

function DevicesTable({
  devices,
  subject,
  now,
  showOwner,
}: {
  devices: readonly VPNDevice[];
  subject: string;
  now: number;
  showOwner: boolean;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">VPN devices</caption>
        <thead className="text-xs text-slate-500 uppercase">
          <tr>
            <th scope="col" className="py-2 pr-4 font-medium">
              Device
            </th>
            <th scope="col" className="py-2 pr-4 font-medium">
              State
            </th>
            <th scope="col" className="py-2 pr-4 font-medium">
              Connection
            </th>
            <th scope="col" className="py-2 pr-4 text-right font-medium">
              Traffic
            </th>
            <th scope="col" className="py-2 font-medium">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {devices.map((d) => (
            <tr key={d.id} data-testid={`device-${d.name}`} className="align-top">
              <th scope="row" className="py-3 pr-4 font-medium text-slate-900">
                {d.name}
                <span className="block font-mono text-xs font-normal text-slate-500">{d.address}</span>
                {showOwner ? (
                  <span className="block text-xs font-normal text-slate-500">{d.owner_name}</span>
                ) : null}
                <span className="block text-xs font-normal text-slate-500">
                  groups: {d.groups.join(", ") || "none"}
                </span>
              </th>
              <td className="py-3 pr-4">
                <span className="flex flex-wrap gap-1">
                  <StatusBadge tone={STATE_TONES[d.state]}>{stateLabel(d.state)}</StatusBadge>
                  {d.active ? <StatusBadge tone="ok">Active</StatusBadge> : null}
                </span>
                {d.active ? (
                  <span className="mt-1 block text-xs text-slate-500">{remaining(d, now)}</span>
                ) : null}
              </td>
              <td className="py-3 pr-4">
                <StatusBadge tone={CONNECTION_TONES[d.connection]}>{stateLabel(d.connection)}</StatusBadge>
                <span className="mt-1 block text-xs text-slate-500">
                  {d.last_handshake_at
                    ? `handshake ${formatTimestamp(d.last_handshake_at)}`
                    : "no handshake yet"}
                </span>
              </td>
              <td className="py-3 pr-4 text-right text-xs text-slate-600 tabular-nums">
                ↓ {formatBytes(d.rx_bytes)}
                <span className="block">↑ {formatBytes(d.tx_bytes)}</span>
              </td>
              <td className="py-3">
                <DeviceActions device={d} isOwner={d.owner_subject === subject} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default async function VPNPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const all = (await searchParams).scope === "all";
  const session = await requireSession();
  const [me, gateways, devices] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<VPNGatewayList>(session, "/api/v1/vpn/gateways"),
    gatewayGet<VPNDeviceList>(session, `/api/v1/vpn/devices${all ? "?scope=all" : ""}`),
  ]);
  redirectIfUnauthorized(session, me, gateways, devices);

  const permissions = me.ok ? me.data.permissions : [];
  const canUse = permissions.includes("vpn.devices.use");
  const canManage = permissions.includes("vpn.devices.manage");
  const subject = me.ok ? me.data.subject : "";
  const items = devices.ok ? devices.data.items : [];
  const converging = items.some((d) => d.state === "PENDING" || d.active);
  // Rendered on the server per request; the page refreshes itself.
  const now = nowMs();

  return (
    <>
      <PageHeader title="VPN" summary={summary} />
      <SectionTabs label="VPN" tabs={VPN_TABS} current="/vpn" />
      <AutoRefresh active={converging} intervalMs={5000} />
      <div className="space-y-6">
        <Card title="Gateway">
          {!gateways.ok ? (
            <ApiError what="gateways" status={gateways.status} problem={gateways.problem} />
          ) : gateways.data.items.length === 0 ? (
            <p data-testid="no-gateway" className="text-sm text-slate-600">
              No gateway has registered. On the gateway host run{" "}
              <code className="font-mono">make vpn-gateway-setup</code> and{" "}
              <code className="font-mono">make wg-agent-install</code> (see docs/vpn.md).
            </p>
          ) : (
            <ul className="space-y-3">
              {gateways.data.items.map((g) => (
                <li key={g.id} data-testid={`gateway-${g.name}`} className="text-sm">
                  <span className="flex flex-wrap items-center gap-2 font-medium text-slate-900">
                    {g.name}
                    <StatusBadge tone={g.status === "READY" ? "ok" : "down"}>
                      {stateLabel(g.status)}
                    </StatusBadge>
                    {g.applied_revision === g.revision ? (
                      <StatusBadge tone="neutral">In sync</StatusBadge>
                    ) : (
                      <StatusBadge tone="warn">Applying</StatusBadge>
                    )}
                  </span>
                  <span className="mt-1 block text-xs text-slate-600">
                    Endpoint <span className="font-mono">{g.endpoint}</span> · tunnel{" "}
                    <span className="font-mono">{g.address}</span> · last report{" "}
                    {formatTimestamp(g.last_seen_at)}
                  </span>
                  <span className="block font-mono text-xs break-all text-slate-500">
                    public key {g.public_key}
                  </span>
                  {g.apply_error ? (
                    <span className="block text-xs text-rose-700">Last error: {g.apply_error}</span>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title={all ? "All devices" : "My devices"}>
          {canManage ? (
            <p className="mb-3 text-sm">
              <Link href={all ? "/vpn" : "/vpn?scope=all"} className="text-slate-700 underline">
                {all ? "Show my devices" : "Show every user's devices"}
              </Link>
            </p>
          ) : null}
          {!devices.ok ? (
            <ApiError what="devices" status={devices.status} problem={devices.problem} />
          ) : items.length === 0 ? (
            <p className="text-sm text-slate-600">No devices enrolled.</p>
          ) : (
            <DevicesTable devices={items} subject={subject} now={now} showOwner={all} />
          )}
          <p className="mt-3 text-xs text-slate-500">
            An enrolled device can reach nothing until its owner activates it, after a recent sign-in. The
            activation ends on its own: the gateway&apos;s kernel drops the device when it expires, even if
            the control plane is down.
          </p>
        </Card>

        {canUse ? (
          <Card title="Enrol a device">
            <EnrolForm pskAvailable />
          </Card>
        ) : (
          <p className="text-sm text-slate-600">Your role can view the VPN but cannot enrol devices.</p>
        )}
      </div>
    </>
  );
}
