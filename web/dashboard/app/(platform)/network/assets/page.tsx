import type { Metadata } from "next";

import { ApiError } from "@/components/api-error";
import { Card, PageHeader } from "@/components/page-header";
import { NETWORK_TABS, SectionTabs } from "@/components/section-tabs";
import { StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { NetworkAssetList } from "@/lib/api/types";
import { formatTimestamp } from "@/lib/format";
import { partyLabel } from "@/lib/netguard";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Assets · Network Monitoring" };

export default async function AssetsPage() {
  const session = await requireSession();
  const assets = await gatewayGet<NetworkAssetList>(session, "/api/v1/network/assets");
  redirectIfUnauthorized(session, assets);

  return (
    <>
      <PageHeader
        title="Network Monitoring"
        summary="Every address seen on ParallelF's networks, attributed to a Cloud workload, a VPN device or the platform."
      />
      <SectionTabs label="Network Monitoring" tabs={NETWORK_TABS} current="/network/assets" />
      <Card title="Assets">
        {!assets.ok ? (
          <ApiError what="assets" status={assets.status} problem={assets.problem} />
        ) : assets.data.items.length === 0 ? (
          <p className="text-sm text-slate-600">No traffic has been seen yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Assets</caption>
              <thead className="text-xs text-slate-500 uppercase">
                <tr>
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Address
                  </th>
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Attribution
                  </th>
                  <th scope="col" className="py-2 pr-4 font-medium">
                    Open ports
                  </th>
                  <th scope="col" className="py-2 text-right font-medium">
                    Last seen
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {assets.data.items.map((a) => (
                  <tr key={a.ip} data-testid={`asset-${a.ip}`}>
                    <th scope="row" className="py-2 pr-4 font-mono text-xs font-medium">
                      {a.ip}
                      <span className="block font-sans font-normal text-slate-500">{a.first_iface}</span>
                    </th>
                    <td className="py-2 pr-4 text-xs">
                      {a.attribution.kind === "unknown" ? (
                        <StatusBadge tone="warn">Unattributed</StatusBadge>
                      ) : (
                        partyLabel(a.attribution)
                      )}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs">{a.open_ports.join(", ") || "—"}</td>
                    <td className="py-2 text-right text-xs text-slate-600">
                      {formatTimestamp(a.last_seen_at)}
                      <span className="block">{a.events.toLocaleString("en-US")} events</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
