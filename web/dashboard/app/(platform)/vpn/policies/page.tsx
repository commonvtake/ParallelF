import type { Metadata } from "next";

import { ApiError } from "@/components/api-error";
import { Card, PageHeader } from "@/components/page-header";
import { SectionTabs, VPN_TABS } from "@/components/section-tabs";
import { PoliciesPanel } from "@/components/vpn/policies-panel";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, VPNPolicyList } from "@/lib/api/types";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Policies · VPN" };

export default async function VPNPoliciesPage() {
  const session = await requireSession();
  const [me, policies] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<VPNPolicyList>(session, "/api/v1/vpn/policies"),
  ]);
  redirectIfUnauthorized(session, me, policies);
  const canManage = me.ok && me.data.permissions.includes("vpn.policies.manage");

  return (
    <>
      <PageHeader title="VPN" summary="Default-deny access policies, compiled into the gateway's firewall." />
      <SectionTabs label="VPN" tabs={VPN_TABS} current="/vpn/policies" />
      <Card title="Access policies">
        {policies.ok ? (
          <PoliciesPanel policies={policies.data.items} canManage={canManage} />
        ) : (
          <ApiError what="policies" status={policies.status} problem={policies.problem} />
        )}
      </Card>
    </>
  );
}
