import type { Metadata } from "next";

import { AuditLog, auditCursor } from "@/components/audit-log";
import { PageHeader } from "@/components/page-header";
import { SectionTabs, VPN_TABS } from "@/components/section-tabs";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { AuditPage as AuditPageData, AuditVerification } from "@/lib/api/types";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Audit · VPN" };

export default async function VPNAuditPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const cursor = auditCursor((await searchParams).before);
  const session = await requireSession();
  const [page, verification] = await Promise.all([
    gatewayGet<AuditPageData>(session, `/api/v1/vpn/audit?limit=50${cursor ? `&before=${cursor}` : ""}`),
    gatewayGet<AuditVerification>(session, "/api/v1/vpn/audit/verify"),
  ]);
  redirectIfUnauthorized(session, page, verification);

  return (
    <>
      <PageHeader
        title="VPN"
        summary="Every enrolment, activation, revocation and policy change, hash-chained."
      />
      <SectionTabs label="VPN" tabs={VPN_TABS} current="/vpn/audit" />
      <AuditLog page={page} verification={verification} basePath="/vpn/audit" />
    </>
  );
}
