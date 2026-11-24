import type { Metadata } from "next";

import { AuditLog, auditCursor } from "@/components/audit-log";
import { PageHeader } from "@/components/page-header";
import { NETWORK_TABS, SectionTabs } from "@/components/section-tabs";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { AuditPage as AuditPageData, AuditVerification } from "@/lib/api/types";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Audit · Network Monitoring" };

function linkFor(resourceType: string, resourceId: string): string | undefined {
  if (resourceType === "alert") return `/network/alerts/${resourceId}`;
  if (resourceType === "incident") return `/network/incidents/${resourceId}`;
  if (resourceType === "scope") return "/network/scopes";
  return undefined;
}

export default async function NetworkAuditPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const cursor = auditCursor((await searchParams).before);
  const session = await requireSession();
  const [page, verification] = await Promise.all([
    gatewayGet<AuditPageData>(session, `/api/v1/network/audit?limit=50${cursor ? `&before=${cursor}` : ""}`),
    gatewayGet<AuditVerification>(session, "/api/v1/network/audit/verify"),
  ]);
  redirectIfUnauthorized(session, page, verification);

  return (
    <>
      <PageHeader
        title="Network Monitoring"
        summary="Every triage decision, incident change, evidence item and scope, hash-chained."
      />
      <SectionTabs label="Network Monitoring" tabs={NETWORK_TABS} current="/network/audit" />
      <AuditLog page={page} verification={verification} basePath="/network/audit" linkFor={linkFor} />
    </>
  );
}
