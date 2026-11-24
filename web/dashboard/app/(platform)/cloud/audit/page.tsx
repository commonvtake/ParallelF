import type { Metadata } from "next";

import { AuditLog, auditCursor } from "@/components/audit-log";
import { CloudNav } from "@/components/cloud/cloud-nav";
import { PageHeader } from "@/components/page-header";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { AuditPage as AuditPageData, AuditVerification } from "@/lib/api/types";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Audit · Cloud" };

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const cursor = auditCursor((await searchParams).before);
  const session = await requireSession();
  const [page, verification] = await Promise.all([
    gatewayGet<AuditPageData>(session, `/api/v1/cloud/audit?limit=50${cursor ? `&before=${cursor}` : ""}`),
    gatewayGet<AuditVerification>(session, "/api/v1/cloud/audit/verify"),
  ]);
  redirectIfUnauthorized(session, page, verification);

  return (
    <>
      <PageHeader
        title="Cloud"
        summary="Every change to cloud resources, in a hash-chained, append-only log."
      />
      <CloudNav current="/cloud/audit" />
      <AuditLog
        page={page}
        verification={verification}
        basePath="/cloud/audit"
        linkFor={(type, id) => (type === "workload" ? `/cloud/workloads/${id}` : undefined)}
      />
    </>
  );
}
