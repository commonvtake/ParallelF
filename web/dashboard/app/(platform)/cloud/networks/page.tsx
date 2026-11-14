import type { Metadata } from "next";

import { ApiError } from "@/components/api-error";
import { CloudNav } from "@/components/cloud/cloud-nav";
import { NetworksPanel } from "@/components/cloud/networks-panel";
import { Card, PageHeader } from "@/components/page-header";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, NetworkList, ProjectPage } from "@/lib/api/types";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Networks · Cloud" };

export default async function NetworksPage() {
  const session = await requireSession();
  const [me, networks, projects] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<NetworkList>(session, "/api/v1/cloud/networks"),
    gatewayGet<ProjectPage>(session, "/api/v1/core/projects?limit=200"),
  ]);
  redirectIfUnauthorized(session, me, networks, projects);

  const canManage = me.ok && me.data.permissions.includes("cloud.networks.manage");

  return (
    <>
      <PageHeader
        title="Cloud"
        summary="Virtual networks: addresses are assigned by the control plane, never by guesswork on the host."
      />
      <CloudNav current="/cloud/networks" />
      <Card title="Networks">
        {networks.ok ? (
          <NetworksPanel
            networks={networks.data.items}
            projects={(projects.ok ? projects.data.items : []).map(({ id, name, slug }) => ({
              id,
              name,
              slug,
            }))}
            canManage={canManage}
          />
        ) : (
          <ApiError what="networks" status={networks.status} problem={networks.problem} />
        )}
      </Card>
    </>
  );
}
