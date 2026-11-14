import type { Metadata } from "next";
import Link from "next/link";

import { ApiError } from "@/components/api-error";
import { AutoRefresh } from "@/components/cloud/auto-refresh";
import { CloudNav } from "@/components/cloud/cloud-nav";
import { CreateWorkloadForm } from "@/components/cloud/create-workload-form";
import { WorkloadStateBadge } from "@/components/cloud/state-badge";
import { Card, PageHeader } from "@/components/page-header";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { FlavorList, Me, NetworkList, ProjectPage, TemplateList, WorkloadList } from "@/lib/api/types";
import { formatMiB, isTransitional } from "@/lib/cloud";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Workloads · Cloud" };

export default async function WorkloadsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const showDeleted = (await searchParams).state === "DELETED";
  const session = await requireSession();
  const [me, workloads, projects, templates, flavors, networks] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<WorkloadList>(session, `/api/v1/cloud/workloads${showDeleted ? "?state=DELETED" : ""}`),
    gatewayGet<ProjectPage>(session, "/api/v1/core/projects?limit=200"),
    gatewayGet<TemplateList>(session, "/api/v1/cloud/templates"),
    gatewayGet<FlavorList>(session, "/api/v1/cloud/flavors"),
    gatewayGet<NetworkList>(session, "/api/v1/cloud/networks"),
  ]);
  redirectIfUnauthorized(session, me, workloads, projects, templates, flavors, networks);

  const canManage = me.ok && me.data.permissions.includes("cloud.workloads.manage");
  const projectList = projects.ok ? projects.data.items : [];
  const projectName = new Map(projectList.map((p) => [p.id, p.name]));
  const items = workloads.ok ? workloads.data.items : [];

  return (
    <>
      <PageHeader
        title="Cloud"
        summary="Virtual machines and containers: what was asked for, where it runs and what state it is in."
      />
      <CloudNav current="/cloud/workloads" />
      <AutoRefresh active={items.some((w) => isTransitional(w.state))} />
      <div className="space-y-6">
        <Card title={showDeleted ? "Deleted workloads" : "Workloads"}>
          <p className="mb-3 text-sm">
            {showDeleted ? (
              <Link href="/cloud/workloads" className="text-slate-700 underline">
                Show live workloads
              </Link>
            ) : (
              <Link href="/cloud/workloads?state=DELETED" className="text-slate-700 underline">
                Show deleted workloads
              </Link>
            )}
          </p>
          {!workloads.ok ? (
            <ApiError what="workloads" status={workloads.status} problem={workloads.problem} />
          ) : items.length === 0 ? (
            <p className="text-sm text-slate-600">
              {showDeleted ? "No deleted workloads." : "No workloads yet."}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <caption className="sr-only">Workloads</caption>
                <thead className="text-xs text-slate-500 uppercase">
                  <tr>
                    <th scope="col" className="py-2 pr-4 font-medium">
                      Name
                    </th>
                    <th scope="col" className="py-2 pr-4 font-medium">
                      Project
                    </th>
                    <th scope="col" className="py-2 pr-4 font-medium">
                      Template
                    </th>
                    <th scope="col" className="py-2 pr-4 font-medium">
                      Size
                    </th>
                    <th scope="col" className="py-2 pr-4 font-medium">
                      Address
                    </th>
                    <th scope="col" className="py-2 pr-4 font-medium">
                      Node
                    </th>
                    <th scope="col" className="py-2 font-medium">
                      State
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {items.map((w) => (
                    <tr key={w.id} data-testid={`workload-${w.name}`}>
                      <th scope="row" className="py-2 pr-4 font-medium">
                        <Link href={`/cloud/workloads/${w.id}`} className="text-slate-900 underline">
                          {w.name}
                        </Link>
                        <span className="block text-xs font-normal text-slate-500">
                          {w.kind === "vm" ? "VM" : "Container"}
                        </span>
                      </th>
                      <td className="py-2 pr-4 text-slate-600">
                        {projectName.get(w.project_id) ?? w.project_id}
                      </td>
                      <td className="py-2 pr-4 text-slate-600">
                        {w.template} <span className="text-slate-400">v{w.template_version}</span>
                      </td>
                      <td className="py-2 pr-4 text-slate-600 tabular-nums">
                        {w.flavor}
                        <span className="block text-xs text-slate-500">
                          {w.vcpus} vCPU · {formatMiB(w.memory_mib)}
                          {w.kind === "vm" ? ` · ${w.disk_gib} GiB` : ""}
                        </span>
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs">
                        {w.ip}
                        <span className="block text-slate-500">{w.network}</span>
                      </td>
                      <td className="py-2 pr-4 text-slate-600">{w.node ?? "—"}</td>
                      <td className="py-2">
                        <WorkloadStateBadge state={w.state} />
                        {w.status_message ? (
                          <span
                            className="mt-1 block max-w-56 truncate text-xs text-slate-500"
                            title={w.status_message}
                          >
                            {w.status_message}
                          </span>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {canManage && !showDeleted ? (
          <Card title="New workload">
            {templates.ok && flavors.ok && networks.ok && projects.ok ? (
              <CreateWorkloadForm
                projects={projectList.map(({ id, name, slug }) => ({ id, name, slug }))}
                templates={templates.data.items}
                flavors={flavors.data.items}
                networks={networks.data.items}
              />
            ) : (
              <p className="text-sm text-slate-600">The catalogue could not be loaded.</p>
            )}
          </Card>
        ) : null}
      </div>
    </>
  );
}
