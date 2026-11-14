import type { Metadata } from "next";
import Link from "next/link";

import { ApiError } from "@/components/api-error";
import { AutoRefresh } from "@/components/cloud/auto-refresh";
import { CloudNav } from "@/components/cloud/cloud-nav";
import { MetricsChart } from "@/components/cloud/metrics-chart";
import { NodeActions } from "@/components/cloud/node-actions";
import { NodeStatusBadge, WorkloadStateBadge } from "@/components/cloud/state-badge";
import { UsageMeter } from "@/components/cloud/usage-meter";
import { WindowPicker } from "@/components/cloud/window-picker";
import { Card, PageHeader } from "@/components/page-header";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, Metrics, Node, NodeList, WorkloadList, WorkloadState } from "@/lib/api/types";
import { formatMiB, isTransitional, parseWindow, series, windowRange } from "@/lib/cloud";
import { formatTimestamp } from "@/lib/format";
import { SECTIONS } from "@/lib/nav";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Cloud" };

const summary = SECTIONS.find((section) => section.href === "/cloud")?.summary ?? "";

function NodeCard({
  node,
  metrics,
  start,
  end,
  canManage,
}: {
  node: Node;
  metrics: Metrics | undefined;
  start: number;
  end: number;
  canManage: boolean;
}) {
  const { cpu, memory } = series(metrics?.points ?? []);
  return (
    <section
      data-testid={`node-${node.name}`}
      className="rounded-lg border border-slate-200 bg-white p-5 shadow-xs"
    >
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
            {node.name} <NodeStatusBadge node={node} />
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            {node.hypervisor || "no hypervisor"} · {node.kvm ? "KVM" : "no KVM"} ·{" "}
            {node.docker ? "Docker" : "no Docker"} · agent {node.agent_version} · last report{" "}
            {formatTimestamp(node.last_seen_at)}
          </p>
        </div>
        {canManage ? <NodeActions node={node} /> : null}
      </div>
      <div className="grid gap-4 sm:grid-cols-3">
        <UsageMeter label="vCPUs allocated" used={node.allocated.vcpus} total={node.allocatable.vcpus} />
        <UsageMeter
          label="Memory allocated"
          used={node.allocated.memory_mib}
          total={node.allocatable.memory_mib}
          format={formatMiB}
        />
        <UsageMeter
          label="Disk allocated"
          used={node.allocated.disk_gib}
          total={node.allocatable.disk_gib}
          format={(v) => `${v} GiB`}
        />
      </div>
      <p className="mt-2 text-xs text-slate-500">
        Allocatable is the host ({node.cpu_count} CPUs, {formatMiB(node.memory_mib)}, {node.disk_gib} GiB)
        minus what is reserved for the host itself ({node.reserved_cpus} CPU,{" "}
        {formatMiB(node.reserved_memory_mib)}, {node.reserved_disk_gib} GiB); vCPUs may be overcommitted.{" "}
        {node.workloads} workload
        {node.workloads === 1 ? "" : "s"} placed.
      </p>
      <div className="mt-4 grid gap-6 lg:grid-cols-2">
        <MetricsChart title="Host CPU busy (%)" points={cpu} start={start} end={end} unit="percent" />
        <MetricsChart title="Host memory in use" points={memory} start={start} end={end} unit="mib" />
      </div>
    </section>
  );
}

export default async function CloudPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const metricWindow = parseWindow((await searchParams).window);
  const session = await requireSession();
  const [me, nodes, workloads] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<NodeList>(session, "/api/v1/cloud/nodes"),
    gatewayGet<WorkloadList>(session, "/api/v1/cloud/workloads"),
  ]);
  redirectIfUnauthorized(session, me, nodes, workloads);

  const nodeList = nodes.ok ? nodes.data.items : [];
  const metrics = await Promise.all(
    nodeList.map((node) =>
      gatewayGet<Metrics>(session, `/api/v1/cloud/nodes/${node.id}/metrics?window=${metricWindow}`),
    ),
  );
  const { start, end } = windowRange(metricWindow);
  const canManageNodes = me.ok && me.data.permissions.includes("cloud.nodes.manage");

  const counts = new Map<WorkloadState, number>();
  for (const w of workloads.ok ? workloads.data.items : [])
    counts.set(w.state, (counts.get(w.state) ?? 0) + 1);
  const converging = [...counts.keys()].some(isTransitional);

  return (
    <>
      <PageHeader title="Cloud" summary={summary}>
        <WindowPicker current={metricWindow} basePath="/cloud" />
      </PageHeader>
      <CloudNav current="/cloud" />
      <AutoRefresh active={converging} />
      <div className="space-y-6">
        <Card title="Workloads">
          {workloads.ok ? (
            counts.size === 0 ? (
              <p className="text-sm text-slate-600">
                No workloads yet.{" "}
                <Link href="/cloud/workloads" className="font-medium underline">
                  Create one
                </Link>
                .
              </p>
            ) : (
              <ul className="flex flex-wrap gap-4" aria-label="Workloads by state">
                {[...counts.entries()].map(([state, count]) => (
                  <li key={state} className="flex items-center gap-2 text-sm">
                    <span className="font-semibold text-slate-900 tabular-nums">{count}</span>
                    <WorkloadStateBadge state={state} />
                  </li>
                ))}
              </ul>
            )
          ) : (
            <ApiError what="workloads" status={workloads.status} problem={workloads.problem} />
          )}
        </Card>

        {!nodes.ok ? (
          <ApiError what="compute nodes" status={nodes.status} problem={nodes.problem} />
        ) : nodeList.length === 0 ? (
          <Card title="Compute nodes">
            <div data-testid="no-nodes" className="space-y-2 text-sm text-slate-600">
              <p>No compute node has registered. Workloads stay pending until one does.</p>
              <p>
                On a Linux host with KVM, run <code className="font-mono">make cloud-host-setup</code> once,
                then <code className="font-mono">make agent</code> (foreground) or{" "}
                <code className="font-mono">make agent-install</code> (systemd). See docs/cloud.md.
              </p>
            </div>
          </Card>
        ) : (
          nodeList.map((node, i) => {
            const result = metrics[i];
            return (
              <NodeCard
                key={node.id}
                node={node}
                metrics={result?.ok ? result.data : undefined}
                start={start}
                end={end}
                canManage={canManageNodes}
              />
            );
          })
        )}
      </div>
    </>
  );
}
