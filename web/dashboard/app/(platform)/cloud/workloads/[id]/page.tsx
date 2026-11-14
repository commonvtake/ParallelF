import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { ApiError } from "@/components/api-error";
import { AutoRefresh } from "@/components/cloud/auto-refresh";
import { CloudNav } from "@/components/cloud/cloud-nav";
import { MetricsChart } from "@/components/cloud/metrics-chart";
import { WorkloadStateBadge } from "@/components/cloud/state-badge";
import { WindowPicker } from "@/components/cloud/window-picker";
import { WorkloadActions } from "@/components/cloud/workload-actions";
import { Card, PageHeader } from "@/components/page-header";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, Metrics, Workload, WorkloadEventList } from "@/lib/api/types";
import { formatMiB, isTransitional, parseWindow, series, windowRange } from "@/lib/cloud";
import { formatTimestamp } from "@/lib/format";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Workload · Cloud" };

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium text-slate-500 uppercase">{label}</dt>
      <dd className="mt-0.5 text-sm break-all text-slate-900">{children}</dd>
    </div>
  );
}

const SAFE_ID = /^[0-9a-f-]{36}$/;

export default async function WorkloadPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { id } = await params;
  if (!SAFE_ID.test(id)) notFound();
  const metricWindow = parseWindow((await searchParams).window);
  const session = await requireSession();
  const base = `/api/v1/cloud/workloads/${id}`;
  const [me, workload, events, metrics] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<Workload>(session, base),
    gatewayGet<WorkloadEventList>(session, `${base}/events`),
    gatewayGet<Metrics>(session, `${base}/metrics?window=${metricWindow}`),
  ]);
  redirectIfUnauthorized(session, me, workload, events, metrics);
  if (!workload.ok && workload.status === 404) notFound();

  const canManage = me.ok && me.data.permissions.includes("cloud.workloads.manage");
  const { start, end } = windowRange(metricWindow);
  const { cpu, memory } = series(metrics.ok ? metrics.data.points : []);

  if (!workload.ok) {
    return (
      <>
        <PageHeader title="Cloud" summary="Workload" />
        <CloudNav current="/cloud/workloads" />
        <ApiError what="the workload" status={workload.status} problem={workload.problem} />
      </>
    );
  }
  const w = workload.data;
  const converging = isTransitional(w.state) || w.generation !== w.observed_generation;

  return (
    <>
      <PageHeader title="Cloud" summary="Workload details, lifecycle and utilisation.">
        <WindowPicker current={metricWindow} basePath={`/cloud/workloads/${w.id}`} />
      </PageHeader>
      <CloudNav current="/cloud/workloads" />
      <AutoRefresh active={converging && w.state !== "DELETED"} />
      <div className="space-y-6">
        <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-xs">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs text-slate-500">
                <Link href="/cloud/workloads" className="underline">
                  Workloads
                </Link>{" "}
                / {w.kind === "vm" ? "Virtual machine" : "Container"}
              </p>
              <h2 className="mt-1 flex items-center gap-2 text-lg font-semibold text-slate-900">
                {w.name} <WorkloadStateBadge state={w.state} />
              </h2>
              {w.status_message ? (
                <p data-testid="status-message" className="mt-1 max-w-2xl text-sm text-slate-600">
                  {w.status_message}
                </p>
              ) : null}
            </div>
            {canManage ? <WorkloadActions workload={w} /> : null}
          </div>
          <dl className="mt-5 grid gap-4 sm:grid-cols-3">
            <Field label="Template">
              {w.template} v{w.template_version}
            </Field>
            <Field label="Flavor">
              {w.flavor}: {w.vcpus} vCPU, {formatMiB(w.memory_mib)}
              {w.kind === "vm" ? `, ${w.disk_gib} GiB` : ""}
            </Field>
            <Field label="Node">{w.node ?? "Not placed yet"}</Field>
            <Field label="Network">{w.network}</Field>
            <Field label="Address">
              <span className="font-mono">{w.ip}</span>
            </Field>
            <Field label="MAC">
              <span className="font-mono">{w.mac}</span>
            </Field>
            <Field label="Desired state">{w.desired_state}</Field>
            <Field label="Generation">
              {w.observed_generation} of {w.generation} applied
            </Field>
            <Field label="Created">{formatTimestamp(w.created_at)}</Field>
          </dl>
        </section>

        <Card title="Utilisation">
          {metrics.ok ? (
            <div className="grid gap-6 lg:grid-cols-2">
              <MetricsChart
                title="CPU (% of its vCPUs)"
                points={cpu}
                start={start}
                end={end}
                unit="percent"
              />
              <MetricsChart title="Memory in use" points={memory} start={start} end={end} unit="mib" />
            </div>
          ) : (
            <ApiError what="metrics" status={metrics.status} problem={metrics.problem} />
          )}
        </Card>

        <Card title="History">
          {events.ok ? (
            <ol aria-label="Workload history" className="divide-y divide-slate-100">
              {events.data.items.map((e) => (
                <li key={e.id} className="flex flex-wrap gap-x-4 gap-y-1 py-2 text-sm">
                  <span className="w-36 shrink-0 text-xs text-slate-500 tabular-nums">
                    {formatTimestamp(e.at)}
                  </span>
                  <span className="w-16 shrink-0 text-xs font-medium text-slate-500 uppercase">{e.type}</span>
                  <span className="min-w-0 flex-1 text-slate-800">{e.message}</span>
                </li>
              ))}
            </ol>
          ) : (
            <ApiError what="the history" status={events.status} problem={events.problem} />
          )}
        </Card>
      </div>
    </>
  );
}
