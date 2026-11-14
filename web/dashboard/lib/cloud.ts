// Pure helpers for the Cloud pages: state presentation, the lifecycle rules
// the API enforces (mirrored so buttons are only offered when they would be
// accepted), unit formatting and chart geometry.

import type { BadgeTone } from "@/components/status-badge";
import type { MetricPoint, Workload, WorkloadState } from "@/lib/api/types";

const STATE_TONES: Record<WorkloadState, BadgeTone> = {
  PENDING: "neutral",
  SCHEDULED: "neutral",
  PROVISIONING: "warn",
  RUNNING: "ok",
  STOPPING: "warn",
  STOPPED: "neutral",
  UNKNOWN: "warn",
  DELETING: "warn",
  DELETED: "neutral",
  ERROR: "down",
};

export function stateTone(state: WorkloadState): BadgeTone {
  return STATE_TONES[state];
}

/** "PROVISIONING" -> "Provisioning". */
export function stateLabel(state: string): string {
  const words = state.toLowerCase().replaceAll("_", " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** States the control plane is still converging; pages refresh while one is shown. */
export function isTransitional(state: WorkloadState): boolean {
  return ["PENDING", "SCHEDULED", "PROVISIONING", "STOPPING", "DELETING"].includes(state);
}

export type Operation = "start" | "stop" | "retry" | "delete";

/**
 * The operations the API accepts for a workload in its current state
 * (services/cloud/internal/domain/transitions.go and store.ChangeDesiredState).
 */
export function allowedOperations(w: Pick<Workload, "state" | "desired_state" | "node_id">): Operation[] {
  if (w.state === "DELETED") return [];
  const placed = Boolean(w.node_id);
  const ops: Operation[] = [];
  if (
    placed &&
    w.desired_state !== "deleted" &&
    ["STOPPED", "STOPPING", "ERROR", "UNKNOWN"].includes(w.state)
  ) {
    ops.push("start");
  }
  if (
    placed &&
    w.desired_state === "running" &&
    ["RUNNING", "PROVISIONING", "SCHEDULED", "ERROR", "UNKNOWN"].includes(w.state)
  ) {
    ops.push("stop");
  }
  if (w.state === "ERROR" && w.desired_state !== "deleted") ops.push("retry");
  if (w.desired_state !== "deleted") ops.push("delete");
  return ops;
}

/** 512 -> "512 MiB", 2048 -> "2 GiB", 1536 -> "1.5 GiB". */
export function formatMiB(mib: number): string {
  if (Math.abs(mib) < 1024) return `${Math.round(mib)} MiB`;
  const gib = mib / 1024;
  return `${Number.isInteger(gib) ? gib : gib.toFixed(1)} GiB`;
}

/** A share in [0, 1]; 0 when there is nothing to share. */
export function fraction(used: number, total: number): number {
  if (!(total > 0)) return 0;
  return Math.min(Math.max(used / total, 0), 1);
}

/** The smallest "nice" axis maximum (1, 2, 2.5, 5 x 10^n) at or above value. */
export function niceMax(value: number): number {
  if (!(value > 0)) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) {
    if (step * magnitude >= value) return step * magnitude;
  }
  return 10 * magnitude;
}

export interface ChartPoint {
  /** Milliseconds since the epoch. */
  t: number;
  value: number;
}

export interface ChartGeometry {
  /** SVG path data of the line; empty with fewer than one point. */
  line: string;
  /** Screen coordinates of each point, in input order. */
  xs: number[];
  ys: number[];
  yMax: number;
  /** Values of the horizontal grid lines, from 0 to yMax. */
  yTicks: number[];
}

/**
 * The gap between samples beyond which the line is broken rather than drawn
 * across missing data: three times the typical interval, at least 30 s.
 */
export function gapThreshold(points: readonly ChartPoint[]): number {
  const steps = points
    .slice(1)
    .map((p, i) => p.t - points[i]!.t)
    .sort((a, b) => a - b);
  const median = steps[Math.floor(steps.length / 2)] ?? 0;
  return Math.max(3 * median, 30_000);
}

/**
 * Lays points out in a width x height box. Time runs left to right across
 * [start, end]; values from 0 (bottom) to a nice maximum, or `fixedMax`.
 * The line is broken where samples are missing.
 */
export function chartGeometry(
  points: readonly ChartPoint[],
  box: { width: number; height: number; start: number; end: number },
  fixedMax?: number,
): ChartGeometry {
  const maxGap = gapThreshold(points);
  const peak = points.reduce((m, p) => Math.max(m, p.value), 0);
  const yMax = fixedMax ?? niceMax(peak);
  const span = Math.max(box.end - box.start, 1);
  const xs = points.map((p) => ((p.t - box.start) / span) * box.width);
  const ys = points.map((p) => box.height - (Math.min(Math.max(p.value, 0), yMax) / yMax) * box.height);
  const line = xs
    .map((x, i) => {
      const jump = i === 0 || points[i]!.t - points[i - 1]!.t > maxGap;
      return `${jump ? "M" : "L"}${x.toFixed(1)},${ys[i]!.toFixed(1)}`;
    })
    .join(" ");
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * yMax);
  return { line, xs, ys, yMax, yTicks };
}

/** Index of the point whose x is closest to `x`, or -1 without points. */
export function nearestIndex(xs: readonly number[], x: number): number {
  let best = -1;
  let distance = Infinity;
  xs.forEach((candidate, i) => {
    const d = Math.abs(candidate - x);
    if (d < distance) {
      best = i;
      distance = d;
    }
  });
  return best;
}

export const METRIC_WINDOWS = ["15m", "1h", "6h", "24h"] as const;
export type MetricWindow = (typeof METRIC_WINDOWS)[number];

const WINDOW_MS: Record<MetricWindow, number> = {
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "6h": 6 * 60 * 60_000,
  "24h": 24 * 60 * 60_000,
};

export function parseWindow(value: string | string[] | undefined): MetricWindow {
  return METRIC_WINDOWS.find((w) => w === value) ?? "1h";
}

export function windowMs(window: MetricWindow): number {
  return WINDOW_MS[window];
}

/** The [start, end] of a window that ends now, in ms since the epoch. */
export function windowRange(window: MetricWindow, now: number = Date.now()): { start: number; end: number } {
  return { start: now - WINDOW_MS[window], end: now };
}

/** Splits metric points into the two single-measure series the pages chart. */
export function series(points: readonly MetricPoint[]): { cpu: ChartPoint[]; memory: ChartPoint[] } {
  const cpu: ChartPoint[] = [];
  const memory: ChartPoint[] = [];
  for (const p of points) {
    const t = Date.parse(p.at);
    if (Number.isNaN(t)) continue;
    cpu.push({ t, value: p.cpu_percent });
    memory.push({ t, value: p.memory_used_mib });
  }
  return { cpu, memory };
}

/** Network names follow the API's resource-name rule. */
export const RESOURCE_NAME_PATTERN = "[a-z][a-z0-9\\-]{1,38}[a-z0-9]";
