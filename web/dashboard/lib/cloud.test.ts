import { describe, expect, it } from "vitest";

import {
  allowedOperations,
  chartGeometry,
  formatMiB,
  gapThreshold,
  fraction,
  isTransitional,
  nearestIndex,
  niceMax,
  parseWindow,
  series,
  stateLabel,
} from "./cloud";

describe("allowedOperations mirrors the API's lifecycle rules", () => {
  const placed = { node_id: "0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f" };

  it.each([
    [{ ...placed, state: "RUNNING", desired_state: "running" }, ["stop", "delete"]],
    [{ ...placed, state: "STOPPED", desired_state: "stopped" }, ["start", "delete"]],
    [{ ...placed, state: "ERROR", desired_state: "running" }, ["start", "stop", "retry", "delete"]],
    [{ ...placed, state: "UNKNOWN", desired_state: "running" }, ["start", "stop", "delete"]],
    [{ ...placed, state: "DELETING", desired_state: "deleted" }, []],
    [{ ...placed, state: "DELETED", desired_state: "deleted" }, []],
    [{ state: "PENDING", desired_state: "running" }, ["delete"]],
    [{ state: "ERROR", desired_state: "running" }, ["retry", "delete"]],
  ] as const)("%o -> %o", (workload, expected) => {
    expect(allowedOperations(workload)).toEqual(expected);
  });
});

describe("presentation", () => {
  it("labels states", () => {
    expect(stateLabel("PROVISIONING")).toBe("Provisioning");
    expect(stateLabel("NOT_READY")).toBe("Not ready");
  });

  it("knows which states are converging", () => {
    expect(isTransitional("PROVISIONING")).toBe(true);
    expect(isTransitional("RUNNING")).toBe(false);
    expect(isTransitional("ERROR")).toBe(false);
  });

  it("formats memory", () => {
    expect(formatMiB(512)).toBe("512 MiB");
    expect(formatMiB(2048)).toBe("2 GiB");
    expect(formatMiB(1536)).toBe("1.5 GiB");
  });

  it("clamps fractions", () => {
    expect(fraction(1, 4)).toBe(0.25);
    expect(fraction(5, 4)).toBe(1);
    expect(fraction(1, 0)).toBe(0);
  });

  it("defaults the metrics window", () => {
    expect(parseWindow("6h")).toBe("6h");
    expect(parseWindow("7d")).toBe("1h");
    expect(parseWindow(undefined)).toBe("1h");
  });
});

describe("chart geometry", () => {
  it("rounds the axis up to a nice maximum", () => {
    expect(niceMax(0)).toBe(1);
    expect(niceMax(37)).toBe(50);
    expect(niceMax(180)).toBe(200);
    expect(niceMax(2100)).toBe(2500);
    expect(niceMax(100)).toBe(100);
  });

  it("places points in the box, time left to right and zero at the bottom", () => {
    const g = chartGeometry(
      [
        { t: 0, value: 0 },
        { t: 50, value: 50 },
        { t: 100, value: 100 },
      ],
      { width: 200, height: 100, start: 0, end: 100 },
    );
    expect(g.yMax).toBe(100);
    expect(g.xs).toEqual([0, 100, 200]);
    expect(g.ys).toEqual([100, 50, 0]);
    expect(g.line).toBe("M0.0,100.0 L100.0,50.0 L200.0,0.0");
    expect(g.yTicks).toEqual([0, 25, 50, 75, 100]);
  });

  it("breaks the line where samples are missing", () => {
    const points = [0, 10_000, 20_000, 30_000, 200_000, 210_000].map((t) => ({ t, value: 1 }));
    expect(gapThreshold(points)).toBe(30_000);
    const g = chartGeometry(points, { width: 210, height: 10, start: 0, end: 210_000 });
    expect(g.line.match(/M/g)).toHaveLength(2);
  });

  it("honours a fixed maximum and clamps values to it", () => {
    const g = chartGeometry([{ t: 0, value: 150 }], { width: 10, height: 10, start: 0, end: 1 }, 100);
    expect(g.ys).toEqual([0]);
  });

  it("finds the nearest point", () => {
    expect(nearestIndex([0, 10, 20], 14)).toBe(1);
    expect(nearestIndex([0, 10, 20], 16)).toBe(2);
    expect(nearestIndex([], 5)).toBe(-1);
  });

  it("splits metric points into one series per measure", () => {
    const { cpu, memory } = series([
      { at: "2026-11-13T10:00:00Z", cpu_percent: 12.5, memory_used_mib: 300 },
      { at: "not a time", cpu_percent: 1, memory_used_mib: 1 },
    ]);
    expect(cpu).toEqual([{ t: Date.parse("2026-11-13T10:00:00Z"), value: 12.5 }]);
    expect(memory).toEqual([{ t: Date.parse("2026-11-13T10:00:00Z"), value: 300 }]);
  });
});
