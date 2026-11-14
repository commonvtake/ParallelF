"use client";

import { type PointerEvent, useId, useState } from "react";

import { type ChartPoint, chartGeometry, formatMiB, nearestIndex } from "@/lib/cloud";

const WIDTH = 640;
const HEIGHT = 170;
const MARGIN = { top: 10, right: 12, bottom: 24, left: 52 };
const PLOT_W = WIDTH - MARGIN.left - MARGIN.right;
const PLOT_H = HEIGHT - MARGIN.top - MARGIN.bottom;
const SERIES_COLOR = "#2a78d6";

function clock(t: number, withDate: boolean): string {
  const iso = new Date(t).toISOString();
  return withDate ? `${iso.slice(5, 10)} ${iso.slice(11, 16)}` : iso.slice(11, 16);
}

interface Props {
  /** Names the single measure; the chart has no legend. */
  title: string;
  points: readonly ChartPoint[];
  /** Start and end of the time window, in ms since the epoch. */
  start: number;
  end: number;
  /** Percentages are drawn on a fixed 0–100 axis; memory on a nice maximum of the data. */
  unit: "percent" | "mib";
}

const FORMATS = {
  percent: (value: number) => `${Number.isInteger(value) ? value : value.toFixed(1)}%`,
  mib: formatMiB,
} as const;

/**
 * A single-measure line chart over a time window, drawn as SVG and hoverable:
 * a crosshair snaps to the nearest sample and a tooltip reads it out. A table
 * of the samples sits beneath it.
 */
export function MetricsChart({ title, points, start, end, unit }: Props) {
  const [hover, setHover] = useState(-1);
  const titleId = useId();
  const format = FORMATS[unit];
  const g = chartGeometry(
    points,
    { width: PLOT_W, height: PLOT_H, start, end },
    unit === "percent" ? 100 : undefined,
  );
  const multiDay = end - start > 12 * 60 * 60_000;
  const xTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => start + f * (end - start));

  function onMove(event: PointerEvent<SVGSVGElement>): void {
    const box = event.currentTarget.getBoundingClientRect();
    const x = ((event.clientX - box.left) / box.width) * WIDTH - MARGIN.left;
    setHover(nearestIndex(g.xs, x));
  }

  const active = hover >= 0 ? points[hover] : undefined;
  const ax = hover >= 0 ? (g.xs[hover] ?? 0) : 0;
  const ay = hover >= 0 ? (g.ys[hover] ?? 0) : 0;

  return (
    <figure className="min-w-0">
      <figcaption id={titleId} className="mb-1 text-sm font-medium text-slate-900">
        {title}
      </figcaption>
      {points.length === 0 ? (
        <p className="rounded-md border border-dashed border-slate-200 p-6 text-center text-sm text-slate-500">
          No samples in this window.
        </p>
      ) : (
        <div className="relative">
          <svg
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            className="block h-auto w-full touch-none select-none"
            role="img"
            aria-labelledby={titleId}
            onPointerMove={onMove}
            onPointerLeave={() => setHover(-1)}
          >
            <g transform={`translate(${MARGIN.left},${MARGIN.top})`}>
              {g.yTicks.map((tick) => {
                const y = PLOT_H - (tick / g.yMax) * PLOT_H;
                return (
                  <g key={tick}>
                    <line x1={0} x2={PLOT_W} y1={y} y2={y} stroke="#e2e8f0" strokeWidth={1} />
                    <text x={-8} y={y} dy="0.32em" textAnchor="end" fontSize={11} fill="#64748b">
                      {format(tick)}
                    </text>
                  </g>
                );
              })}
              {xTicks.map((t, i) => (
                <text
                  key={t}
                  x={(i / (xTicks.length - 1)) * PLOT_W}
                  y={PLOT_H + 17}
                  textAnchor={i === 0 ? "start" : i === xTicks.length - 1 ? "end" : "middle"}
                  fontSize={11}
                  fill="#64748b"
                >
                  {clock(t, multiDay)}
                </text>
              ))}
              <path
                d={g.line}
                fill="none"
                stroke={SERIES_COLOR}
                strokeWidth={2}
                strokeLinejoin="round"
                strokeLinecap="round"
              />
              {active ? (
                <g pointerEvents="none">
                  <line x1={ax} x2={ax} y1={0} y2={PLOT_H} stroke="#94a3b8" strokeWidth={1} />
                  <circle cx={ax} cy={ay} r={4} fill={SERIES_COLOR} stroke="#fff" strokeWidth={2} />
                </g>
              ) : null}
              {/* A transparent hit area larger than the line. */}
              <rect width={PLOT_W} height={PLOT_H} fill="transparent" />
            </g>
          </svg>
          {active ? (
            <div
              role="status"
              className="pointer-events-none absolute top-0 rounded-md border border-slate-200 bg-white px-2 py-1 text-xs shadow-sm"
              style={{
                left: `${((MARGIN.left + ax) / WIDTH) * 100}%`,
                transform: ax > PLOT_W / 2 ? "translateX(calc(-100% - 8px))" : "translateX(8px)",
              }}
            >
              <span className="block text-slate-500">{clock(active.t, true)} UTC</span>
              <span className="font-medium text-slate-900 tabular-nums">{format(active.value)}</span>
            </div>
          ) : null}
        </div>
      )}
      {points.length > 0 ? (
        <details className="mt-1 text-xs text-slate-600">
          <summary className="cursor-pointer">Show as table</summary>
          <div className="mt-2 max-h-48 overflow-y-auto">
            <table className="w-full text-left">
              <thead>
                <tr>
                  <th scope="col" className="py-1 pr-4 font-medium">
                    Time (UTC)
                  </th>
                  <th scope="col" className="py-1 text-right font-medium">
                    {title}
                  </th>
                </tr>
              </thead>
              <tbody className="tabular-nums">
                {[...points].reverse().map((p) => (
                  <tr key={p.t}>
                    <td className="py-0.5 pr-4">{clock(p.t, true)}</td>
                    <td className="py-0.5 text-right">{format(p.value)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      ) : null}
    </figure>
  );
}
