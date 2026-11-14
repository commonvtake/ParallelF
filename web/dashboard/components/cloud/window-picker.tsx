import Link from "next/link";

import { METRIC_WINDOWS, type MetricWindow } from "@/lib/cloud";

/** Links that switch the metrics window (?window=) of the current page. */
export function WindowPicker({ current, basePath }: { current: MetricWindow; basePath: string }) {
  return (
    <div
      role="group"
      aria-label="Time window"
      className="inline-flex rounded-md border border-slate-300 text-xs"
    >
      {METRIC_WINDOWS.map((w) => (
        <Link
          key={w}
          href={`${basePath}?window=${w}`}
          aria-current={w === current ? "true" : undefined}
          className={`px-2.5 py-1 first:rounded-l-md last:rounded-r-md ${
            w === current ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
          }`}
        >
          {w}
        </Link>
      ))}
    </div>
  );
}
