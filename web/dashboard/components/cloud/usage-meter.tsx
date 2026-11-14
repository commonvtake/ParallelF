import { fraction } from "@/lib/cloud";

/**
 * A labelled meter of allocated against allocatable capacity. The numbers
 * are always printed; the bar only supports them.
 */
export function UsageMeter({
  label,
  used,
  total,
  format = (value: number) => String(value),
}: {
  label: string;
  used: number;
  total: number;
  format?: (value: number) => string;
}) {
  const share = fraction(used, total);
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2 text-sm">
        <span className="text-slate-600">{label}</span>
        <span className="text-slate-900 tabular-nums">
          {format(used)} <span className="text-slate-500">of {format(total)}</span>
        </span>
      </div>
      <div
        role="meter"
        aria-label={`${label} allocated`}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={Math.min(used, total)}
        aria-valuetext={`${format(used)} of ${format(total)}`}
        className="mt-1 h-2 overflow-hidden rounded-full bg-slate-100"
      >
        <div className="h-full rounded-full bg-[#2a78d6]" style={{ width: `${(share * 100).toFixed(1)}%` }} />
      </div>
    </div>
  );
}
