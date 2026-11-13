const STYLES = {
  ok: "border-emerald-200 bg-emerald-50 text-emerald-800",
  warn: "border-amber-200 bg-amber-50 text-amber-800",
  down: "border-rose-200 bg-rose-50 text-rose-800",
  neutral: "border-slate-200 bg-slate-100 text-slate-700",
} as const;

export type BadgeTone = keyof typeof STYLES;

/** A small labelled pill. The label carries the meaning; colour only supports it. */
export function StatusBadge({ tone, children }: { tone: BadgeTone; children: string }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${STYLES[tone]}`}>
      {children}
    </span>
  );
}
