import type { ReactNode } from "react";

export function PageHeader({ title, summary, children }: { title: string; summary: string; children?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="mt-1 max-w-2xl text-sm text-slate-600">{summary}</p>
      </div>
      {children}
    </header>
  );
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-xs">
      {title ? <h2 className="mb-3 text-sm font-semibold text-slate-900">{title}</h2> : null}
      {children}
    </section>
  );
}
