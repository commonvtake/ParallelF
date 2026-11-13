"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { isActive, SECTIONS } from "@/lib/nav";

/** Primary navigation. Sections that are not built yet are marked "Planned". */
export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex shrink-0 flex-col bg-slate-900 text-slate-200 md:w-60">
      <div className="flex items-center gap-2 px-5 py-4">
        <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
        <span className="text-base font-semibold tracking-tight text-white">ParallelF</span>
      </div>
      <nav aria-label="Sections" className="flex gap-1 overflow-x-auto px-3 pb-3 md:flex-col md:overflow-visible">
        {SECTIONS.map((section) => {
          const active = isActive(section.href, pathname);
          return (
            <Link
              key={section.href}
              href={section.href}
              aria-current={active ? "page" : undefined}
              className={`flex items-center justify-between gap-3 rounded-md px-3 py-2 text-sm whitespace-nowrap transition-colors ${
                active ? "bg-slate-700 font-medium text-white" : "text-slate-300 hover:bg-slate-800 hover:text-white"
              }`}
            >
              <span>{section.label}</span>
              {section.status === "not-implemented" ? (
                <span className="rounded border border-slate-600 px-1.5 py-0.5 text-[10px] font-medium tracking-wide text-slate-400 uppercase">
                  Planned
                </span>
              ) : null}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
