import Link from "next/link";

const TABS = [
  { href: "/cloud", label: "Overview" },
  { href: "/cloud/workloads", label: "Workloads" },
  { href: "/cloud/networks", label: "Networks" },
  { href: "/cloud/audit", label: "Audit" },
] as const;

export type CloudTab = (typeof TABS)[number]["href"];

/** Tabs between the Cloud pages. */
export function CloudNav({ current }: { current: CloudTab }) {
  return (
    <nav aria-label="Cloud" className="mb-6 flex gap-1 border-b border-slate-200">
      {TABS.map((tab) => {
        const active = tab.href === current;
        return (
          <Link
            key={tab.href}
            href={tab.href}
            aria-current={active ? "page" : undefined}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${
              active
                ? "border-slate-900 font-medium text-slate-900"
                : "border-transparent text-slate-600 hover:text-slate-900"
            }`}
          >
            {tab.label}
          </Link>
        );
      })}
    </nav>
  );
}
