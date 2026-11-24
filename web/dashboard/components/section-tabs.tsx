import Link from "next/link";

/** Tabs between the pages of one section. */
export function SectionTabs({
  label,
  tabs,
  current,
}: {
  label: string;
  tabs: readonly { href: string; label: string }[];
  current: string;
}) {
  return (
    <nav aria-label={label} className="mb-6 flex gap-1 border-b border-slate-200">
      {tabs.map((tab) => {
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

export const NETWORK_TABS = [
  { href: "/network", label: "Alerts" },
  { href: "/network/incidents", label: "Incidents" },
  { href: "/network/assets", label: "Assets" },
  { href: "/network/scopes", label: "Discovery scopes" },
  { href: "/network/audit", label: "Audit" },
] as const;

export const VPN_TABS = [
  { href: "/vpn", label: "Devices" },
  { href: "/vpn/policies", label: "Policies" },
  { href: "/vpn/audit", label: "Audit" },
] as const;
