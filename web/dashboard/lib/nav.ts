// Single source of truth for the dashboard's sections.

export type SectionStatus = "available" | "not-implemented";

export interface Section {
  href: string;
  label: string;
  status: SectionStatus;
  /** One-line description shown on the overview page. */
  summary: string;
}

export const SECTIONS: readonly Section[] = [
  {
    href: "/",
    label: "Overview",
    status: "available",
    summary: "Live health of the platform's services and dependencies.",
  },
  {
    href: "/cloud",
    label: "Cloud",
    status: "not-implemented",
    summary: "Virtual machines, containers, scheduling and virtual networks.",
  },
  {
    href: "/vpn",
    label: "VPN",
    status: "not-implemented",
    summary: "WireGuard devices, access policies and connection monitoring.",
  },
  {
    href: "/network",
    label: "Network Monitoring",
    status: "not-implemented",
    summary: "Authorized discovery, telemetry, topology, alerts and incidents.",
  },
  {
    href: "/lab",
    label: "Security Lab",
    status: "not-implemented",
    summary: "Isolated environments for defensive game-security research.",
  },
  {
    href: "/ai",
    label: "AI Investigator",
    status: "not-implemented",
    summary: "Read-only, evidence-cited incident investigations.",
  },
  {
    href: "/settings",
    label: "Settings",
    status: "available",
    summary: "Your profile, roles, projects and session.",
  },
];

/** True when `pathname` is the section at `href` or a page beneath it. */
export function isActive(href: string, pathname: string): boolean {
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}
