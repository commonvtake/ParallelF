import type { Metadata } from "next";

import { NotImplemented } from "@/components/not-implemented";
import { SECTIONS } from "@/lib/nav";

export const metadata: Metadata = { title: "Network Monitoring" };

const section = SECTIONS.find((candidate) => candidate.href === "/network");

const PLANNED = [
  "Discovery restricted to signed, authorized scopes",
  "Telemetry from Zeek and Suricata on platform-owned networks",
  "Asset inventory and network topology",
  "Detection rules, alerts and incident management",
] as const;

export default function Page() {
  return (
    <NotImplemented
      title="Network Monitoring"
      summary={section?.summary ?? ""}
      planned={PLANNED}
      designDoc="subsystems/netguard.md"
      milestones="M9–M10"
    />
  );
}
