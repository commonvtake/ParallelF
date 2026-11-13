import type { Metadata } from "next";

import { NotImplemented } from "@/components/not-implemented";
import { SECTIONS } from "@/lib/nav";

export const metadata: Metadata = { title: "Cloud" };

const section = SECTIONS.find((candidate) => candidate.href === "/cloud");

const PLANNED = [
  "Virtual machines (KVM/libvirt) and containers behind one workload API",
  "Filter-and-score scheduler with quotas",
  "Declarative lifecycle management through node agents",
  "Virtual networks with IP address management and isolation",
] as const;

export default function Page() {
  return (
    <NotImplemented
      title="Cloud"
      summary={section?.summary ?? ""}
      planned={PLANNED}
      designDoc="subsystems/cloud.md"
      milestones="M4–M5"
    />
  );
}
