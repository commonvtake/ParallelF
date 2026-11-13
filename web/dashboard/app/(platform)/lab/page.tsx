import type { Metadata } from "next";

import { NotImplemented } from "@/components/not-implemented";
import { SECTIONS } from "@/lib/nav";

export const metadata: Metadata = { title: "Security Lab" };

const section = SECTIONS.find((candidate) => candidate.href === "/lab");

const PLANNED = [
  "Disposable lab environments with no route out",
  "Client/server trust research on a self-built Unity game",
  "Educational vulnerable programs with fixes and regression tests",
  "Findings recorded with their mitigation and verification",
] as const;

export default function Page() {
  return (
    <NotImplemented
      title="Security Lab"
      summary={section?.summary ?? ""}
      planned={PLANNED}
      designDoc="subsystems/security-lab.md"
      milestones="M11–M12"
    />
  );
}
