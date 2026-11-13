import type { Metadata } from "next";

import { NotImplemented } from "@/components/not-implemented";
import { SECTIONS } from "@/lib/nav";

export const metadata: Metadata = { title: "VPN" };

const section = SECTIONS.find((candidate) => candidate.href === "/vpn");

const PLANNED = [
  "WireGuard device enrolment with keys generated on the device",
  "Groups and default-deny access policies",
  "MFA-gated, time-limited access that expires on its own",
  "Connection monitoring and immediate revocation",
] as const;

export default function Page() {
  return (
    <NotImplemented
      title="VPN"
      summary={section?.summary ?? ""}
      planned={PLANNED}
      designDoc="subsystems/vpn.md"
      milestones="M7–M8"
    />
  );
}
