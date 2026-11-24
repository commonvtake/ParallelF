// Helpers for the NetGuard (Network Monitoring) pages.

import type { BadgeTone } from "@/components/status-badge";
import type { NetworkAlert, NetworkIncident, NetworkParty } from "@/lib/api/types";

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

const SEVERITY_TONES: Record<Severity, BadgeTone> = {
  info: "neutral",
  low: "neutral",
  medium: "warn",
  high: "down",
  critical: "down",
};

export function severityTone(severity: string): BadgeTone {
  return SEVERITY_TONES[severity as Severity] ?? "neutral";
}

export function alertStatusTone(status: NetworkAlert["status"]): BadgeTone {
  return status === "open" ? "warn" : status === "acknowledged" ? "neutral" : "ok";
}

export function incidentStatusTone(status: NetworkIncident["status"]): BadgeTone {
  return status === "resolved" ? "ok" : status === "investigating" ? "warn" : "down";
}

const DETECTORS: Record<string, string> = {
  "suricata.passthrough": "Suricata signature",
  "ng.port_scan": "Port scan",
  "ng.new_device": "New device",
  "ng.lab_egress_attempt": "Lab egress attempt",
  "ng.dns_anomaly": "DNS anomaly",
};

export function detectorLabel(detector: string): string {
  return DETECTORS[detector] ?? detector;
}

const KINDS: Record<NetworkParty["kind"], string> = {
  workload: "Cloud workload",
  vpn_device: "VPN device",
  network_gateway: "Network gateway",
  infrastructure: "Platform",
  unknown: "Unattributed",
};

/** "VPN device alice/laptop (10.255.0.2)" or "Unattributed 10.20.1.9". */
export function partyLabel(party: NetworkParty | undefined): string {
  if (!party) return "—";
  const kind = KINDS[party.kind] ?? party.kind;
  return party.name ? `${kind} ${party.name} (${party.ip})` : `${kind} ${party.ip}`;
}

/** Transitions an analyst may make from a status, in display order. */
export function alertActions(
  status: NetworkAlert["status"],
): Array<"acknowledged" | "closed" | "suppressed" | "open"> {
  switch (status) {
    case "open":
      return ["acknowledged", "suppressed", "closed"];
    case "acknowledged":
      return ["suppressed", "closed"];
    case "suppressed":
      return ["open", "closed"];
    default:
      return [];
  }
}

/** UTF-8 text as base64, for JSON evidence uploads. */
export function textToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Splits "a, b c" into ["a", "b", "c"]. */
export function splitList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

/** Port numbers from free text; null when one is not a valid port. */
export function parsePorts(value: string): number[] | null {
  const ports: number[] = [];
  for (const item of splitList(value)) {
    const n = Number(item);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return null;
    ports.push(n);
  }
  return ports;
}
