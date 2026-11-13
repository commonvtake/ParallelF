import { describe, expect, it } from "vitest";

import { SECTIONS, isActive } from "./nav";

describe("navigation", () => {
  it("lists the seven sections in order", () => {
    expect(SECTIONS.map((section) => section.label)).toEqual([
      "Overview",
      "Cloud",
      "VPN",
      "Network Monitoring",
      "Security Lab",
      "AI Investigator",
      "Settings",
    ]);
  });

  it("marks only Overview and Settings as available", () => {
    const available = SECTIONS.filter((section) => section.status === "available").map((s) => s.label);
    expect(available).toEqual(["Overview", "Settings"]);
  });

  it("has unique, absolute hrefs", () => {
    const hrefs = SECTIONS.map((section) => section.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
    for (const href of hrefs) expect(href.startsWith("/")).toBe(true);
  });

  it("matches the active section", () => {
    expect(isActive("/", "/")).toBe(true);
    expect(isActive("/", "/cloud")).toBe(false);
    expect(isActive("/cloud", "/cloud")).toBe(true);
    expect(isActive("/cloud", "/cloud/workloads")).toBe(true);
    expect(isActive("/lab", "/labs")).toBe(false);
  });
});
