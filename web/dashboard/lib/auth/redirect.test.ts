import { describe, expect, it } from "vitest";

import { isSameOrigin, sanitizeReturnTo } from "./redirect";

describe("sanitizeReturnTo", () => {
  it("keeps same-origin paths", () => {
    expect(sanitizeReturnTo("/settings")).toBe("/settings");
    expect(sanitizeReturnTo("/cloud?tab=networks")).toBe("/cloud?tab=networks");
    expect(sanitizeReturnTo("/")).toBe("/");
  });

  it.each([
    ["absolute URL", "https://evil.example/"],
    ["protocol-relative URL", "//evil.example/path"],
    ["backslash trick", "/\\evil.example"],
    ["javascript scheme", "javascript:alert(1)"],
    ["relative path", "settings"],
    ["control characters", "/settings\r\nSet-Cookie: x=1"],
    ["auth endpoint", "/auth/logout"],
    ["bff endpoint", "/bff/api/core/projects"],
    ["empty", ""],
    ["too long", `/${"a".repeat(600)}`],
  ])("rejects %s", (_name, target) => {
    expect(sanitizeReturnTo(target)).toBe("/");
  });

  it("handles missing values", () => {
    expect(sanitizeReturnTo(null)).toBe("/");
    expect(sanitizeReturnTo(undefined)).toBe("/");
  });
});

describe("isSameOrigin", () => {
  const publicUrl = "http://localhost:3000";

  it("accepts the dashboard's own origin", () => {
    expect(isSameOrigin("http://localhost:3000", publicUrl)).toBe(true);
  });

  it.each([
    ["missing header", null],
    ["other host", "http://evil.example"],
    ["other port", "http://localhost:3001"],
    ["other scheme", "https://localhost:3000"],
    ["opaque origin", "null"],
    ["garbage", "not a url"],
  ])("rejects %s", (_name, origin) => {
    expect(isSameOrigin(origin, publicUrl)).toBe(false);
  });
});
