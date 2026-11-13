import { describe, expect, it } from "vitest";

import { buildUpstreamPath } from "./paths";

describe("buildUpstreamPath", () => {
  it("maps known domains to the versioned gateway API", () => {
    expect(buildUpstreamPath(["core", "projects"])).toBe("/api/v1/core/projects");
    expect(buildUpstreamPath(["core", "projects", "0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f"])).toBe(
      "/api/v1/core/projects/0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f",
    );
    expect(buildUpstreamPath(["system", "status"])).toBe("/api/v1/system/status");
    expect(buildUpstreamPath(["ai", "info"])).toBe("/api/v1/ai/info");
  });

  it.each([
    ["empty path", []],
    ["unknown domain", ["admin", "users"]],
    ["parent traversal", ["core", "..", "..", "healthz"]],
    ["current-directory segment", ["core", ".", "projects"]],
    ["encoded slash", ["core", "projects/../../x"]],
    ["query injection", ["core", "projects?x=1"]],
    ["whitespace", ["core", "pro jects"]],
    ["empty segment", ["core", ""]],
    ["too deep", ["core", ...Array.from({ length: 12 }, () => "a")]],
  ])("refuses %s", (_name, segments) => {
    expect(buildUpstreamPath(segments)).toBeNull();
  });
});
