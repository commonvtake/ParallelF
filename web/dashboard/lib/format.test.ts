import { describe, expect, it } from "vitest";

import { escapeHtml, formatTimestamp } from "./format";

describe("formatTimestamp", () => {
  it("renders UTC to the minute regardless of the server's locale", () => {
    expect(formatTimestamp("2026-11-13T18:21:45.123456Z")).toBe("2026-11-13 18:21 UTC");
    expect(formatTimestamp("2026-11-13T12:21:45-06:00")).toBe("2026-11-13 18:21 UTC");
  });

  it("returns unparseable input unchanged", () => {
    expect(formatTimestamp("not a date")).toBe("not a date");
  });
});

describe("escapeHtml", () => {
  it("escapes every character that is significant in HTML", () => {
    expect(escapeHtml(`/x?a=1&b="2"<script>'`)).toBe("/x?a=1&amp;b=&quot;2&quot;&lt;script&gt;&#39;");
  });
});
