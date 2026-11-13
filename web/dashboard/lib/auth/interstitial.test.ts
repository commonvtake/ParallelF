import { describe, expect, it } from "vitest";

import { signedInPage } from "./interstitial";

describe("signedInPage", () => {
  it("navigates to the return path", () => {
    const html = signedInPage("/settings?tab=projects");

    expect(html).toContain('<meta http-equiv="refresh" content="0;url=/settings?tab=projects">');
    expect(html).toContain('<a href="/settings?tab=projects">');
  });

  it("escapes characters that could break out of the attribute", () => {
    const html = signedInPage('/x"><script>alert(1)</script>');

    expect(html).not.toContain("<script>");
    expect(html).toContain("&quot;&gt;&lt;script&gt;");
  });
});
