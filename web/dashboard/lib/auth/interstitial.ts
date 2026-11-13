// The page shown for an instant after a successful sign-in.

import { escapeHtml } from "@/lib/format";

/**
 * Returns an HTML document that immediately navigates to `returnTo`.
 *
 * The callback cannot answer with an HTTP redirect: that redirect would be
 * part of a navigation started by the identity provider's site, and
 * browsers withhold SameSite=Strict cookies from such requests. A
 * navigation started by this same-origin document carries the new session
 * cookie. `returnTo` must already be sanitised to a same-origin path.
 */
export function signedInPage(returnTo: string): string {
  const target = escapeHtml(returnTo);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=${target}">
<meta name="robots" content="noindex">
<title>Signing in · ParallelF</title>
</head>
<body>
<p>Signed in. <a href="${target}">Continue to ParallelF</a></p>
</body>
</html>
`;
}
