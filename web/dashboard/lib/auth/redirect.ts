// Helpers that keep redirects and cross-origin requests on our own origin.

const FALLBACK = "/";

/**
 * Returns `target` when it is a same-origin relative path, otherwise "/".
 * Prevents open redirects through the `returnTo` login parameter.
 */
export function sanitizeReturnTo(target: string | null | undefined): string {
  if (!target || target.length > 512) return FALLBACK;
  // Must be an absolute path; "//host" and "/\host" are protocol-relative URLs.
  if (!target.startsWith("/") || target.startsWith("//") || target.startsWith("/\\")) return FALLBACK;
  if (/[\u0000-\u001f\u007f]/.test(target)) return FALLBACK;
  // Never return to the auth endpoints themselves.
  if (target.startsWith("/auth/") || target.startsWith("/bff/")) return FALLBACK;
  try {
    const resolved = new URL(target, "http://dashboard.invalid");
    if (resolved.origin !== "http://dashboard.invalid") return FALLBACK;
    return resolved.pathname + resolved.search;
  } catch {
    return FALLBACK;
  }
}

/**
 * True when a state-changing request was sent by a page on our own origin.
 * Browsers always attach Origin to cross-origin POST/DELETE requests, so a
 * missing or different Origin is rejected (CSRF defence in depth on top of
 * the SameSite=Strict session cookie).
 */
export function isSameOrigin(originHeader: string | null, publicUrl: string): boolean {
  if (!originHeader) return false;
  try {
    return new URL(originHeader).origin === new URL(publicUrl).origin;
  } catch {
    return false;
  }
}
