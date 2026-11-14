// Mapping of browser requests under /bff/api/ to gateway API paths.

const ALLOWED_DOMAINS = new Set(["core", "cloud", "ai", "system"]);
const SAFE_SEGMENT = /^[A-Za-z0-9._~-]+$/;

/**
 * Builds the gateway path for `/bff/api/<segments...>`, or returns null when
 * the request must not be forwarded. Only known API domains are reachable
 * and every segment is restricted to unreserved URL characters, so a
 * request cannot escape `/api/v1/<domain>/`.
 */
export function buildUpstreamPath(segments: readonly string[]): string | null {
  if (segments.length === 0 || segments.length > 12) return null;
  const [domain] = segments;
  if (!domain || !ALLOWED_DOMAINS.has(domain)) return null;
  for (const segment of segments) {
    if (segment === "." || segment === ".." || !SAFE_SEGMENT.test(segment)) return null;
  }
  return `/api/v1/${segments.join("/")}`;
}
