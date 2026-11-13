import type { NextConfig } from "next";

// Static security headers for every response. A nonce-based script policy
// needs per-request middleware and is tracked as a follow-up (see README).
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  // "same-origin": no referrer is ever sent to another site. "no-referrer"
  // would also make browsers send `Origin: null` on same-site form posts,
  // which the CSRF origin check (lib/auth/redirect.ts) must then refuse.
  { key: "Referrer-Policy", value: "same-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
  { key: "Content-Security-Policy", value: "frame-ancestors 'none'; base-uri 'none'; object-src 'none'" },
];

const nextConfig: NextConfig = {
  // Self-contained server bundle for the container image.
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
