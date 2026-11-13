// Server-side configuration, read from the environment at request time so
// one container image runs in every environment.

export interface AppConfig {
  /** Browser-facing origin of the dashboard, e.g. http://localhost:3000 */
  publicUrl: string;
  /** Base URL of pf-gateway as reachable from this server. */
  gatewayUrl: string;
  oidc: {
    /** Exact issuer expected in ID tokens (the browser-facing provider URL). */
    issuer: string;
    /** Discovery document URL as reachable from this server. */
    discoveryUrl: string;
    clientId: string;
    clientSecret: string;
  };
  /** Mark cookies Secure and use the __Host- prefix. Requires HTTPS. */
  cookieSecure: boolean;
  /** Absolute lifetime of a dashboard session, in seconds. */
  sessionTtlSeconds: number;
  version: string;
}

export class ConfigError extends Error {}

function httpUrl(name: string, value: string | undefined, problems: string[]): string {
  const trimmed = (value ?? "").trim().replace(/\/+$/, "");
  if (!trimmed) {
    problems.push(`${name} is required`);
    return "";
  }
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("scheme");
  } catch {
    problems.push(`${name} must be an absolute http(s) URL`);
    return "";
  }
  return trimmed;
}

export function loadConfig(env: Record<string, string | undefined>): AppConfig {
  const problems: string[] = [];

  const required = (name: string): string => {
    const value = (env[name] ?? "").trim();
    if (!value) problems.push(`${name} is required`);
    return value;
  };

  const ttlHours = Number(env.PF_SESSION_TTL_HOURS ?? "12");
  if (!Number.isFinite(ttlHours) || ttlHours <= 0 || ttlHours > 24 * 7) {
    problems.push("PF_SESSION_TTL_HOURS must be a number between 0 and 168");
  }

  const cookieSecureRaw = (env.PF_COOKIE_SECURE ?? "true").trim().toLowerCase();
  if (cookieSecureRaw !== "true" && cookieSecureRaw !== "false") {
    problems.push("PF_COOKIE_SECURE must be true or false");
  }

  const config: AppConfig = {
    publicUrl: httpUrl("PF_PUBLIC_URL", env.PF_PUBLIC_URL, problems),
    gatewayUrl: httpUrl("PF_GATEWAY_URL", env.PF_GATEWAY_URL, problems),
    oidc: {
      issuer: httpUrl("PF_OIDC_ISSUER", env.PF_OIDC_ISSUER, problems),
      discoveryUrl: httpUrl("PF_OIDC_DISCOVERY_URL", env.PF_OIDC_DISCOVERY_URL, problems),
      clientId: required("PF_OIDC_CLIENT_ID"),
      clientSecret: required("PF_OIDC_CLIENT_SECRET"),
    },
    cookieSecure: cookieSecureRaw !== "false",
    sessionTtlSeconds: Math.round(ttlHours * 3600),
    version: (env.PF_VERSION ?? "dev").trim() || "dev",
  };

  if (problems.length > 0) {
    throw new ConfigError(`invalid configuration: ${problems.join("; ")}`);
  }
  return config;
}

let cached: AppConfig | undefined;

/** Returns the validated configuration, loading it on first use. */
export function getConfig(): AppConfig {
  cached ??= loadConfig(process.env);
  return cached;
}
