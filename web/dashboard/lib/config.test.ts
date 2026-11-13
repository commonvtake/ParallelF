import { describe, expect, it } from "vitest";

import { ConfigError, loadConfig } from "./config";

const valid = {
  PF_PUBLIC_URL: "http://localhost:3000/",
  PF_GATEWAY_URL: "http://gateway:8000",
  PF_OIDC_ISSUER: "http://localhost:8080/realms/parallelf",
  PF_OIDC_DISCOVERY_URL: "http://keycloak:8080/realms/parallelf/.well-known/openid-configuration",
  PF_OIDC_CLIENT_ID: "parallelf-dashboard",
  PF_OIDC_CLIENT_SECRET: "secret",
};

describe("loadConfig", () => {
  it("applies defaults and strips trailing slashes", () => {
    const config = loadConfig(valid);

    expect(config.publicUrl).toBe("http://localhost:3000");
    expect(config.cookieSecure).toBe(true);
    expect(config.sessionTtlSeconds).toBe(12 * 3600);
    expect(config.version).toBe("dev");
  });

  it("reads optional settings", () => {
    const config = loadConfig({
      ...valid,
      PF_COOKIE_SECURE: "false",
      PF_SESSION_TTL_HOURS: "1",
      PF_VERSION: "1.2.3",
    });

    expect(config.cookieSecure).toBe(false);
    expect(config.sessionTtlSeconds).toBe(3600);
    expect(config.version).toBe("1.2.3");
  });

  it("reports every problem at once without echoing secrets", () => {
    const attempt = () =>
      loadConfig({
        PF_PUBLIC_URL: "localhost:3000",
        PF_OIDC_CLIENT_SECRET: "",
        PF_COOKIE_SECURE: "maybe",
        PF_SESSION_TTL_HOURS: "-1",
      });

    expect(attempt).toThrow(ConfigError);
    try {
      attempt();
    } catch (error) {
      const message = (error as Error).message;
      for (const name of [
        "PF_PUBLIC_URL",
        "PF_GATEWAY_URL",
        "PF_OIDC_ISSUER",
        "PF_OIDC_DISCOVERY_URL",
        "PF_OIDC_CLIENT_ID",
        "PF_OIDC_CLIENT_SECRET",
        "PF_COOKIE_SECURE",
        "PF_SESSION_TTL_HOURS",
      ]) {
        expect(message).toContain(name);
      }
    }
  });
});
