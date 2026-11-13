import { describe, expect, it, vi } from "vitest";

import { MemorySessionStore } from "./store";
import { REFRESH_SKEW_MS, ensureAccessToken } from "./tokens";

function setup(overrides: { refreshToken?: string; expiresInMs: number }) {
  const now = 1_000_000;
  const store = new MemorySessionStore(() => now);
  const session = store.createSession(
    {
      user: { subject: "user-1", username: "owner" },
      accessToken: "access-1",
      accessTokenExpiresAt: now + overrides.expiresInMs,
      refreshToken: overrides.refreshToken,
    },
    3600,
  );
  return { store, session, now: () => now };
}

describe("ensureAccessToken", () => {
  it("returns the current token while it is fresh", async () => {
    const { store, session, now } = setup({ refreshToken: "refresh-1", expiresInMs: REFRESH_SKEW_MS + 1 });
    const refresh = vi.fn();

    await expect(ensureAccessToken(session, store, refresh, now)).resolves.toBe("access-1");
    expect(refresh).not.toHaveBeenCalled();
  });

  it("refreshes a token that is about to expire and stores the result", async () => {
    const { store, session, now } = setup({ refreshToken: "refresh-1", expiresInMs: REFRESH_SKEW_MS });
    const refresh = vi.fn().mockResolvedValue({
      accessToken: "access-2",
      accessTokenExpiresAt: now() + 300_000,
      refreshToken: "refresh-2",
    });

    await expect(ensureAccessToken(session, store, refresh, now)).resolves.toBe("access-2");

    expect(refresh).toHaveBeenCalledWith("refresh-1");
    const stored = store.getSession(session.id);
    expect(stored?.accessToken).toBe("access-2");
    expect(stored?.refreshToken).toBe("refresh-2");
  });

  it("shares one refresh between concurrent callers", async () => {
    const { store, session, now } = setup({ refreshToken: "refresh-1", expiresInMs: 0 });
    const refresh = vi.fn().mockResolvedValue({ accessToken: "access-2", accessTokenExpiresAt: now() + 300_000 });

    const results = await Promise.all([
      ensureAccessToken(session, store, refresh, now),
      ensureAccessToken(session, store, refresh, now),
      ensureAccessToken(session, store, refresh, now),
    ]);

    expect(results).toEqual(["access-2", "access-2", "access-2"]);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("ends the session when the refresh token is rejected", async () => {
    const { store, session, now } = setup({ refreshToken: "refresh-1", expiresInMs: 0 });
    const refresh = vi.fn().mockRejectedValue(new Error("invalid_grant"));

    await expect(ensureAccessToken(session, store, refresh, now)).resolves.toBeUndefined();
    expect(store.getSession(session.id)).toBeUndefined();
  });

  it("ends the session when there is no refresh token", async () => {
    const { store, session, now } = setup({ expiresInMs: 0 });
    const refresh = vi.fn();

    await expect(ensureAccessToken(session, store, refresh, now)).resolves.toBeUndefined();
    expect(refresh).not.toHaveBeenCalled();
    expect(store.getSession(session.id)).toBeUndefined();
  });
});
