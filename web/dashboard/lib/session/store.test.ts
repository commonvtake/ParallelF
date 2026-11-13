import { describe, expect, it } from "vitest";

import { MemorySessionStore, randomToken, type NewSession } from "./store";

function clock(start = 1_000_000) {
  let now = start;
  return { now: () => now, advance: (ms: number) => (now += ms) };
}

const tokens: NewSession = {
  user: { subject: "user-1", username: "owner" },
  accessToken: "access-1",
  accessTokenExpiresAt: 1_300_000,
  refreshToken: "refresh-1",
  idToken: "id-1",
};

describe("randomToken", () => {
  it("returns distinct URL-safe values with 256 bits of entropy", () => {
    const a = randomToken();
    const b = randomToken();

    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe("MemorySessionStore sessions", () => {
  it("creates a session with an opaque id and absolute expiry", () => {
    const time = clock();
    const store = new MemorySessionStore(time.now);

    const session = store.createSession(tokens, 3600);

    expect(session.id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(session.expiresAt).toBe(time.now() + 3_600_000);
    expect(store.getSession(session.id)?.user.subject).toBe("user-1");
  });

  it("expires sessions at their absolute lifetime", () => {
    const time = clock();
    const store = new MemorySessionStore(time.now);
    const session = store.createSession(tokens, 60);

    time.advance(59_999);
    expect(store.getSession(session.id)).toBeDefined();
    time.advance(1);
    expect(store.getSession(session.id)).toBeUndefined();
    expect(store.sessionCount).toBe(0);
  });

  it("returns nothing for unknown or missing ids", () => {
    const store = new MemorySessionStore();

    expect(store.getSession(undefined)).toBeUndefined();
    expect(store.getSession("")).toBeUndefined();
    expect(store.getSession("unknown")).toBeUndefined();
  });

  it("updates tokens and keeps the previous refresh token when none is returned", () => {
    const store = new MemorySessionStore();
    const session = store.createSession(tokens, 3600);

    const updated = store.updateTokens(session.id, { accessToken: "access-2", accessTokenExpiresAt: 9 });

    expect(updated?.accessToken).toBe("access-2");
    expect(updated?.refreshToken).toBe("refresh-1");
    expect(store.updateTokens("unknown", { accessToken: "x", accessTokenExpiresAt: 1 })).toBeUndefined();
  });

  it("deletes sessions", () => {
    const store = new MemorySessionStore();
    const session = store.createSession(tokens, 3600);

    store.deleteSession(session.id);

    expect(store.getSession(session.id)).toBeUndefined();
    expect(() => store.deleteSession(undefined)).not.toThrow();
  });
});

describe("MemorySessionStore pending logins", () => {
  const pending = { state: "state-1", codeVerifier: "verifier", nonce: "nonce", returnTo: "/settings" };

  it("consumes a pending login exactly once", () => {
    const store = new MemorySessionStore();
    store.createPendingLogin(pending);

    expect(store.consumePendingLogin("state-1")?.codeVerifier).toBe("verifier");
    expect(store.consumePendingLogin("state-1")).toBeUndefined();
  });

  it("rejects unknown and expired states", () => {
    const time = clock();
    const store = new MemorySessionStore(time.now);
    store.createPendingLogin(pending);

    expect(store.consumePendingLogin("other")).toBeUndefined();
    expect(store.consumePendingLogin(undefined)).toBeUndefined();

    time.advance(10 * 60 * 1000);
    expect(store.consumePendingLogin("state-1")).toBeUndefined();
  });
});
