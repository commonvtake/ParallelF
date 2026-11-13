// Access-token freshness for server-side sessions.

import type { TokenSet } from "@/lib/auth/oidc";

import type { MemorySessionStore, Session } from "./store";

/** Refresh when the access token has less than this long to live. */
export const REFRESH_SKEW_MS = 30_000;

export type RefreshFn = (refreshToken: string) => Promise<TokenSet>;

// One refresh per session at a time: concurrent requests share the result.
const inFlight = new Map<string, Promise<string | undefined>>();

/**
 * Returns a usable access token for the session, refreshing it when it is
 * about to expire. Returns undefined when the session can no longer be
 * used; the session is then removed and the user must sign in again.
 */
export async function ensureAccessToken(
  session: Session,
  store: MemorySessionStore,
  refresh: RefreshFn,
  now: () => number = Date.now,
): Promise<string | undefined> {
  if (session.accessTokenExpiresAt - now() > REFRESH_SKEW_MS) {
    return session.accessToken;
  }
  if (!session.refreshToken) {
    store.deleteSession(session.id);
    return undefined;
  }

  const pending = inFlight.get(session.id);
  if (pending) return pending;

  const attempt = refresh(session.refreshToken)
    .then((tokens) => store.updateTokens(session.id, tokens)?.accessToken)
    .catch(() => {
      // The provider rejected the refresh token (expired or revoked session).
      store.deleteSession(session.id);
      return undefined;
    })
    .finally(() => inFlight.delete(session.id));

  inFlight.set(session.id, attempt);
  return attempt;
}
