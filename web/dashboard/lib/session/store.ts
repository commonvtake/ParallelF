// Server-side session storage.
//
// The browser only ever holds an opaque, random session id in an HttpOnly
// cookie. OIDC tokens stay in this process's memory and are never sent to
// the browser.
//
// This implementation keeps sessions in memory, which is correct for the
// single dashboard instance of local development. Running several
// instances needs a shared store behind the same interface.

import { randomBytes } from "node:crypto";

export interface SessionUser {
  subject: string;
  username: string;
  name?: string;
  email?: string;
}

export interface Session {
  id: string;
  user: SessionUser;
  accessToken: string;
  /** Unix time (ms) at which the access token expires. */
  accessTokenExpiresAt: number;
  refreshToken?: string;
  idToken?: string;
  createdAt: number;
  /** Unix time (ms) after which the session is invalid regardless of use. */
  expiresAt: number;
}

export interface PendingLogin {
  state: string;
  codeVerifier: string;
  nonce: string;
  returnTo: string;
  expiresAt: number;
}

export type NewSession = Omit<Session, "id" | "createdAt" | "expiresAt">;

const PENDING_LOGIN_TTL_MS = 10 * 60 * 1000;
const MAX_SESSIONS = 10_000;
const MAX_PENDING_LOGINS = 10_000;

/** 256 bits from the OS CSPRNG, URL-safe. */
export function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

export class MemorySessionStore {
  private readonly sessions = new Map<string, Session>();
  private readonly pendingLogins = new Map<string, PendingLogin>();

  constructor(private readonly now: () => number = Date.now) {}

  createSession(data: NewSession, ttlSeconds: number): Session {
    this.sweep();
    if (this.sessions.size >= MAX_SESSIONS) {
      // Drop the oldest session rather than grow without bound.
      const oldest = this.sessions.keys().next().value;
      if (oldest !== undefined) this.sessions.delete(oldest);
    }
    const createdAt = this.now();
    const session: Session = { ...data, id: randomToken(), createdAt, expiresAt: createdAt + ttlSeconds * 1000 };
    this.sessions.set(session.id, session);
    return session;
  }

  getSession(id: string | undefined): Session | undefined {
    if (!id) return undefined;
    const session = this.sessions.get(id);
    if (!session) return undefined;
    if (session.expiresAt <= this.now()) {
      this.sessions.delete(id);
      return undefined;
    }
    return session;
  }

  updateTokens(
    id: string,
    tokens: Pick<Session, "accessToken" | "accessTokenExpiresAt"> & Partial<Pick<Session, "refreshToken" | "idToken">>,
  ): Session | undefined {
    const session = this.getSession(id);
    if (!session) return undefined;
    session.accessToken = tokens.accessToken;
    session.accessTokenExpiresAt = tokens.accessTokenExpiresAt;
    if (tokens.refreshToken) session.refreshToken = tokens.refreshToken;
    if (tokens.idToken) session.idToken = tokens.idToken;
    return session;
  }

  deleteSession(id: string | undefined): void {
    if (id) this.sessions.delete(id);
  }

  createPendingLogin(data: Omit<PendingLogin, "expiresAt">): PendingLogin {
    this.sweep();
    if (this.pendingLogins.size >= MAX_PENDING_LOGINS) {
      const oldest = this.pendingLogins.keys().next().value;
      if (oldest !== undefined) this.pendingLogins.delete(oldest);
    }
    const pending: PendingLogin = { ...data, expiresAt: this.now() + PENDING_LOGIN_TTL_MS };
    this.pendingLogins.set(pending.state, pending);
    return pending;
  }

  /** Returns and removes the pending login: a state value works only once. */
  consumePendingLogin(state: string | undefined): PendingLogin | undefined {
    if (!state) return undefined;
    const pending = this.pendingLogins.get(state);
    if (!pending) return undefined;
    this.pendingLogins.delete(state);
    return pending.expiresAt > this.now() ? pending : undefined;
  }

  /** Removes expired entries. */
  sweep(): void {
    const now = this.now();
    for (const [id, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(id);
    }
    for (const [state, pending] of this.pendingLogins) {
      if (pending.expiresAt <= now) this.pendingLogins.delete(state);
    }
  }

  get sessionCount(): number {
    return this.sessions.size;
  }
}

// One store per process. `globalThis` keeps it across module reloads in
// development and across the separately bundled routes in production.
const globalStore = globalThis as typeof globalThis & { __pfSessionStore?: MemorySessionStore };

export function getSessionStore(): MemorySessionStore {
  globalStore.__pfSessionStore ??= new MemorySessionStore();
  return globalStore.__pfSessionStore;
}
