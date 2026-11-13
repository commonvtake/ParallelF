// Request-scoped session access for server components and route handlers.

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { refreshTokens } from "@/lib/auth/oidc";
import { getConfig } from "@/lib/config";

import { sessionCookieName } from "./cookies";
import { getSessionStore, type Session } from "./store";
import { ensureAccessToken } from "./tokens";

/** The current session, or undefined when the visitor is not signed in. */
export async function getSession(): Promise<Session | undefined> {
  const jar = await cookies();
  const id = jar.get(sessionCookieName(getConfig().cookieSecure))?.value;
  return getSessionStore().getSession(id);
}

/** The current session; visitors who are not signed in go to /login. */
export async function requireSession(): Promise<Session> {
  const session = await getSession();
  if (!session) redirect("/login");
  return session;
}

/** A valid access token for the session, or undefined if it has ended. */
export function getAccessToken(session: Session): Promise<string | undefined> {
  return ensureAccessToken(session, getSessionStore(), refreshTokens);
}
