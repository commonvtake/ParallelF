// Server-side client for the gateway API. Used by server components; the
// browser reaches the same API through /bff/api/ (see app/bff).

import { redirect } from "next/navigation";

import { getConfig } from "@/lib/config";
import { errorMessage, log } from "@/lib/log";
import { getAccessToken } from "@/lib/session/session";
import { getSessionStore, type Session } from "@/lib/session/store";

import { parseProblem, type Problem } from "./problem";

export type ApiResult<T> = { ok: true; data: T } | { ok: false; status: number; problem: Problem };

const TIMEOUT_MS = 10_000;

/** GETs a gateway path on behalf of the session's user. */
export async function gatewayGet<T>(session: Session, path: string): Promise<ApiResult<T>> {
  const token = await getAccessToken(session);
  if (!token) {
    return { ok: false, status: 401, problem: parseProblem(401, null) };
  }

  let response: Response;
  try {
    response = await fetch(`${getConfig().gatewayUrl}${path}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    log.error("gateway request failed", { path, error: errorMessage(error) });
    return { ok: false, status: 503, problem: parseProblem(503, null) };
  }

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    return { ok: false, status: response.status, problem: parseProblem(response.status, body) };
  }
  return { ok: true, data: body as T };
}

/**
 * Ends the dashboard session and sends the user to sign in again when the
 * API no longer accepts their token.
 */
export function redirectIfUnauthorized(session: Session, ...results: ApiResult<unknown>[]): void {
  if (results.some((result) => !result.ok && result.status === 401)) {
    getSessionStore().deleteSession(session.id);
    redirect("/login?error=session_expired");
  }
}
