// Completes the authorization code flow and creates the dashboard session.

import { timingSafeEqual } from "node:crypto";

import { type NextRequest, NextResponse } from "next/server";

import { signedInPage } from "@/lib/auth/interstitial";
import { completeLogin } from "@/lib/auth/oidc";
import { getConfig } from "@/lib/config";
import { errorMessage, log } from "@/lib/log";
import {
  loginCookieName,
  loginCookieOptions,
  sessionCookieName,
  sessionCookieOptions,
} from "@/lib/session/cookies";
import { getSessionStore } from "@/lib/session/store";

export const dynamic = "force-dynamic";

function sameValue(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  const config = getConfig();
  const secure = config.cookieSecure;
  const store = getSessionStore();
  const params = request.nextUrl.searchParams;

  const clearLoginCookie = (response: NextResponse): NextResponse => {
    response.cookies.set(loginCookieName(secure), "", { ...loginCookieOptions(secure), maxAge: 0 });
    response.headers.set("cache-control", "no-store");
    return response;
  };
  const fail = (code: string): NextResponse =>
    clearLoginCookie(NextResponse.redirect(new URL(`/login?error=${code}`, config.publicUrl), 303));

  // The state must be the one this browser was given when it started.
  const state = params.get("state");
  const cookieState = request.cookies.get(loginCookieName(secure))?.value;
  if (!state || !cookieState || !sameValue(state, cookieState)) {
    return fail("invalid_state");
  }
  const pending = store.consumePendingLogin(state);
  if (!pending) {
    return fail("login_expired");
  }

  const providerError = params.get("error");
  if (providerError) {
    log.warn("identity provider returned an error", { error: providerError.slice(0, 100) });
    return fail("provider_error");
  }

  try {
    const { user, ...tokens } = await completeLogin(request.nextUrl.search, pending);
    const session = store.createSession({ user, ...tokens }, config.sessionTtlSeconds);
    log.info("signed in", { subject: user.subject });

    const response = new NextResponse(signedInPage(pending.returnTo), {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
    response.cookies.set(
      sessionCookieName(secure),
      session.id,
      sessionCookieOptions(secure, config.sessionTtlSeconds),
    );
    return clearLoginCookie(response);
  } catch (error) {
    log.warn("sign-in failed", { error: errorMessage(error) });
    return fail("login_failed");
  }
}
