// Starts the OpenID Connect authorization code flow (with PKCE).

import { type NextRequest, NextResponse } from "next/server";

import { beginLogin } from "@/lib/auth/oidc";
import { sanitizeReturnTo } from "@/lib/auth/redirect";
import { getConfig } from "@/lib/config";
import { errorMessage, log } from "@/lib/log";
import { loginCookieName, loginCookieOptions } from "@/lib/session/cookies";
import { getSessionStore } from "@/lib/session/store";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const config = getConfig();
  const returnTo = sanitizeReturnTo(request.nextUrl.searchParams.get("returnTo"));

  try {
    const { url, pending } = await beginLogin(returnTo);
    getSessionStore().createPendingLogin(pending);

    const response = NextResponse.redirect(url, 303);
    // Ties the login to this browser: the callback only accepts a `state`
    // that matches this cookie.
    response.cookies.set(
      loginCookieName(config.cookieSecure),
      pending.state,
      loginCookieOptions(config.cookieSecure),
    );
    response.headers.set("cache-control", "no-store");
    return response;
  } catch (error) {
    log.error("sign-in could not start", { error: errorMessage(error) });
    return NextResponse.redirect(new URL("/login?error=provider_unavailable", config.publicUrl), 303);
  }
}
