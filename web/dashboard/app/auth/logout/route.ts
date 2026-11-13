// Ends the dashboard session and the identity provider's SSO session.

import { type NextRequest, NextResponse } from "next/server";

import { endSessionUrl } from "@/lib/auth/oidc";
import { isSameOrigin } from "@/lib/auth/redirect";
import { problemResponse } from "@/lib/bff/respond";
import { getConfig } from "@/lib/config";
import { errorMessage, log } from "@/lib/log";
import { sessionCookieName, sessionCookieOptions } from "@/lib/session/cookies";
import { getSession } from "@/lib/session/session";
import { getSessionStore } from "@/lib/session/store";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const config = getConfig();
  if (!isSameOrigin(request.headers.get("origin"), config.publicUrl)) {
    return problemResponse(403, "forbidden", "Permission denied", "Cross-origin requests are not accepted.");
  }

  let target = new URL("/login", config.publicUrl);
  const session = await getSession();
  if (session) {
    getSessionStore().deleteSession(session.id);
    log.info("signed out", { subject: session.user.subject });
    if (session.idToken) {
      try {
        target = await endSessionUrl(session.idToken);
      } catch (error) {
        // The local session is already gone; only single sign-out is skipped.
        log.warn("provider sign-out unavailable", { error: errorMessage(error) });
      }
    }
  }

  const response = NextResponse.redirect(target, 303);
  response.cookies.set(
    sessionCookieName(config.cookieSecure),
    "",
    sessionCookieOptions(config.cookieSecure, 0),
  );
  response.headers.set("cache-control", "no-store");
  return response;
}
