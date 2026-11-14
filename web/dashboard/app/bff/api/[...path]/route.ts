// Backend-for-frontend proxy: /bff/api/<domain>/... -> gateway /api/v1/<domain>/...
//
// The browser authenticates with its session cookie; this handler attaches
// the session's access token server-side, so tokens never reach the browser.

import { type NextRequest, NextResponse } from "next/server";

import { buildUpstreamPath } from "@/lib/api/paths";
import { isSameOrigin } from "@/lib/auth/redirect";
import { crossOriginRefused, problemResponse } from "@/lib/bff/respond";
import { getConfig } from "@/lib/config";
import { errorMessage, log } from "@/lib/log";
import { getAccessToken, getSession } from "@/lib/session/session";

export const dynamic = "force-dynamic";

const MAX_BODY_BYTES = 1 << 20;
const TIMEOUT_MS = 15_000;
const SAFE_METHODS = new Set(["GET", "HEAD"]);
const PASSED_RESPONSE_HEADERS = ["content-type", "location", "x-request-id"];

interface RouteContext {
  params: Promise<{ path: string[] }>;
}

async function forward(request: NextRequest, context: RouteContext): Promise<NextResponse> {
  const config = getConfig();
  const method = request.method;

  const origin = request.headers.get("origin");
  if (!SAFE_METHODS.has(method) && !isSameOrigin(origin, config.publicUrl)) {
    return crossOriginRefused(request.nextUrl.pathname, origin);
  }

  const session = await getSession();
  if (!session) {
    return problemResponse(401, "unauthorized", "Authentication required", "Sign in to continue.");
  }

  const { path } = await context.params;
  const upstreamPath = buildUpstreamPath(path);
  if (!upstreamPath) {
    return problemResponse(404, "not-found", "Resource not found", "No such route.");
  }

  const token = await getAccessToken(session);
  if (!token) {
    return problemResponse(
      401,
      "unauthorized",
      "Authentication required",
      "Your session has ended. Sign in again.",
    );
  }

  const headers = new Headers({ authorization: `Bearer ${token}`, accept: "application/json" });
  let body: ArrayBuffer | undefined;
  if (!SAFE_METHODS.has(method)) {
    body = await request.arrayBuffer();
    if (body.byteLength > MAX_BODY_BYTES) {
      return problemResponse(413, "payload-too-large", "Payload too large");
    }
    const contentType = request.headers.get("content-type");
    if (contentType) headers.set("content-type", contentType);
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${config.gatewayUrl}${upstreamPath}${request.nextUrl.search}`, {
      method,
      headers,
      body: body && body.byteLength > 0 ? body : undefined,
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    log.error("gateway request failed", { path: upstreamPath, error: errorMessage(error) });
    return problemResponse(502, "bad-gateway", "Upstream unavailable", "The API gateway did not respond.");
  }

  const responseHeaders = new Headers({ "cache-control": "no-store" });
  for (const name of PASSED_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) responseHeaders.set(name, value);
  }
  const hasBody = upstream.status !== 204 && upstream.status !== 304 && method !== "HEAD";
  return new NextResponse(hasBody ? upstream.body : null, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

export { forward as DELETE, forward as GET, forward as POST, forward as PUT };
