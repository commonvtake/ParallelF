// Problem responses produced by the dashboard server itself.

import { NextResponse } from "next/server";

import type { Problem } from "@/lib/api/problem";
import { log } from "@/lib/log";

const PROBLEM_TYPE_BASE = "https://parallelf.dev/problems/";

/** Builds an RFC 9457 response in the same format as the backend services. */
export function problemResponse(status: number, slug: string, title: string, detail?: string): NextResponse {
  const problem: Problem = { type: PROBLEM_TYPE_BASE + slug, title, status, ...(detail ? { detail } : {}) };
  return NextResponse.json(problem, {
    status,
    headers: { "content-type": "application/problem+json", "cache-control": "no-store" },
  });
}

/** Refuses a state-changing request whose Origin is not the dashboard's own. */
export function crossOriginRefused(path: string, origin: string | null): NextResponse {
  log.warn("cross-origin request refused", { path, origin: origin?.slice(0, 200) ?? null });
  return problemResponse(403, "forbidden", "Permission denied", "Cross-origin requests are not accepted.");
}
