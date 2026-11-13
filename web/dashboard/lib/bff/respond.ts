// Problem responses produced by the dashboard server itself.

import { NextResponse } from "next/server";

import type { Problem } from "@/lib/api/problem";

const PROBLEM_TYPE_BASE = "https://parallelf.dev/problems/";

/** Builds an RFC 9457 response in the same format as the backend services. */
export function problemResponse(status: number, slug: string, title: string, detail?: string): NextResponse {
  const problem: Problem = { type: PROBLEM_TYPE_BASE + slug, title, status, ...(detail ? { detail } : {}) };
  return NextResponse.json(problem, {
    status,
    headers: { "content-type": "application/problem+json", "cache-control": "no-store" },
  });
}
