import { NextResponse } from "next/server";

// Evaluated per request so the version comes from the running container.
export const dynamic = "force-dynamic";

/** Liveness probe. Same JSON shape as the Go and Python services. */
export function GET(): NextResponse {
  return NextResponse.json(
    { status: "ok", service: "pf-dashboard", version: process.env.PF_VERSION ?? "dev" },
    { headers: { "cache-control": "no-store" } },
  );
}
