// RFC 9457 problem details as returned by every ParallelF service.

import type { components } from "./schema.gen";

export type Problem = components["schemas"]["Problem"];

/** Parses a problem document, tolerating bodies that are not one. */
export function parseProblem(status: number, body: unknown): Problem {
  if (body && typeof body === "object") {
    const candidate = body as Record<string, unknown>;
    if (typeof candidate.title === "string" && typeof candidate.status === "number") {
      return candidate as unknown as Problem;
    }
  }
  return {
    type: "about:blank",
    title: status >= 500 ? "The service is unavailable" : "The request failed",
    status,
  };
}

/** A short, user-presentable description of a problem. */
export function describeProblem(problem: Problem): string {
  const fieldMessages = (problem.errors ?? [])
    .map((error) => error.message ?? `${error.field}: ${error.code}`)
    .filter(Boolean);
  if (fieldMessages.length > 0) return fieldMessages.join(" ");
  return problem.detail ?? problem.title;
}
