// Browser-side calls to the API through the backend-for-frontend proxy.

import { describeProblem, parseProblem } from "./problem";

/** A user-presentable explanation of a failed BFF response. */
export async function failureMessage(response: Response): Promise<string> {
  if (response.status === 401) return "Your session has ended. Reload the page and sign in again.";
  const body: unknown = await response.json().catch(() => null);
  return describeProblem(parseProblem(response.status, body));
}

/** Sends a JSON request to /bff/api/<path>. */
export function bff(path: string, method: string, body?: unknown): Promise<Response> {
  return fetch(`/bff/api/${path}`, {
    method,
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
