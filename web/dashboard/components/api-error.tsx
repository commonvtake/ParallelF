import { describeProblem, type Problem } from "@/lib/api/problem";

/** Shown in place of data that could not be loaded from the API. */
export function ApiError({ what, status, problem }: { what: string; status: number; problem: Problem }) {
  const denied = status === 403;
  return (
    <div role="alert" className="rounded-md border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
      <p className="font-medium">
        {denied ? `You do not have access to ${what}.` : `Could not load ${what}.`}
      </p>
      <p className="mt-1">{describeProblem(problem)}</p>
      {problem.request_id ? (
        <p className="mt-1 font-mono text-xs text-amber-800">Request ID: {problem.request_id}</p>
      ) : null}
    </div>
  );
}
