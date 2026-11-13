import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { sanitizeReturnTo } from "@/lib/auth/redirect";
import { getSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Sign in" };

const ERROR_MESSAGES: Record<string, string> = {
  session_expired: "Your session has ended. Sign in again to continue.",
  provider_unavailable: "The identity provider could not be reached. Check that it is running and try again.",
  provider_error: "The identity provider reported an error. Try again.",
  invalid_state: "The sign-in attempt could not be verified. Start again from this page.",
  login_expired: "The sign-in attempt took too long. Start again.",
  login_failed: "Sign-in could not be completed. Try again.",
};

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

interface Props {
  searchParams: Promise<{ error?: string | string[]; returnTo?: string | string[] }>;
}

export default async function LoginPage({ searchParams }: Props) {
  const params = await searchParams;
  const error = first(params.error);
  const returnTo = sanitizeReturnTo(first(params.returnTo));

  // Keep showing the page when an error is reported, so the message is read.
  if (!error && (await getSession())) {
    redirect(returnTo);
  }

  const message = error ? (ERROR_MESSAGES[error] ?? "Sign-in failed. Try again.") : undefined;
  const loginHref = returnTo === "/" ? "/auth/login" : `/auth/login?returnTo=${encodeURIComponent(returnTo)}`;

  return (
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center gap-6 p-6">
      <div>
        <p className="flex items-center gap-2 text-sm font-semibold tracking-tight text-slate-900">
          <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
          ParallelF
        </p>
        <h1 className="mt-4 text-2xl font-semibold tracking-tight">Sign in</h1>
        <p className="mt-1 text-sm text-slate-600">
          You will be sent to the platform&apos;s identity provider to authenticate.
        </p>
      </div>
      {message ? (
        <p role="alert" className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          {message}
        </p>
      ) : null}
      {/* A plain anchor: this is a route handler that redirects, not a page to prefetch. */}
      <a
        href={loginHref}
        className="rounded-md bg-slate-900 px-4 py-2.5 text-center text-sm font-medium text-white hover:bg-slate-700"
      >
        Sign in
      </a>
    </main>
  );
}
