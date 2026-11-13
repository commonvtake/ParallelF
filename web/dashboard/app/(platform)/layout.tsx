import type { ReactNode } from "react";

import { Sidebar } from "@/components/sidebar";
import { requireSession } from "@/lib/session/session";

/** Shell for every signed-in page. Visitors without a session go to /login. */
export default async function PlatformLayout({ children }: { children: ReactNode }) {
  const session = await requireSession();
  const displayName = session.user.name ?? session.user.username;

  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-end gap-4 border-b border-slate-200 bg-white px-6 py-3">
          <span className="text-sm text-slate-600">
            Signed in as <span className="font-medium text-slate-900">{displayName}</span>
          </span>
          <form action="/auth/logout" method="post">
            <button
              type="submit"
              className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100"
            >
              Sign out
            </button>
          </form>
        </header>
        <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">{children}</main>
      </div>
    </div>
  );
}
