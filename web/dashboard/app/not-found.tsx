import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto flex min-h-screen max-w-md flex-col items-start justify-center gap-4 p-6">
      <p className="text-sm font-medium text-slate-500">404</p>
      <h1 className="text-2xl font-semibold">Page not found</h1>
      <p className="text-slate-600">This address does not match any page of the dashboard.</p>
      <Link href="/" className="text-sm font-medium text-indigo-700 underline underline-offset-4">
        Go to the overview
      </Link>
    </main>
  );
}
