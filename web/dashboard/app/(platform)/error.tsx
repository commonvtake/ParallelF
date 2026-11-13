"use client";

/** Error boundary for signed-in pages. */
export default function PlatformError({ reset }: { error: Error; reset: () => void }) {
  return (
    <div role="alert" className="rounded-md border border-rose-200 bg-rose-50 p-5 text-sm text-rose-900">
      <p className="font-medium">This page could not be displayed.</p>
      <p className="mt-1">The error has been logged by the dashboard server.</p>
      <button
        type="button"
        onClick={reset}
        className="mt-3 rounded-md border border-rose-300 bg-white px-3 py-1.5 font-medium hover:bg-rose-100"
      >
        Try again
      </button>
    </div>
  );
}
