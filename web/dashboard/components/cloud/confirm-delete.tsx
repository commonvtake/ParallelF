"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useId, useState } from "react";

import { bff, failureMessage } from "@/lib/api/browser";

interface Props {
  /** What is deleted, for the labels: "workload", "network". */
  noun: string;
  name: string;
  /** BFF path of the resource, e.g. "cloud/workloads/<id>". */
  path: string;
  /** Where to go after a successful delete; the page refreshes otherwise. */
  redirectTo?: string;
  disabled?: boolean;
}

/**
 * Deletion behind a typed confirmation. The API enforces the same rule: a
 * DELETE without ?confirm=<name> is refused with 428, so a stray request
 * cannot destroy anything.
 */
export function ConfirmDelete({ noun, name, path, redirectTo, disabled }: Props) {
  const router = useRouter();
  const inputId = useId();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (typed !== name) return;
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff(`${path}?confirm=${encodeURIComponent(typed)}`, "DELETE");
      if (!response.ok) {
        setError(await failureMessage(response));
        return;
      }
      setOpen(false);
      setTyped("");
      if (redirectTo) router.push(redirectTo);
      router.refresh();
    } catch {
      setError("The dashboard server could not be reached.");
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen(true)}
        aria-label={`Delete ${noun} ${name}`}
        className="rounded-md border border-rose-300 px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-50 disabled:opacity-50"
      >
        Delete
      </button>
    );
  }

  return (
    <form
      onSubmit={(event) => void submit(event)}
      className="flex w-full flex-col gap-2 rounded-md border border-rose-200 bg-rose-50 p-3 sm:w-auto"
    >
      <label htmlFor={inputId} className="text-sm text-rose-900">
        This permanently deletes the {noun}. Type <span className="font-mono font-medium">{name}</span> to
        confirm.
      </label>
      <input
        id={inputId}
        value={typed}
        onChange={(event) => setTyped(event.target.value)}
        autoComplete="off"
        autoFocus
        className="rounded-md border border-rose-300 bg-white px-2 py-1 font-mono text-sm"
      />
      {error ? (
        <p role="alert" className="text-sm text-rose-900">
          {error}
        </p>
      ) : null}
      <div className="flex gap-2">
        <button
          type="submit"
          disabled={busy || typed !== name}
          className="rounded-md bg-rose-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-800 disabled:opacity-50"
        >
          {busy ? "Deleting…" : `Delete ${noun}`}
        </button>
        <button
          type="button"
          onClick={() => {
            setOpen(false);
            setTyped("");
            setError(undefined);
          }}
          className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
