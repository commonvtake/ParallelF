"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { bff, failureMessage } from "@/lib/api/browser";
import type { NetworkIncident, NetworkIncidentCreate } from "@/lib/api/types";
import { SEVERITIES } from "@/lib/netguard";

const FIELD = "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal";

/** Opens an incident without alerts (alerts can be linked from their pages). */
export function IncidentCreate() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const body: NetworkIncidentCreate = {
      title: String(data.get("title") ?? "").trim(),
      severity: String(data.get("severity") ?? "medium") as NetworkIncidentCreate["severity"],
      summary: String(data.get("summary") ?? "").trim(),
    };
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff("network/incidents", "POST", body);
      if (!response.ok) {
        setError(await failureMessage(response));
        return;
      }
      const incident = (await response.json()) as NetworkIncident;
      router.push(`/network/incidents/${incident.id}`);
    } catch {
      setError("The dashboard server could not be reached.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(event) => void submit(event)} className="grid gap-3 sm:grid-cols-3">
      <label className="block text-sm font-medium text-slate-700 sm:col-span-2">
        Incident title
        <input name="title" required minLength={3} maxLength={200} className={FIELD} />
      </label>
      <label className="block text-sm font-medium text-slate-700">
        Severity
        <select name="severity" defaultValue="medium" className={FIELD}>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </label>
      <label className="block text-sm font-medium text-slate-700 sm:col-span-3">
        Summary
        <textarea name="summary" rows={2} maxLength={5000} className={FIELD} />
      </label>
      <div>
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
        >
          Open incident
        </button>
      </div>
      {error ? (
        <p role="alert" className="rounded-md border border-rose-200 bg-rose-50 p-2 text-sm text-rose-900 sm:col-span-3">
          {error}
        </p>
      ) : null}
    </form>
  );
}
