"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState, useTransition } from "react";

import { bff, failureMessage } from "@/lib/api/browser";
import type { NetworkEvidenceCreate, NetworkIncident, NetworkIncidentUpdate } from "@/lib/api/types";
import { textToBase64 } from "@/lib/netguard";

const FIELD = "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal";
const BUTTON =
  "rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50";

/** Status changes, notes and analyst evidence for one incident. */
export function IncidentActions({ incident }: { incident: NetworkIncident }) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const pending = busy || refreshing;
  const resolved = incident.status === "resolved";

  async function send(path: string, method: string, body: unknown, form: HTMLFormElement): Promise<void> {
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff(path, method, body);
      if (!response.ok) {
        setError(await failureMessage(response));
        return;
      }
      form.reset();
      startRefresh(() => router.refresh());
    } catch {
      setError("The dashboard server could not be reached.");
    } finally {
      setBusy(false);
    }
  }

  function update(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const body: NetworkIncidentUpdate = {};
    const status = String(data.get("status") ?? "");
    if (status === "investigating" || status === "resolved") body.status = status;
    const note = String(data.get("note") ?? "").trim();
    if (note) body.note = note;
    void send(`network/incidents/${incident.id}`, "PATCH", body, form);
  }

  function addNote(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const body: NetworkEvidenceCreate = {
      kind: "note",
      name: String(data.get("name") ?? "").trim(),
      content: textToBase64(String(data.get("content") ?? "")),
    };
    void send(`network/incidents/${incident.id}/evidence`, "POST", body, form);
  }

  return (
    <div className="space-y-6">
      <form onSubmit={update} className="space-y-3">
        <label className="block text-sm font-medium text-slate-700">
          Status
          <select name="status" defaultValue="" className={FIELD}>
            <option value="">Unchanged ({incident.status})</option>
            {incident.status === "open" || incident.status === "resolved" ? (
              <option value="investigating">{resolved ? "Reopen (investigating)" : "Investigating"}</option>
            ) : null}
            {!resolved ? <option value="resolved">Resolved</option> : null}
          </select>
        </label>
        <label className="block text-sm font-medium text-slate-700">
          Timeline note
          <textarea name="note" rows={3} maxLength={5000} className={FIELD} />
        </label>
        <button type="submit" disabled={pending} className={BUTTON}>
          Update incident
        </button>
      </form>

      {resolved ? (
        <p className="text-sm text-slate-600">A resolved incident takes no new evidence; reopen it first.</p>
      ) : (
        <form onSubmit={addNote} className="space-y-3 border-t border-slate-100 pt-4">
          <h3 className="text-sm font-semibold text-slate-900">Add an evidence note</h3>
          <label className="block text-sm font-medium text-slate-700">
            Evidence name
            <input name="name" required maxLength={200} className={FIELD} />
          </label>
          <label className="block text-sm font-medium text-slate-700">
            Evidence text
            <textarea name="content" required rows={4} className={FIELD} />
          </label>
          <p className="text-xs text-slate-500">
            Evidence is stored with its SHA-256 and can never be changed or deleted.
          </p>
          <button type="submit" disabled={pending} className={BUTTON}>
            Add evidence
          </button>
        </form>
      )}
      {error ? (
        <p role="alert" className="rounded-md border border-rose-200 bg-rose-50 p-2 text-sm text-rose-900">
          {error}
        </p>
      ) : null}
    </div>
  );
}
