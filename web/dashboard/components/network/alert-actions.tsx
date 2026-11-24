"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState, useTransition } from "react";

import { bff, failureMessage } from "@/lib/api/browser";
import type { NetworkAlert, NetworkAlertStatusChange, NetworkIncident } from "@/lib/api/types";
import { alertActions, SEVERITIES } from "@/lib/netguard";

const FIELD = "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal";
const LABELS = {
  acknowledged: "Acknowledge",
  closed: "Close",
  suppressed: "Suppress",
  open: "Lift suppression",
} as const;
const SUPPRESS_FOR = [
  { value: "1h", label: "1 hour" },
  { value: "8h", label: "8 hours" },
  { value: "24h", label: "1 day" },
  { value: "168h", label: "7 days" },
] as const;

/** Triage of one alert, and opening an incident from it. */
export function AlertActions({ alert }: { alert: NetworkAlert }) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [suppressFor, setSuppressFor] = useState<string>(SUPPRESS_FOR[1].value);
  const [reason, setReason] = useState("");
  const pending = busy || refreshing;

  async function send(path: string, method: string, body: unknown): Promise<Response | undefined> {
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff(path, method, body);
      if (!response.ok) {
        setError(await failureMessage(response));
        return undefined;
      }
      return response;
    } catch {
      setError("The dashboard server could not be reached.");
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  async function change(status: NetworkAlertStatusChange["status"]): Promise<void> {
    const body: NetworkAlertStatusChange = { status, reason: reason.trim() };
    if (status === "suppressed") body.suppress_for = suppressFor;
    if (await send(`network/alerts/${alert.id}/status`, "POST", body)) {
      setReason("");
      startRefresh(() => router.refresh());
    }
  }

  async function openIncident(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const response = await send("network/incidents", "POST", {
      title: String(data.get("title") ?? "").trim(),
      severity: String(data.get("severity") ?? "medium"),
      alert_ids: [alert.id],
    });
    if (response) {
      const incident = (await response.json()) as NetworkIncident;
      router.push(`/network/incidents/${incident.id}`);
    }
  }

  const actions = alertActions(alert.status);
  return (
    <div className="space-y-4">
      {actions.length > 0 ? (
        <div className="space-y-3">
          <label className="block text-sm font-medium text-slate-700">
            Reason
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={1000}
              className={FIELD}
              placeholder="Required to suppress"
            />
          </label>
          <label className="block text-sm font-medium text-slate-700">
            Suppress for
            <select value={suppressFor} onChange={(e) => setSuppressFor(e.target.value)} className={FIELD}>
              {SUPPRESS_FOR.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <div className="flex flex-wrap gap-2">
            {actions.map((status) => (
              <button
                key={status}
                type="button"
                disabled={pending}
                onClick={() => void change(status)}
                className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50"
              >
                {LABELS[status]}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <p className="text-sm text-slate-600">This alert is closed.</p>
      )}

      {alert.incident_id ? (
        <p className="text-sm">
          Part of{" "}
          <a href={`/network/incidents/${alert.incident_id}`} className="underline">
            an incident
          </a>
          .
        </p>
      ) : (
        <form
          onSubmit={(event) => void openIncident(event)}
          className="space-y-3 border-t border-slate-100 pt-4"
        >
          <h3 className="text-sm font-semibold text-slate-900">Open an incident</h3>
          <label className="block text-sm font-medium text-slate-700">
            Incident title
            <input
              name="title"
              required
              minLength={3}
              maxLength={200}
              defaultValue={alert.title}
              className={FIELD}
            />
          </label>
          <label className="block text-sm font-medium text-slate-700">
            Severity
            <select name="severity" defaultValue={alert.severity} className={FIELD}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <button
            type="submit"
            disabled={pending}
            className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
          >
            Open incident
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
