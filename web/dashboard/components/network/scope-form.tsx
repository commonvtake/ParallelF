"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState, useTransition } from "react";

import { bff } from "@/lib/api/browser";
import { describeProblem, parseProblem } from "@/lib/api/problem";
import type { NetworkScopeCreate } from "@/lib/api/types";
import { RESOURCE_NAME_PATTERN } from "@/lib/cloud";
import { parsePorts, splitList } from "@/lib/netguard";

const FIELD = "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal";

/** Issues a signed discovery scope (owners and admins, after a recent sign-in). */
export function ScopeForm() {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ message: string; reauth: boolean }>();
  const [tcp, setTcp] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const ports = parsePorts(String(data.get("ports") ?? ""));
    if (ports === null) {
      setError({ message: "Ports must be numbers between 1 and 65535.", reauth: false });
      return;
    }
    const body: NetworkScopeCreate = {
      name: String(data.get("name") ?? "").trim(),
      cidrs: splitList(String(data.get("cidrs") ?? "")),
      techniques: tcp ? ["icmp-echo", "tcp-connect"] : ["icmp-echo"],
      ports: tcp ? ports : [],
      rate_pps: Number(data.get("rate_pps") ?? 20),
      duration: String(data.get("duration") ?? "1h"),
      authorization_note: String(data.get("authorization_note") ?? "").trim(),
    };
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff("network/scopes", "POST", body);
      if (!response.ok) {
        const problem = parseProblem(response.status, await response.json().catch(() => null));
        setError({
          message: describeProblem(problem),
          reauth: problem.type.endsWith("/reauthentication-required"),
        });
        return;
      }
      form.reset();
      setTcp(false);
      startRefresh(() => router.refresh());
    } catch {
      setError({ message: "The dashboard server could not be reached.", reauth: false });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(event) => void submit(event)} className="grid gap-3 sm:grid-cols-2">
      <label className="block text-sm font-medium text-slate-700">
        Scope name
        <input name="name" required pattern={RESOURCE_NAME_PATTERN} className={FIELD} />
      </label>
      <label className="block text-sm font-medium text-slate-700">
        Networks (CIDRs)
        <input name="cidrs" required placeholder="10.255.0.0/24" className={`${FIELD} font-mono`} />
      </label>
      <label className="flex items-center gap-2 text-sm font-medium text-slate-700">
        <input type="checkbox" checked={tcp} onChange={(e) => setTcp(e.target.checked)} />
        Also try TCP connections (besides ICMP echo)
      </label>
      <label className="block text-sm font-medium text-slate-700">
        Ports
        <input
          name="ports"
          disabled={!tcp}
          required={tcp}
          placeholder="22, 443"
          className={`${FIELD} font-mono`}
        />
      </label>
      <label className="block text-sm font-medium text-slate-700">
        Probes per second
        <input name="rate_pps" type="number" min={1} max={100} defaultValue={20} className={FIELD} />
      </label>
      <label className="block text-sm font-medium text-slate-700">
        Valid for
        <select name="duration" defaultValue="1h" className={FIELD}>
          <option value="15m">15 minutes</option>
          <option value="1h">1 hour</option>
          <option value="8h">8 hours</option>
          <option value="24h">24 hours</option>
        </select>
      </label>
      <label className="block text-sm font-medium text-slate-700 sm:col-span-2">
        Authorization
        <textarea
          name="authorization_note"
          required
          minLength={10}
          maxLength={1000}
          rows={2}
          placeholder="Who authorised this discovery, and why"
          className={FIELD}
        />
      </label>
      <div className="sm:col-span-2">
        <button
          type="submit"
          disabled={busy || refreshing}
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
        >
          Issue scope
        </button>
      </div>
      {error ? (
        <p
          role="alert"
          className="rounded-md border border-rose-200 bg-rose-50 p-2 text-sm text-rose-900 sm:col-span-2"
        >
          {error.message}{" "}
          {error.reauth ? (
            <a href="/auth/login?reauth=1&returnTo=/network/scopes" className="font-medium underline">
              Sign in again
            </a>
          ) : null}
        </p>
      ) : null}
    </form>
  );
}
