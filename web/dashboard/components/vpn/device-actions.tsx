"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { ConfirmDelete } from "@/components/cloud/confirm-delete";
import { bff } from "@/lib/api/browser";
import { describeProblem, parseProblem } from "@/lib/api/problem";
import type { VPNDevice } from "@/lib/api/types";
import { ACTIVATION_CHOICES } from "@/lib/vpn";

/** Activate, deactivate and revoke one device. */
export function DeviceActions({ device, isOwner }: { device: VPNDevice; isOwner: boolean }) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ message: string; reauth: boolean }>();
  const [ttl, setTtl] = useState<number>(ACTIVATION_CHOICES[0].seconds);
  const live = device.state === "PENDING" || device.state === "ENROLLED";
  const pending = busy || refreshing;

  async function post(path: string, body?: unknown): Promise<void> {
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff(`vpn/devices/${device.id}/${path}`, "POST", body);
      if (!response.ok) {
        const problem = parseProblem(response.status, await response.json().catch(() => null));
        setError({
          message: describeProblem(problem),
          reauth: problem.type.endsWith("/reauthentication-required"),
        });
        return;
      }
      startRefresh(() => router.refresh());
    } catch {
      setError({ message: "The dashboard server could not be reached.", reauth: false });
    } finally {
      setBusy(false);
    }
  }

  if (!live) return null;
  return (
    <div className="flex flex-wrap items-start gap-2">
      {isOwner && !device.active ? (
        <>
          <select
            aria-label={`Activation length for ${device.name}`}
            value={ttl}
            onChange={(event) => setTtl(Number(event.target.value))}
            className="rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          >
            {ACTIVATION_CHOICES.map((c) => (
              <option key={c.seconds} value={c.seconds}>
                {c.label}
              </option>
            ))}
          </select>
          <button
            type="button"
            disabled={pending}
            onClick={() => void post("activate", { ttl_seconds: ttl })}
            className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
          >
            Activate
          </button>
        </>
      ) : null}
      {device.active ? (
        <button
          type="button"
          disabled={pending}
          onClick={() => void post("deactivate")}
          className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50"
        >
          Deactivate
        </button>
      ) : null}
      <ConfirmDelete
        noun="device"
        verb="Revoke"
        name={device.name}
        path={`vpn/devices/${device.id}`}
        disabled={pending}
      />
      {error ? (
        <p
          role="alert"
          className="w-full rounded-md border border-rose-200 bg-rose-50 p-2 text-sm text-rose-900"
        >
          {error.message}{" "}
          {error.reauth ? (
            <a href="/auth/login?reauth=1&returnTo=/vpn" className="font-medium underline">
              Sign in again
            </a>
          ) : null}
        </p>
      ) : null}
    </div>
  );
}
