"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { bff, failureMessage } from "@/lib/api/browser";
import type { Workload } from "@/lib/api/types";
import { allowedOperations, type Operation } from "@/lib/cloud";

import { ConfirmDelete } from "./confirm-delete";

const LABELS: Record<Exclude<Operation, "delete">, string> = {
  start: "Start",
  stop: "Stop",
  retry: "Retry",
};

type Props = {
  workload: Pick<Workload, "id" | "name" | "state" | "desired_state" | "node_id">;
};

/** Lifecycle buttons for one workload: only the operations its state allows. */
export function WorkloadActions({ workload }: Props) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const operations = allowedOperations(workload);
  const pending = busy || refreshing;

  async function run(operation: Exclude<Operation, "delete">): Promise<void> {
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff(`cloud/workloads/${workload.id}/${operation}`, "POST");
      if (!response.ok) {
        setError(await failureMessage(response));
        return;
      }
      startRefresh(() => router.refresh());
    } catch {
      setError("The dashboard server could not be reached.");
    } finally {
      setBusy(false);
    }
  }

  if (operations.length === 0) return null;
  return (
    <div className="flex flex-wrap items-start gap-2">
      {operations
        .filter((op): op is Exclude<Operation, "delete"> => op !== "delete")
        .map((op) => (
          <button
            key={op}
            type="button"
            disabled={pending}
            onClick={() => void run(op)}
            className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50"
          >
            {LABELS[op]}
          </button>
        ))}
      {operations.includes("delete") ? (
        <ConfirmDelete
          noun="workload"
          name={workload.name}
          path={`cloud/workloads/${workload.id}`}
          disabled={pending}
        />
      ) : null}
      {error ? (
        <p
          role="alert"
          className="w-full rounded-md border border-rose-200 bg-rose-50 p-2 text-sm text-rose-900"
        >
          {error}
        </p>
      ) : null}
    </div>
  );
}
