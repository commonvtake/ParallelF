"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { bff, failureMessage } from "@/lib/api/browser";
import type { Node } from "@/lib/api/types";

import { ConfirmDelete } from "./confirm-delete";

/** Cordon, uncordon and (for a node that stopped reporting) delete. */
export function NodeActions({ node }: { node: Pick<Node, "id" | "name" | "status" | "schedulable"> }) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const action = node.schedulable ? "cordon" : "uncordon";

  async function toggle(): Promise<void> {
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff(`cloud/nodes/${node.id}/${action}`, "POST");
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

  return (
    <div className="flex flex-wrap items-start gap-2">
      <button
        type="button"
        disabled={busy || refreshing}
        onClick={() => void toggle()}
        title={node.schedulable ? "Stop placing new workloads on this node" : "Allow new workloads again"}
        className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50"
      >
        {node.schedulable ? "Cordon" : "Uncordon"}
      </button>
      {node.status !== "READY" ? (
        <ConfirmDelete noun="node" name={node.name} path={`cloud/nodes/${node.id}`} />
      ) : null}
      {error ? (
        <p role="alert" className="w-full text-sm text-rose-900">
          {error}
        </p>
      ) : null}
    </div>
  );
}
