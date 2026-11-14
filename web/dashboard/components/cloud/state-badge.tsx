import { StatusBadge } from "@/components/status-badge";
import type { Node, WorkloadState } from "@/lib/api/types";
import { stateLabel, stateTone } from "@/lib/cloud";

export function WorkloadStateBadge({ state }: { state: WorkloadState }) {
  return <StatusBadge tone={stateTone(state)}>{stateLabel(state)}</StatusBadge>;
}

export function NodeStatusBadge({ node }: { node: Pick<Node, "status" | "schedulable"> }) {
  if (node.status !== "READY") return <StatusBadge tone="down">{stateLabel(node.status)}</StatusBadge>;
  if (!node.schedulable) return <StatusBadge tone="warn">Cordoned</StatusBadge>;
  return <StatusBadge tone="ok">Ready</StatusBadge>;
}
