"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState, useTransition } from "react";

import { ConfirmDelete } from "@/components/cloud/confirm-delete";
import { StatusBadge } from "@/components/status-badge";
import { bff, failureMessage } from "@/lib/api/browser";
import type { VPNPolicy, VPNPolicyCreate } from "@/lib/api/types";
import { RESOURCE_NAME_PATTERN } from "@/lib/cloud";

const FIELD = "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal";

function list(value: FormDataEntryValue | null): string[] {
  return String(value ?? "")
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter(Boolean);
}

/** Access policies in evaluation order; managers may add and delete them. */
export function PoliciesPanel({
  policies,
  canManage,
}: {
  policies: readonly VPNPolicy[];
  canManage: boolean;
}) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [protocol, setProtocol] = useState<VPNPolicyCreate["protocol"]>("tcp");

  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const body: VPNPolicyCreate = {
      name: String(data.get("name") ?? "").trim(),
      priority: Number(data.get("priority")),
      action: data.get("action") === "deny" ? "deny" : "allow",
      groups: list(data.get("groups")),
      destinations: list(data.get("destinations")),
      protocol,
      ports: protocol === "tcp" || protocol === "udp" ? list(data.get("ports")) : [],
      description: String(data.get("description") ?? "").trim(),
    };
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff("vpn/policies", "POST", body);
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

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-600">
        Traffic from the tunnel is denied unless the device is active and a policy allows it. Policies run in
        priority order (lowest first); the first match decides.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Access policies</caption>
          <thead className="text-xs text-slate-500 uppercase">
            <tr>
              <th scope="col" className="py-2 pr-4 font-medium">
                Priority
              </th>
              <th scope="col" className="py-2 pr-4 font-medium">
                Name
              </th>
              <th scope="col" className="py-2 pr-4 font-medium">
                Groups
              </th>
              <th scope="col" className="py-2 pr-4 font-medium">
                Destinations
              </th>
              <th scope="col" className="py-2 pr-4 font-medium">
                Traffic
              </th>
              <th scope="col" className="py-2 font-medium">
                Action
              </th>
              {canManage ? (
                <th scope="col" className="py-2 font-medium">
                  <span className="sr-only">Manage</span>
                </th>
              ) : null}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {policies.map((p) => (
              <tr key={p.id} data-testid={`policy-${p.name}`}>
                <td className="py-2 pr-4 tabular-nums">{p.priority}</td>
                <th scope="row" className="py-2 pr-4 font-medium text-slate-900">
                  {p.name}
                  {p.description ? (
                    <span className="block text-xs font-normal text-slate-500">{p.description}</span>
                  ) : null}
                </th>
                <td className="py-2 pr-4 font-mono text-xs">{p.groups.join(", ")}</td>
                <td className="py-2 pr-4 font-mono text-xs">{p.destinations.join(", ")}</td>
                <td className="py-2 pr-4 font-mono text-xs">
                  {p.protocol}
                  {p.ports.length > 0 ? ` ${p.ports.join(", ")}` : ""}
                </td>
                <td className="py-2 pr-4">
                  <StatusBadge tone={p.action === "allow" ? "ok" : "down"}>
                    {p.action === "allow" ? "Allow" : "Deny"}
                  </StatusBadge>
                </td>
                {canManage ? (
                  <td className="py-2">
                    <ConfirmDelete noun="policy" name={p.name} path={`vpn/policies/${p.id}`} />
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {canManage ? (
        <form
          onSubmit={(event) => void create(event)}
          className="grid gap-3 border-t border-slate-100 pt-4 sm:grid-cols-3"
        >
          <h3 className="text-sm font-semibold text-slate-900 sm:col-span-3">New policy</h3>
          {error ? (
            <p
              role="alert"
              className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900 sm:col-span-3"
            >
              {error}
            </p>
          ) : null}
          <label className="text-sm font-medium text-slate-700">
            Policy name
            <input
              name="name"
              required
              pattern={RESOURCE_NAME_PATTERN}
              autoComplete="off"
              className={`${FIELD} font-mono`}
            />
          </label>
          <label className="text-sm font-medium text-slate-700">
            Priority
            <input
              name="priority"
              type="number"
              required
              min={1}
              max={10000}
              defaultValue={200}
              className={FIELD}
            />
          </label>
          <label className="text-sm font-medium text-slate-700">
            Action
            <select name="action" className={FIELD} defaultValue="allow">
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </select>
          </label>
          <label className="text-sm font-medium text-slate-700">
            Groups
            <input
              name="groups"
              required
              placeholder="owner, admin"
              autoComplete="off"
              className={`${FIELD} font-mono`}
            />
          </label>
          <label className="text-sm font-medium text-slate-700">
            Destinations
            <input
              name="destinations"
              required
              placeholder="platform, 10.20.1.0/24"
              autoComplete="off"
              className={`${FIELD} font-mono`}
            />
          </label>
          <div className="grid grid-cols-2 gap-2">
            <label className="text-sm font-medium text-slate-700">
              Protocol
              <select
                name="protocol"
                value={protocol}
                onChange={(e) => setProtocol(e.target.value as VPNPolicyCreate["protocol"])}
                className={FIELD}
              >
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="icmp">icmp</option>
                <option value="any">any</option>
              </select>
            </label>
            <label className="text-sm font-medium text-slate-700">
              Ports
              <input
                name="ports"
                disabled={protocol !== "tcp" && protocol !== "udp"}
                placeholder="22, 8000-8100"
                autoComplete="off"
                className={`${FIELD} font-mono`}
              />
            </label>
          </div>
          <label className="text-sm font-medium text-slate-700 sm:col-span-2">
            Description <span className="font-normal text-slate-500">(optional)</span>
            <input name="description" maxLength={500} autoComplete="off" className={FIELD} />
          </label>
          <div className="self-end">
            <button
              type="submit"
              disabled={busy || refreshing}
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
            >
              {busy ? "Creating…" : "Create policy"}
            </button>
          </div>
        </form>
      ) : null}
    </div>
  );
}
