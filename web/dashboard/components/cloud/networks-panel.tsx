"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState, useTransition } from "react";

import { bff, failureMessage } from "@/lib/api/browser";
import type { Network, NetworkCreate, NetworkKind, Project } from "@/lib/api/types";
import { RESOURCE_NAME_PATTERN } from "@/lib/cloud";

import { ConfirmDelete } from "./confirm-delete";

interface Props {
  networks: readonly Network[];
  projects: readonly Pick<Project, "id" | "name" | "slug">[];
  canManage: boolean;
}

const FIELD = "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal";

const KINDS: { kind: NetworkKind; label: string; help: string }[] = [
  { kind: "nat", label: "NAT", help: "DHCP, a host gateway and outbound access through the host." },
  { kind: "isolated", label: "Isolated", help: "DHCP and a host address, but no route out." },
  {
    kind: "lab",
    label: "Lab",
    help: "A bare bridge: no host address, no DHCP, no route. VMs with static addressing only.",
  },
];

/** Lists networks and, for managers, creates and deletes them. */
export function NetworksPanel({ networks, projects, canManage }: Props) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [kind, setKind] = useState<NetworkKind>("nat");
  const projectName = new Map(projects.map((p) => [p.id, p.name]));

  async function create(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const body: NetworkCreate = {
      project_id: String(data.get("project_id") ?? ""),
      name: String(data.get("name") ?? "").trim(),
      kind,
      cidr: String(data.get("cidr") ?? "").trim(),
    };
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff("cloud/networks", "POST", body);
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
      {networks.length === 0 ? (
        <p className="text-sm text-slate-600">No networks yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Virtual networks</caption>
            <thead className="text-xs text-slate-500 uppercase">
              <tr>
                <th scope="col" className="py-2 pr-4 font-medium">
                  Name
                </th>
                <th scope="col" className="py-2 pr-4 font-medium">
                  Project
                </th>
                <th scope="col" className="py-2 pr-4 font-medium">
                  Kind
                </th>
                <th scope="col" className="py-2 pr-4 font-medium">
                  CIDR
                </th>
                <th scope="col" className="py-2 pr-4 font-medium">
                  Gateway
                </th>
                <th scope="col" className="py-2 pr-4 text-right font-medium">
                  Workloads
                </th>
                {canManage ? (
                  <th scope="col" className="py-2 font-medium">
                    <span className="sr-only">Actions</span>
                  </th>
                ) : null}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {networks.map((n) => (
                <tr key={n.id} data-testid={`network-${n.name}`}>
                  <th scope="row" className="py-2 pr-4 font-medium text-slate-900">
                    {n.name}
                    <span className="block font-mono text-xs font-normal text-slate-500">
                      {n.bridge_name}
                    </span>
                  </th>
                  <td className="py-2 pr-4 text-slate-600">
                    {projectName.get(n.project_id) ?? n.project_id}
                  </td>
                  <td className="py-2 pr-4 text-slate-600">{n.kind}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{n.cidr}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{n.gateway_ip ?? "none"}</td>
                  <td className="py-2 pr-4 text-right tabular-nums">
                    {n.workloads} <span className="text-slate-500">/ {n.capacity}</span>
                  </td>
                  {canManage ? (
                    <td className="py-2">
                      <ConfirmDelete
                        noun="network"
                        name={n.name}
                        path={`cloud/networks/${n.id}`}
                        disabled={n.workloads > 0}
                      />
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {canManage && projects.length > 0 ? (
        <form
          onSubmit={(event) => void create(event)}
          className="grid gap-3 border-t border-slate-100 pt-4 sm:grid-cols-2"
        >
          <h3 className="text-sm font-semibold text-slate-900 sm:col-span-2">New network</h3>
          {error ? (
            <p
              role="alert"
              className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900 sm:col-span-2"
            >
              {error}
            </p>
          ) : null}
          <label className="text-sm font-medium text-slate-700">
            Project
            <select name="project_id" className={FIELD}>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.slug})
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm font-medium text-slate-700">
            Network name
            <input
              name="name"
              required
              minLength={3}
              maxLength={40}
              pattern={RESOURCE_NAME_PATTERN}
              title="3–40 characters: lower-case letters, digits and hyphens, starting with a letter."
              placeholder="lab-net"
              autoComplete="off"
              className={`${FIELD} font-mono`}
            />
          </label>
          <fieldset className="text-sm sm:col-span-2">
            <legend className="font-medium text-slate-700">Kind</legend>
            <div className="mt-1 grid gap-2 sm:grid-cols-3">
              {KINDS.map((option) => (
                <label
                  key={option.kind}
                  className={`flex cursor-pointer gap-2 rounded-md border p-3 ${
                    kind === option.kind ? "border-slate-900" : "border-slate-200"
                  }`}
                >
                  <input
                    type="radio"
                    name="kind"
                    value={option.kind}
                    checked={kind === option.kind}
                    onChange={() => setKind(option.kind)}
                    className="mt-0.5"
                  />
                  <span>
                    <span className="block font-medium text-slate-900">{option.label}</span>
                    <span className="block text-xs text-slate-600">{option.help}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
          <div>
            <label className="text-sm font-medium text-slate-700">
              CIDR
              <input
                name="cidr"
                required
                placeholder="10.42.0.0/24"
                autoComplete="off"
                aria-describedby="cidr-help"
                className={`${FIELD} font-mono`}
              />
            </label>
            <p id="cidr-help" className="mt-1 text-xs text-slate-500">
              Inside 10.0.0.0/8 (not 10.255.0.0/16), /16 to /27, not overlapping another network.
            </p>
          </div>
          <div className="self-end">
            <button
              type="submit"
              disabled={busy || refreshing}
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
            >
              {busy ? "Creating…" : "Create network"}
            </button>
          </div>
        </form>
      ) : null}
    </div>
  );
}
