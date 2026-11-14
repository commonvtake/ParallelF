"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { bff, failureMessage } from "@/lib/api/browser";
import type { Flavor, Network, Project, Template, Workload, WorkloadCreate } from "@/lib/api/types";
import { formatMiB, RESOURCE_NAME_PATTERN } from "@/lib/cloud";

interface Props {
  projects: readonly Pick<Project, "id" | "name" | "slug">[];
  templates: readonly Template[];
  flavors: readonly Flavor[];
  networks: readonly Network[];
}

const FIELD = "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal";

/** The newest non-deprecated version of each template. */
function latest(templates: readonly Template[]): Template[] {
  const byName = new Map<string, Template>();
  for (const t of templates) {
    if (t.deprecated) continue;
    const seen = byName.get(t.name);
    if (!seen || t.version > seen.version) byName.set(t.name, t);
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/** Admits a new VM or container workload. */
export function CreateWorkloadForm({ projects, templates, flavors, networks }: Props) {
  const router = useRouter();
  const choices = latest(templates);
  const [projectId, setProjectId] = useState(projects[0]?.id ?? "");
  const [templateName, setTemplateName] = useState(choices[0]?.name ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const template = choices.find((t) => t.name === templateName);
  const projectNetworks = networks.filter((n) => n.project_id === projectId);
  const isVM = template?.kind === "vm";

  if (projects.length === 0) {
    return <p className="text-sm text-slate-600">Create a project in Settings first.</p>;
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const keys = String(data.get("ssh_keys") ?? "")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    const flavor = String(data.get("flavor") ?? "");
    const body: WorkloadCreate = {
      project_id: projectId,
      name: String(data.get("name") ?? "").trim(),
      template: templateName,
      network_id: String(data.get("network_id") ?? ""),
      ...(flavor ? { flavor } : {}),
      ...(isVM && keys.length > 0 ? { ssh_authorized_keys: keys } : {}),
    };
    setBusy(true);
    setError(undefined);
    try {
      const response = await bff("cloud/workloads", "POST", body);
      if (!response.ok) {
        setError(await failureMessage(response));
        return;
      }
      const created = (await response.json()) as Workload;
      router.push(`/cloud/workloads/${created.id}`);
    } catch {
      setError("The dashboard server could not be reached.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(event) => void submit(event)} className="grid gap-3 sm:grid-cols-2">
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
        <select
          name="project_id"
          value={projectId}
          onChange={(event) => setProjectId(event.target.value)}
          className={FIELD}
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.slug})
            </option>
          ))}
        </select>
      </label>
      <label className="text-sm font-medium text-slate-700">
        Name
        <input
          name="name"
          required
          minLength={3}
          maxLength={40}
          pattern={RESOURCE_NAME_PATTERN}
          title="3–40 characters: lower-case letters, digits and hyphens, starting with a letter."
          placeholder="web-1"
          autoComplete="off"
          className={`${FIELD} font-mono`}
        />
      </label>
      <div>
        <label className="text-sm font-medium text-slate-700">
          Template
          <select
            name="template"
            value={templateName}
            onChange={(event) => setTemplateName(event.target.value)}
            aria-describedby="template-help"
            className={FIELD}
          >
            {choices.map((t) => (
              <option key={t.name} value={t.name}>
                {t.name} — {t.kind === "vm" ? "VM" : "container"}
              </option>
            ))}
          </select>
        </label>
        <p id="template-help" className="mt-1 text-xs text-slate-500">
          {template?.description}
        </p>
      </div>
      <label className="text-sm font-medium text-slate-700">
        Flavor
        <select name="flavor" defaultValue="" className={FIELD}>
          <option value="">Template default{template ? ` (${template.default_flavor.name})` : ""}</option>
          {flavors.map((f) => (
            <option key={f.id} value={f.name}>
              {f.name} — {f.vcpus} vCPU, {formatMiB(f.memory_mib)}
              {isVM ? `, ${f.disk_gib} GiB` : ""}
            </option>
          ))}
        </select>
      </label>
      <div className="sm:col-span-2">
        {projectNetworks.length === 0 ? (
          <p className="text-sm text-slate-600">
            <span className="font-medium text-slate-700">Network: </span>
            this project has no network yet. Create one on the Networks tab.
          </p>
        ) : (
          <label className="text-sm font-medium text-slate-700">
            Network
            <select name="network_id" required aria-describedby="network-help" className={FIELD}>
              {projectNetworks.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.name} — {n.kind}, {n.cidr}
                </option>
              ))}
            </select>
          </label>
        )}
        <p id="network-help" className="mt-1 text-xs text-slate-500">
          A network holds either VMs or containers. Lab networks take only VMs whose template configures a
          static address{template && !template.static_network ? "; this template does not" : ""}.
        </p>
      </div>
      {isVM ? (
        <label className="text-sm font-medium text-slate-700 sm:col-span-2">
          SSH public keys <span className="font-normal text-slate-500">(optional, one per line)</span>
          <textarea name="ssh_keys" rows={2} spellCheck={false} className={`${FIELD} font-mono text-xs`} />
        </label>
      ) : null}
      <div className="sm:col-span-2">
        <button
          type="submit"
          disabled={busy || projectNetworks.length === 0}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
        >
          {busy ? "Creating…" : "Create workload"}
        </button>
      </div>
    </form>
  );
}
