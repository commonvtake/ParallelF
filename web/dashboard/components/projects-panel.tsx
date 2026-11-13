"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState, useTransition } from "react";

import { describeProblem, parseProblem } from "@/lib/api/problem";
import type { Project } from "@/lib/api/types";
import { formatTimestamp } from "@/lib/format";

interface Props {
  projects: readonly Project[];
  canCreate: boolean;
  canDelete: boolean;
}

async function failureMessage(response: Response): Promise<string> {
  if (response.status === 401) return "Your session has ended. Reload the page and sign in again.";
  const body: unknown = await response.json().catch(() => null);
  return describeProblem(parseProblem(response.status, body));
}

/** Lists projects and, when the caller's role allows, creates and deletes them. */
export function ProjectsPanel({ projects, canCreate, canDelete }: Props) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const pending = busy || refreshing;

  async function send(run: () => Promise<Response>, onSuccess?: () => void): Promise<void> {
    setBusy(true);
    setError(undefined);
    try {
      const response = await run();
      if (!response.ok) {
        setError(await failureMessage(response));
        return;
      }
      onSuccess?.();
      // Re-render the server component so the list comes from the API again.
      startRefresh(() => router.refresh());
    } catch {
      setError("The dashboard server could not be reached.");
    } finally {
      setBusy(false);
    }
  }

  function handleCreate(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const body = JSON.stringify({
      slug: String(data.get("slug") ?? "").trim(),
      name: String(data.get("name") ?? "").trim(),
      description: String(data.get("description") ?? "").trim(),
    });
    void send(
      () =>
        fetch("/bff/api/core/projects", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body,
        }),
      () => form.reset(),
    );
  }

  function handleDelete(project: Project): void {
    void send(() => fetch(`/bff/api/core/projects/${encodeURIComponent(project.id)}`, { method: "DELETE" }));
  }

  return (
    <div className="space-y-4">
      {error ? (
        <p role="alert" className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900">
          {error}
        </p>
      ) : null}

      {projects.length === 0 ? (
        <p className="text-sm text-slate-600">
          No projects yet.{canCreate ? " Create the first one below." : ""}
        </p>
      ) : (
        <ul aria-label="Projects" className="divide-y divide-slate-100">
          {projects.map((project) => (
            <li key={project.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
              <div className="min-w-0">
                <p className="text-sm font-medium text-slate-900">
                  {project.name} <span className="font-mono font-normal text-slate-500">{project.slug}</span>
                </p>
                {project.description ? <p className="text-sm text-slate-600">{project.description}</p> : null}
                <p className="text-xs text-slate-500">Created {formatTimestamp(project.created_at)}</p>
              </div>
              {canDelete ? (
                <button
                  type="button"
                  disabled={pending}
                  onClick={() => handleDelete(project)}
                  aria-label={`Delete project ${project.slug}`}
                  className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50"
                >
                  Delete
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      )}

      {canCreate ? (
        <form onSubmit={handleCreate} className="grid gap-3 border-t border-slate-100 pt-4 sm:grid-cols-2">
          <label className="text-sm font-medium text-slate-700">
            Slug
            <input
              name="slug"
              required
              minLength={3}
              maxLength={40}
              pattern="[a-z][a-z0-9\-]{1,38}[a-z0-9]"
              title="3–40 characters: lower-case letters, digits and hyphens, starting with a letter."
              placeholder="demo-lab"
              autoComplete="off"
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-sm font-normal"
            />
          </label>
          <label className="text-sm font-medium text-slate-700">
            Name
            <input
              name="name"
              required
              maxLength={100}
              placeholder="Demo lab"
              autoComplete="off"
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal"
            />
          </label>
          <label className="text-sm font-medium text-slate-700 sm:col-span-2">
            Description <span className="font-normal text-slate-500">(optional)</span>
            <input
              name="description"
              maxLength={500}
              autoComplete="off"
              className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-sm font-normal"
            />
          </label>
          <div className="sm:col-span-2">
            <button
              type="submit"
              disabled={pending}
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
            >
              {pending ? "Working…" : "Create project"}
            </button>
          </div>
        </form>
      ) : (
        <p className="border-t border-slate-100 pt-4 text-sm text-slate-600">
          Your role can view projects but cannot create or delete them.
        </p>
      )}
    </div>
  );
}
