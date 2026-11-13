import type { Metadata } from "next";

import { ApiError } from "@/components/api-error";
import { Card, PageHeader } from "@/components/page-header";
import { ProjectsPanel } from "@/components/projects-panel";
import { StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { Me, ProjectPage } from "@/lib/api/types";
import { formatTimestamp } from "@/lib/format";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "Settings" };

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-medium text-slate-500 uppercase">{label}</dt>
      <dd className="mt-0.5 text-sm break-all text-slate-900">{value}</dd>
    </div>
  );
}

export default async function SettingsPage() {
  const session = await requireSession();
  const [me, projects] = await Promise.all([
    gatewayGet<Me>(session, "/api/v1/core/me"),
    gatewayGet<ProjectPage>(session, "/api/v1/core/projects?limit=200"),
  ]);
  redirectIfUnauthorized(session, me, projects);

  const permissions = me.ok ? me.data.permissions : [];

  return (
    <>
      <PageHeader title="Settings" summary="Your profile, roles, projects and session." />
      <div className="space-y-6">
        <Card title="Profile">
          {me.ok ? (
            <dl className="grid gap-4 sm:grid-cols-2">
              <Field label="Username" value={me.data.username} />
              <Field label="Name" value={me.data.name ?? "—"} />
              <Field label="Email" value={me.data.email ?? "—"} />
              <Field label="Subject" value={me.data.subject} />
            </dl>
          ) : (
            <ApiError what="your profile" status={me.status} problem={me.problem} />
          )}
        </Card>

        {me.ok ? (
          <Card title="Roles and permissions">
            <p className="mb-2 text-sm text-slate-600">
              Roles are assigned in the identity provider. Each role grants a fixed set of permissions.
            </p>
            <div className="flex flex-wrap gap-2" data-testid="roles">
              {me.data.roles.length === 0 ? (
                <span className="text-sm text-slate-600">No platform role is assigned to this account.</span>
              ) : (
                me.data.roles.map((role) => (
                  <StatusBadge key={role} tone="neutral">
                    {role}
                  </StatusBadge>
                ))
              )}
            </div>
            {permissions.length > 0 ? (
              <ul className="mt-3 grid gap-1 font-mono text-xs text-slate-700 sm:grid-cols-2">
                {permissions.map((permission) => (
                  <li key={permission}>{permission}</li>
                ))}
              </ul>
            ) : null}
          </Card>
        ) : null}

        <Card title="Projects">
          {projects.ok ? (
            <ProjectsPanel
              projects={projects.data.items}
              canCreate={permissions.includes("core.projects.create")}
              canDelete={permissions.includes("core.projects.delete")}
            />
          ) : (
            <ApiError what="projects" status={projects.status} problem={projects.problem} />
          )}
        </Card>

        <Card title="Session">
          <dl className="grid gap-4 sm:grid-cols-2">
            <Field label="Signed in" value={formatTimestamp(new Date(session.createdAt).toISOString())} />
            <Field label="Expires" value={formatTimestamp(new Date(session.expiresAt).toISOString())} />
          </dl>
          <p className="mt-3 text-sm text-slate-600">
            The browser holds only a random session identifier in an HttpOnly cookie. Access tokens stay on the
            dashboard server.
          </p>
        </Card>
      </div>
    </>
  );
}
