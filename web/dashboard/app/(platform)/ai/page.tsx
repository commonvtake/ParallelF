import type { Metadata } from "next";

import { ApiError } from "@/components/api-error";
import { Card, PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { gatewayGet, redirectIfUnauthorized } from "@/lib/api/gateway";
import type { AIInfo } from "@/lib/api/types";
import { requireSession } from "@/lib/session/session";

export const metadata: Metadata = { title: "AI Investigator" };

export default async function AIPage() {
  const session = await requireSession();
  const info = await gatewayGet<AIInfo>(session, "/api/v1/ai/info");
  redirectIfUnauthorized(session, info);

  return (
    <>
      <PageHeader title="AI Investigator" summary="Read-only, evidence-cited incident investigations.">
        <StatusBadge tone="neutral">Not implemented yet</StatusBadge>
      </PageHeader>
      <div className="space-y-4">
        <div data-testid="not-implemented" className="rounded-lg border border-dashed border-slate-300 bg-white p-5">
          <p className="text-sm font-medium text-slate-900">Investigations are not implemented yet.</p>
          <p className="mt-1 max-w-2xl text-sm text-slate-600">
            The AI service is running and answers authenticated requests, but it cannot investigate anything
            and makes no calls to a language model. The list below is the service&apos;s own report of its
            capabilities. They are planned for roadmap milestone M13.
          </p>
        </div>
        <Card title="Service">
          {info.ok ? (
            <>
              <p className="mb-3 text-sm text-slate-600">
                <span className="font-mono text-slate-900">{info.data.service}</span>, version{" "}
                <span className="font-mono text-slate-900">{info.data.version}</span>
              </p>
              <ul className="divide-y divide-slate-100">
                {info.data.capabilities.map((capability) => (
                  <li key={capability.name} className="flex flex-wrap items-start justify-between gap-3 py-3">
                    <div>
                      <p className="font-mono text-sm text-slate-900">{capability.name}</p>
                      <p className="text-sm text-slate-600">{capability.description}</p>
                    </div>
                    <StatusBadge tone={capability.status === "available" ? "ok" : "neutral"}>
                      {capability.status === "available" ? "Available" : "Not implemented"}
                    </StatusBadge>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <ApiError what="the AI service" status={info.status} problem={info.problem} />
          )}
        </Card>
      </div>
    </>
  );
}
