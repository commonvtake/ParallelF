import { Card, PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";

const DOCS_BASE = "https://github.com/commonvtake/ParallelF/blob/main/docs/architecture";

interface Props {
  title: string;
  summary: string;
  /** Capabilities the section will provide, from the architecture documents. */
  planned: readonly string[];
  /** Path of the design document below docs/architecture. */
  designDoc: string;
  /** Roadmap milestones that deliver this section, e.g. "M4–M5". */
  milestones: string;
}

/**
 * The page body for a section that has no functionality yet. It states that
 * plainly and never renders sample or placeholder data.
 */
export function NotImplemented({ title, summary, planned, designDoc, milestones }: Props) {
  return (
    <>
      <PageHeader title={title} summary={summary}>
        <StatusBadge tone="neutral">Not implemented yet</StatusBadge>
      </PageHeader>
      <div data-testid="not-implemented" className="space-y-4">
        <div className="rounded-lg border border-dashed border-slate-300 bg-white p-5">
          <p className="text-sm font-medium text-slate-900">This section is not implemented yet.</p>
          <p className="mt-1 max-w-2xl text-sm text-slate-600">
            Nothing here is connected to a backend, and no data is shown because none exists. It is planned for
            roadmap milestone {milestones}.
          </p>
        </div>
        <Card title="Planned capabilities">
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
            {planned.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <p className="mt-4 text-sm">
            <a
              href={`${DOCS_BASE}/${designDoc}`}
              rel="noreferrer"
              className="font-medium text-indigo-700 underline underline-offset-4"
            >
              Read the design document
            </a>
          </p>
        </Card>
      </div>
    </>
  );
}
