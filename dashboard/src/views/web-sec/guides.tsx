/**
 * SecOps guides as a modal (the upstream WebQ SecOpsGuideModal). The text is engine data
 * (web-sec/engine/websec/guides.py), so the workbench, the CLI and the MCP tools read the
 * same guides; opening one from a check jumps straight to the guide that explains it.
 */
import { ArrowSquareOutIcon, BookOpenIcon } from "@phosphor-icons/react";
import { Modal } from "../../components/ui";
import type { WebSecGuide } from "../../lib/api";

export function GuideModal({ guides, error, selected, onSelect, labels, onClose }: {
  guides: WebSecGuide[];
  error: string;
  selected: string;
  onSelect: (id: string) => void;
  labels: Map<string, string>;
  onClose: () => void;
}) {
  const shown = selected ? guides.filter((guide) => guide.id === selected) : guides;
  return (
    <Modal title="SecOps guides" icon={<BookOpenIcon size={18} />} description="What to fix, check by check." onClose={onClose}>
      <div className="max-h-[65vh] space-y-4 overflow-y-auto text-sm">
        {error ? <p role="alert" className="text-(--iux-danger)"><span>Guides could not be loaded.</span> {error}</p> : null}
        {!error && !guides.length ? <p role="status">Loading guides…</p> : null}
        {guides.length > 1 ? (
          <nav aria-label="Guides" className="flex flex-wrap gap-1">
            <button type="button" className="iux-btn" data-variant={selected ? "outline" : "primary"} onClick={() => onSelect("")}>
              All guides
            </button>
            {guides.map((guide) => (
              <button key={guide.id} type="button" className="iux-btn" aria-current={guide.id === selected ? "true" : undefined}
                data-variant={guide.id === selected ? "primary" : "outline"} onClick={() => onSelect(guide.id)}>
                {guide.title}
              </button>
            ))}
          </nav>
        ) : null}
        {shown.map((guide) => (
          <section key={guide.id} aria-labelledby={`guide-${guide.id}`} className="space-y-2 border-t border-(--iux-border) pt-3">
            <h3 id={`guide-${guide.id}`} className="font-semibold">{guide.title}</h3>
            <ul className="list-disc space-y-1 ps-5">
              {guide.points.map((point) => <li key={point}>{point}</li>)}
            </ul>
            {guide.checks.length ? (
              <p className="flex flex-wrap gap-x-2 gap-y-1 text-xs text-(--iux-muted-foreground)">
                <span>Checks</span>
                {guide.checks.map((id) => <span key={id} className="rounded border border-(--iux-border) px-1.5">{labels.get(id) ?? id}</span>)}
              </p>
            ) : null}
            {guide.refs.length ? (
              <p className="flex flex-wrap gap-3 text-xs">
                {guide.refs.map((ref) => (
                  <a key={ref} href={ref} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 break-all underline">
                    {ref.replace(/^https:\/\//, "")}
                    <ArrowSquareOutIcon size={12} aria-hidden="true" />
                  </a>
                ))}
              </p>
            ) : null}
          </section>
        ))}
      </div>
    </Modal>
  );
}
