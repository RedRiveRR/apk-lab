/**
 * SecOps guides as a modal (the upstream WebQ SecOpsGuideModal). The text is engine data
 * (web-sec/engine/websec/guides.py), so the workbench, the CLI and the MCP tools read the
 * same guides; opening one from a check jumps straight to the guide that explains it.
 */
import { ArrowSquareOutIcon, BookOpenIcon } from "@phosphor-icons/react";
import { Modal } from "../../components/ui";
import type { WebSecGuide, WebSecReference } from "../../lib/api";

const PORT_KIND: Record<string, string> = {
  database: "Database", plaintext: "Plain-text protocol", admin: "Admin or alternate", service: "Standard service"
};

function ReferenceTables({ reference }: { reference: WebSecReference }) {
  return (
    <section aria-labelledby="guide-reference" className="space-y-3 border-t border-(--iux-border) pt-3">
      <h3 id="guide-reference" className="font-semibold">Reference</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <caption className="pb-1 text-start text-(--iux-muted-foreground)">Headers the posture check reads</caption>
          <thead><tr className="text-(--iux-muted-foreground)"><th className="py-1 pe-3">Header</th><th>Expected</th></tr></thead>
          <tbody>
            {reference.headers.map((row) => (
              <tr key={row.header} className="border-t border-(--iux-border)">
                <td className="py-1 pe-3 font-mono" translate="no">{row.header}</td>
                <td>{row.expect}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <caption className="pb-1 text-start text-(--iux-muted-foreground)">Ports the exposure check connects to (intrusive, confirmed per scan)</caption>
          <thead><tr className="text-(--iux-muted-foreground)"><th className="py-1 pe-3">Port</th><th className="pe-3">Service</th><th>Kind</th></tr></thead>
          <tbody>
            {reference.ports.map((row) => (
              <tr key={row.port} className="border-t border-(--iux-border)">
                <td className="py-1 pe-3 tabular-nums" dir="ltr">{row.port}</td>
                <td className="pe-3" translate="no">{row.service || "—"}</td>
                <td>{PORT_KIND[row.kind] ?? row.kind}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function GuideModal({ guides, reference, error, selected, onSelect, labels, onClose }: {
  guides: WebSecGuide[];
  reference?: WebSecReference;
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
            {reference ? (
              <button type="button" className="iux-btn" aria-current={selected === "reference" ? "true" : undefined}
                data-variant={selected === "reference" ? "primary" : "outline"} onClick={() => onSelect("reference")}>
                Reference
              </button>
            ) : null}
          </nav>
        ) : null}
        {selected !== "reference" ? shown.map((guide) => (
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
        )) : null}
        {reference && (!selected || selected === "reference") ? <ReferenceTables reference={reference} /> : null}
      </div>
    </Modal>
  );
}
