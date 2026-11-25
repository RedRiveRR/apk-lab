/**
 * Run-to-run compare: two stored reports of one target, diffed by the engine
 * (`websec compare`, the same matching as `scan --diff`). Findings match on check and
 * kind, so a reworded finding is not reported as new.
 */
import type { WebSecCompare, WebSecReportFile, WebSecSeverity } from "../../lib/api";

const SEVERITIES: WebSecSeverity[] = ["critical", "high", "medium", "low", "info"];

/** "20261124T101500Z-95.json" → "2026-11-24 10:15 UTC"; anything else is shown as is. */
export function runLabel(name: string): string {
  const match = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})\d{2}Z-(\d+)\.json$/.exec(name);
  return match ? `${match[1]}-${match[2]}-${match[3]} ${match[4]}:${match[5]} UTC · ${match[6]}` : name;
}

/** A new critical or high finding is a regression the operator must look at. */
export const regressed = (diff: WebSecCompare | null): boolean =>
  !!diff && diff.new.some((item) => item.severity === "critical" || item.severity === "high");

export function ComparePanel({ reports, from, to, onFrom, onTo, diff, error, loading, labels, severityClass }: {
  reports: WebSecReportFile[];
  from: string;
  to: string;
  onFrom: (name: string) => void;
  onTo: (name: string) => void;
  diff: WebSecCompare | null;
  error: string;
  loading: boolean;
  labels: Map<string, string>;
  severityClass: Record<WebSecSeverity, string>;
}) {
  if (reports.length < 2) return <p className="text-sm text-(--iux-muted-foreground)">Run two scans of this target to compare them.</p>;
  const delta = diff ? diff.score.delta : 0;
  return (
    <div className="space-y-3 text-sm">
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="flex min-w-0 flex-col gap-1">
          <span className="text-(--iux-muted-foreground)">Earlier run</span>
          <select className="iux-input" value={from} onChange={(event) => onFrom(event.target.value)}>
            {reports.map((entry) => <option key={entry.name} value={entry.name} disabled={entry.name === to}>{runLabel(entry.name)}</option>)}
          </select>
        </label>
        <label className="flex min-w-0 flex-col gap-1">
          <span className="text-(--iux-muted-foreground)">Later run</span>
          <select className="iux-input" value={to} onChange={(event) => onTo(event.target.value)}>
            {reports.map((entry) => <option key={entry.name} value={entry.name} disabled={entry.name === from}>{runLabel(entry.name)}</option>)}
          </select>
        </label>
      </div>
      {loading ? <p role="status" className="text-(--iux-muted-foreground)">Comparing…</p> : null}
      {error ? <p role="alert" className="text-(--iux-danger)">{error}</p> : null}
      {diff && !loading ? (
        <div role="region" aria-label="Run comparison" className="space-y-3">
          <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-lg font-semibold" dir="ltr">{diff.grade.previous} → {diff.grade.current}</span>
            <span dir="ltr" className={`tabular-nums ${delta > 0 ? "text-(--iux-success)" : delta < 0 ? "text-(--iux-danger)" : "text-(--iux-muted-foreground)"}`}>
              {diff.score.previous} → {diff.score.current} ({delta > 0 ? "+" : ""}{delta})
            </span>
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-start text-xs">
              <thead>
                <tr className="text-(--iux-muted-foreground)">
                  <th className="py-1">Severity</th>
                  <th>Earlier run</th>
                  <th>Later run</th>
                </tr>
              </thead>
              <tbody>
                {SEVERITIES.map((severity) => (
                  <tr key={severity} className="border-t border-(--iux-border)">
                    <td className={`py-1 ${severityClass[severity]}`}>{severity}</td>
                    <td className="tabular-nums">{diff.summary[severity]?.previous ?? 0}</td>
                    <td className="tabular-nums">{diff.summary[severity]?.current ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {([["new", "New findings", diff.new], ["resolved", "Resolved findings", diff.resolved]] as const).map(([key, title, items]) => (
            <div key={key}>
              <h3 className="text-xs font-semibold">{title} <span dir="ltr" className="tabular-nums text-(--iux-muted-foreground)">({items.length})</span></h3>
              {items.length ? (
                <ul className="mt-1 space-y-1">
                  {items.map((item) => (
                    <li key={`${item.module}-${item.title}`} className="flex flex-wrap gap-x-2">
                      <span className={`text-xs font-semibold uppercase ${severityClass[item.severity] ?? ""}`}>{item.severity}</span>
                      <span>{item.title}</span>
                      <span className="text-xs text-(--iux-muted-foreground)">{labels.get(item.module) ?? item.module}</span>
                    </li>
                  ))}
                </ul>
              ) : <p className="mt-1 text-xs text-(--iux-muted-foreground)">None</p>}
            </div>
          ))}
          {diff.modules.length ? (
            <div>
              <h3 className="text-xs font-semibold">Check status changes</h3>
              <ul className="mt-1 space-y-1 text-xs">
                {diff.modules.map((change) => (
                  <li key={change.id}>
                    <span>{labels.get(change.id) ?? change.id}</span>{" "}
                    <span dir="ltr" className="text-(--iux-muted-foreground)">{change.previous ?? "—"} → {change.current ?? "—"}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
