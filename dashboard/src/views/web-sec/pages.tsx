import { Fragment, useEffect, useMemo, useState } from "react";
import {
  ArrowSquareOutIcon,
  CaretDownIcon,
  CaretRightIcon,
  DownloadSimpleIcon,
  PlayIcon,
  ShieldCheckIcon,
  StopIcon,
  XIcon
} from "@phosphor-icons/react";
import { AppShell } from "../../shell/app-shell";
import { Badge, CopyButton, Empty, PageHead, Section } from "../../components/ui";
import {
  api,
  type WebSecFinding,
  type WebSecJob,
  type WebSecModule,
  type WebSecReport,
  type WebSecReportFile,
  type WebSecSeverity,
  type WebSecStatus
} from "../../lib/api";
import { hasData, ModulePanel } from "./panels";

const SEVERITIES: WebSecSeverity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_CLASS: Record<WebSecSeverity, string> = {
  critical: "text-[#ff7b72]",
  high: "text-[#ff9f6e]",
  medium: "text-[#e3b341]",
  low: "text-[#79c0ff]",
  info: "text-(--iux-muted-foreground)"
};
const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error));

const EXPORT_MIME: Record<string, string> = {
  json: "application/json",
  sarif: "application/json",
  html: "text/html",
  markdown: "text/markdown"
};
const EXPORT_EXTENSION: Record<string, string> = { json: "json", sarif: "sarif", html: "html", markdown: "md" };

function gradeClass(grade: string): string {
  if (grade.startsWith("A")) return "text-(--iux-success)";
  if (grade.startsWith("B")) return "text-[#79c0ff]";
  if (grade.startsWith("C")) return "text-[#e3b341]";
  return "text-[#ff7b72]";
}

function Summary({ report }: { report: WebSecReport }) {
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      <span className={`text-2xl font-bold ${gradeClass(report.grade)}`}>{report.grade}</span>
      <span className="text-(--iux-muted-foreground)">{report.score}/100</span>
      {SEVERITIES.map((severity) => (
        <span key={severity} className={SEVERITY_CLASS[severity]}>
          {severity} {report.summary[severity] ?? 0}
        </span>
      ))}
    </div>
  );
}

function FindingCard({ finding, open }: { finding: WebSecFinding; open: boolean }) {
  return (
    <details open={open} className="rounded-lg border border-(--iux-border) bg-(--iux-panel) px-3 py-2">
      <summary className="cursor-pointer text-sm">
        <span className={`mr-2 text-xs font-semibold uppercase ${SEVERITY_CLASS[finding.severity]}`}>
          {finding.severity}
        </span>
        {finding.title}
        <span className="ml-2 text-xs text-(--iux-muted-foreground)">{finding.module}</span>
      </summary>
      <div className="mt-2 space-y-2 text-sm text-(--iux-muted-foreground)">
        <p>{finding.detail}</p>
        {finding.evidence ? (
          <pre className="max-h-48 overflow-auto rounded bg-(--iux-bg) p-2 text-xs whitespace-pre-wrap break-words">
            {finding.evidence}
          </pre>
        ) : null}
        {finding.remediation ? (
          <p>
            <span className="font-semibold text-(--iux-foreground)">Fix</span> {finding.remediation}
          </p>
        ) : null}
        {finding.refs.filter(Boolean).length ? (
          <p className="flex flex-wrap gap-3">
            {finding.refs.filter(Boolean).map((ref) => (
              <a key={ref} href={ref} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline">
                {ref}
                <ArrowSquareOutIcon size={12} />
              </a>
            ))}
          </p>
        ) : null}
      </div>
    </details>
  );
}

export default function WebSecLabPage() {
  const [status, setStatus] = useState<WebSecStatus | null>(null);
  const [modules, setModules] = useState<WebSecModule[]>([]);
  const [target, setTarget] = useState("");
  const [preset, setPreset] = useState("standard");
  const [scheme, setScheme] = useState<"http" | "https">("https");
  const [active, setActive] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState<WebSecJob | null>(null);
  const [viewer, setViewer] = useState<{ name: string; format: string; content: string } | null>(null);
  const [history, setHistory] = useState<{ target: string; scanned_at: string; grade: string; score: number; summary: Record<string, number> }[]>([]);
  const [reports, setReports] = useState<WebSecReportFile[]>([]);
  const [filter, setFilter] = useState<WebSecSeverity | "all">("all");
  const [openModules, setOpenModules] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const report = job?.state === "done" ? job.report : undefined;
  const running = job?.state === "running";
  const ready = status?.state === "ready";
  const scopeNote = status?.notes.find((note) => note.startsWith("Scope")) ?? "";

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      api.websecStatus().then((value) => !cancelled && setStatus(value)).catch(() => undefined);
      api.websecModules().then((value) => !cancelled && setModules(value.modules)).catch(() => undefined);
    };
    load();
    const timer = window.setInterval(load, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    api.websecHistory().then((value) => setHistory(value.entries)).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    let timer = 0;
    const tick = () => {
      api.websecJob(jobId).then((value) => {
        if (cancelled) return;
        setJob(value);
        if (value.state !== "running") {
          window.clearInterval(timer);
          setBusy(false);
          api.websecHistory().then((payload) => !cancelled && setHistory(payload.entries)).catch(() => undefined);
        }
      }).catch((reason) => {
        if (cancelled) return;
        window.clearInterval(timer);
        setError(errorText(reason));
        setBusy(false);
      });
    };
    tick();
    timer = window.setInterval(tick, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [jobId]);

  useEffect(() => {
    const current = (job?.target || target).trim();
    if (!report && !current) return;
    api.websecReports(current)
      .then((value) => setReports(value.reports))
      .catch(() => setReports([]));
  }, [report, target, job?.target]);

  const findings = useMemo(() => {
    const list = report?.findings ?? [];
    return filter === "all" ? list : list.filter((finding) => finding.severity === filter);
  }, [report, filter]);

  const toggleModule = (id: string) => {
    setOpenModules((current) =>
      current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  };

  const start = async () => {
    setError("");
    setViewer(null);
    setBusy(true);
    try {
      const created = await api.websecStart({
        target: target.trim(),
        preset,
        scheme,
        active,
        modules: selected.length ? selected : undefined
      });
      setJob(created);
      setJobId(created.id);
    } catch (reason) {
      setError(errorText(reason));
      setBusy(false);
    }
  };

  const cancel = async () => {
    if (!jobId) return;
    try {
      const value = await api.websecCancel(jobId);
      setJob(value);
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setBusy(false);
    }
  };

  const openReport = async (name: string, format: string) => {
    const current = report?.target || target.trim();
    if (!current) return;
    setError("");
    try {
      const value = await api.websecReport(current, name, format);
      setViewer({ name, format, content: value.content });
    } catch (reason) {
      setError(errorText(reason));
    }
  };

  const download = async (name: string, format: string) => {
    const current = report?.target || target.trim();
    if (!current) return;
    try {
      const value = await api.websecReport(current, name, format);
      const mime = EXPORT_MIME[format] ?? "application/octet-stream";
      const extension = EXPORT_EXTENSION[format] ?? format;
      const blob = new Blob([value.content], { type: mime });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${current}.${name.replace(/\.json$/, "")}.${extension}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (reason) {
      setError(errorText(reason));
    }
  };

  return (
    <AppShell activeId="web-sec">
      <main className="space-y-6">
        <PageHead
          icon={<ShieldCheckIcon size={22} />}
          title="Web Sec Lab"
          description="Scope-guarded web posture assessment"
          actions={
            status ? (
              <Badge tone={ready ? "success" : status.state === "needs-setup" ? "warning" : "danger"}>
                {ready ? "Ready" : status.state === "needs-setup" ? "Needs setup" : "Unavailable"}
              </Badge>
            ) : null
          }
        />

        {error ? (
          <p role="alert" className="rounded-md border border-(--iux-danger) px-3 py-2 text-sm text-(--iux-danger)">
            {error}
          </p>
        ) : null}

        {status && !ready ? (
          <div className="space-y-2 rounded-md border border-(--iux-border) px-3 py-3 text-sm">
            {status.reasons.length ? (
              <ul className="list-disc space-y-1 pl-5 text-(--iux-muted-foreground)">
                {status.reasons.map((reason) => <li key={reason}>{reason}</li>)}
              </ul>
            ) : null}
            {!status.reasons.length ? <p>Declare a scope before scanning.</p> : null}
            <a className="underline" href="/labs/websec/">Status</a>
          </div>
        ) : null}

        <Section title="Scan" description={scopeNote || status?.notes?.[0] || ""}>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-(--iux-muted-foreground)">Target</span>
              <input
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="example.test"
                spellCheck={false}
                className="rounded border border-(--iux-border) bg-(--iux-bg) px-2 py-1.5"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-(--iux-muted-foreground)">Preset</span>
              <select
                value={preset}
                onChange={(event) => setPreset(event.target.value)}
                className="rounded border border-(--iux-border) bg-(--iux-bg) px-2 py-1.5"
              >
                <option value="quick">Quick</option>
                <option value="standard">Standard</option>
                <option value="full">Full</option>
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-(--iux-muted-foreground)">Protocol</span>
              <select
                value={scheme}
                onChange={(event) => setScheme(event.target.value as "http" | "https")}
                className="rounded border border-(--iux-border) bg-(--iux-bg) px-2 py-1.5"
              >
                <option value="https">https</option>
                <option value="http">http</option>
              </select>
            </label>
            <div className="flex items-end gap-2">
              <button
                type="button"
                onClick={start}
                disabled={!ready || busy || !target.trim()}
                className="inline-flex items-center gap-2 rounded bg-[#f36c21] px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50"
              >
                <PlayIcon size={14} />
                Scan
              </button>
              {running ? (
                <button type="button" onClick={cancel} className="inline-flex items-center gap-2 rounded border border-(--iux-border) px-3 py-1.5 text-sm">
                  <StopIcon size={14} />
                  Cancel
                </button>
              ) : null}
            </div>
          </div>

          <label className="mt-3 flex items-start gap-2 text-sm">
            <input type="checkbox" aria-label="Allow intrusive checks" checked={active} onChange={(event) => setActive(event.target.checked)} className="mt-1" />
            <span>
              <span className="font-medium">Allow intrusive checks</span>
              <span className="block text-xs text-(--iux-muted-foreground)">Only with written authorization for this host.</span>
            </span>
          </label>

          <details className="mt-3 text-sm">
            <summary className="cursor-pointer text-(--iux-muted-foreground)">
              Checks {selected.length ? `(${selected.length})` : ""}
            </summary>
            <div className="mt-2 grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
              {modules.map((module) => (
                <label key={module.id} className="flex items-start gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={selected.includes(module.id)}
                    onChange={(event) => setSelected((current) =>
                      event.target.checked ? [...current, module.id] : current.filter((id) => id !== module.id))}
                    className="mt-0.5"
                  />
                  <span>
                    {module.label}
                    {module.active ? <span className="ml-1 text-(--iux-muted-foreground)">(active)</span> : null}
                  </span>
                </label>
              ))}
            </div>
          </details>

          {running ? (
            <p aria-live="polite" className="mt-3 text-sm text-(--iux-muted-foreground)">
              Scanning {job?.target}…
            </p>
          ) : null}
          {job?.state === "error" ? <p role="alert" className="mt-3 text-sm text-(--iux-danger)">The scan failed. {job.error}</p> : null}
        </Section>

        {report ? (
          <Section
            title="Findings"
            description={`${report.target} · ${report.started_at} · ${report.duration_seconds}s`}
            action={<Summary report={report} />}
          >
            <div className="mb-3 flex flex-wrap gap-1">
              {(["all", ...SEVERITIES] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setFilter(value)}
                  className={`rounded border px-2 py-0.5 text-xs ${filter === value ? "border-[#f36c21] text-[#f36c21]" : "border-(--iux-border) text-(--iux-muted-foreground)"}`}
                >
                  {value === "all" ? "All" : value}
                </button>
              ))}
            </div>
            <div className="space-y-2">
              {findings.length ? (
                findings.map((finding, index) => (
                  <FindingCard key={`${finding.module}-${finding.title}-${index}`} finding={finding} open={index === 0} />
                ))
              ) : (
                <Empty>No findings at this preset.</Empty>
              )}
            </div>

            <details className="mt-4 text-sm">
              <summary className="cursor-pointer text-(--iux-muted-foreground)">Checks</summary>
              <table className="mt-2 w-full text-left text-xs">
                <thead>
                  <tr className="text-(--iux-muted-foreground)">
                    <th className="py-1">Check</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {report.modules.map((module) => {
                    const open = openModules.includes(module.id);
                    return (
                      <Fragment key={module.id}>
                        <tr className="border-t border-(--iux-border)">
                          <td className="py-1">
                            {hasData(module) ? (
                              <button
                                type="button"
                                aria-expanded={open}
                                aria-controls={`${module.id}-panel`}
                                onClick={() => toggleModule(module.id)}
                                className="inline-flex items-center gap-1 hover:underline"
                              >
                                {open ? <CaretDownIcon size={12} /> : <CaretRightIcon size={12} />}
                                {module.label}
                              </button>
                            ) : (
                              module.label
                            )}
                          </td>
                          <td>{module.status}</td>
                          <td>{module.findings}</td>
                          <td>{module.duration_ms} ms</td>
                        </tr>
                        {open ? (
                          <tr>
                            <td colSpan={4} className="py-2 pr-3">
                              <div id={`${module.id}-panel`}>
                                <ModulePanel module={module} />
                              </div>
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </details>
          </Section>
        ) : null}

        <Section title="Reports" description={target.trim()}>
          {reports.length ? (
            <ul className="space-y-1 text-sm">
              {reports.map((entry) => (
                <li key={entry.name} className="flex flex-wrap items-center gap-3 border-t border-(--iux-border) py-1">
                  <span className="font-mono text-xs">{entry.name}</span>
                  <span className="text-xs text-(--iux-muted-foreground)">{entry.bytes} bytes</span>
                  <button type="button" className="underline" onClick={() => openReport(entry.name, "markdown")}>Open</button>
                  <button type="button" className="inline-flex items-center gap-1 underline" onClick={() => download(entry.name, "json")}>
                    <DownloadSimpleIcon size={12} />
                    JSON
                  </button>
                  <button type="button" className="underline" onClick={() => download(entry.name, "sarif")}>SARIF</button>
                  <button type="button" className="underline" onClick={() => download(entry.name, "html")}>HTML</button>
                  <button type="button" className="underline" onClick={() => download(entry.name, "markdown")}>Markdown</button>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No scans yet.</Empty>
          )}
          {viewer ? (
            <div className="mt-3">
              <div className="mb-1 flex items-center justify-between text-xs text-(--iux-muted-foreground)">
                <span className="font-mono">{viewer.name} · {viewer.format}</span>
                <span className="flex items-center gap-2">
                  <CopyButton text={viewer.content} />
                  <button type="button" aria-label="Close" onClick={() => setViewer(null)}>
                    <XIcon size={14} />
                  </button>
                </span>
              </div>
              <pre className="max-h-96 overflow-auto rounded border border-(--iux-border) bg-(--iux-bg) p-2 text-xs whitespace-pre-wrap">
                {viewer.content}
              </pre>
            </div>
          ) : null}
        </Section>

        <Section title="History">
          {history.length ? (
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs text-(--iux-muted-foreground)">
                  <th className="py-1">Target</th>
                  <th>Grade</th>
                  <th>Findings</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry, index) => (
                  <tr key={`${entry.target}-${entry.scanned_at}-${index}`} className="border-t border-(--iux-border)">
                    <td className="py-1">{entry.target}</td>
                    <td className={gradeClass(entry.grade)}>{entry.grade} ({entry.score})</td>
                    <td>{entry.summary?.total ?? 0}</td>
                    <td className="text-xs text-(--iux-muted-foreground)">{entry.scanned_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>No scans yet.</Empty>
          )}
        </Section>
      </main>
    </AppShell>
  );
}
