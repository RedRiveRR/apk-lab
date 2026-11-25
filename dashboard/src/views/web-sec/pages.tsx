/**
 * Web Sec Lab workbench, on the os-lab one-click standard (lat.md/ux-readiness.md):
 * one primary action (Scan, shortcut S) goes from a target to a graded report; every other
 * ability is a collapsed row with a one-line live summary. Choices are stored by the engine
 * in the private storage folder (never the browser), and intrusive checks are opted in and
 * confirmed per scan, never saved. Agents get the same abilities from console/mcp_websec.py.
 */
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowSquareOutIcon,
  BookOpenIcon,
  CaretDownIcon,
  CaretRightIcon,
  DownloadSimpleIcon,
  PlayIcon,
  ShieldCheckIcon,
  StopIcon,
  XIcon
} from "@phosphor-icons/react";
import { AppShell } from "../../shell/app-shell";
import { Badge, CopyButton, Empty, IconButton, Modal, PageHead, Section } from "../../components/ui";
import { CareList, CareRow } from "../cleanup/care-sections";
import {
  api,
  type WebSecBulkJob,
  type WebSecCompare,
  type WebSecFinding,
  type WebSecGuides,
  type WebSecHistoryEntry,
  type WebSecJob,
  type WebSecModule,
  type WebSecMonitorStatus,
  type WebSecPreferences,
  type WebSecReport,
  type WebSecReportFile,
  type WebSecSeverity,
  type WebSecStats,
  type WebSecStatus
} from "../../lib/api";
import { hasData, ModulePanel } from "./panels";
import { GuideModal } from "./guides";
import { ComparePanel, regressed, runLabel } from "./compare";
import { intervalLabel, MonitorBanner, MonitorPanel } from "./monitor";
import { HistoryPanel } from "./history";

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
  markdown: "text/markdown",
  pdf: "application/pdf",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
};
const EXPORT_EXTENSION: Record<string, string> = { json: "json", sarif: "sarif", html: "html", markdown: "md", pdf: "pdf", docx: "docx" };
const BULK_MAX = 20; // matches console/websec_api.py MAX_BULK
const PRESET_LABEL: Record<string, string> = { quick: "Quick", standard: "Standard", full: "Full" };
const TARGET_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$/; // matches the console and engine validators

function gradeClass(grade: string): string {
  if (grade.startsWith("A")) return "text-(--iux-success)";
  if (grade.startsWith("B")) return "text-[#79c0ff]";
  if (grade.startsWith("C")) return "text-[#e3b341]";
  return "text-[#ff7b72]";
}

/** Open a collapsed row the way a link would, even when the hash already names it. */
function openRow(id: string) {
  if (window.location.hash === `#${id}`) window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  window.location.hash = id;
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

function FindingCard({ finding, open, onGuide }: { finding: WebSecFinding; open: boolean; onGuide?: () => void }) {
  return (
    <details open={open} className="rounded-lg border border-(--iux-border) bg-(--iux-panel) px-3 py-2">
      <summary className="cursor-pointer text-sm">
        <span className={`me-2 text-xs font-semibold uppercase ${SEVERITY_CLASS[finding.severity]}`}>
          {finding.severity}
        </span>
        {finding.title}
        <span className="ms-2 text-xs text-(--iux-muted-foreground)">{finding.module}</span>
        {finding.cwe ? (
          <a
            href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace(/^CWE-/, "")}.html`}
            target="_blank"
            rel="noreferrer"
            title={[finding.cwe_name, finding.owasp].filter(Boolean).join(" · ")}
            className="ms-2 rounded border border-(--iux-border) px-1.5 font-mono text-[10px] text-(--iux-muted-foreground) hover:underline"
            translate="no"
          >
            {finding.cwe}
          </a>
        ) : null}
      </summary>
      <div className="mt-2 space-y-2 text-sm text-(--iux-muted-foreground)">
        <p>{finding.detail}</p>
        {finding.owasp ? <p className="text-xs" translate="no">{`${finding.cwe} ${finding.cwe_name} · OWASP ${finding.owasp}`}</p> : null}
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
              <a key={ref} href={ref} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 break-all underline">
                {ref}
                <ArrowSquareOutIcon size={12} />
              </a>
            ))}
          </p>
        ) : null}
        {onGuide ? (
          <button type="button" className="iux-btn" data-variant="outline" onClick={onGuide}>
            <BookOpenIcon size={14} aria-hidden="true" />
            Guide
          </button>
        ) : null}
      </div>
    </details>
  );
}

export default function WebSecLabPage() {
  const [status, setStatus] = useState<WebSecStatus | null>(null);
  const [modules, setModules] = useState<WebSecModule[]>([]);
  const [presets, setPresets] = useState<Record<string, string[]> | null>(null);
  const [target, setTarget] = useState("");
  const [preset, setPreset] = useState("standard");
  const [scheme, setScheme] = useState<"http" | "https">("https");
  const [active, setActive] = useState(false);
  const [confirmActive, setConfirmActive] = useState(false);
  const [timeoutText, setTimeoutText] = useState("");
  const [deadlineText, setDeadlineText] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [jobId, setJobId] = useState("");
  const [job, setJob] = useState<WebSecJob | null>(null);
  const [viewer, setViewer] = useState<{ name: string; format: string; content: string } | null>(null);
  const [history, setHistory] = useState<WebSecHistoryEntry[]>([]);
  const [reports, setReports] = useState<WebSecReportFile[]>([]);
  const [filter, setFilter] = useState<WebSecSeverity | "all">("all");
  const [openModules, setOpenModules] = useState<string[]>([]);
  const [loadedReport, setLoadedReport] = useState<WebSecReport | null>(null);
  const [stats, setStats] = useState<WebSecStats | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [bulkTargets, setBulkTargets] = useState<string[]>([]);
  const [bulkPreset, setBulkPreset] = useState("quick");
  const [bulkJobId, setBulkJobId] = useState("");
  const [bulkJob, setBulkJob] = useState<WebSecBulkJob | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  // saved choices (engine store, private storage folder)
  const [prefsLoaded, setPrefsLoaded] = useState(false);
  const [prefsNote, setPrefsNote] = useState("");
  const [savedTarget, setSavedTarget] = useState("");
  const [saveState, setSaveState] = useState<{ ok: boolean; text: string } | null>(null);
  const lastSaved = useRef("");
  // guides
  const [guides, setGuides] = useState<WebSecGuides | null>(null);
  const [guidesError, setGuidesError] = useState("");
  const [guideOpen, setGuideOpen] = useState(false);
  const [guideId, setGuideId] = useState("");
  // compare
  const [compareFrom, setCompareFrom] = useState("");
  const [compareTo, setCompareTo] = useState("");
  const [diff, setDiff] = useState<WebSecCompare | null>(null);
  const [diffError, setDiffError] = useState("");
  const [diffLoading, setDiffLoading] = useState(false);
  const pendingCompare = useRef<{ from: string; to: string } | null>(null);
  // monitor
  const [monitor, setMonitor] = useState<WebSecMonitorStatus | null>(null);
  const [monitorError, setMonitorError] = useState("");

  const report = loadedReport ?? (job?.state === "done" ? job.report : undefined);
  const running = job?.state === "running";
  const ready = status?.state === "ready";
  const scopeNote = status?.notes.find((note) => note.startsWith("Scope")) ?? "";
  const reportTarget = (report?.target || job?.target || target).trim();

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      api.websecStatus().then((value) => !cancelled && setStatus(value)).catch(() => undefined);
      api.websecModules().then((value) => {
        if (cancelled) return;
        setModules(value.modules);
        setPresets(value.presets ?? null);
      }).catch(() => undefined);
    };
    load();
    const timer = window.setInterval(load, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const reloadHistory = () => {
    api.websecHistory().then((value) => setHistory(value.entries)).catch(() => undefined);
    api.websecStats().then(setStats).catch(() => setStats(null));
    const current = (report?.target || job?.target || target).trim();
    if (current) api.websecReports(current).then((value) => setReports(value.reports)).catch(() => undefined);
  };

  useEffect(() => {
    reloadHistory();
    api.websecGuides().then(setGuides).catch((reason) => setGuidesError(errorText(reason)));
  }, []);

  const loadMonitor = () => {
    api.websecMonitor().then((value) => {
      setMonitor(value);
      setMonitorError("");
    }).catch((reason) => setMonitorError(errorText(reason)));
  };
  useEffect(() => {
    loadMonitor();
    const timer = window.setInterval(loadMonitor, 30000);
    return () => window.clearInterval(timer);
  }, []);

  // Saved choices: read once, then every change is written back (debounced). A store from
  // another version is read by the engine; ids the catalogue no longer lists are kept.
  useEffect(() => {
    api.websecPreferences().then((payload) => {
      const scan = payload.preferences.scan;
      setTarget((current) => current || scan.target);
      setSavedTarget(scan.target);
      setPreset(scan.preset);
      setScheme(scan.scheme);
      setSelected(scan.modules);
      setTimeoutText(scan.timeout == null ? "" : String(scan.timeout));
      setDeadlineText(scan.deadline == null ? "" : String(scan.deadline));
      setBulkPreset(payload.preferences.bulk.preset);
      lastSaved.current = JSON.stringify(payload.preferences);
      setPrefsNote(payload.configError ?? "");
      setPrefsLoaded(true);
    }).catch(() => setPrefsNote("Saved choices are unavailable; defaults apply."));
  }, []);

  const prefsPayload = (targetValue: string): WebSecPreferences | null => {
    const timeout = timeoutText.trim() === "" ? null : Number(timeoutText);
    const deadline = deadlineText.trim() === "" ? null : Number(deadlineText);
    if (timeout !== null && (!Number.isFinite(timeout) || timeout < 1 || timeout > 30)) return null;
    if (deadline !== null && (!Number.isFinite(deadline) || deadline < 10 || deadline > 600)) return null;
    return {
      scan: { target: targetValue, preset, scheme, modules: selected, timeout, deadline },
      bulk: { preset: bulkPreset }
    };
  };

  useEffect(() => {
    if (!prefsLoaded) return;
    const payload = prefsPayload(savedTarget);
    if (!payload) return;
    const serialized = JSON.stringify(payload);
    if (serialized === lastSaved.current) return;
    const timer = window.setTimeout(() => {
      api.websecSavePreferences(payload).then(() => {
        lastSaved.current = serialized;
        setSaveState({ ok: true, text: "Saved on this computer" });
      }).catch((reason) => setSaveState({ ok: false, text: errorText(reason) }));
    }, 500);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefsLoaded, preset, scheme, selected, timeoutText, deadlineText, bulkPreset, savedTarget]);

  // Default target from live state: the saved one, else the most recently scanned host.
  useEffect(() => {
    if (prefsLoaded && !target && !savedTarget && history[0]?.target) setTarget(history[0].target);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefsLoaded, history]);

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
          if (!cancelled) reloadHistory();
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
    if (!bulkJobId) return;
    let cancelled = false;
    let timer = 0;
    const tick = () => {
      api.websecBulkJob(bulkJobId).then((value) => {
        if (cancelled) return;
        setBulkJob(value);
        if (value.state !== "running") {
          window.clearInterval(timer);
          setBulkBusy(false);
        }
      }).catch((reason) => {
        if (cancelled) return;
        window.clearInterval(timer);
        setError(errorText(reason));
        setBulkBusy(false);
      });
    };
    tick();
    timer = window.setInterval(tick, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [bulkJobId]);

  useEffect(() => {
    if (!reportTarget) {
      setReports([]);
      return;
    }
    let cancelled = false;
    api.websecReports(reportTarget)
      .then((value) => !cancelled && setReports(value.reports))
      .catch(() => !cancelled && setReports([]));
    return () => {
      cancelled = true;
    };
  }, [report, reportTarget]);

  // Compare defaults to the latest two runs; a history row can ask for a specific pair.
  useEffect(() => {
    const names = reports.map((entry) => entry.name);
    const pending = pendingCompare.current;
    if (pending && names.includes(pending.from) && names.includes(pending.to)) {
      pendingCompare.current = null;
      setCompareFrom(pending.from);
      setCompareTo(pending.to);
      return;
    }
    if (names.length < 2) {
      setCompareFrom("");
      setCompareTo("");
      return;
    }
    setCompareTo((current) => (names.includes(current) ? current : names[0]));
    setCompareFrom((current) => (names.includes(current) ? current : names[1]));
  }, [reports]);

  useEffect(() => {
    if (!reportTarget || !compareFrom || !compareTo || compareFrom === compareTo) {
      setDiff(null);
      return;
    }
    let cancelled = false;
    setDiffLoading(true);
    setDiffError("");
    api.websecCompare(reportTarget, compareFrom, compareTo)
      .then((value) => !cancelled && setDiff(value))
      .catch((reason) => {
        if (cancelled) return;
        setDiff(null);
        setDiffError(errorText(reason));
      })
      .finally(() => !cancelled && setDiffLoading(false));
    return () => {
      cancelled = true;
    };
  }, [reportTarget, compareFrom, compareTo]);

  const findings = useMemo(() => {
    const list = report?.findings ?? [];
    return filter === "all" ? list : list.filter((finding) => finding.severity === filter);
  }, [report, filter]);

  const known = useMemo(() => new Set(modules.map((module) => module.id)), [modules]);
  // Saved ids the catalogue no longer lists stay in the store but are never sent.
  const chosen = useMemo(() => selected.filter((id) => known.has(id)), [selected, known]);
  // The checks this scan would select: the explicit choice, else the preset. Without the
  // preset table (an older console) every check counts, so the dialog never under-reports.
  const effective = useMemo<string[] | null>(() => {
    if (chosen.length) return chosen;
    if (preset === "full") return modules.map((module) => module.id);
    return presets?.[preset] ?? null;
  }, [chosen, preset, presets, modules]);
  const intrusiveModules = useMemo(
    () => modules.filter((module) => module.active && (!effective || effective.includes(module.id))),
    [modules, effective]);

  const moduleLabels = useMemo(() => new Map(modules.map((module) => [module.id, module.label])), [modules]);
  const progress = running ? job?.progress : undefined;
  const guideFor = (moduleId: string) => guides?.byCheck[moduleId] ?? "";
  const showGuide = (id: string) => {
    setGuideId(id);
    setGuideOpen(true);
  };

  const toggleModule = (id: string) => {
    setOpenModules((current) =>
      current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  };

  const canScan = ready && !busy && !running && !!target.trim();

  const start = async () => {
    if (!canScan) return;
    setError("");
    setViewer(null);
    setLoadedReport(null);
    const clean = target.trim().toLowerCase();
    if (TARGET_PATTERN.test(clean)) setSavedTarget(clean);
    if (active && intrusiveModules.length) {
      setConfirmActive(true);
      return;
    }
    // Nothing intrusive in this selection, so there is nothing to confirm: run passively
    // rather than silently going active.
    await runScan(false);
  };

  const runScan = async (intrusive: boolean) => {
    const timeout = timeoutText.trim() === "" ? undefined : Number(timeoutText);
    const deadline = deadlineText.trim() === "" ? undefined : Number(deadlineText);
    if (timeout !== undefined && (!Number.isFinite(timeout) || timeout < 1 || timeout > 30)) {
      setError("Request timeout must be between 1 and 30 seconds.");
      setConfirmActive(false);
      return;
    }
    if (deadline !== undefined && (!Number.isFinite(deadline) || deadline < 10 || deadline > 600)) {
      setError("Scan budget must be between 10 and 600 seconds.");
      setConfirmActive(false);
      return;
    }
    setConfirmActive(false);
    setBusy(true);
    try {
      const created = await api.websecStart({
        target: target.trim(),
        preset,
        scheme,
        active: intrusive,
        modules: chosen.length ? chosen : undefined,
        timeout,
        deadline
      });
      setJob(created);
      setJobId(created.id);
    } catch (reason) {
      setError(errorText(reason));
      setBusy(false);
    }
  };

  // "S" starts the primary action when no field has focus (the Cleanup Lab shortcut rule).
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() !== "s" || event.metaKey || event.ctrlKey || event.altKey || event.shiftKey) return;
      const node = event.target as HTMLElement | null;
      if (node && (node.isContentEditable || ["INPUT", "TEXTAREA", "SELECT", "BUTTON"].includes(node.tagName) || node.closest("dialog"))) return;
      if (!canScan) return;
      event.preventDefault();
      void start();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

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

  const parseBulkFile = (file: File) => {
    file.text().then((text) => {
      const targets: string[] = [];
      for (const line of text.split(/\r?\n/)) {
        const candidate = line.split(",")[0].trim();
        if (!candidate || candidate.startsWith("#")) continue;
        if (!targets.includes(candidate)) targets.push(candidate);
        if (targets.length >= BULK_MAX) break;
      }
      setBulkTargets(targets);
    }).catch(() => setError("The targets file could not be read."));
  };

  const startBulk = async () => {
    setError("");
    setBulkBusy(true);
    try {
      const created = await api.websecBulkStart({ targets: bulkTargets, preset: bulkPreset });
      setBulkJob(created);
      setBulkJobId(created.id);
    } catch (reason) {
      setError(errorText(reason));
      setBulkBusy(false);
    }
  };

  const openHistoryEntry = (entry: WebSecHistoryEntry) => {
    if (!entry.name) return;
    setError("");
    api.websecReport(entry.target, entry.name, "json").then((value) => {
      try {
        setLoadedReport(JSON.parse(value.content) as WebSecReport);
        setFilter("all");
        setOpenModules([]);
        window.scrollTo({ top: 0, behavior: "smooth" });
      } catch {
        setError("The stored report is not valid JSON.");
      }
    }).catch((reason) => setError(errorText(reason)));
  };

  // Compare a history row with the run before it on the same target.
  const compareHistoryEntry = (entry: WebSecHistoryEntry) => {
    const runs = history.filter((item) => item.target === entry.target && item.name);
    const index = runs.findIndex((item) => item.name === entry.name);
    const previous = index >= 0 ? runs[index + 1] : undefined;
    if (!entry.name || !previous?.name) return;
    pendingCompare.current = { from: previous.name, to: entry.name };
    if (entry.target === reportTarget && reports.some((item) => item.name === previous.name)) {
      pendingCompare.current = null;
      setCompareFrom(previous.name);
      setCompareTo(entry.name);
    } else {
      setLoadedReport(null);
      setJob(null);
      setTarget(entry.target);
    }
    openRow("websec-compare");
  };

  const compareTarget = (host: string) => {
    if (host !== reportTarget) {
      pendingCompare.current = null;
      setLoadedReport(null);
      setJob(null);
      setTarget(host);
    }
    openRow("websec-compare");
  };

  const openReport = async (name: string, format: string) => {
    if (!reportTarget) return;
    setError("");
    try {
      const value = await api.websecReport(reportTarget, name, format);
      setViewer({ name, format, content: value.content });
    } catch (reason) {
      setError(errorText(reason));
    }
  };

  const download = async (name: string, format: string) => {
    if (!reportTarget) return;
    try {
      const value = await api.websecReport(reportTarget, name, format);
      const mime = EXPORT_MIME[format] ?? "application/octet-stream";
      const extension = EXPORT_EXTENSION[format] ?? format;
      // PDF and DOCX arrive base64-encoded inside the JSON response
      const body = value.encoding === "base64"
        ? Uint8Array.from(atob(value.content), (char) => char.charCodeAt(0))
        : value.content;
      const blob = new Blob([body], { type: mime });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${reportTarget}.${name.replace(/\.json$/, "")}.${extension}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (reason) {
      setError(errorText(reason));
    }
  };

  const intrusiveCount = modules.filter((module) => module.active).length;
  const bulkSummary = bulkJob?.state === "running"
    ? <span>running</span>
    : bulkJob?.state === "done" && bulkJob.results
      ? <><span dir="ltr" className="tabular-nums">{bulkJob.results.targets.length}</span> <span>targets checked</span></>
      : bulkTargets.length
        ? <><span dir="ltr" className="tabular-nums">{bulkTargets.length}</span> <span>targets ready</span></>
        : <span>up to 20 targets</span>;

  return (
    <AppShell activeId="web-sec">
      <main className="space-y-5">
        <PageHead
          icon={<ShieldCheckIcon size={22} />}
          title="Web Sec Lab"
          description="Scope-guarded web posture assessment"
          actions={
            <>
              <IconButton label="SecOps guides" onClick={() => showGuide("")}>
                <BookOpenIcon size={16} />
              </IconButton>
              {status ? (
                <Badge tone={ready ? "success" : status.state === "needs-setup" ? "warning" : "danger"}>
                  {ready ? "Ready" : status.state === "needs-setup" ? "Needs setup" : "Unavailable"}
                </Badge>
              ) : null}
            </>
          }
        />

        {error ? (
          <p role="alert" className="rounded-md border border-(--iux-danger) px-3 py-2 text-sm text-(--iux-danger)">
            {error}
          </p>
        ) : null}

        <MonitorBanner monitor={monitor} onCompare={compareTarget} />

        {status && !ready ? (
          <div className="space-y-2 rounded-md border border-(--iux-border) px-3 py-3 text-sm">
            {status.reasons.length ? (
              <ul className="list-disc space-y-1 ps-5 text-(--iux-muted-foreground)">
                {status.reasons.map((reason) => <li key={reason}>{reason}</li>)}
              </ul>
            ) : null}
            {!status.reasons.length ? <p>Declare a scope before scanning.</p> : null}
            <a className="underline" href="/labs/websec/">Status</a>
          </div>
        ) : null}

        <Section title="Scan" description={scopeNote || status?.notes?.[0] || ""}>
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex min-w-0 flex-1 basis-56 flex-col gap-1 text-sm">
              <span className="text-(--iux-muted-foreground)">Target</span>
              <input
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    void start();
                  }
                }}
                placeholder="example.test"
                spellCheck={false}
                autoCapitalize="off"
                className="iux-input"
              />
            </label>
            <button
              type="button"
              onClick={() => void start()}
              disabled={!canScan}
              aria-keyshortcuts="S"
              title="Shortcut: S"
              className="iux-btn"
              data-variant="primary"
            >
              <PlayIcon size={14} aria-hidden="true" />
              Scan
            </button>
            {running ? (
              <button type="button" onClick={cancel} className="iux-btn" data-variant="outline">
                <StopIcon size={14} aria-hidden="true" />
                Cancel
              </button>
            ) : null}
          </div>

          <p className="mt-2 flex flex-wrap items-center gap-x-1.5 text-xs text-(--iux-muted-foreground)">
            <span>{PRESET_LABEL[preset] ?? preset}</span>
            <span aria-hidden="true">·</span>
            <span dir="ltr">{scheme}</span>
            <span aria-hidden="true">·</span>
            {effective ? <><span dir="ltr" className="tabular-nums">{effective.length}</span> <span>checks</span></> : <span>preset checks</span>}
            <span aria-hidden="true">·</span>
            <button type="button" className="underline" onClick={() => openRow("websec-options")}>Change</button>
          </p>

          <label className="mt-3 flex items-start gap-2 text-sm">
            <input type="checkbox" aria-label="Allow intrusive checks" checked={active} onChange={(event) => setActive(event.target.checked)} className="mt-1" />
            <span>
              <span className="font-medium">Allow intrusive checks</span>
              <span className="block text-xs text-(--iux-muted-foreground)">Only with written authorization for this host. Asked again before every scan; never saved.</span>
            </span>
          </label>

          {progress && progress.modules.length ? (
            <ul aria-live="polite" className="mt-3 space-y-1">
              {progress.modules.map((module, index) => {
                const firstPending = progress.modules.findIndex((entry) => !entry.status);
                const state = module.status ?? (index === firstPending ? "running" : "pending");
                return (
                  <li key={module.id} className="flex items-center gap-2 text-xs">
                    <span className={state === "running" ? "text-[#f36c21]" : "text-(--iux-muted-foreground)"}>{state}</span>
                    <span>{moduleLabels.get(module.id) ?? module.id}</span>
                  </li>
                );
              })}
            </ul>
          ) : running ? (
            <p aria-live="polite" className="mt-3 text-sm text-(--iux-muted-foreground)">
              Scanning {job?.target}…
            </p>
          ) : null}
          {job?.state === "error" ? <p role="alert" className="mt-3 text-sm text-(--iux-danger)">The scan failed. {job.error}</p> : null}
        </Section>

        {confirmActive ? (
          <Modal
            title="Confirm the active scan"
            description="Only with written authorization for this host."
            onClose={() => setConfirmActive(false)}
          >
            <div className="space-y-3 text-sm">
              <p>The scan would run these checks actively:</p>
              <ul className="list-disc space-y-1 ps-5">
                {intrusiveModules.map((module) => (
                  <li key={module.id}>
                    {module.label}
                    <span className="ms-1 font-mono text-xs text-(--iux-muted-foreground)">({module.id})</span>
                  </li>
                ))}
              </ul>
              {scopeNote ? <p className="text-xs text-(--iux-muted-foreground)">{scopeNote}</p> : null}
              <div className="flex flex-wrap gap-2 pt-1">
                <button type="button" onClick={() => runScan(true)} className="iux-btn" data-variant="primary">
                  Run with intrusive checks
                </button>
                <button type="button" onClick={() => runScan(false)} className="iux-btn" data-variant="outline">
                  Scan passively
                </button>
              </div>
            </div>
          </Modal>
        ) : null}

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
                  aria-pressed={filter === value}
                  onClick={() => setFilter(value)}
                  className={`iux-touch-target rounded border px-2 py-0.5 text-xs ${filter === value ? "border-[#f36c21] text-[#f36c21]" : "border-(--iux-border) text-(--iux-muted-foreground)"}`}
                >
                  {value === "all" ? "All" : value}
                </button>
              ))}
              {reports.length >= 2 ? (
                <button type="button" className="iux-btn ms-auto" data-variant="outline" onClick={() => openRow("websec-compare")}>
                  Compare with the previous run
                </button>
              ) : null}
            </div>
            <div className="space-y-2">
              {findings.length ? (
                findings.map((finding, index) => (
                  <FindingCard
                    key={`${finding.module}-${finding.title}-${index}`}
                    finding={finding}
                    open={index === 0}
                    onGuide={guideFor(finding.module) ? () => showGuide(guideFor(finding.module)) : undefined}
                  />
                ))
              ) : (
                <Empty>No findings at this preset.</Empty>
              )}
            </div>

            <details className="mt-4 text-sm">
              <summary className="cursor-pointer text-(--iux-muted-foreground)">Checks</summary>
              <div className="mt-2 overflow-x-auto">
                <table className="mt-2 w-full text-left text-xs">
                  <thead>
                    <tr className="text-(--iux-muted-foreground)">
                      <th className="py-1">Check</th>
                      <th>Status</th>
                      <th>Findings</th>
                      <th>Time</th>
                      <th><span className="sr-only">Guide</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.modules.map((module) => {
                      const open = openModules.includes(module.id);
                      const guide = guideFor(module.id);
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
                            <td>
                              {guide ? (
                                <IconButton label={`Guide for ${module.label}`} onClick={() => showGuide(guide)}>
                                  <BookOpenIcon size={14} />
                                </IconButton>
                              ) : null}
                            </td>
                          </tr>
                          {open ? (
                            <tr>
                              <td colSpan={5} className="py-2 pe-3">
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
              </div>
            </details>
          </Section>
        ) : null}

        {/* Everything else, collapsed, with a live one-line summary; nothing was removed. */}
        <CareList label="Web Sec Lab options">
          <CareRow
            id="websec-options"
            title="Scan options"
            attention={!!prefsNote || saveState?.ok === false}
            summary={<>
              <span>{PRESET_LABEL[preset] ?? preset}</span> · <span dir="ltr">{scheme}</span> · {chosen.length
                ? <><span dir="ltr" className="tabular-nums">{chosen.length}</span> <span>chosen checks</span></>
                : <span>preset checks</span>} · <span>{prefsLoaded ? "saved on this computer" : "not saved"}</span>
            </>}
          >
            <div className="space-y-3 text-sm">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <label className="flex min-w-0 flex-col gap-1">
                  <span className="text-(--iux-muted-foreground)">Preset</span>
                  <select value={preset} onChange={(event) => setPreset(event.target.value)} className="iux-input">
                    <option value="quick">Quick</option>
                    <option value="standard">Standard</option>
                    <option value="full">Full</option>
                  </select>
                </label>
                <label className="flex min-w-0 flex-col gap-1">
                  <span className="text-(--iux-muted-foreground)">Protocol</span>
                  <select value={scheme} onChange={(event) => setScheme(event.target.value as "http" | "https")} className="iux-input">
                    <option value="https">https</option>
                    <option value="http">http</option>
                  </select>
                </label>
                <label className="flex min-w-0 flex-col gap-1">
                  <span className="text-(--iux-muted-foreground)">Request timeout (s)</span>
                  <input type="number" min={1} max={30} step="0.5" placeholder="6" value={timeoutText}
                    onChange={(event) => setTimeoutText(event.target.value)} className="iux-input" />
                </label>
                <label className="flex min-w-0 flex-col gap-1">
                  <span className="text-(--iux-muted-foreground)">Scan budget (s)</span>
                  <input type="number" min={10} max={600} step="1" placeholder="60" value={deadlineText}
                    onChange={(event) => setDeadlineText(event.target.value)} className="iux-input" />
                </label>
              </div>
              <fieldset>
                <legend className="flex flex-wrap items-center gap-2 text-(--iux-muted-foreground)">
                  <span>Checks</span>
                  <span className="text-xs">{chosen.length ? "a chosen set replaces the preset" : "none chosen: the preset decides"}</span>
                  {selected.length ? (
                    <button type="button" className="text-xs underline" onClick={() => setSelected([])}>Use the preset</button>
                  ) : null}
                </legend>
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
                        {module.active ? <span className="ms-1 text-(--iux-muted-foreground)">(active)</span> : null}
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
              {prefsNote ? <p role="alert" className="text-xs text-(--iux-warning)">{prefsNote}</p> : null}
              {saveState ? (
                <p role={saveState.ok ? "status" : "alert"} className={`text-xs ${saveState.ok ? "text-(--iux-muted-foreground)" : "text-(--iux-danger)"}`}>
                  {saveState.ok ? saveState.text : <><span>Not saved:</span> {saveState.text}</>}
                </p>
              ) : null}
            </div>
          </CareRow>

          <CareRow
            id="websec-reports"
            title="Reports"
            summary={reports.length
              ? <><span dir="ltr" className="tabular-nums">{reports.length}</span> <span>stored</span> · <span dir="ltr">{reportTarget}</span></>
              : <span>none yet</span>}
          >
            {reports.length ? (
              <ul className="space-y-1 text-sm">
                {reports.map((entry) => (
                  <li key={entry.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-(--iux-border) py-1 first:border-t-0">
                    <span className="font-mono text-xs">{entry.name}</span>
                    <span className="text-xs text-(--iux-muted-foreground)">{entry.bytes} bytes</span>
                    <button type="button" className="iux-btn" data-variant="ghost" onClick={() => openReport(entry.name, "markdown")}>Open</button>
                    <button type="button" className="iux-btn" data-variant="ghost" onClick={() => download(entry.name, "json")}>
                      <DownloadSimpleIcon size={12} aria-hidden="true" />
                      JSON
                    </button>
                    <button type="button" className="iux-btn" data-variant="ghost" onClick={() => download(entry.name, "sarif")}>SARIF</button>
                    <button type="button" className="iux-btn" data-variant="ghost" onClick={() => download(entry.name, "html")}>HTML</button>
                    <button type="button" className="iux-btn" data-variant="ghost" onClick={() => download(entry.name, "markdown")}>Markdown</button>
                    <button type="button" className="iux-btn" data-variant="ghost" onClick={() => download(entry.name, "pdf")}>PDF</button>
                    <button type="button" className="iux-btn" data-variant="ghost" onClick={() => download(entry.name, "docx")}>DOCX</button>
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
                    <IconButton label="Close" onClick={() => setViewer(null)}>
                      <XIcon size={14} />
                    </IconButton>
                  </span>
                </div>
                <pre className="max-h-96 overflow-auto rounded border border-(--iux-border) bg-(--iux-bg) p-2 text-xs whitespace-pre-wrap">
                  {viewer.content}
                </pre>
              </div>
            ) : null}
          </CareRow>

          <CareRow
            id="websec-compare"
            title="Compare runs"
            attention={regressed(diff)}
            summary={diff
              ? <><span dir="ltr">{diff.grade.previous} → {diff.grade.current}</span> · <span dir="ltr" className="tabular-nums">{diff.new.length}</span> <span>new</span> · <span dir="ltr" className="tabular-nums">{diff.resolved.length}</span> <span>resolved</span></>
              : <span>{reports.length < 2 ? "needs two runs" : diffError ? "unavailable" : "…"}</span>}
          >
            <ComparePanel
              reports={reports}
              from={compareFrom}
              to={compareTo}
              onFrom={setCompareFrom}
              onTo={setCompareTo}
              diff={diff}
              error={diffError}
              loading={diffLoading}
              labels={moduleLabels}
              severityClass={SEVERITY_CLASS}
            />
          </CareRow>

          <CareRow
            id="websec-monitor"
            title="Monitor"
            attention={!!monitor?.activeWarnings.length || !!monitor?.configError}
            summary={!monitor
              ? <span>{monitorError ? "unavailable" : "…"}</span>
              : monitor.activeWarnings.length
                ? <><span dir="ltr" className="tabular-nums">{monitor.activeWarnings.length}</span> <span>{monitor.activeWarnings.length === 1 ? "warning" : "warnings"}</span></>
                : monitor.config.enabled
                  ? <><span>on</span> · <span dir="ltr" className="tabular-nums">{monitor.config.targets.length}</span> <span>targets</span> · <span>{intervalLabel(monitor.config.intervalMinutes)}</span></>
                  : <span>off</span>}
          >
            <MonitorPanel monitor={monitor} error={monitorError} reload={loadMonitor} currentTarget={target.trim()} />
          </CareRow>

          <CareRow id="websec-bulk" title="Bulk validation" summary={bulkSummary}>
            <div className="flex flex-wrap items-end gap-3 text-sm">
              <label className="flex min-w-0 flex-col gap-1">
                <span className="text-(--iux-muted-foreground)">Targets file</span>
                <input
                  type="file"
                  accept=".txt,.csv,text/plain,text/csv"
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) parseBulkFile(file);
                    event.target.value = "";
                  }}
                  className="iux-input"
                />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-(--iux-muted-foreground)">Bulk preset</span>
                <select value={bulkPreset} onChange={(event) => setBulkPreset(event.target.value)} className="iux-input">
                  <option value="quick">Quick</option>
                  <option value="standard">Standard</option>
                  <option value="full">Full</option>
                </select>
              </label>
              <button
                type="button"
                onClick={startBulk}
                disabled={!ready || bulkBusy || !bulkTargets.length}
                className="iux-btn"
                data-variant="primary"
              >
                Validate
              </button>
            </div>
            <p className="mt-2 text-xs text-(--iux-muted-foreground)">One target per line, up to 20. Bulk runs are passive.</p>

            {bulkJob?.state === "running" ? (
              <p aria-live="polite" className="mt-3 text-sm text-(--iux-muted-foreground)">
                {`Scanning ${bulkJob.results?.count ?? bulkTargets.length} targets…`}
              </p>
            ) : null}
            {bulkJob?.state === "error" ? <p role="alert" className="mt-3 text-sm text-(--iux-danger)">The scan failed. {bulkJob.error}</p> : null}
            {bulkJob?.state === "done" && bulkJob.results ? (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="text-xs text-(--iux-muted-foreground)">
                      <th className="py-1">Target</th>
                      <th>Grade</th>
                      <th>Score</th>
                      <th>Findings</th>
                      <th>Note</th>
                    </tr>
                  </thead>
                  <tbody>
                    {bulkJob.results.targets.map((entry, index) => (
                      <tr key={`${entry.target}-${index}`} className="border-t border-(--iux-border)">
                        <td className="py-1">{entry.target}</td>
                        <td className={entry.grade ? gradeClass(entry.grade) : ""}>{entry.grade || "—"}</td>
                        <td>{entry.grade ? entry.score : "—"}</td>
                        <td>{entry.grade ? (entry.summary?.total ?? 0) : "—"}</td>
                        <td className="text-xs text-(--iux-muted-foreground)">{entry.error}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </CareRow>

          <CareRow
            id="websec-history"
            title="History"
            summary={history.length ? <><span dir="ltr" className="tabular-nums">{stats?.runs ?? history.length}</span> <span>runs</span></> : <span>none yet</span>}
          >
            <HistoryPanel history={history} stats={stats} gradeClass={gradeClass} onOpen={openHistoryEntry}
              onCompare={compareHistoryEntry} reload={reloadHistory} />
          </CareRow>

          <CareRow
            id="websec-catalogue"
            title="Catalogue"
            summary={<><span dir="ltr" className="tabular-nums">{modules.length}</span> <span>checks</span> · <span dir="ltr" className="tabular-nums">{intrusiveCount}</span> <span>intrusive</span></>}
          >
            {modules.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="text-(--iux-muted-foreground)">
                      <th className="py-1">Module</th>
                      <th>Description</th>
                      <th>Group</th>
                      <th>Weight</th>
                      <th>Upstream</th>
                      <th>Active</th>
                    </tr>
                  </thead>
                  <tbody>
                    {modules.map((module) => (
                      <tr key={module.id} className="border-t border-(--iux-border)">
                        <td className="py-1">
                          {module.label}
                          <span className="ms-1 font-mono text-[10px] text-(--iux-muted-foreground)">{module.id}</span>
                        </td>
                        <td className="text-(--iux-muted-foreground)">{module.description}</td>
                        <td>{module.group}</td>
                        <td>{module.weight}</td>
                        <td className="text-(--iux-muted-foreground)">{module.upstream}</td>
                        <td>{module.active ? <span className="text-(--iux-muted-foreground)">(active)</span> : ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <Empty>The catalogue is not loaded yet.</Empty>}
          </CareRow>

          <CareRow
            id="websec-guides"
            title="Guides"
            summary={guides ? <><span dir="ltr" className="tabular-nums">{guides.guides.length}</span> <span>guides</span></> : <span>{guidesError ? "unavailable" : "…"}</span>}
          >
            {guidesError ? <p role="alert" className="text-sm text-(--iux-danger)"><span>Guides could not be loaded.</span> {guidesError}</p> : null}
            {guides ? (
              <div className="flex flex-wrap gap-2">
                {guides.guides.map((guide) => (
                  <button key={guide.id} type="button" className="iux-btn" data-variant="outline" onClick={() => showGuide(guide.id)}>
                    <BookOpenIcon size={14} aria-hidden="true" />
                    {guide.title}
                  </button>
                ))}
              </div>
            ) : null}
          </CareRow>

          <CareRow
            id="websec-environment"
            title="Environment"
            summary={status ? <span dir="ltr" className="font-mono">{status.version || "web-sec"}</span> : <span>…</span>}
          >
            {status ? (
              <div className="space-y-1 text-xs text-(--iux-muted-foreground)">
                <p>Python <span className="font-mono">{status.python}</span></p>
                <p>Storage <span className="font-mono break-all">{status.storage}</span></p>
                <p>History keeps 50 runs and 20 reports per target.</p>
                <p><a className="underline" href="/labs/websec/">Status</a></p>
              </div>
            ) : null}
          </CareRow>
        </CareList>

        {guideOpen ? (
          <GuideModal
            guides={guides?.guides ?? []}
            reference={guides?.reference}
            error={guidesError}
            selected={guideId}
            onSelect={setGuideId}
            labels={moduleLabels}
            onClose={() => setGuideOpen(false)}
          />
        ) : null}
      </main>
    </AppShell>
  );
}
