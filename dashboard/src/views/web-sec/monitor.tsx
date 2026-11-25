/**
 * The Web Sec Lab monitor on the workbench: a banner while a monitored target is worse
 * than before (or the scope is expiring), and the Monitor row's settings, per-target
 * state and recent events. The engine sends the desktop notification; this is the
 * in-window half of "signal outside the window" (lat.md/ux-readiness.md).
 */
import { useEffect, useState } from "react";
import { api, type WebSecMonitorConfig, type WebSecMonitorStatus } from "../../lib/api";

const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error));
const INTERVAL_LABEL: Record<number, string> = { 60: "Hourly", 360: "Every 6 hours", 1440: "Daily", 10080: "Weekly" };
const REMINDER_LABEL: Record<number, string> = { 0: "Off", 6: "Every 6 hours", 24: "Daily", 168: "Weekly" };
const TARGET_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$/;

export const intervalLabel = (minutes: number) => INTERVAL_LABEL[minutes] ?? `${minutes} min`;

function when(seconds?: number): string {
  if (!seconds) return "never";
  return new Date(seconds * 1000).toLocaleString();
}

export function MonitorBanner({ monitor, onCompare }: { monitor: WebSecMonitorStatus | null; onCompare: (target: string) => void }) {
  const warnings = monitor?.activeWarnings ?? [];
  if (!warnings.length) return null;
  const critical = warnings.some((warning) => warning.level === "critical");
  return (
    <div role={critical ? "alert" : "status"}
      className={`rounded-md border p-3 text-sm ${critical ? "border-(--iux-danger)/60 bg-(--iux-danger)/10" : "border-(--iux-warning)/50 bg-(--iux-warning)/10"}`}>
      <p className="font-medium">{critical ? "The monitor found a serious regression" : "The monitor found a regression"}</p>
      <ul className="mt-1 space-y-1 text-xs">
        {warnings.map((warning) => (
          <li key={`${warning.target}-${warning.since}`} className="flex flex-wrap items-center gap-x-2">
            {warning.target ? (
              <>
                <span dir="ltr" className="font-medium" translate="no">{warning.target}</span>
                <span translate="no">{warning.message}</span>
                <button type="button" className="iux-touch-target underline" onClick={() => onCompare(warning.target)}>Compare runs</button>
              </>
            ) : warning.message === "scope-expired" ? (
              <span>The scope has expired; monitor scans are refused until it is renewed.</span>
            ) : (
              <span>The scope expires soon; renew the written authorization.</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function MonitorPanel({ monitor, error, reload, currentTarget }: {
  monitor: WebSecMonitorStatus | null;
  error: string;
  reload: () => void;
  currentTarget: string;
}) {
  const [draft, setDraft] = useState<WebSecMonitorConfig | null>(null);
  const [targetsText, setTargetsText] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (!monitor || draft) return;
    setDraft(monitor.config);
    setTargetsText(monitor.config.targets.join("\n"));
  }, [monitor, draft]);

  if (error && !monitor) return <p role="alert" className="text-sm text-(--iux-danger)"><span>The monitor is unavailable.</span> {error}</p>;
  if (!monitor || !draft) return <p role="status" className="text-sm text-(--iux-muted-foreground)">Loading the monitor…</p>;

  const targets = targetsText.split(/\r?\n/).map((line) => line.trim().toLowerCase()).filter(Boolean);
  const invalid = targets.filter((target) => !TARGET_PATTERN.test(target));
  const set = <K extends keyof WebSecMonitorConfig>(key: K, value: WebSecMonitorConfig[K]) => setDraft({ ...draft, [key]: value });

  const save = async () => {
    setBusy(true);
    setResult(null);
    try {
      const saved = await api.websecMonitorConfig({ ...draft, targets });
      setDraft(saved.config);
      setTargetsText(saved.config.targets.join("\n"));
      setResult({ ok: true, text: "Saved on this computer" });
      reload();
    } catch (reason) {
      setResult({ ok: false, text: errorText(reason) });
    } finally {
      setBusy(false);
    }
  };

  const runNow = async () => {
    setBusy(true);
    setResult(null);
    try {
      await api.websecMonitorRun();
      setResult({ ok: true, text: "The check started; results appear here when it finishes." });
      window.setTimeout(reload, 3000);
    } catch (reason) {
      setResult({ ok: false, text: errorText(reason) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4 text-sm">
      <p className="text-xs text-(--iux-muted-foreground)">Monitor scans are always passive, use the declared scope and run while the os-lab console is open.</p>
      {monitor.configError ? <p role="alert" className="text-xs text-(--iux-warning)">{monitor.configError}</p> : null}
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={draft.enabled} onChange={(event) => set("enabled", event.target.checked)} />
        <span className="font-medium">Monitor these targets</span>
      </label>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="flex min-w-0 flex-col gap-1 sm:row-span-2">
          <span className="text-(--iux-muted-foreground)">Monitored targets</span>
          <textarea rows={4} value={targetsText} spellCheck={false} onChange={(event) => setTargetsText(event.target.value)}
            className="iux-input font-mono text-xs" placeholder="example.test" />
          <span className="text-xs text-(--iux-muted-foreground)">One host per line, up to 10.</span>
          {currentTarget && TARGET_PATTERN.test(currentTarget) && !targets.includes(currentTarget.toLowerCase()) ? (
            <button type="button" className="iux-touch-target self-start text-xs underline"
              onClick={() => setTargetsText([...targets, currentTarget.toLowerCase()].join("\n"))}>
              Add the current target
            </button>
          ) : null}
          {invalid.length ? <span role="alert" className="text-xs text-(--iux-danger)"><span>Not a host name:</span> <span dir="ltr">{invalid.join(", ")}</span></span> : null}
        </label>
        <label className="flex min-w-0 flex-col gap-1">
          <span className="text-(--iux-muted-foreground)">How often</span>
          <select className="iux-input" value={draft.intervalMinutes} onChange={(event) => set("intervalMinutes", Number(event.target.value))}>
            {(monitor.intervals.length ? monitor.intervals : [60, 360, 1440, 10080]).map((minutes) => <option key={minutes} value={minutes}>{intervalLabel(minutes)}</option>)}
          </select>
        </label>
        <label className="flex min-w-0 flex-col gap-1">
          <span className="text-(--iux-muted-foreground)">Monitor preset</span>
          <select className="iux-input" value={draft.preset} onChange={(event) => set("preset", event.target.value as WebSecMonitorConfig["preset"])}>
            <option value="quick">Quick</option>
            <option value="standard">Standard</option>
          </select>
        </label>
        <label className="flex min-w-0 flex-col gap-1">
          <span className="text-(--iux-muted-foreground)">Alert on new findings</span>
          <select className="iux-input" value={draft.alertOn} onChange={(event) => set("alertOn", event.target.value as WebSecMonitorConfig["alertOn"])}>
            <option value="critical">Critical only</option>
            <option value="high">High and above</option>
            <option value="medium">Medium and above</option>
            <option value="low">Low and above</option>
          </select>
        </label>
        <label className="flex min-w-0 flex-col gap-1">
          <span className="text-(--iux-muted-foreground)">Remind while unresolved</span>
          <select className="iux-input" value={draft.reminderHours} onChange={(event) => set("reminderHours", Number(event.target.value))}>
            {[0, 6, 24, 168].map((hours) => <option key={hours} value={hours}>{REMINDER_LABEL[hours]}</option>)}
          </select>
        </label>
        <label className="flex min-w-0 flex-col gap-1">
          <span className="text-(--iux-muted-foreground)">Warn before the scope expires (days)</span>
          <input type="number" min={1} max={60} className="iux-input" value={draft.scopeWarnDays}
            onChange={(event) => set("scopeWarnDays", Math.max(1, Math.min(60, Number(event.target.value) || 1)))} />
        </label>
      </div>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={draft.notify} onChange={(event) => set("notify", event.target.checked)} />
        <span>Desktop notifications</span>
      </label>
      <div className="flex flex-wrap gap-2">
        <button type="button" className="iux-btn" data-variant="primary" disabled={busy || !!invalid.length || targets.length > 10} onClick={() => void save()}>
          Save monitor
        </button>
        <button type="button" className="iux-btn" data-variant="outline" disabled={busy || !monitor.config.targets.length} onClick={() => void runNow()}>
          Check now
        </button>
      </div>
      {result ? <p role={result.ok ? "status" : "alert"} className={`text-xs ${result.ok ? "text-(--iux-muted-foreground)" : "text-(--iux-danger)"}`}>{result.text}</p> : null}
      {monitor.runner?.lastTick.error ? <p role="alert" className="text-xs text-(--iux-danger)"><span>The last check failed:</span> {monitor.runner.lastTick.error}</p> : null}

      {monitor.config.targets.length ? (
        <div className="overflow-x-auto">
          <table className="w-full text-start text-xs">
            <thead>
              <tr className="text-(--iux-muted-foreground)">
                <th className="py-1">Target</th>
                <th>Grade</th>
                <th>Last check</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {monitor.config.targets.map((target) => {
                const entry = monitor.targets[target] ?? {};
                const warning = monitor.activeWarnings.find((item) => item.target === target);
                return (
                  <tr key={target} className="border-t border-(--iux-border)">
                    <td className="py-1" dir="ltr">{target}</td>
                    <td>{entry.grade ?? "—"}</td>
                    <td>{when(entry.lastRun)}</td>
                    <td>{entry.status === "error"
                      ? <span className="text-(--iux-danger)" translate="no">{entry.error}</span>
                      : warning ? <span className={warning.level === "critical" ? "text-(--iux-danger)" : "text-(--iux-warning)"}>{warning.level}</span>
                        : entry.lastRun ? <span>ok</span> : <span>pending</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}

      <div>
        <h3 className="text-xs font-semibold">Recent events</h3>
        {monitor.events.length ? (
          <ul className="mt-1 space-y-1 text-xs">
            {monitor.events.slice(0, 10).map((event, index) => (
              <li key={`${event.at}-${index}`} className="flex flex-wrap gap-x-2">
                <span className="font-mono text-(--iux-muted-foreground)">{when(event.at)}</span>
                <span className="font-medium">{event.kind}</span>
                {event.target ? <span dir="ltr">{event.target}</span> : null}
                <span className="text-(--iux-muted-foreground)" translate="no">{event.message}</span>
              </li>
            ))}
          </ul>
        ) : <p className="mt-1 text-xs text-(--iux-muted-foreground)">No events yet.</p>}
      </div>
    </div>
  );
}
