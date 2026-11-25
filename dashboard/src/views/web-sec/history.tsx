/**
 * The History row: statistics over every stored run, a per-target timeline with
 * favourites (kept through pruning), multi-select delete and clear. Deleting ends at
 * the shared confirmation dialog; nothing is removed before the console confirms.
 */
import { useState } from "react";
import { StarIcon } from "@phosphor-icons/react";
import { Empty, Modal } from "../../components/ui";
import { api, type WebSecHistoryEntry, type WebSecStats } from "../../lib/api";
import { runLabel } from "./compare";

const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error));

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

type Pending = { kind: "delete"; target: string; names: string[] } | { kind: "clear"; target: string };

export function HistoryPanel({ history, stats, gradeClass, onOpen, onCompare, reload }: {
  history: WebSecHistoryEntry[];
  stats: WebSecStats | null;
  gradeClass: (grade: string) => string;
  onOpen: (entry: WebSecHistoryEntry) => void;
  onCompare: (entry: WebSecHistoryEntry) => void;
  reload: () => void;
}) {
  const [historyTarget, setHistoryTarget] = useState("");
  const [favouritesOnly, setFavouritesOnly] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [pending, setPending] = useState<Pending | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const targets = [...new Set(history.map((entry) => entry.target))];
  const timeline = history.filter((entry) =>
    (!historyTarget || entry.target === historyTarget) && (!favouritesOnly || entry.favourite));
  const key = (entry: WebSecHistoryEntry) => `${entry.target}/${entry.name}`;
  const chosen = timeline.filter((entry) => entry.name && selected.includes(key(entry)));
  const chosenTargets = [...new Set(chosen.map((entry) => entry.target))];

  const act = async (work: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await work();
      setSelected([]);
      reload();
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setBusy(false);
    }
  };

  const confirm = () => {
    if (!pending) return;
    const job = pending;
    setPending(null);
    void act(async () => {
      if (job.kind === "delete") await api.websecDeleteRuns(job.target, job.names);
      else await api.websecClearRuns(job.target ? { target: job.target } : { all: true });
    });
  };

  return (
    <div className="space-y-3">
      {stats && stats.runs ? (
        <p className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-(--iux-muted-foreground)">
          <span><span dir="ltr" className="tabular-nums">{stats.targets}</span> <span>targets</span></span>
          <span><span dir="ltr" className="tabular-nums">{stats.runs}</span> <span>runs</span></span>
          <span><span dir="ltr" className="tabular-nums">{stats.reports}</span> <span>stored</span> · <span dir="ltr">{size(stats.bytes)}</span></span>
          <span><span dir="ltr" className="tabular-nums">{stats.favourites}</span> <span>favourites</span></span>
          <span className="flex gap-1" aria-label="Latest grades">
            {Object.entries(stats.grades).sort().map(([grade, count]) => (
              <span key={grade} className={`rounded border border-(--iux-border) px-1.5 ${gradeClass(grade)}`} dir="ltr">{grade} {count}</span>
            ))}
          </span>
        </p>
      ) : null}
      {history.length ? (
        <>
          <div className="flex flex-wrap items-end gap-3 text-sm">
            <label className="flex flex-col gap-1 sm:w-64">
              <span className="text-(--iux-muted-foreground)">Target</span>
              <select value={historyTarget} onChange={(event) => { setHistoryTarget(event.target.value); setSelected([]); }} className="iux-input">
                <option value="">All targets</option>
                {targets.map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
            <label className="flex items-center gap-2 pb-2">
              <input type="checkbox" checked={favouritesOnly} onChange={(event) => setFavouritesOnly(event.target.checked)} />
              <span>Favourites only</span>
            </label>
          </div>
          <ol>
            {timeline.map((entry, index) => {
              const runs = history.filter((item) => item.target === entry.target && item.name);
              const position = runs.findIndex((item) => item.name === entry.name);
              const comparable = !!entry.name && position >= 0 && position + 1 < runs.length;
              return (
                <li key={`${entry.target}-${entry.scanned_at}-${index}`} className="relative border-s border-(--iux-border) pb-3 ps-4 last:pb-0">
                  <span className="absolute -start-[4.5px] top-1.5 size-2 rounded-full bg-[#f36c21]" aria-hidden="true" />
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                    {entry.name ? (
                      <input type="checkbox" aria-label={`Select ${entry.name}`} checked={selected.includes(key(entry))}
                        onChange={(event) => setSelected((current) => event.target.checked
                          ? [...current, key(entry)] : current.filter((value) => value !== key(entry)))} />
                    ) : null}
                    <span className="font-mono text-xs text-(--iux-muted-foreground)">{entry.scanned_at || (entry.name ? runLabel(entry.name) : "")}</span>
                    {historyTarget ? null : <span>{entry.target}</span>}
                    <span className={gradeClass(entry.grade)}>{entry.grade} ({entry.score})</span>
                    <span className="text-xs text-(--iux-muted-foreground)"><span dir="ltr" className="tabular-nums">{entry.summary?.total ?? 0}</span> <span>findings</span></span>
                    <span className="text-xs text-(--iux-muted-foreground)">{entry.preset}</span>
                    {entry.name ? (
                      <button type="button" className="iux-btn" data-variant="ghost" aria-pressed={!!entry.favourite}
                        aria-label="Favourite" title="Favourite" disabled={busy}
                        onClick={() => void act(() => api.websecFavourite(entry.target, entry.name!, !entry.favourite))}>
                        <StarIcon size={14} weight={entry.favourite ? "fill" : "regular"} className={entry.favourite ? "text-[#e3b341]" : ""} />
                      </button>
                    ) : null}
                    {entry.name ? <button type="button" className="iux-btn" data-variant="ghost" onClick={() => onOpen(entry)}>Open</button> : null}
                    {comparable ? <button type="button" className="iux-btn" data-variant="ghost" onClick={() => onCompare(entry)}>Compare</button> : null}
                  </div>
                </li>
              );
            })}
          </ol>
          {!timeline.length ? <Empty>No favourite runs yet.</Empty> : null}
          <div className="flex flex-wrap gap-2">
            <button type="button" className="iux-btn" data-variant="outline" disabled={busy || !chosen.length || chosenTargets.length !== 1}
              title={chosenTargets.length > 1 ? "Pick runs of one target" : undefined}
              onClick={() => setPending({ kind: "delete", target: chosenTargets[0], names: chosen.map((entry) => entry.name!) })}>
              Delete selected
            </button>
            <button type="button" className="iux-btn" data-variant="outline" disabled={busy}
              onClick={() => setPending({ kind: "clear", target: historyTarget })}>
              {historyTarget ? "Clear this target's history" : "Clear all history"}
            </button>
          </div>
        </>
      ) : (
        <Empty>No scans yet.</Empty>
      )}
      {error ? <p role="alert" className="text-sm text-(--iux-danger)">{error}</p> : null}

      {pending ? (
        <Modal
          title={pending.kind === "delete" ? "Delete the selected runs?" : pending.target ? "Clear this target's history?" : "Clear all history?"}
          description="The reports are removed from this computer. This cannot be undone."
          onClose={() => setPending(null)}
        >
          <div className="space-y-3 text-sm">
            {pending.kind === "delete" ? (
              <ul className="list-disc space-y-1 ps-5 font-mono text-xs">
                {pending.names.map((name) => <li key={name}>{name}</li>)}
              </ul>
            ) : (
              <p dir="ltr" className="font-mono text-xs">{pending.target || targets.join(", ")}</p>
            )}
            <div className="flex flex-wrap gap-2">
              <button type="button" className="iux-btn" data-variant="primary" onClick={confirm}>Delete</button>
              <button type="button" className="iux-btn" data-variant="outline" onClick={() => setPending(null)}>Cancel</button>
            </div>
          </div>
        </Modal>
      ) : null}
    </div>
  );
}
