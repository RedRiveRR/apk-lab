# Web Sec Lab

Web Sec Lab assesses one authorized host and grades its posture. It is engine-only: standard-library Python, no VM, no Docker and no third-party package.

Operators start at [[web-sec/README.md]]; the boundary is recorded in
[[web-sec/knowledge/scope-and-authorization.md]]. The port from
`frkndncr/WebAnalyzer` and `keyvanarasteh/WebQ` is mapped, with its exclusions, in
[[web-sec/knowledge/upstream.md]].

## Engine

[[web-sec/engine/websec/registry.py#module]] registers a check: a function of the scan context that returns JSON, optionally with findings.

[[web-sec/engine/websec/catalog.py#ensure_loaded]] imports the 16 built-in checks
from [[web-sec/engine/websec/checks]] and then discovers the 13 plugins in
[[web-sec/engine/websec/plugins]] plus `$WEBSEC_PLUGIN_DIRS`. A broken plugin is
recorded and never stops a scan. [[web-sec/engine/websec/runner.py#run_scan]]
selects a preset, enforces the deadline and records `ok`, `empty`, `error`,
`skipped` or `refused` per module. Each check's upstream counterpart and traffic
class is in [[web-sec/knowledge/modules.md]].

## Scope first

[[web-sec/engine/websec/scope.py#Guard]] asks the repository guard about every host before a socket is opened.

It loads `console/scope_guard.py` instead of re-implementing the rule, and the
transports check again on every HTTP redirect hop:
[[web-sec/engine/websec/net/http.py#HttpClient]],
[[web-sec/engine/websec/net/dns.py#Resolver]],
[[web-sec/engine/websec/net/tls.py#probe]],
[[web-sec/engine/websec/net/whois.py#query]] and
[[web-sec/engine/websec/net/ports.py#connect_test]]. Three read-only public
registries are allowlisted for checks that need public data — crt.sh, the Wayback
CDX API and NVD — and `Context.infra()` is the only client that may reach them.
No exploitation payloads, brute force or RCE probes were ported.

## Reports

[[web-sec/engine/websec/report.py#to_sarif]] emits SARIF 2.1.0 with `WEBSEC/<module>/<kind>` rule ids (the stable kind each check declares, title slug as fallback) and the usual severity mapping.

[[web-sec/engine/websec/report.py#to_markdown]] and `to_html` are pure functions of
the same document. [[web-sec/engine/websec/export.py]] adds PDF (standard fonts,
Latin-1, marked when glyphs are lost) and DOCX from the same outline, standard
library only. [[web-sec/engine/websec/grade.py]] turns findings into the
`A+ … F` grade, capped per module so one noisy check cannot dominate.
[[web-sec/knowledge/report-schema.md]] documents every field.
[[web-sec/engine/websec/history.py#History]] keeps a bounded JSONL summary (each entry
names its stored report) and the last 20 reports per target under `web-sec/storage`,
mode 0700/0600. Up to 10 runs per target can be favourites (`favourites.json`), which
pruning keeps; `runs stats|favourite|delete|clear` manages stored runs, and the
console (`/api/websec/runs/…`), the workbench History row (multi-select delete and
clear behind the confirmation dialog) and MCP (`websec_stats`, `websec_favourite`,
`websec_delete_runs` and `websec_clear_history`, the last two with `confirm: true`)
use it.

## Console and CLI

`./labctl websec <command>` runs [[web-sec/run.py]]. The console answers `/api/websec/…` behind the localhost guard.

`scan --diff <report.json>` compares a run with a stored report of the same target
(findings match on module and kind), `compare --target --old --new` does the same for
two stored runs, `bulk --csv` writes one row per target and exits with the worst
grade, and `scan --progress <file>` streams JSONL per-module events for the console.
`plan <target>` is the no-network review: it normalizes the target, asks the scope
guard and lists which checks would run, holding intrusive ones back without
`--active`. `modules --json` also lists each preset's checks, and `guides --json`
prints the SecOps guides.

[[web-sec/engine/websec/preferences.py]] stores the workbench choices (target,
preset, protocol, check selection, pacing, bulk preset) as `preferences.json` in the
private storage folder; `prefs --json` reads and `prefs --save` validates and writes
them. A store from another version is read, unknown check ids are kept, corruption
falls back to defaults with a `configError`. Intrusive mode is deliberately not a
preference. [[web-sec/engine/websec/guides.py]] holds the guides as data, each naming
the checks it explains; a test keeps every catalogue check in exactly one guide.

[[console/websec_control.py#lab_status]] reports Python, storage and scope
separately, so the dashboard can say what is missing, and
[[console/websec_control.py#build_plan]] produces the typed `status|doctor|setup`
command the operator confirms. [[console/websec_api.py#WebSecAPI]] starts one scan
child process at a time, tails the engine's JSONL progress file so a running job
reports per-check state, runs bounded passive bulk validation through the engine,
reads the report back with a size cap, and validates every stored report name
before opening it. It also serves `/api/websec/preferences` (GET, POST),
`/api/websec/plan` (POST), `/api/websec/compare` and `/api/websec/guides` through
the engine; an engine usage error answers 400.

## Monitor

[[web-sec/engine/websec/monitor.py]] is the opt-in passive posture monitor; the console runs `monitor tick` every minute on a background thread.

Config and state live in `web-sec/storage/monitor.json` (atomic, 0600): up to 10
in-scope targets, an interval (hourly, 6 h, daily, weekly), a quick or standard
preset, an alert threshold, notifications, reminder hours and scope-warning days.
A tick scans only the due targets, never actively, stores the reports and compares
each run with the previous one: `warning` (a new finding at or above the threshold,
or a grade drop), `critical` (a new critical, or a fall to D/F), `escalated`,
`reminder` while unresolved, `recovered`, `scope-expiring`/`scope-expired`, and one
`error` per distinct failure. [[web-sec/engine/websec/notify.py]] sends a native
notification per actionable event with fixed argv. An idle tick writes nothing,
and [[console/websec_api.py#MonitorRunner]] never overlaps a workbench scan. The
workbench shows a banner (linked to Compare runs) and a Monitor row; MCP has
`websec_monitor`, `websec_monitor_config` and `websec_monitor_run`.

## MCP tools

[[console/mcp_websec.py]] adds the Web Sec Lab to the os-lab MCP server on the same console API, engine and scope guard as the workbench.

Read-only tools cover status, the catalogue (with each check's guide), guides,
preferences, history, reports, one rendered report, compare and job state.
`websec_review` is the plan and sends nothing to the target. `websec_scan` runs a
scope-checked scan as a job; `active: true` also needs `confirm: true`, the
workbench's confirmation dialog. `websec_bulk` is passive only. Tools take host
names and report names, never paths, URLs or commands, and are refused inside
`macos_task`. Tests: [[android-lab/lab/tests/test_mcp_websec.py]].

## Dashboard

`/web-sec/` is the workbench (sidebar: Workbench, Monitor, Compare runs, History, Bulk validation, Guides, Readiness & setup; each row link opens its row by hash), implemented in [[dashboard/src/views/web-sec/pages.tsx]] on the one-click standard of [[lat.md/ux-readiness.md#One-click standard]].

One primary action, **Scan** (shortcut `S` when no field has focus), goes from a
target to a graded report; a one-line summary names the preset, protocol and check
count. The intrusive opt-in sits beside it, is asked again in the confirmation
dialog for the checks the selection would actually run, and is never saved.
Findings, severity filters, per-module drill-down panels and a Guide button per
finding and check follow the report.

A monitor banner sits above the scan while a monitored target is worse than before.

Everything else is a collapsed row of one list with a live summary: Scan options
(preset, protocol, pacing, check selection; saved on this computer through the
engine store), Reports (Markdown preview and JSON/SARIF/HTML/Markdown downloads),
Compare runs ([[dashboard/src/views/web-sec/compare.tsx]], latest two runs by
default, an attention dot when a run adds a critical or high finding), Monitor
([[dashboard/src/views/web-sec/monitor.tsx]]), Bulk
validation, History (open a run, or compare it with the one before), Catalogue,
Guides and Environment. A row opens when a link or button targets its id.
[[dashboard/src/views/web-sec/guides.tsx]] shows the SecOps guides as a modal,
straight on the guide for the check it was opened from. The default target is the
saved one, else the most recently scanned host. The public `/labs/websec/` page has
its own read-only readiness and boundaries view. Module names come from the engine
catalogue, so the dashboard translates only its own chrome and the guide text.

## Tests

The engine suite runs offline: [[web-sec/engine/tests/conftest.py]] replaces DNS, HTTP, TLS, WHOIS and port transports with fakes.

`cd web-sec/engine && python3 -m pytest -q` also exercises the DNS codec, the TLS
DER parser and every report format; [[web-sec/engine/tests/test_workbench.py]]
covers preferences, plan, compare and guide coverage. Console contracts live in
[[android-lab/lab/tests/test_websec_console.py]], the MCP tools in
[[android-lab/lab/tests/test_mcp_websec.py]], and the workbench in
[[dashboard/e2e/web-sec.spec.ts]], including a case that every row is still listed
and opens.
