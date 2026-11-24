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

[[web-sec/engine/websec/report.py#to_sarif]] emits SARIF 2.1.0 with `WEBSEC/<module>/<title>` rule ids and the usual severity mapping.

[[web-sec/engine/websec/report.py#to_markdown]] and `to_html` are pure functions of
the same document. [[web-sec/engine/websec/grade.py]] turns findings into the
`A+ … F` grade, capped per module so one noisy check cannot dominate.
[[web-sec/knowledge/report-schema.md]] documents every field.
[[web-sec/engine/websec/history.py#History]] keeps a bounded JSONL summary and the
last 20 reports per target under `web-sec/storage`, mode 0700/0600.

## Console and CLI

`./labctl websec <command>` runs [[web-sec/run.py]]. The console answers `/api/websec/…` behind the localhost guard.

[[console/websec_control.py#lab_status]] reports Python, storage and scope
separately, so the dashboard can say what is missing, and
[[console/websec_control.py#build_plan]] produces the typed `status|doctor|setup`
command the operator confirms. [[console/websec_api.py#WebSecAPI]] starts one scan
child process at a time, reads the report back with a size cap, and validates every
stored report name before opening it.

## Dashboard

`/web-sec/` is the workbench, implemented in [[dashboard/src/views/web-sec/pages.tsx]].

It renders the engine catalogue, a target form with preset, protocol and the
explicit `--active` opt-in, live scan state, findings filtered by severity, the
per-check table, stored reports with a Markdown preview and JSON download, and
history. The public `/labs/websec/` page uses the generic lab page for readiness.
Module names come from the engine catalogue, so the dashboard translates only its
own chrome.

## Tests

The engine suite runs offline: [[web-sec/engine/tests/conftest.py]] replaces DNS, HTTP, TLS, WHOIS and port transports with fakes.

`cd web-sec/engine && python3 -m pytest -q` also exercises the DNS codec, the TLS
DER parser and every report format. Console contracts live in
[[android-lab/lab/tests/test_websec_console.py]]; the workbench in
[[dashboard/e2e/web-sec.spec.ts]].
