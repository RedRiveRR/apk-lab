# Upstream provenance

Two projects were reviewed and ported into this lab. Both are MIT-licensed; the
ported code is a reimplementation against os-lab's contracts, not a vendored copy.

| Project | Commit reviewed | Licence | What was used |
|---|---|---|---|
| [`frkndncr/WebAnalyzer`](https://github.com/frkndncr/WebAnalyzer) | `8bbe0b4` (2026-11-10) | MIT, © 2025 Furkan Dinçer | module registry and plugin discovery, 16 modules, 12 plugins, JSON/SARIF/Markdown report shape, presets |
| [`keyvanarasteh/WebQ`](https://github.com/keyvanarasteh/WebQ) | `564bd3d` (2026-07-07) | MIT (package.json) | WHOIS/DNS/SSL/port/header drill-downs, bulk validation, scan history, dependency health, React source-leak view |

WebQ's README describes a Rust `web-analyzer` crate; its `src-tauri/Cargo.toml`
pins `web-analyzer 0.1.11`, so the Tauri commands mirror the crate's module names
rather than the Python project. This lab ports the behaviour, not either
implementation's internals.

## Mapping

| Upstream | Here | Notes |
|---|---|---|
| WebAnalyzer `modules/registry.py` | `websec/registry.py` | same decorator/registry idea; ids are stable snake_case, labels are display text |
| WebAnalyzer plugins | `websec/plugins/` | same contract: `@module(...)`, one file per plugin, `WEBSEC_PLUGIN_DIRS` |
| WebAnalyzer `utils/formats.py` | `websec/report.py` | SARIF rule ids are `WEBSEC/…`, not `WA/…` |
| WebQ Tauri commands | checks + `websec_history` | one check per command family; SQLite replaced by bounded JSONL |
| WebQ `honeypot.rs` | not ported | see below |

## Deliberately not ported

| Upstream | Why |
|---|---|
| `WebAnalyzer/payloads/` (SQLi, XSS, SSTI, LFI, XXE, command injection, SSRF, auth bypass) | payload wordlists are exploitation material; this lab is defensive |
| `WebQ` `scan_react_rce_command`, `scan_react_rce_full`, `scan_react2shell` | RCE confirmation probes; the defensive half is `react_exposure` |
| `WebQ` honeypot listener | a decoy service would need its own isolation story; out of scope for this pass |
| WebAnalyzer database, FastAPI dashboard, Docker image | the lab uses os-lab's console and dashboard instead |
| Any DoS, brute force or path-dictionary loop | replaced by bounded, fixed-list checks |

## Adaptations worth knowing

- **No path brute force.** Upstream `Advanced Content Scan` probed guessed paths;
  `content_scan` reads only resources the page references.
- **No nmap dependency.** `port_exposure` uses TCP connects and a banner read over
  20 declared ports; NVD is queried only with `--cve-lookup`.
- **Origin discovery is passive.** `origin_exposure` never probes an address that
  is not a name under the target; it reports candidates, not a "bypass".
- **Attack Path Planner → remediation_plan.** Findings are ordered into fixes; no
  exploit chain is drawn.
- **Third-party registries are explicit.** Only crt.sh, the Wayback CDX API and
  NVD are contacted, through a dedicated allowlisted client.

## Refreshing the port

1. Read the upstream diff for the files in the mapping table.
2. Change one check; keep its id and finding titles stable (they are SARIF rules).
3. Run `cd web-sec/engine && python3 -m pytest -q`; add a fixture for the changed
   parser or module.
4. Update `knowledge/modules.md` and this file with the new commit.
