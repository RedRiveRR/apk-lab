# Web Sec Lab — port plan (local only)

Branch `feat/web-sec-lab`, worktree `.worktrees/web-sec-lab`.
Nothing in this plan is pushed, opened as a PR, or reserved. The branch stays local
until the owner says otherwise.

## Goal

Add a fifth engine-style lab, `web-sec`, that ports the assessment capability of two
upstream projects into os-lab's own contracts ([[labctl]], console readiness/actions,
scope guard, dashboard workbench, lat.md):

- `frkndncr/WebAnalyzer` — Python scanner: 16 built-in modules + 12 plugins, JSON/SARIF/
  Markdown output, module registry, plugin discovery. MIT, © 2025 Furkan Dinçer.
- `keyvanarasteh/WebQ` — Svelte 5 + Tauri desktop UI over the Rust `web-analyzer` crate
  (not over the Python project): WHOIS/DNS/SSL/ports/headers detail views, SEO, technology
  fingerprinting, bulk validation, contact spidering, subdomain takeover, CDN origin
  exposure, Nmap→CVE correlation, SQLite scan history, dependency/system health.

The lab is a **defensive web assessment** lab: it profiles a target you own or are
authorized to test, grades its posture, and produces fix-oriented reports. Every network
action passes the repository scope guard first ([[console/scope_guard.py]]).

## What is ported, and as what

### Built-in modules (16)

| Upstream module | `web-sec` module | Behaviour | Traffic |
|---|---|---|---|
| Domain Information | `domain_info` | WHOIS over TCP/43, registrar, dates, nameservers, status | passive |
| DNS Records | `dns_records` | A, AAAA, MX, TXT, NS, CNAME, SOA, CAA via a stdlib DNS client | passive |
| GEO Analysis | `geo_analysis` | address class, reverse name, CDN/cloud owner from an offline table | passive |
| SEO Analysis | `seo_analysis` | 13 categories: title/meta/OG/canonical/robots/sitemap/headings/images/links | passive |
| Web Technologies | `web_technologies` | CMS, framework, server, CDN, analytics signatures from headers + HTML | passive |
| Contact Spy | `contact_spy` | bounded same-host BFS (≤25 pages, robots-aware) for emails/phones/socials | passive |
| Subdomain Discovery | `subdomain_discovery` | crt.sh certificate transparency; optional `subfinder` when installed | passive |
| Security Analysis | `security_analysis` | header grade A+–F, TLS version/cipher, CORS, cookie flags, WAF hints | passive |
| Advanced Content Scan | `content_scan` | secret patterns (cloud keys, tokens, private keys, JWTs) in fetched HTML/JS + source-map exposure | passive |
| Web Archive Spy | `archive_spy` | Wayback CDX URLs matching sensitive names, no payload fetching | passive |
| SSL SAN Association | `ssl_san` | DER SAN extraction, asset map, expiry | passive |
| Subdomain Takeover | `subdomain_takeover` | 36-service fingerprint registry against dangling CNAMEs | passive |
| CloudFlare Bypass | `origin_exposure` | CDN classification of A records, SPF/MX and SAN origin hints | passive |
| Nmap Zero Day Scan | `port_exposure` | bounded TCP connect check (18 ports), banner grab, optional NVD lookup | **active** |
| Phishing Domain Protection | `lookalike_domains` | typosquat/homoglyph generation, DNS + certificate presence | passive |
| Attack Path Planner | `remediation_plan` | findings aggregated into a prioritised fix list | none |

### Plugins (12)

`asset_inventory`, `cloud_storage`, `cookies_cors`, `dns_health`, `dns_zone_transfer`,
`email_security`, `exposed_files`, `http_methods`, `js_library_vulns`,
`privacy_trackers`, `security_txt`, `tls_health`.

The plugin contract is upstream's, kept deliberately:
`@module("Name", description=..., group=..., weight=..., active=False)` over a
`fn(target)` (or `fn(target, results)`) returning JSON-serialisable data, discovered from
`web-sec/engine/websec/plugins/` and `$WEBSEC_PLUGIN_DIRS`.

### WebQ-only features

| WebQ feature | Port |
|---|---|
| Scan history | append-only JSONL per target under `web-sec/storage/history/`, bounded retention |
| Bulk domain validation | `websec bulk <file>` — typed input, bounded concurrency (max 4) |
| Dependency/system health | `websec doctor`, console readiness reasons |
| WHOIS/SSL/ports/headers drill-downs | workbench detail panels fed by the module results |
| React source leak view | `react_exposure` plugin: source maps, `__NEXT_DATA__`, chunk listing |
| SQLite database | not ported; JSONL keeps the lab dependency-free |

## Deliberately not ported

These upstream capabilities are exploitation or destructive-test features, and os-lab is
an authorization-only, defensive project ([[lat.md/tooling.md#Security and licensing]]):

- `payloads/` wordlists (SQLi, XSS, SSTI, LFI, XXE, command injection, SSRF, auth bypass).
- `scan_react_rce_command` / `scan_react_rce_full` / `scan_react2shell` RCE confirmation probes.
- Any DoS, brute-force, credential-stuffing or path-brute-force loop.

Each has a defensive counterpart in the table above: leak detection instead of injection,
banner/CVE matching instead of exploit verification, bounded standard-path checks instead
of dictionary scanning. `attack_path_planner` is ported as remediation ordering only — no
exploit chain graph.

Optional, last: WebQ's honeypot decoy listener, reimplemented as a loopback-only HTTP
decoy that records requests (`websec honeypot --port 5089`). No external binding.

## Architecture

```
web-sec/
  engine/websec/
    cli.py            status | doctor | scan | bulk | report | plugins | honeypot
    registry.py       ModuleSpec, @module, presets, plugin discovery
    config.py         typed options, caps, pacing, env
    scope.py          console/scope_guard.py adapter; refuses before any socket
    net/              dns.py (UDP/TCP 53), http.py (urllib, caps, redirects),
                      tls.py (certificate + SAN DER parse), whois.py (TCP 43)
    checks/           16 built-in modules
    plugins/          12 plugins + react_exposure
    report.py         JSON, SARIF 2.1.0, Markdown, text, HTML
    history.py        bounded JSONL store
    grade.py          score + A+..F from findings
  Makefile, scripts/setup.sh, scripts/preflight.sh, .env.example
  knowledge/          scope-and-authorization.md, modules.md, report-schema.md, upstream.md
  engine/tests/       offline unit tests with fake transports, no network
```

- **Standard library only.** No `requests`, `dnspython`, `python-whois`, `nmap`; the lab
  works on a bare host, like [[source-lab]]. Optional shell-outs (`subfinder`, `dig`) are
  announced when missing, never required.
- **Scope before socket.** `scope.py` resolves the repo root, imports
  `console/scope_guard.py`, and every transport calls `assert_in_scope("host", target)`
  first. A refusal is a finding, not a crash. Offline tests run with a fake guard.
- **Budgeted traffic.** Per-host pacing, max 25 pages crawled, 512 KiB per response,
  8 KiB per string, 60 s default deadline, `active` modules require `--active` and a
  matching scope entry.
- **Report contract.** `{"tool", "scope", "targets":[{target, started_at, duration_seconds,
  score, grade, summary, modules, findings}]}`; findings carry `id, module, severity,
  title, detail, evidence, remediation, refs`. SARIF rule ids are
  `WEBSEC/<module>/<slug>`, `security-severity` mapped critical 9.5 … info 0.5.

## Surfaces

- **CLI / labctl** — `./labctl websec status|setup|scan|bulk|doctor|report|plugins`,
  proxying to `web-sec/run.py`.
- **Console** — `console/websec_control.py` (readiness, typed action plans),
  `console/websec_api.py` (`/api/websec/…`: modules, scan jobs, history, report download,
  scope status), mounted from `android-lab/lab/web_ui.py`; `LABS["websec"]`,
  `provider_for` → `native-python`, `setup_details`.
- **Dashboard** — `/web-sec/` workbench (module catalogue, target form with active-scan
  confirmation, findings table with severity filters, grade, history, report download) and
  `/labs/websec/` public readiness page; nav + command palette + `lab-page` hints; i18n keys
  in all eight locales; e2e spec registered in `dashboard/e2e/affected.json`.
- **Knowledge** — new `lat.md/web-sec.md` node, entry in `lat.md/lat.md`, row in
  `lat.md/overview.md`, lab list in `README.md`, `how-to-use.ts`.

## Phases

| Phase | Deliverable | Acceptance |
|---|---|---|
| P0 | worktree, this plan | branch exists from `origin/master` |
| P1 | engine core: registry, scope, net primitives, report, grade, CLI, `domain_info` + `dns_records` | `python3 -m pytest web-sec/tests -q` green offline |
| P2 | remaining 14 modules + 12 plugins, presets, bulk, history | unit tests per module with fake transports; no network in tests |
| P3 | console + labctl + readiness/actions + run-tests stage | console tests: ready/needs-setup/unavailable, scope refusal, job lifecycle |
| P4 | dashboard workbench + i18n + e2e | `npm run check`, `npm run test:i18n`, `npm run build` pass |
| P5 | knowledge/lat.md/README/how-to-use | `lat check` passes |
| P6 | verification and handover | `scripts/run-tests.sh --changed`, e2e in the mode the user picks; branch stays local |

## Status

Implemented on `feat/web-sec-lab` (local only):

- **P1–P2 — engine.** 16 built-in checks + 13 plugins, presets, bulk, JSONL history,
  JSON/SARIF/Markdown/HTML reports, grading, CLI, 56 offline tests under
  `web-sec/engine/tests`.
- **P3 — console.** `console/websec_control.py`, `console/websec_api.py`,
  `/api/websec/…` in `android-lab/lab/web_ui.py`, `LABS["websec"]`, the `websec`
  stage in `scripts/run-tests.sh`, `./labctl websec`, and 11 console tests.
- **P4 — dashboard.** `/web-sec/` workbench, `/labs/websec/` readiness page, nav and
  command palette entries, 26 new strings in all eight locales, and
  `dashboard/e2e/web-sec.spec.ts` registered in `e2e/affected.json`.
- **P5 — knowledge.** `lat.md/web-sec.md`, `lat.md/lat.md`, `lat.md/overview.md`,
  README, `how-to-use.ts`, and the four `web-sec/knowledge/` documents.

Outstanding: P6 verification (the commands below) and the e2e mode choice.

## Verification

```
python3 -m pytest -q web-sec/tests                          # engine, offline
scripts/run-tests.sh --changed                              # unit stages this branch touches
(cd dashboard && npm run check && npm run test:i18n && npm run build)
lat check
scripts/e2e.sh --dry-run --changed                          # show the mode, then ask before running
```

`dashboard/dist` is never committed. No push, no PR, no reservation file.

## Risks and mitigations

- **Scope creep from 28 checks.** Phase P2 is one module per commit-sized unit; the
  catalogue marks unsupported checks `skipped` with a reason instead of failing a scan.
- **Network flakiness in tests.** All tests inject fake DNS/HTTP/TLS transports; live
  checks are exercised only by the optional `--live` smoke target (`127.0.0.1`).
- **i18n surface.** Module names/descriptions come from the engine catalogue, so the
  dashboard adds only page chrome keys, not 28 translated descriptions.
- **Upstream drift.** `web-sec/knowledge/upstream.md` records the ported commit of each
  source repo and which features map where.
