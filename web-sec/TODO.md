# Web Sec Lab — coverage and remaining work

This file tracks feature and UX coverage against the two upstream projects.
It is **not** a plan for removing provenance: both projects are MIT-licensed, so
their copyright and permission notice travels with substantial portions of the
port. The mapping stays in [knowledge/upstream.md](knowledge/upstream.md), and the
commit that introduces the engine names it.

For locations, the state of the branch and the continuation checklist, read
[docs/HANDOFF-web-sec-lab.md](../docs/HANDOFF-web-sec-lab.md).

## Feature coverage

### WebAnalyzer

| Upstream | Status | Where |
|---|---|---|
| Module registry, presets, plugin discovery | done | `engine/websec/registry.py`, `catalog.py` |
| 16 built-in modules | done | `engine/websec/checks/` |
| 12 plugins | done | `engine/websec/plugins/` |
| JSON / SARIF 2.1.0 / Markdown reports | done | `engine/websec/report.py` |
| Plugin contract (`@module`, `WEBANALYZER_PLUGIN_DIRS`) | done as `@module` + `WEBSEC_PLUGIN_DIRS` | `registry.py` |
| FastAPI app, SQLite database, Docker image | not ported | os-lab console + bounded JSONL replace them |
| `payloads/` injection wordlists | excluded by policy | exploitation material; see `knowledge/upstream.md` |

### WebQ

| Upstream feature | Feature | UX |
|---|---|---|
| WHOIS, DNS, SSL chain, IP resolution, HTTP status | done (`domain_info`, `dns_records`, `ssl_san`, `geo_analysis`, `security_analysis`) | drill-down panels in the workbench |
| Port matrix | done (`port_exposure`, active) | drill-down panel with the port table and CVE matches |
| Security headers / cookies / CORS | done (`security_analysis`, `cookies_cors`) | headers/cookies drill-down panel |
| SEO cards (13 categories) | done (`seo_analysis`) | SEO drill-down panel |
| Technology matrix | done (`web_technologies`) | technology drill-down panel |
| Contact spider | done (`contact_spy`) | data only |
| Subdomain probing | done (`subdomain_discovery`, crt.sh) | data only |
| Secret scanner | done (`content_scan`) | findings only |
| Takeover analysis | done (`subdomain_takeover`) | findings only |
| Cloudflare origin view | adapted (`origin_exposure`, passive) | findings only |
| Nmap → NVD correlation | adapted (`port_exposure --cve-lookup`) | findings only |
| Bulk domain validation | done (CLI `bulk --csv`, console endpoint, workbench form) | per-target grade table with refusal rows |
| Scan history | done (JSONL + dashboard timeline) | per-target timeline, open or compare from a row; Compare runs row (`compare`, `/api/websec/compare`) |
| Dependency / system health | done (`doctor`, console readiness) | lab page |
| React source-leak view | done (`react_exposure`) | findings only |
| React RCE / React2Shell probes | excluded by policy | — |
| Honeypot listener | excluded (out of scope) | — |
| SQLite database manager | replaced by JSONL | no manager UI (intentional) |
| Settings screen | done in the workbench (pacing overrides with engine bounds, environment, history limits) | — |
| Command palette | done (global palette entries) | — |
| In-app SecOps guides | done (`websec/guides.py`, `guides --json`, console, MCP) | modal from the header, each finding and each check |

## Completed in this pass

- **Per-module drill-down panels** over `report.modules[].data` (WHOIS, DNS grid,
  certificate, headers/cookies, CORS, port matrix, SEO, technologies) with a
  generic fallback for every other module; the e2e spec opens two panels.
- **Bulk validation UI** on a new console job endpoint (`POST /api/websec/bulk`,
  at most 20 passive targets, one heavy job at a time) with a per-target grade
  table; out-of-scope targets render as refusal rows.
- **Export controls**: JSON, SARIF, HTML and Markdown downloads with per-format
  MIME types and a copy button on the open preview.
- **Active-scan confirmation dialog** naming the intrusive checks and the scope
  entry, with run-actively / run-passively / cancel.
- **History timeline** with a target filter and open-from-row (history entries
  now carry the stored report's name).
- **Live per-check progress**: the engine streams JSONL events, the console
  exposes parsed module order and statuses on the running job, the workbench
  lists done / running / pending checks.
- **Catalogue browser**, **mobile pass at 390 px** (scrollable tables plus an
  overflow e2e case), **dedicated public page** for `/labs/websec/`, and a
  **settings surface** (request timeout and scan budget overrides with the
  engine's bounds, environment, history limits).
- Engine gaps closed: `bulk --csv` with a worst-grade exit code, SARIF rule ids
  frozen per module + kind (every check declares a kind), the curated port
  service map, one-level-deep content-scan chunks, the CDN IPv4 range table in
  `origin_exposure`, and `scan --diff`.

## Completed in the one-click pass

- **One-click workbench.** One primary Scan (shortcut `S`) with a live summary; every
  other ability is a collapsed row with a one-line summary (Scan options, Reports,
  Compare runs, Bulk validation, History, Catalogue, Guides, Environment). The
  active-scan dialog lists only the intrusive checks the selection would run
  (`modules --json` now carries preset membership).
- **Saved choices** in the engine store (`websec/preferences.py`, `prefs`,
  `/api/websec/preferences`): versioned, validated, unknown check ids kept, never the
  intrusive mode. The default target is the saved one, else the last scanned host.
- **MCP tools** (`console/mcp_websec.py`): 14 tools, read-only, review
  (`websec_review` = `plan`, no network), scan as a job with `confirm: true` for
  intrusive checks, passive bulk. `mcp_server.py` now reads the MCP `arguments` key.
- **Compare UI** (`compare`, `/api/websec/compare`, Compare runs row, Compare from a
  history entry) and **SecOps guides as modals**.

## Remaining

### UX standard (lat.md/ux-readiness.md)

1. ~~Signal outside the window~~ — done: monitor events notify natively, escalate,
   remind while true, can be switched off; banner and Monitor row in the workbench.
2. **Visual pass** after the functional work: 390 px and tablet, 200% zoom, both
   themes, `fa`/`ar` right-to-left, coarse-pointer size of the severity chips,
   drill-down toggles and check boxes.
3. Use `/api/websec/plan` in the confirmation dialog so the engine's scope verdict
   is shown, not only the client-side preset table.
4. `Guide for <check>` is a dynamic accessible label and is not translated.

### Engine port gaps

1. ~~CI gates~~ — done: `--fail-on`, `--baseline`, `--summary`, `compare --fail-on-new`,
   `web-sec/action.yml`.
2. ~~CWE / OWASP Top 10 mapping~~ — done: `websec/taxonomy.py`, SARIF tags, the
   findings UI, MCP summaries; old reports are labelled on read.
3. ~~Monitor and notifications~~ — done: `websec/monitor.py`, `websec/notify.py`,
   console runner, `/api/websec/monitor*`, three MCP tools.
4. ~~Content scan depth~~ — done: 25 patterns with an entropy floor and a static
   DOM-XSS source→sink pass (`checks/taint.py`), all passive.
5. ~~Report cover, target lists, concurrency~~ — done: `--client/--author/--title` on
   `scan` and `report`, `bulk -` reads stdin, `bulk --concurrency 1-8`.
6. Decide on WebAnalyzer's Overview / Threat-intel / Network-map pages: port an
   overview or record the exclusion.

### WebQ gaps

1. ~~Dedicated drill-down panels~~ — done for `contact_spy`, `subdomain_discovery`,
   `content_scan` (secrets and DOM-XSS candidates), `subdomain_takeover`,
   `origin_exposure` and `react_exposure`.
2. PDF and DOCX export (or document printing the HTML report).
3. History management: favourite, delete a run, delete several, clear all, global
   statistics.
4. Reference pages (ports, headers, status codes, domains): fold into the guides or
   record the exclusion.
5. ~~React signatures view~~ — excluded: it is the honeypot's exploit-signature
   catalogue (see `knowledge/upstream.md`); `react_exposure` has its own panel.

### Documentation

1. ~~upstream.md exclusions~~ — done (API Security Scanner, ownership/demo mode).
2. ~~README~~ — done (new commands, CI and agents).

### Landing

1. ~~Commit the one-click pass~~ — done.
2. Optional: `cveLookup` and module selection in the bulk form.
3. Full verification block, then e2e in an owner-approved mode: the Web Sec spec,
   then `--full` once before the PR. E2e is deliberately held until every item above
   is done.
4. Push and open the PR.

## Verification expected for each item

- Engine change: `cd web-sec/engine && python3 -m pytest -q`, plus a new fixture.
- Console change: `android-lab/lab/tests/test_websec_console.py`.
- Dashboard change: `npm run check`, `npm run test:i18n`, the new e2e case, then the
  mode the owner picks for `scripts/e2e.sh`.
- Knowledge change: `lat check`.
