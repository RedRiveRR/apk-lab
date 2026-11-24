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
| Scan history | done (JSONL + dashboard timeline) | per-target timeline, open from a row; run-to-run diff via `scan --diff` |
| Dependency / system health | done (`doctor`, console readiness) | lab page |
| React source-leak view | done (`react_exposure`) | findings only |
| React RCE / React2Shell probes | excluded by policy | — |
| Honeypot listener | excluded (out of scope) | — |
| SQLite database manager | replaced by JSONL | no manager UI (intentional) |
| Settings screen | done in the workbench (pacing overrides with engine bounds, environment, history limits) | — |
| Command palette | done (global palette entries) | — |
| In-app SecOps guides | knowledge docs exist | **missing** as modals |

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

## Remaining

1. **Compare UI in the workbench.** `scan --diff` does the matching; the timeline
   still needs a console endpoint and a panel to show a run-to-run diff.
2. **In-app SecOps guides as modals** (knowledge docs exist; no modal surface).
3. Optional polish: expose `cveLookup` and module selection in the bulk form once
   a real workload asks for them.

## Verification expected for each item

- Engine change: `cd web-sec/engine && python3 -m pytest -q`, plus a new fixture.
- Console change: `android-lab/lab/tests/test_websec_console.py`.
- Dashboard change: `npm run check`, `npm run test:i18n`, the new e2e case, then the
  mode the owner picks for `scripts/e2e.sh`.
- Knowledge change: `lat check`.
