# Web Sec Lab — coverage and remaining work

This file tracks feature and UX coverage against the two upstream projects.
It is **not** a plan for removing provenance: both projects are MIT-licensed, so
their copyright and permission notice travels with substantial portions of the
port. The mapping stays in [knowledge/upstream.md](knowledge/upstream.md), and the
commit that introduces the engine names it.

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
| WHOIS, DNS, SSL chain, IP resolution, HTTP status | done (`domain_info`, `dns_records`, `ssl_san`, `geo_analysis`, `security_analysis`) | data only in the module table; no drill-down panel |
| Port matrix | done (`port_exposure`, active) | data only; no matrix view |
| Security headers / cookies / CORS | done (`security_analysis`, `cookies_cors`) | findings only |
| SEO cards (13 categories) | done (`seo_analysis`) | data only |
| Technology matrix | done (`web_technologies`) | data only |
| Contact spider | done (`contact_spy`) | data only |
| Subdomain probing | done (`subdomain_discovery`, crt.sh) | data only |
| Secret scanner | done (`content_scan`) | findings only |
| Takeover analysis | done (`subdomain_takeover`) | findings only |
| Cloudflare origin view | adapted (`origin_exposure`, passive) | findings only |
| Nmap → NVD correlation | adapted (`port_exposure --cve-lookup`) | findings only |
| Bulk domain validation | done in CLI (`bulk`) | **missing** |
| Scan history | done (JSONL + dashboard table) | list only; no timeline/diff |
| Dependency / system health | done (`doctor`, console readiness) | lab page |
| React source-leak view | done (`react_exposure`) | findings only |
| React RCE / React2Shell probes | excluded by policy | — |
| Honeypot listener | excluded (out of scope) | — |
| SQLite database manager | replaced by JSONL | no manager UI (intentional) |
| Settings screen | partial (env + CLI options) | **missing** |
| Command palette | done (global palette entries) | — |
| In-app SecOps guides | knowledge docs exist | **missing** as modals |

## UX gaps, in priority order

1. **Per-module drill-down panels.** Read `report.modules[].data` and render WHOIS
   facts, the DNS grid, certificate names/expiry, the header/cookie table, the port
   matrix, SEO cards and the technology matrix. Acceptance: each module with data
   gets a panel, and the e2e spec opens the WHOIS and headers panels.
2. **Bulk validation UI.** File input, per-target grade table, bounded progress.
   Acceptance: mocked job renders three targets and one refusal.
3. **Export controls.** SARIF, HTML and Markdown download next to the JSON one,
   with a copy button. Acceptance: each download returns the right MIME type.
4. **Active-scan confirmation.** Replace the bare checkbox with a dialog that names
   the intrusive modules and the scope entry they rely on.
5. **History timeline.** Per-target timeline, open a stored report from a row,
   compare two reports. Acceptance: clicking a row loads that report.
6. **Live progress.** The API reports `running`; add per-module progress so the
   workbench can show which check is running and which were skipped.
7. **Catalogue browser.** A page or panel with module descriptions, group, weight,
   upstream name and the active flag (the inline checkbox list is a stopgap).
8. **Mobile layout pass** for the workbench at 390 px (the public crawl does not
   cover console-only routes).
9. **Public readiness page polish** for `/labs/websec/` beyond the generic lab page.
10. **Settings surface.** Show storage path, resolver, pacing and history limits;
    allow overriding them with the same typed validation as the CLI.

## Engine gaps

- `bulk` writes one JSON per target; add a CSV summary and an exit code for the
  worst grade.
- SARIF rule ids use the finding title; freeze one rule per module + kind so a
  wording change does not create a new rule.
- `port_exposure` service detection is banner-only; add a small curated service map
  for ports without a banner.
- `content_scan` scans the first five scripts; follow imported chunks one level
  deeper with the same byte cap.
- `origin_exposure` is header-based; add a CDN range table for the common providers.
- Add `--diff <report.json>` to compare two scans of the same target.

## Verification expected for each item

- Engine change: `cd web-sec/engine && python3 -m pytest -q`, plus a new fixture.
- Console change: `android-lab/lab/tests/test_websec_console.py`.
- Dashboard change: `npm run check`, `npm run test:i18n`, the new e2e case, then the
  mode the owner picks for `scripts/e2e.sh`.
- Knowledge change: `lat check`.
