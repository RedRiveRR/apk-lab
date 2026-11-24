# Report schema

One scan produces one document. Everything else (SARIF, Markdown, HTML, text) is
a pure function of it, so the console and the dashboard always show the same
numbers.

## Top level

```json
{
  "tool": {"name": "Web Sec Lab", "version": "0.1.0", "uri": "…", "schema_version": 1},
  "generated_at": "2026-11-24T00:00:00+00:00",
  "target": "example.test",
  "url": "https://example.test",
  "started_at": "2026-11-24T00:00:00+00:00",
  "duration_seconds": 4.2,
  "preset": "standard",
  "active": false,
  "score": 95,
  "grade": "A",
  "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 2, "total": 3},
  "refused": false,
  "refusal": "",
  "modules": [],
  "findings": []
}
```

`score` starts at 100 and loses points per finding: critical 25, high 12, medium 5,
low 2, info 0 — at most three findings of one severity per module. `grade` maps
the score to `A+ … F` (97/93/90, 87/83/80, 77/73/70, 67/63/60).

`refused` is true when a module was stopped by the scope guard mid-scan; the scan
stops there and `refusal` carries the guard's reason.

## Module outcomes

```json
{
  "id": "security_analysis",
  "label": "Security posture",
  "status": "ok",
  "duration_ms": 820,
  "findings": 2,
  "error": "",
  "note": "",
  "data": {}
}
```

`status` is `ok`, `empty`, `error`, `skipped` or `refused`. `note` explains a skip
(active check without `--active`, deadline reached), `error` carries the exception
for a failed check. `data` is the module's own bounded JSON.

## Findings

```json
{
  "module": "security_analysis",
  "severity": "medium",
  "title": "Content-Security-Policy is missing",
  "detail": "Nothing limits which scripts, frames or connections the page may load.",
  "evidence": "",
  "remediation": "Start with a report-only policy, then enforce script-src 'self'.",
  "refs": [],
  "kind": "csp-missing"
}
```

`severity` is one of `critical`, `high`, `medium`, `low`, `info`. `kind` is the
stable rule identity every check declares; SARIF and `scan --diff` match
findings by it, so rewording a title does not create a new rule. Evidence is
truncated to 1200 characters and secrets are masked before they reach a report.

## SARIF 2.1.0

- `runs[0].tool.driver.name` is `oslab-websec`.
- `ruleId` is `WEBSEC/<module>/<slug(kind)>`, falling back to the title slug for
  a finding whose check declares no kind.
- Level: critical/high → `error`, medium → `warning`, low/info → `note`.
- `properties["security-severity"]`: 9.5, 8.0, 5.5, 3.0, 0.5.
- Each result points at the target URL as its artifact location.

## Markdown and HTML

Both are generated from the same document, in that order: summary table, findings
(severity, module, detail, evidence, fix, references), module table with status and
duration. The HTML page is self-contained — inline CSS, no scripts — so it can be
attached to a report without a viewer.
