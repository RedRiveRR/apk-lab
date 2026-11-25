"""Report formats: JSON, SARIF 2.1.0, Markdown, text and a self-contained HTML page.

Every function is a pure function of the scan document, so formatting is tested
without a network and the CLI, console and dashboard agree on the same values.
"""
from __future__ import annotations

import html as html_module
import json
import re
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from .taxonomy import annotate
from .version import SCHEMA_VERSION, TOOL_NAME, TOOL_URI, VERSION

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.5"}
FORMATS = ("json", "sarif", "markdown", "md", "text", "html")
THRESHOLDS = ("none", "info", "low", "medium", "high", "critical")
COVER_KEYS = ("client", "author", "title")
MAX_COVER = 120


def clean_cover(cover: Optional[Dict[str, object]]) -> Dict[str, str]:
    """Report-cover text (client, author, title): single-line, bounded, empty keys dropped."""
    cleaned: Dict[str, str] = {}
    for key in COVER_KEYS:
        value = " ".join(str((cover or {}).get(key) or "").split())[:MAX_COVER]
        if value:
            cleaned[key] = value
    return cleaned


def build(result, cover: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    """The canonical document for one scan; every finding carries its CWE / OWASP label."""
    document = {
        "tool": {"name": TOOL_NAME, "version": VERSION, "uri": TOOL_URI,
                 "schema_version": SCHEMA_VERSION},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    document.update(result.as_dict())
    document["findings"] = [annotate(dict(finding)) for finding in document["findings"]]
    if clean_cover(cover):
        document["cover"] = clean_cover(cover)
    return document


def with_taxonomy(document: Dict[str, object]) -> Dict[str, object]:
    """A stored report from before the CWE mapping, labelled on read; newer ones are unchanged."""
    findings = document.get("findings") or []
    if all("cwe" in finding for finding in findings):
        return document
    return {**document, "findings": [annotate(dict(finding)) for finding in findings]}


def at_least(severity: str, threshold: str) -> bool:
    """True when ``severity`` reaches ``threshold`` (``none`` never does)."""
    if threshold not in THRESHOLDS or threshold == "none":
        return False
    return SEVERITIES.index(severity) <= SEVERITIES.index(threshold) if severity in SEVERITIES else False


def exceeds(findings: Iterable[Dict[str, object]], threshold: str) -> List[Dict[str, object]]:
    """The findings at or above the gate."""
    return [finding for finding in findings if at_least(str(finding.get("severity")), threshold)]


def _label(finding: Dict[str, object]) -> str:
    cwe, owasp = str(finding.get("cwe") or ""), str(finding.get("owasp") or "")
    return " · ".join(part for part in (cwe, owasp) if part)


def ci_summary(document: Dict[str, object], new: Optional[List[Dict[str, object]]] = None,
               threshold: str = "none") -> str:
    """A short Markdown block for a CI job summary (``$GITHUB_STEP_SUMMARY``)."""
    summary = document.get("summary") or {}
    lines = [f"### {TOOL_NAME}: {document.get('target')} — grade {document.get('grade')} "
             f"({document.get('score')}/100)", "",
             "| " + " | ".join(SEVERITIES) + " | total |",
             "| " + " | ".join("---:" for _ in SEVERITIES) + " | ---: |",
             "| " + " | ".join(str(summary.get(severity, 0)) for severity in SEVERITIES)
             + f" | {summary.get('total', 0)} |", ""]
    if new is not None:
        lines += [f"**{len(new)} new finding(s) since the baseline.**", ""]
    shown = new if new is not None else list(document.get("findings") or [])
    for finding in shown[:20]:
        label = _label(finding)
        lines.append(f"- **{finding.get('severity')}** {finding.get('title')} (`{finding.get('module')}`)"
                     + (f" — {label}" if label else ""))
    if len(shown) > 20:
        lines.append(f"- … {len(shown) - 20} more")
    if threshold != "none":
        failing = exceeds(shown, threshold)
        lines += ["", f"Gate `--fail-on {threshold}`: " + (f"**failed** ({len(failing)})" if failing else "passed")]
    return "\n".join(lines) + "\n"


def slug(text: str) -> str:
    value = re.sub(r"[^a-z0-9_]+", "-", str(text).lower()).strip("-")
    return value[:80] or "finding"


def rule_id(finding: Dict[str, object]) -> str:
    """One frozen rule per module + kind; findings without a kind keep the title slug."""
    kind = str(finding.get("kind") or "").strip()
    suffix = slug(kind) if kind else slug(str(finding["title"]))
    return f"WEBSEC/{slug(str(finding['module']))}/{suffix}"


def to_json(document: Dict[str, object], indent: Optional[int] = 2) -> str:
    return json.dumps(document, indent=indent, sort_keys=False, ensure_ascii=False)


def to_sarif(document: Dict[str, object]) -> str:
    rules: Dict[str, Dict[str, object]] = {}
    results: List[Dict[str, object]] = []
    for finding in document["findings"]:
        identifier = rule_id(finding)
        if identifier not in rules:
            rules[identifier] = {
                "id": identifier,
                "name": finding["title"],
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding["detail"] or finding["title"]},
                "help": {"text": finding["remediation"] or "Review the finding and the module data."},
                "properties": {
                    "tags": ["web", "posture", str(finding["module"])]
                    + ([f"external/cwe/{str(finding['cwe']).lower()}"] if finding.get("cwe") else [])
                    + ([f"owasp/{str(finding['owasp']).split(' ')[0]}"] if finding.get("owasp") else []),
                    "security-severity": _SECURITY_SEVERITY[finding["severity"]],
                },
            }
        results.append({
            "ruleId": identifier,
            "level": _SARIF_LEVEL[finding["severity"]],
            "message": {"text": f"{finding['title']}. {finding['detail']}".strip()},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": document["url"]}}}],
            "properties": {"module": finding["module"], "severity": finding["severity"],
                           **({"cwe": finding["cwe"], "owasp": finding.get("owasp", "")} if finding.get("cwe") else {})},
        })
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "oslab-websec",
                "fullName": TOOL_NAME,
                "version": VERSION,
                "informationUri": TOOL_URI,
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"target": document["target"], "grade": document["grade"],
                           "score": document["score"]},
        }],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _summary_table(summary: Dict[str, int]) -> List[str]:
    lines = ["| Severity | Findings |", "| --- | ---: |"]
    for severity in SEVERITIES:
        lines.append(f"| {severity} | {summary.get(severity, 0)} |")
    lines.append(f"| **total** | **{summary.get('total', 0)}** |")
    return lines


def _cover_lines(document: Dict[str, object]) -> List[str]:
    cover = document.get("cover") or {}
    parts = [f"Prepared for {cover['client']}" if cover.get("client") else "",
             f"by {cover['author']}" if cover.get("author") else ""]
    text = " ".join(part for part in parts if part)
    return [text, ""] if text else []


def to_markdown(document: Dict[str, object]) -> str:
    cover = document.get("cover") or {}
    lines = [
        f"# {cover.get('title') or TOOL_NAME + ' report'} — {document['target']}",
        "",
        *_cover_lines(document),
        f"**Grade {document['grade']}** · {document['score']}/100 · "
        f"scanned {document['started_at']} · {document['duration_seconds']}s · "
        f"preset `{document['preset']}`" + (" · active" if document["active"] else ""),
        "",
        f"Target URL: {document['url']}",
        "",
    ]
    if document.get("refused"):
        lines += [f"> The scan stopped: {document['refusal']}", ""]
    lines += ["## Summary", ""] + _summary_table(document["summary"]) + [""]
    findings = document["findings"]
    if findings:
        lines += ["## Findings", ""]
        for finding in findings:
            label = _label(finding)
            lines += [f"### {finding['severity'].upper()} — {finding['title']}", "",
                      f"Module: `{finding['module']}`" + (f" · {label}" if label else ""), ""]
            if finding["detail"]:
                lines += [finding["detail"], ""]
            if finding["evidence"]:
                lines += ["```", finding["evidence"], "```", ""]
            if finding["remediation"]:
                lines += [f"**Fix:** {finding['remediation']}", ""]
            if finding["refs"]:
                lines += ["References: " + ", ".join(finding["refs"]), ""]
    else:
        lines += ["## Findings", "", "No findings at this preset.", ""]
    lines += ["## Modules", "", "| Module | Status | Findings | Time |", "| --- | --- | ---: | ---: |"]
    for module in document["modules"]:
        note = module["note"] or module["error"]
        label = module["label"] + (f" — {note}" if note else "")
        lines.append(f"| {label} | {module['status']} | {module['findings']} | {module['duration_ms']} ms |")
    lines += ["", f"Generated by {TOOL_NAME} {VERSION} — authorized testing only.", ""]
    return "\n".join(lines)


def to_text(document: Dict[str, object]) -> str:
    lines = [
        f"{TOOL_NAME} {VERSION} — {document['target']}",
        f"grade {document['grade']} ({document['score']}/100), preset {document['preset']}, "
        f"{document['duration_seconds']}s",
    ]
    if document.get("refused"):
        lines.append(f"refused: {document['refusal']}")
    summary = document["summary"]
    lines.append("findings: " + ", ".join(f"{severity} {summary[severity]}" for severity in SEVERITIES))
    for finding in document["findings"]:
        label = _label(finding)
        lines.append(f"[{finding['severity']}] {finding['title']} ({finding['module']}"
                     + (f"; {label}" if label else "") + ")")
        if finding["detail"]:
            lines.append(f"    {finding['detail']}")
        if finding["remediation"]:
            lines.append(f"    fix: {finding['remediation']}")
    skipped = [m for m in document["modules"] if m["status"] != "ok"]
    for module in skipped:
        lines.append(f"[{module['status']}] {module['label']}: {module['note'] or module['error']}")
    return "\n".join(lines) + "\n"


_CSS = """
body{font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;background:#0f1115;color:#e7e9ee}
main{max-width:980px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px;color:#c9d1d9}
.meta{color:#9aa4b2;font-size:13px}.grade{display:inline-block;padding:4px 12px;border-radius:999px;background:#1f6feb;color:#fff;font-weight:600;margin-right:8px}
table{width:100%;border-collapse:collapse;margin:8px 0 24px;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #232a35}td.num{text-align:right}
.finding{border:1px solid #232a35;border-radius:10px;padding:14px 16px;margin:12px 0;background:#141922}
.sev{font-weight:700;text-transform:uppercase;font-size:12px;letter-spacing:.04em}
.critical,.high{color:#ff7b72}.medium{color:#e3b341}.low{color:#79c0ff}.info{color:#8b949e}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
pre{background:#0b0f16;border:1px solid #232a35;border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word}
.muted{color:#8b949e}.pill{border:1px solid #30363d;border-radius:6px;padding:1px 6px;font-size:12px;color:#9aa4b2}
footer{margin-top:40px;color:#8b949e;font-size:12px}
"""


def to_html(document: Dict[str, object]) -> str:
    escape = html_module.escape
    rows = []
    for finding in document["findings"]:
        evidence = f"<pre>{escape(finding['evidence'])}</pre>" if finding["evidence"] else ""
        fix = f"<p><strong>Fix:</strong> {escape(finding['remediation'])}</p>" if finding["remediation"] else ""
        label = _label(finding)
        tag = f' <span class="pill">{escape(label)}</span>' if label else ""
        rows.append(
            f'<article class="finding"><div class="sev {escape(finding["severity"])}">'
            f'{escape(finding["severity"])} · <span class="pill">{escape(finding["module"])}</span>{tag}</div>'
            f'<h3>{escape(finding["title"])}</h3><p>{escape(finding["detail"])}</p>'
            f"{evidence}{fix}</article>"
        )
    if not rows:
        rows.append('<p class="muted">No findings at this preset.</p>')
    modules = "".join(
        f"<tr><td>{escape(module['label'])}</td><td>{escape(module['status'])}</td>"
        f'<td class="num">{module["findings"]}</td><td class="num">{module["duration_ms"]} ms</td></tr>'
        for module in document["modules"]
    )
    summary = "".join(f"<tr><td>{severity}</td><td class='num'>{document['summary'][severity]}</td></tr>"
                      for severity in SEVERITIES)
    cover = document.get("cover") or {}
    heading = escape(str(cover.get("title") or document["target"]))
    byline = " · ".join(escape(text) for text in (
        f"Prepared for {cover['client']}" if cover.get("client") else "",
        f"by {cover['author']}" if cover.get("author") else "") if text)
    cover_html = (f'<p class="meta">{escape(str(document["target"]))}</p>' if cover.get("title") else "") + \
        (f'<p class="meta">{byline}</p>' if byline else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(TOOL_NAME)} — {escape(str(document['target']))}</title><style>{_CSS}</style></head>
<body><main>
<h1>{heading}</h1>
{cover_html}
<p class="meta"><span class="grade">Grade {escape(str(document['grade']))}</span>
{escape(str(document['score']))}/100 · {escape(str(document['duration_seconds']))}s · preset
{escape(str(document['preset']))}{' · active' if document['active'] else ''}</p>
<p class="meta">{escape(str(document['url']))}</p>
<h2>Summary</h2><table><thead><tr><th>Severity</th><th>Findings</th></tr></thead>
<tbody>{summary}</tbody></table>
<h2>Findings</h2>{''.join(rows)}
<h2>Modules</h2><table><thead><tr><th>Module</th><th>Status</th><th>Findings</th><th>Time</th></tr></thead>
<tbody>{modules}</tbody></table>
<footer>Generated by {escape(TOOL_NAME)} {escape(VERSION)} — authorized testing only.</footer>
</main></body></html>"""


def render(document: Dict[str, object], fmt: str) -> str:
    name = (fmt or "json").lower()
    if name == "json":
        return to_json(document)
    if name == "sarif":
        return to_sarif(document)
    if name in ("markdown", "md"):
        return to_markdown(document)
    if name == "text":
        return to_text(document)
    if name == "html":
        return to_html(document)
    raise ValueError(f"unknown format: {fmt} (choose {', '.join(FORMATS)})")


def counts(findings: Iterable[Dict[str, object]]) -> Dict[str, int]:
    result = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        result[finding["severity"]] += 1
    result["total"] = sum(result[severity] for severity in SEVERITIES)
    return result
