"""Archived sensitive URLs from the Wayback CDX index (WebAnalyzer ``Web Archive Spy``)."""
from __future__ import annotations

import json
from typing import Dict, List

from ..models import Finding
from ..registry import module

SENSITIVE = ("env", "config", "backup", "dump", "sql", "git", "admin", "token", "key",
             "secret", "password", "credential", "phpinfo", "swagger", "graphql", ".zip",
             ".tar", ".bak", "api/v1")
MAX_ROWS = 2000


@module("archive_spy", label="Archived URL exposure",
        description="Wayback CDX URLs whose names suggest configuration, backups or secrets",
        group="security", weight="medium", order=110, upstream="Web Archive Spy")
def archive_spy(ctx):
    query = (f"https://web.archive.org/cdx/search/cdx?url={ctx.target}/*"
             "&output=json&fl=original,timestamp,statuscode&collapse=urlkey&limit=2000")
    response = ctx.infra(query)
    if response.error or response.status != 200:
        return {"available": False, "reason": response.error or f"Wayback answered {response.status}"}, []
    try:
        rows = json.loads(response.body.decode("utf-8", "replace"))
    except ValueError:
        return {"available": False, "reason": "the CDX answer is not JSON"}, []
    if not isinstance(rows, list) or len(rows) < 2:
        return {"available": True, "count": 0, "sensitive": []}, []
    header = [str(column).lower() for column in rows[0]]
    records: List[Dict[str, str]] = []
    for row in rows[1:MAX_ROWS]:
        if not isinstance(row, list) or len(row) < len(header):
            continue
        entry = dict(zip(header, [str(cell) for cell in row]))
        url = entry.get("original", "")
        lowered = url.lower()
        if not any(marker in lowered for marker in SENSITIVE):
            continue
        records.append({"url": url[:500], "timestamp": entry.get("timestamp", "")[:14],
                        "status": entry.get("statuscode", "")[:4]})
    data = {"available": True, "count": len(rows) - 1, "sensitive": records[:100],
            "truncated": len(rows) - 1 >= MAX_ROWS}
    findings: List[Finding] = []
    if records:
        findings.append(Finding(
            module="archive_spy", kind="sensitive-archives", severity="medium",
            title="Archived URLs suggest exposed configuration or backups",
            detail=f"{len(records)} archived URL(s) match sensitive names.",
            evidence="\n".join(record["url"] for record in records[:5]),
            remediation="Remove the artefacts, purge the archive where possible, and rotate any secret they contained."))
    return data, findings
