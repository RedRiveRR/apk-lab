"""Secret and source-map exposure in what the site already serves.

Upstream probed guessed paths (``/config``, ``/.env``) for leaks. This port reads
only resources the page itself references, which finds the same class of leak
without a dictionary scan.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from typing import Dict, List

from ..models import Finding
from ..registry import module
from .common import find_secrets, parse_html, same_host

SOURCE_MAP = re.compile(r"[#@]\s*sourceMappingURL=([^\s*/][^\s]*)", re.I)
MAX_SCRIPTS = 5
MAX_SCAN_BYTES = 256 * 1024


def _scan(blobs: Dict[str, str]) -> Dict[str, Dict[str, object]]:
    grouped: "OrderedDict[str, Dict[str, object]]" = OrderedDict()
    for source, text in blobs.items():
        for hit in find_secrets(text):
            entry = grouped.setdefault(str(hit["kind"]), {
                "kind": hit["kind"], "severity": hit["severity"],
                "remediation": hit["remediation"], "count": 0, "samples": [], "where": set(),
            })
            entry["count"] = int(entry["count"]) + 1
            if len(entry["samples"]) < 3:
                entry["samples"].append(hit["value"])
            entry["where"].add(source)
    for entry in grouped.values():
        entry["where"] = sorted(entry["where"])[:5]
    return grouped


@module("content_scan", label="Content and secret exposure",
        description="Secret patterns in served HTML and scripts, source maps, framework data blobs",
        group="security", weight="heavy", order=70, upstream="Advanced Content Scan")
def content_scan(ctx):
    root = ctx.page("/")
    if root.error:
        return {"available": False, "reason": root.error}, []
    page = parse_html(root.text)
    blobs: Dict[str, str] = {}
    for index, inline in enumerate(page.inline[:MAX_SCRIPTS]):
        blobs[f"inline[{index}]"] = inline[:MAX_SCAN_BYTES]
    scripts = [ctx.absolute(src) for src in page.scripts][:MAX_SCRIPTS]
    scanned = 0
    for url in scripts:
        if not same_host(url, ctx.target):
            continue
        response = ctx.http.get(url)
        if response.error or response.status >= 400:
            continue
        scanned += 1
        blobs[url.rsplit("/", 1)[-1][:80] or "script"] = response.text[:MAX_SCAN_BYTES]
    secrets = _scan(blobs)
    maps = sorted({match.group(1).strip("\"'").split("?")[0]
                   for text in blobs.values() for match in SOURCE_MAP.finditer(text)})[:10]
    exposed_maps = []
    for candidate in maps[:2]:
        url = ctx.absolute(candidate)
        if same_host(url, ctx.target):
            response = ctx.http.head(url)
            if not response.error and response.status == 200:
                exposed_maps.append(url)
    next_data = "__NEXT_DATA__" in root.text
    data = {
        "available": True,
        "scripts_scanned": scanned + len(page.inline[:MAX_SCRIPTS]),
        "bytes_scanned": sum(len(text) for text in blobs.values()),
        "secrets": [{"kind": entry["kind"], "severity": entry["severity"], "count": entry["count"],
                     "samples": entry["samples"], "where": entry["where"]}
                    for entry in secrets.values()],
        "source_maps": maps,
        "exposed_source_maps": exposed_maps,
        "framework_data": {"next_data": next_data},
    }
    findings: List[Finding] = []
    for entry in secrets.values():
        findings.append(Finding(
            module="content_scan", kind=str(entry["kind"]), severity=str(entry["severity"]),
            title=f"{entry['kind']} appears in served content",
            detail=f"{entry['count']} occurrence(s) in {', '.join(entry['where'])}.",
            evidence=", ".join(str(sample) for sample in entry["samples"]),
            remediation=str(entry["remediation"])))
    if exposed_maps:
        findings.append(Finding(
            module="content_scan", kind="source-maps", severity="medium",
            title="Source maps are publicly readable",
            detail=f"{len(exposed_maps)} linked source map(s) answered 200.",
            evidence=", ".join(exposed_maps),
            remediation="Disable source maps in production builds, or restrict them to internal users."))
    if next_data:
        findings.append(Finding(
            module="content_scan", kind="next-data", severity="info",
            title="The page ships a __NEXT_DATA__ blob",
            detail="Server-rendered props are readable by anyone; confirm nothing sensitive is included.",
            remediation="Keep secrets out of getServerSideProps/getStaticProps payloads."))
    return data, findings
