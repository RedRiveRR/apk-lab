"""Secret and source-map exposure in what the site already serves.

Upstream probed guessed paths (``/config``, ``/.env``) for leaks. This port reads
only resources the page itself references, which finds the same class of leak
without a dictionary scan.
"""
from __future__ import annotations

import re
from collections import OrderedDict
from typing import Dict, List
from urllib.parse import urljoin

from ..models import Finding
from ..registry import module
from .common import find_secrets, parse_html, same_host
from .taint import find_taint_chains

SOURCE_MAP = re.compile(r"[#@]\s*sourceMappingURL=([^\s*/][^\s]*)", re.I)
_IMPORT = re.compile(r"""(?:\bimport\b[^;()]{0,200}?from\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)["']([^"']{2,200})["']""")
MAX_SCRIPTS = 5
MAX_SCAN_BYTES = 256 * 1024
MAX_CHUNKS = 5


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


def _imports(text: str) -> List[str]:
    """Relative and root-relative script references worth following one level."""
    specs = []
    for match in _IMPORT.finditer(text):
        spec = match.group(1)
        if spec.startswith(("./", "../", "/")) and not spec.endswith((".css", ".map")):
            specs.append(spec)
    return specs


@module("content_scan", label="Content and secret exposure",
        description="Secret patterns (with an entropy floor) and DOM-XSS source-to-sink candidates in served HTML and scripts, source maps, framework data blobs",
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
    queue = [url for url in scripts if same_host(url, ctx.target)]
    seen: set = set()
    depth = 0
    while queue and depth <= 1:  # the page's scripts plus one level of imported chunks
        follow: List[str] = []
        for url in queue:
            if url in seen:
                continue
            seen.add(url)
            response = ctx.http.get(url)
            if response.error or response.status >= 400:
                continue
            scanned += 1
            text = response.text[:MAX_SCAN_BYTES]
            blobs[url.rsplit("/", 1)[-1][:80] or "script"] = text
            if depth == 0:
                for spec in _imports(text):
                    candidate = urljoin(url, spec)
                    if same_host(candidate, ctx.target) and candidate not in seen:
                        follow.append(candidate)
                    if len(follow) >= MAX_CHUNKS:
                        break
        queue = follow
        depth += 1
    secrets = _scan(blobs)
    taint = []
    for where, text in blobs.items():
        for chain in find_taint_chains(text):
            taint.append({"where": where, **chain})
            if len(taint) >= 10:
                break
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
        "taint": taint,
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
    for chain in taint[:5]:
        findings.append(Finding(
            module="content_scan", kind="dom-taint", severity="medium",
            title=f"A URL or storage value may reach {chain['sink']} (DOM-XSS candidate)",
            detail=(f"In {chain['where']}, {chain['variable']} is read from a user-controlled source on line "
                    f"{chain['source_line']} and used in {chain['sink']} on line {chain['line']}. "
                    "This is a static match, not a confirmed bug."),
            evidence=str(chain["code"]),
            remediation="Write untrusted values with textContent or a sanitizer such as DOMPurify; "
                        "never pass them to innerHTML, document.write or eval.",
            refs=("https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",)))
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
