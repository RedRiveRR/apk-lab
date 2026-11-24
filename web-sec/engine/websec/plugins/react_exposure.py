"""React/Next.js exposure views from WebQ (``scan_react_source_leak`` and friends).

WebQ could confirm RCE against React Server Components. This port keeps only the
read-only half: is a development build shipped, and does the framework data blob
carry values that should not be public?
"""
from __future__ import annotations

import json
import re
from typing import Dict, List

from ..models import Finding
from ..registry import module

NEXT_DATA = re.compile(r'<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.I | re.S)
DEVELOPMENT = ("react-dom.development.js", "react.development.js", "__REACT_DEVTOOLS_GLOBAL_HOOK__")
SENSITIVE = ("token", "secret", "password", "passwd", "apikey", "api_key", "credential",
             "private", "session", "cookie")


def _keys(value, prefix="", depth=0) -> List[str]:
    found: List[str] = []
    if depth > 6:
        return found
    if isinstance(value, dict):
        for key, item in list(value.items())[:80]:
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(marker in str(key).lower() for marker in SENSITIVE):
                found.append(path)
            found.extend(_keys(item, path, depth + 1))
    elif isinstance(value, list):
        for index, item in enumerate(value[:10]):
            found.extend(_keys(item, f"{prefix}[{index}]", depth + 1))
    return found[:40]


@module("react_exposure", label="Framework data exposure",
        description="Development builds and sensitive keys in __NEXT_DATA__",
        group="security", weight="light", order=320, upstream="React source leak (WebQ)")
def react_exposure(ctx):
    response = ctx.page("/")
    if response.error:
        return {"available": False, "reason": response.error}, []
    html = response.text
    lowered = html.lower()
    development = [marker for marker in DEVELOPMENT if marker.lower() in lowered]
    match = NEXT_DATA.search(html)
    keys: List[str] = []
    parsed = False
    if match:
        try:
            keys = _keys(json.loads(match.group(1)))
            parsed = True
        except ValueError:
            keys = []
    data = {"development_build": development, "next_data": bool(match),
            "next_data_parsed": parsed, "sensitive_keys": keys}
    findings: List[Finding] = []
    if development:
        findings.append(Finding(
            module="react_exposure", severity="medium",
            title="A React development build is served",
            detail=f"Markers present: {', '.join(development[:3])}",
            remediation="Build with NODE_ENV=production and remove development bundles from the origin."))
    if keys:
        findings.append(Finding(
            module="react_exposure", severity="high",
            title="Framework data contains sensitive key names",
            detail=f"{len(keys)} key(s) look like secrets: {', '.join(keys[:5])}",
            evidence="\n".join(keys[:10]),
            remediation="Move these values server-side; the blob is readable by every visitor."))
    return data, findings
