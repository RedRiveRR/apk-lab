"""Known-vulnerable JavaScript library versions (upstream plugin ``JS Library Vulnerabilities``).

The advisory table is bundled, so the check works offline and never sends a page
to a third party.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from ..models import Finding
from ..registry import module
from ..checks.common import parse_html

#: library, version regex, first fixed version, CVE, severity
ADVISORIES: Tuple[Tuple[str, str, str, str, str], ...] = (
    ("jQuery", r"jquery[-.@/]?(\d+\.\d+\.\d+)", "3.5.0", "CVE-2020-11022", "medium"),
    ("Bootstrap", r"bootstrap[-.@/]?(\d+\.\d+\.\d+)", "4.3.1", "CVE-2019-8331", "medium"),
    ("Lodash", r"lodash[-.@/]?(\d+\.\d+\.\d+)", "4.17.21", "CVE-2021-23337", "high"),
    ("Moment.js", r"moment[-.@/]?(\d+\.\d+\.\d+)", "2.29.4", "CVE-2022-31129", "medium"),
    ("Axios", r"axios[-.@/]?(\d+\.\d+\.\d+)", "0.21.2", "CVE-2020-28168", "medium"),
    ("AngularJS", r"angular(?:\.min)?[-.@/]?(\d+\.\d+\.\d+)", "1.8.3", "EOL", "high"),
)


def _tuple(version: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in version.split(".")[:3])


@module("js_library_vulns", label="JavaScript library versions",
        description="Version comparison against a bundled advisory table",
        group="posture", weight="light", order=280)
def js_library_vulns(ctx):
    response = ctx.page("/")
    if response.error:
        return {"available": False, "reason": response.error}, []
    page = parse_html(response.text)
    corpus = " ".join(page.scripts + page.inline[:10] + [response.text[:200_000]])
    found: List[Dict[str, str]] = []
    for library, pattern, fixed, reference, severity in ADVISORIES:
        match = re.search(pattern, corpus, re.I)
        if not match:
            continue
        version = match.group(1)
        if _tuple(version) >= _tuple(fixed):
            continue
        found.append({"library": library, "version": version, "fixed": fixed,
                      "reference": reference, "severity": severity})
    data = {"libraries": found}
    findings: List[Finding] = []
    for entry in found:
        findings.append(Finding(
            module="js_library_vulns", kind="outdated-library", severity=entry["severity"],
            title=f"{entry['library']} {entry['version']} is older than {entry['fixed']}",
            detail=f"Known issue: {entry['reference']}",
            remediation=f"Upgrade {entry['library']} to {entry['fixed']} or newer.",
            refs=(f"https://nvd.nist.gov/vuln/detail/{entry['reference']}" if entry["reference"].startswith("CVE") else "",)))
    return data, findings
