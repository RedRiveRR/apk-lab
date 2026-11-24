"""A short, fixed list of standard paths (upstream plugin ``Exposed Files``). Active.

This is not a directory brute force: ten known file names, one request each, and
the module stops at the first sign of a WAF block.
"""
from __future__ import annotations

from typing import List

from ..models import Finding
from ..registry import module

PATHS = (
    ("/.git/HEAD", "high", "The Git directory is served"),
    ("/.env", "high", "An environment file is served"),
    ("/.DS_Store", "low", "A macOS metadata file is served"),
    ("/server-status", "medium", "The Apache server-status page is public"),
    ("/phpinfo.php", "high", "phpinfo() output is public"),
    ("/web.config", "medium", "The IIS configuration file is served"),
    ("/backup.zip", "high", "A backup archive is served"),
    ("/config.json", "medium", "A configuration file is served"),
    ("/Dockerfile", "low", "The Dockerfile is served"),
    ("/.svn/entries", "medium", "Subversion metadata is served"),
)


@module("exposed_files", label="Exposed standard files",
        description="Ten well-known paths checked for public files",
        group="security", weight="heavy", order=290, active=True)
def exposed_files(ctx):
    found: List[dict] = []
    checked = 0
    for path, severity, description in PATHS:
        if ctx.expired():
            break
        response = ctx.http.request(ctx.url.rstrip("/") + path)
        checked += 1
        if response.error or response.status != 200 or not response.body:
            continue
        if path == "/.git/HEAD" and b"ref:" not in response.body:
            continue
        if path == "/.env" and b"=" not in response.body:
            continue
        found.append({"path": path, "severity": severity, "description": description,
                      "bytes": len(response.body), "status": response.status})
        if response.status == 403 and checked > 6:
            break
    data = {"checked": checked, "paths": [entry["path"] for entry in found], "found": found}
    findings: List[Finding] = []
    for entry in found:
        findings.append(Finding(
            module="exposed_files", kind=str(entry["description"]), severity=str(entry["severity"]),
            title=str(entry["description"]),
            detail=f"{entry['path']} answered 200 with {entry['bytes']} bytes.",
            evidence=str(entry["path"]),
            remediation="Remove the file from the document root and block the path at the edge."))
    return data, findings
