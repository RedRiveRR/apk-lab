"""Bucket references in the served page (upstream plugin ``Cloud Storage``).

The module reports references only. It does not list or probe the bucket, which
would touch an asset outside the declared scope.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ..models import Finding
from ..registry import module

PATTERNS = (
    ("Amazon S3", re.compile(r"https?://([a-z0-9.\-]+)\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com", re.I)),
    ("Google Cloud Storage", re.compile(r"https?://storage\.googleapis\.com/([a-z0-9._\-]+)", re.I)),
    ("Azure Blob Storage", re.compile(r"https?://([a-z0-9]+)\.blob\.core\.windows\.net", re.I)),
    ("Amazon S3 (path style)", re.compile(r"https?://s3[a-z0-9.\-]*\.amazonaws\.com/([a-z0-9._\-]+)", re.I)),
)


@module("cloud_storage", label="Cloud storage references",
        description="Bucket names referenced by the page, without probing them",
        group="inventory", weight="light", order=300)
def cloud_storage(ctx):
    response = ctx.page("/")
    if response.error:
        return {"available": False, "reason": response.error}, []
    corpus = response.text[:500_000]
    for script in response.cookies:
        del script
    buckets: Dict[str, str] = {}
    for provider, pattern in PATTERNS:
        for match in pattern.finditer(corpus):
            buckets.setdefault(match.group(1).lower(), provider)
    data = {"buckets": [{"name": name, "provider": provider} for name, provider in sorted(buckets.items())][:30]}
    findings: List[Finding] = []
    if buckets:
        findings.append(Finding(
            module="cloud_storage", severity="info",
            title="The page references cloud storage buckets",
            detail=", ".join(f"{name} ({provider})" for name, provider in list(buckets.items())[:5]),
            remediation="Confirm each bucket is intended to be public and carries no sensitive objects."))
    return data, findings
