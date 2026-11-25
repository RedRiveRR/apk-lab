"""Certificate names and validity (WebAnalyzer ``SSL SAN Association``)."""
from __future__ import annotations

from typing import Dict, List

from ..models import Finding
from ..registry import module


@module("ssl_san", label="Certificate names",
        description="SAN names, issuer and expiry from the TLS certificate",
        group="security", weight="light", order=100, upstream="SSL SAN Association")
def ssl_san(ctx):
    if ctx.options.scheme != "https":
        return {"available": False, "reason": "the scan uses http, so there is no certificate to read"}, []
    tls = ctx.tls()
    if getattr(tls, "error", ""):
        return {"available": False, "reason": tls.error}, []
    data = tls.as_dict()
    sans = list(getattr(tls, "sans", []) or [])
    wildcard = [name for name in sans if name.startswith("*.")]
    data["name_count"] = len(sans)
    data["wildcards"] = wildcard
    findings: List[Finding] = []
    if not sans:
        findings.append(Finding(
            module="ssl_san", kind="no-sans", severity="medium",
            title="The certificate has no subject alternative names",
            detail="Modern clients ignore the legacy common name.",
            remediation="Reissue the certificate with every served name in the SAN list."))
    if wildcard:
        findings.append(Finding(
            module="ssl_san", kind="wildcard-name", severity="info",
            title="The certificate uses a wildcard name",
            detail=f"{', '.join(wildcard[:4])}",
            remediation="A wildcard is acceptable; confirm every matching name is intentional."))
    unrelated = [name for name in sans if "." in name and not (
        ctx.target == name.lstrip("*.") or name.lstrip("*.").endswith("." + ctx.target)
        or ctx.target.endswith("." + name.lstrip("*.")))]
    if unrelated:
        data["unrelated_names"] = unrelated[:20]
        findings.append(Finding(
            module="ssl_san", kind="unrelated-names", severity="info",
            title="The certificate covers names outside this domain",
            detail=f"{len(unrelated)} name(s) are not under {ctx.target}.",
            evidence=", ".join(unrelated[:10]),
            remediation="Split certificates per product so one exposure does not name the others."))
    return data, findings
