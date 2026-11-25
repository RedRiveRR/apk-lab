"""Protocol version support (upstream plugin ``TLS Health``). Active."""
from __future__ import annotations

from typing import List

from ..models import Finding
from ..registry import module


@module("tls_health", label="TLS health",
        description="Accepted TLS versions and the negotiated cipher",
        group="security", weight="heavy", order=240, active=True)
def tls_health(ctx):
    versions = ctx.tls_versions()
    supported = [entry["version"] for entry in versions if entry.get("supported")]
    data = {"versions": versions, "supported": supported}
    findings: List[Finding] = []
    legacy = [name for name in supported if name in ("TLSv1", "TLSv1_1")]
    if legacy:
        findings.append(Finding(
            module="tls_health", kind="obsolete-versions", severity="high",
            title="Obsolete TLS versions are accepted",
            detail=f"{', '.join(legacy)} still complete a handshake.",
            remediation="Set the minimum version to TLS 1.2 in the server configuration."))
    if supported and "TLSv1_3" not in supported:
        findings.append(Finding(
            module="tls_health", kind="no-tls13", severity="low",
            title="TLS 1.3 is not accepted",
            detail=f"Supported: {', '.join(supported)}",
            remediation="Enable TLS 1.3 when the TLS stack supports it."))
    if not supported:
        findings.append(Finding(
            module="tls_health", kind="no-handshake", severity="medium",
            title="No TLS version completed a handshake",
            detail="The probe could not agree a protocol with 443/tcp.",
            remediation="Confirm that the endpoint serves TLS on 443."))
    return data, findings
