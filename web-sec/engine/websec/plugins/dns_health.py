"""Delegation health: NS count, CAA, DNSSEC and SOA (upstream plugin ``DNS Health``)."""
from __future__ import annotations

from typing import List

from ..models import Finding
from ..net.dns import DnsError
from ..registry import module


@module("dns_health", label="DNS health",
        description="Nameserver count, CAA, DNSSEC delegation and SOA serial",
        group="posture", weight="light", order=210)
def dns_health(ctx):
    def values(rtype, name=None):
        try:
            return ctx.dns.values(name or ctx.target, rtype)
        except DnsError:
            return []

    nameservers = [str(value).rstrip(".") for value in values("NS")]
    caa = values("CAA")
    ds = values("DS")
    soa = values("SOA")
    data = {"nameservers": nameservers[:12], "caa": caa[:10], "dnssec": bool(ds),
            "soa": soa[0] if soa else {}, "caa_present": bool(caa)}
    findings: List[Finding] = []
    if len(nameservers) < 2:
        findings.append(Finding(
            module="dns_health", severity="medium",
            title="The zone is served by a single nameserver",
            detail=f"{len(nameservers)} NS record(s).",
            remediation="Publish at least two nameservers on different networks."))
    if not caa:
        findings.append(Finding(
            module="dns_health", severity="low",
            title="No CAA record restricts certificate issuance",
            detail="Any public CA may issue a certificate for this name.",
            remediation="Add CAA records naming only the CAs you use."))
    if not ds:
        findings.append(Finding(
            module="dns_health", severity="info",
            title="The zone is not DNSSEC-signed",
            detail="No DS record was returned for the delegation.",
            remediation="Sign the zone if your resolver and registrar support it."))
    return data, findings
