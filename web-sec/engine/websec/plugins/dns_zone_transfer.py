"""Zone-transfer audit against the zone's own nameservers (upstream ``DNS Zone Transfer``)."""
from __future__ import annotations

from typing import List

from ..models import Finding
from ..net.dns import DnsError
from ..registry import module


@module("dns_zone_transfer", label="Zone transfer audit",
        description="Ask each nameserver for an AXFR; an answered transfer is a critical leak",
        group="security", weight="heavy", order=220, active=True)
def dns_zone_transfer(ctx):
    try:
        nameservers = [str(value).rstrip(".") for value in ctx.dns.values(ctx.target, "NS")]
    except DnsError as exc:
        return {"available": False, "reason": str(exc)}, []
    results: List[dict] = []
    for server in nameservers[:4]:
        if ctx.expired():
            break
        outcome = ctx.dns.axfr(server, ctx.target)
        results.append(outcome)
    data = {"nameservers": nameservers[:8], "results": results}
    findings: List[Finding] = []
    for outcome in results:
        if outcome.get("rcode") == 0 and int(outcome.get("records") or 0) > 0:
            findings.append(Finding(
                module="dns_zone_transfer", kind="axfr-allowed", severity="critical",
                title=f"Zone transfer is allowed by {outcome['server']}",
                detail=f"{outcome['records']} records were returned without authentication.",
                remediation="Restrict AXFR to the secondary nameservers by address."))
    return data, findings
