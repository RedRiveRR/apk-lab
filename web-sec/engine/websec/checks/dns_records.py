"""DNS records via the stdlib resolver (WebAnalyzer ``DNS Records``)."""
from __future__ import annotations

import ipaddress
from typing import Dict, List

from ..models import Finding
from ..net.dns import DnsError
from ..registry import module

TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA")


@module("dns_records", label="DNS records",
        description="A, AAAA, MX, TXT, NS, CNAME, SOA and CAA records",
        group="recon", weight="light", order=20, upstream="DNS Records")
def dns_records(ctx):
    try:
        ipaddress.ip_address(ctx.target)
    except ValueError:
        pass
    else:
        return {"records": {}, "addresses": [ctx.target], "errors": {},
                "note": "the target is an address, so there is no zone to query"}, []
    records: Dict[str, List[object]] = {}
    errors: Dict[str, str] = {}
    for rtype in TYPES:
        try:
            records[rtype] = ctx.dns.values(ctx.target, rtype)
        except DnsError as exc:
            records[rtype] = []
            errors[rtype] = str(exc)
    addresses = list(records.get("A", [])) + list(records.get("AAAA", []))
    data = {"records": records, "addresses": addresses[:20], "errors": errors}
    findings: List[Finding] = []
    if not addresses:
        chain = ctx.dns.cname_chain(ctx.target)
        data["cname_chain"] = chain
        findings.append(Finding(
            module="dns_records", severity="high",
            title="The host has no A or AAAA record",
            detail="The name does not resolve to an address" + (f"; CNAME chain: {' → '.join(chain)}" if chain else "."),
            remediation="Publish the address record the service actually uses, or remove the stale name."))
    chain = ctx.dns.cname_chain(ctx.target)
    if chain:
        data["cname_chain"] = chain
        if len(chain) > 2:
            findings.append(Finding(module="dns_records", severity="info",
                                    title="The CNAME chain has more than two hops",
                                    detail=" → ".join([ctx.target] + chain),
                                    remediation="Flatten the chain to reduce resolution latency and failure points."))
    return data, findings
