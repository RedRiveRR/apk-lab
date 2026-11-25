"""A consolidated inventory of everything the scan observed (upstream ``Asset Inventory``)."""
from __future__ import annotations

from typing import Dict, List

from ..registry import module


@module("asset_inventory", label="Asset inventory",
        description="Hosts, addresses, certificate names and technologies in one table",
        group="inventory", weight="light", order=310, needs_results=True)
def asset_inventory(ctx, results):
    dns = results.get("dns_records") or {}
    geo = results.get("geo_analysis") or {}
    subs = results.get("subdomain_discovery") or {}
    san = results.get("ssl_san") or {}
    tech = results.get("web_technologies") or {}
    records = dns.get("records") or {}
    hosts: Dict[str, List[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "CNAME"):
        for value in records.get(rtype) or []:
            if isinstance(value, dict):
                value = value.get("exchange") or value.get("target") or ""
            if value:
                hosts.setdefault(str(value).rstrip("."), []).append(rtype)
    addresses = [entry.get("address") for entry in geo.get("addresses") or [] if entry.get("address")]
    names = list(subs.get("names") or [])
    certificate_names = list(san.get("sans") or [])
    technologies = [entry.get("name") for entry in tech.get("entries") or [] if entry.get("name")]
    data = {
        "target": ctx.target,
        "addresses": addresses[:20],
        "dns_names": sorted(hosts)[:40],
        "subdomains": names[:100],
        "certificate_names": certificate_names[:100],
        "technologies": technologies[:30],
        "counts": {
            "addresses": len(addresses),
            "subdomains": len(names),
            "certificate_names": len(certificate_names),
            "technologies": len(technologies),
        },
    }
    return data, []
