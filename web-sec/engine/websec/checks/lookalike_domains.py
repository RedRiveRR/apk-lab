"""Lookalike and typosquat presence (WebAnalyzer ``Phishing Domain Protection``).

The module generates the usual variants and asks DNS whether they exist. It does
not register, contact or fetch anything from them.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Set

from ..models import Finding
from ..registry import module

TLDS = ("com", "net", "org", "info", "co", "io", "site", "online")
HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "m": "rn", "v": "u", "w": "vv", "a": "4", "e": "3"}
MAX_VARIANTS = 120
MAX_LOOKUPS = 24


def _variants(host: str) -> List[str]:
    name, _, tld = host.rpartition(".")
    if not name:
        return []
    base = name.replace("-", "")
    candidates: Set[str] = set()
    for index in range(len(base)):
        candidates.add(base[:index] + base[index + 1:])
        candidates.add(base[:index] + base[index] + base[index:])
        if index + 1 < len(base):
            candidates.add(base[:index] + base[index + 1] + base[index] + base[index + 2:])
    for index, character in enumerate(base):
        replacement = HOMOGLYPHS.get(character)
        if replacement:
            candidates.add(base[:index] + replacement + base[index + 1:])
    candidates.add(f"{name}-{tld}")
    candidates.add(name.replace("-", ""))
    variants = []
    for candidate in sorted(candidates):
        if not candidate or candidate == name:
            continue
        if len(candidate) > 60:
            continue
        variants.append(f"{candidate}.{tld}")
    for alternate in TLDS:
        if alternate != tld:
            variants.append(f"{name}.{alternate}")
    return variants[:MAX_VARIANTS]


@module("lookalike_domains", label="Lookalike domains",
        description="Typosquat and homoglyph variants that already resolve",
        group="security", weight="medium", order=150, upstream="Phishing Domain Protection")
def lookalike_domains(ctx):
    try:
        ipaddress.ip_address(ctx.target)
        return {"variants": 0, "looked_up": 0, "registered": [],
                "note": "an address has no lookalike domain names"}, []
    except ValueError:
        pass
    variants = _variants(ctx.target)
    registered: List[Dict[str, object]] = []
    lookups = 0
    for variant in variants:
        if lookups >= MAX_LOOKUPS or ctx.expired():
            break
        lookups += 1
        try:
            addresses = ctx.dns_fast.resolve(variant)
        except Exception:
            continue
        if addresses:
            registered.append({"domain": variant, "addresses": addresses[:3]})
    data = {"variants": len(variants), "looked_up": lookups,
            "registered": registered}
    findings: List[Finding] = []
    for entry in registered:
        findings.append(Finding(
            module="lookalike_domains", severity="medium",
            title=f"Lookalike domain resolves: {entry['domain']}",
            detail=f"Addresses: {', '.join(entry['addresses'])}",
            remediation="Monitor or defensively register the variant; do not browse to it from this lab."))
    return data, findings
