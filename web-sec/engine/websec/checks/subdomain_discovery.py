"""Passive subdomain discovery through certificate transparency (crt.sh)."""
from __future__ import annotations

import ipaddress
import json
from typing import Dict, List

from ..models import Finding
from ..registry import module

INTERESTING = ("dev", "staging", "stage", "test", "qa", "uat", "admin", "internal",
               "jenkins", "git", "gitlab", "ci", "vpn", "old", "backup", "demo")
MAX_NAMES = 500


@module("subdomain_discovery", label="Subdomain discovery",
        description="Certificate-transparency names for the target domain (crt.sh)",
        group="recon", weight="medium", order=90, upstream="Subdomain Discovery")
def subdomain_discovery(ctx):
    try:
        ipaddress.ip_address(ctx.target)
    except ValueError:
        pass
    else:
        return {"available": False, "reason": "an address has no subdomains"}, []
    query = f"https://crt.sh/?q=%25.{ctx.target}&output=json"
    response = ctx.infra(query)
    if response.error or response.status != 200:
        return {"available": False, "reason": response.error or f"crt.sh answered {response.status}"}, []
    try:
        rows = json.loads(response.body.decode("utf-8", "replace"))
    except ValueError:
        return {"available": False, "reason": "crt.sh returned a body that is not JSON"}, []
    names = set()
    for row in rows if isinstance(rows, list) else []:
        for value in str(row.get("name_value", "")).splitlines():
            name = value.strip().lower().lstrip("*.").rstrip(".")
            if name.endswith("." + ctx.target) or name == ctx.target:
                names.add(name)
    ordered = sorted(names)[:MAX_NAMES]
    interesting = [name for name in ordered if any(
        name.split(".")[0] == prefix or name.split(".")[0].startswith(prefix + "-")
        for prefix in INTERESTING)]
    data = {"available": True, "count": len(ordered), "names": ordered,
            "interesting": interesting, "source": "crt.sh"}
    findings: List[Finding] = []
    if interesting:
        findings.append(Finding(
            module="subdomain_discovery", severity="low",
            title="Non-production names appear in certificate transparency",
            detail=f"{len(interesting)} candidate(s): {', '.join(interesting[:6])}",
            evidence="\n".join(interesting[:20]),
            remediation="Retire stale names, and put staging behind authentication."))
    return data, findings
