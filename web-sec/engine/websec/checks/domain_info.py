"""Domain registration facts from WHOIS (WebAnalyzer ``Domain Information``)."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import List, Optional

from ..models import Finding
from ..registry import module

_EXPIRY_KEYS = ("registry expiry date", "expiry date", "expiration date", "paid-till",
                "expires", "renewal date")
_DATE_FORMATS = ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                 "%d.%m.%Y", "%Y.%m.%d", "%d-%b-%Y", "%Y/%m/%d")
_BAD_STATUS = ("clienthold", "pendingdelete", "redemptionperiod", "serverhold")


def _expiry(fields) -> Optional[datetime]:
    for key in _EXPIRY_KEYS:
        for value in fields.get(key, []):
            text = value.strip().split(" ")[0].replace("Z", "")
            for pattern in _DATE_FORMATS:
                try:
                    parsed = datetime.strptime(text, pattern)
                except ValueError:
                    continue
                return parsed.replace(tzinfo=timezone.utc)
    return None


@module("domain_info", label="Domain information",
        description="WHOIS registrar, registration dates, nameservers and status",
        group="recon", weight="light", order=10, upstream="Domain Information")
def domain_info(ctx):
    try:
        ipaddress.ip_address(ctx.target)
    except ValueError:
        pass
    else:
        return {"available": False, "reason": "the target is an address, so it has no registration"}, []
    whois = ctx.whois()
    if not whois.ok:
        return {"available": False, "reason": whois.error or "the registry returned no fields",
                "server": whois.server}, []
    data = whois.as_dict()
    data["available"] = True
    findings: List[Finding] = []
    expiry = _expiry(whois.fields)
    if expiry is not None:
        days = int((expiry - datetime.now(timezone.utc)).total_seconds() // 86400)
        data["expires"] = expiry.date().isoformat()
        data["days_left"] = days
        if days < 0:
            findings.append(Finding(module="domain_info", severity="critical",
                                    title="The domain registration has expired",
                                    detail=f"WHOIS reports an expiry date of {data['expires']}.",
                                    remediation="Renew the domain now; an expired registration can be taken over."))
        elif days <= 30:
            findings.append(Finding(module="domain_info", severity="high",
                                    title="The domain registration expires within 30 days",
                                    detail=f"Expiry {data['expires']} ({days} days).",
                                    remediation="Renew the registration and enable auto-renew."))
        elif days <= 90:
            findings.append(Finding(module="domain_info", severity="medium",
                                    title="The domain registration expires within 90 days",
                                    detail=f"Expiry {data['expires']} ({days} days).",
                                    remediation="Renew the registration and enable auto-renew."))
    status = " ".join(whois.all("status") + whois.all("domain status")).lower()
    for marker in _BAD_STATUS:
        if marker in status:
            findings.append(Finding(module="domain_info", severity="high",
                                    title=f"The registry status contains {marker}",
                                    detail="The domain is suspended or slated for deletion.",
                                    remediation="Contact the registrar and resolve the suspension."))
            break
    nameservers = whois.all("name server") + whois.all("nserver")
    data["nameservers"] = sorted({server.split()[0].lower() for server in nameservers if server})[:12]
    if not data["nameservers"]:
        findings.append(Finding(module="domain_info", severity="medium",
                                title="No nameservers are published in WHOIS",
                                detail="An empty delegation can indicate a lapsed registration.",
                                remediation="Confirm the delegation with the registrar."))
    return data, findings
