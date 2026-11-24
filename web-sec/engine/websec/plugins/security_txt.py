"""RFC 9116 ``/.well-known/security.txt`` (upstream plugin ``Security.txt``)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

from ..models import Finding
from ..registry import module


def _fields(text: str) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    for line in text.splitlines():
        if line.strip().startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        found.setdefault(key.strip().lower(), []).append(value.strip()[:500])
    return found


@module("security_txt", label="Security.txt",
        description="RFC 9116 contact file, contacts and expiry",
        group="posture", weight="light", order=200)
def security_txt(ctx):
    response = ctx.page("/.well-known/security.txt")
    if response.error or response.status != 200:
        return {"present": False, "status": response.status, "error": response.error}, []
    parsed = _fields(response.text)
    expires = (parsed.get("expires") or [""])[0]
    contacts = parsed.get("contact") or []
    data = {"present": True, "contacts": contacts[:10], "expires": expires,
            "canonical": (parsed.get("canonical") or [""])[0],
            "policy": (parsed.get("policy") or [""])[0]}
    findings: List[Finding] = []
    if not contacts:
        findings.append(Finding(module="security_txt", severity="low", kind="no-contact",
                                title="security.txt has no Contact field",
                                detail="A researcher cannot report a vulnerability through the declared channel.",
                                remediation="Add at least one Contact (mailto: or https: URL)."))
    if expires:
        try:
            when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if when < datetime.now(timezone.utc):
                findings.append(Finding(module="security_txt", severity="low", kind="expired",
                                        title="security.txt has expired",
                                        detail=f"Expires {expires}.",
                                        remediation="Refresh the file before its expiry date."))
        except ValueError:
            findings.append(Finding(module="security_txt", severity="info", kind="expires-unreadable",
                                    title="security.txt has an unreadable Expires value",
                                    detail=expires[:100],
                                    remediation="Use an ISO 8601 timestamp."))
    else:
        findings.append(Finding(module="security_txt", severity="low", kind="no-expires",
                                title="security.txt has no Expires field",
                                detail="RFC 9116 requires one.",
                                remediation="Add Expires with an ISO 8601 date."))
    return data, findings
