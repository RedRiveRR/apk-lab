"""CORS reflection and cookie inventory (upstream plugin ``Cookies & CORS``). Active."""
from __future__ import annotations

from typing import List

from ..models import Finding
from ..registry import module
from ..checks.security_analysis import parse_cookie

PROBE_ORIGIN = "https://os-lab.test"


@module("cookies_cors", label="CORS and cookies",
        description="Origin reflection with a harmless probe origin, and the cookie inventory",
        group="security", weight="heavy", order=260, active=True)
def cookies_cors(ctx):
    plain = ctx.http.get(ctx.url)
    probe = ctx.http.get(ctx.url, headers={"Origin": PROBE_ORIGIN})
    allow_origin = probe.header("access-control-allow-origin", "")
    allow_credentials = probe.header("access-control-allow-credentials", "").lower()
    reflected = allow_origin == PROBE_ORIGIN
    preflight = ctx.http.request(ctx.url, "OPTIONS", headers={
        "Origin": PROBE_ORIGIN,
        "Access-Control-Request-Method": "GET",
    })
    cookies = [parse_cookie(raw) for raw in plain.cookies]
    data = {
        "origin": PROBE_ORIGIN,
        "allow_origin": allow_origin,
        "allow_credentials": allow_credentials,
        "reflected": reflected,
        "preflight_status": preflight.status,
        "preflight_allow_methods": preflight.header("access-control-allow-methods", ""),
        "cookies": cookies,
    }
    findings: List[Finding] = []
    if reflected and allow_credentials == "true":
        findings.append(Finding(
            module="cookies_cors", kind="cors-credentials-reflection", severity="high",
            title="CORS reflects an arbitrary origin together with credentials",
            detail=f"{PROBE_ORIGIN} is echoed in Access-Control-Allow-Origin with credentials allowed.",
            remediation="Check the Origin against an allowlist; never reflect it blindly."))
    elif reflected:
        findings.append(Finding(
            module="cookies_cors", kind="cors-origin-reflection", severity="medium",
            title="CORS reflects an arbitrary origin",
            detail=f"{PROBE_ORIGIN} is echoed in Access-Control-Allow-Origin.",
            remediation="Answer only the origins that need the response."))
    elif allow_origin == "*" and allow_credentials == "true":
        findings.append(Finding(
            module="cookies_cors", kind="cors-wildcard-credentials", severity="high",
            title="CORS combines a wildcard with credentials",
            detail="Browsers reject this combination, and the intent is unsafe.",
            remediation="Use an explicit allowlist."))
    return data, findings
