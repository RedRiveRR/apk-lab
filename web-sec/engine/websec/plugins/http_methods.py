"""Declared HTTP methods (upstream plugin ``HTTP Methods & Redirects``). Active."""
from __future__ import annotations

from typing import List

from ..models import Finding
from ..registry import module

RISKY = ("PUT", "DELETE", "PATCH", "PROPFIND", "MOVE", "COPY")


@module("http_methods", label="HTTP methods",
        description="OPTIONS Allow list and TRACE echo",
        group="security", weight="heavy", order=250, active=True)
def http_methods(ctx):
    options = ctx.http.request(ctx.url, "OPTIONS")
    trace = ctx.http.request(ctx.url, "TRACE")
    allow = options.header("allow", "")
    declared = [method.strip().upper() for method in allow.split(",") if method.strip()]
    data = {"options_status": options.status, "allow": declared[:20],
            "trace_status": trace.status, "trace_echo": bool(trace.body),
            "options_error": options.error, "trace_error": trace.error}
    findings: List[Finding] = []
    risky = [method for method in declared if method in RISKY]
    if risky:
        findings.append(Finding(
            module="http_methods", kind="write-methods", severity="medium",
            title="The server advertises write or WebDAV methods",
            detail=f"Allow: {', '.join(declared)}",
            remediation="Disable the methods the application does not need at the server or edge."))
    if trace.status == 200 and trace.body:
        findings.append(Finding(
            module="http_methods", kind="trace-echo", severity="medium",
            title="TRACE is accepted and echoes the request",
            detail="TRACE can be abused in cross-site tracing setups.",
            remediation="Disable TRACE in the web server configuration."))
    return data, findings
