"""A prioritised fix list from the findings already collected.

Upstream called this ``Attack Path Planner`` and drew exploit chains. This port
keeps the useful half: what to fix first, grouped by severity, with the module
that observed it. It never suggests how to exploit anything.
"""
from __future__ import annotations

from typing import Dict, List

from ..models import SEVERITIES, Finding
from ..registry import module


@module("remediation_plan", label="Remediation plan",
        description="Findings ordered into a fix list, highest severity first",
        group="posture", weight="light", order=990, upstream="Attack Path Planner",
        needs_results=True)
def remediation_plan(ctx, results):
    findings: List[Finding] = []
    for collected in ctx.findings_by_module.values():
        findings.extend(collected)
    findings.sort(key=lambda item: (item.rank, item.module, item.title))
    items = [{"severity": finding.severity, "title": finding.title,
              "module": finding.module, "fix": finding.remediation}
             for finding in findings[:80] if finding.severity != "info"]
    counts = {severity: sum(1 for finding in findings if finding.severity == severity)
              for severity in SEVERITIES}
    actions: List[str] = []
    for item in items:
        if item["fix"] and item["fix"] not in actions:
            actions.append(item["fix"])
        if len(actions) >= 10:
            break
    data = {"items": items, "counts": counts, "top_actions": actions,
            "note": "ordered by severity; each action names the module that observed it"}
    return data, []
