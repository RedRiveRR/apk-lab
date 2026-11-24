"""Findings and module outcomes: the only shapes a check may return.

A check returns a mapping of JSON-serialisable data, optionally accompanied by
:class:`Finding` objects. Everything is bounded here, so one verbose module
cannot bloat a report or the console response.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: position for position, name in enumerate(SEVERITIES)}
MAX_TITLE = 300
MAX_TEXT = 2000
MAX_EVIDENCE = 1200
MAX_RESULTS = 200


def clamp(text: Any, limit: int) -> str:
    """A single-line, length-bounded string for reports and the console."""
    value = " ".join(str(text).split()) if text is not None else ""
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, len(SEVERITIES))


@dataclass(frozen=True)
class Finding:
    """One observation with a severity and, when possible, a fix."""

    module: str
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    refs: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"unknown severity: {self.severity!r}")
        for name, limit in (("title", MAX_TITLE), ("detail", MAX_TEXT),
                            ("evidence", MAX_EVIDENCE), ("remediation", MAX_TEXT)):
            object.__setattr__(self, name, clamp(getattr(self, name), limit))
        object.__setattr__(self, "module", clamp(self.module, 64))
        object.__setattr__(self, "refs", tuple(clamp(ref, 500) for ref in self.refs)[:8])
        if not self.title:
            raise ValueError("a finding needs a title")

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "refs": list(self.refs),
        }


@dataclass
class ModuleOutcome:
    """What one module produced, including why it did not produce anything."""

    id: str
    label: str
    status: str = "ok"           # ok | empty | error | skipped | refused
    duration_ms: int = 0
    data: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    error: str = ""
    note: str = ""

    def as_dict(self, include_data: bool = True) -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "findings": len(self.findings),
            "error": self.error,
            "note": self.note,
        }
        if include_data:
            payload["data"] = self.data
        return payload


def as_findings(value: Any, module: str) -> List[Finding]:
    """Accept a bare data mapping, a ``(data, findings)`` pair, or a findings list."""
    if value is None:
        return []
    if isinstance(value, Finding):
        return [value]
    if isinstance(value, Mapping):
        return []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        found: List[Finding] = []
        for item in value:
            if isinstance(item, Finding):
                found.append(item)
            elif isinstance(item, Mapping):
                found.append(Finding(module=module, **dict(item)))
            else:
                raise TypeError(f"{module} returned a non-finding in its list: {type(item).__name__}")
        return found
    raise TypeError(f"{module} returned {type(value).__name__}; expected a mapping or findings")


def split_module_value(value: Any, module: str) -> Tuple[Dict[str, Any], List[Finding]]:
    """Normalise a check's return value into ``(data, findings)``."""
    if isinstance(value, tuple) and len(value) == 2:
        data, findings = value
        if not isinstance(data, Mapping):
            raise TypeError(f"{module} returned a pair whose first item is {type(data).__name__}")
        return dict(data), as_findings(findings, module)
    if isinstance(value, Mapping):
        return dict(value), []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return {}, as_findings(value, module)
    if value is None:
        return {}, []
    raise TypeError(f"{module} returned {type(value).__name__}")


def summarise(findings: Sequence[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    counts["total"] = len(findings)
    return counts


def sort_findings(findings: Sequence[Finding]) -> List[Finding]:
    """Most severe first, then by module and title, so reports are stable."""
    return sorted(findings, key=lambda f: (f.rank, f.module, f.title))


def bounded_list(values: Sequence[Any], limit: int = MAX_RESULTS) -> List[Any]:
    return list(values)[:limit]


def bounded_text(value: Optional[str], limit: int = MAX_TEXT) -> str:
    return clamp(value or "", limit)
