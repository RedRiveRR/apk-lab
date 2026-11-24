"""Run a scan: select modules, honour the budget, collect bounded outcomes."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .config import Options
from .context import Context
from .grade import score_and_grade
from .models import ModuleOutcome, Finding, sort_findings, split_module_value, summarise
from .registry import ModuleSpec, select
from .scope import Guard, ScopeRefused


@dataclass
class ScanResult:
    target: str
    url: str
    started_at: str
    duration_seconds: float
    options: Options
    outcomes: Dict[str, ModuleOutcome] = field(default_factory=dict)
    refused: bool = False
    refusal: str = ""

    @property
    def findings(self) -> List[Finding]:
        collected: List[Finding] = []
        for outcome in self.outcomes.values():
            collected.extend(outcome.findings)
        return sort_findings(collected)

    @property
    def summary(self) -> Dict[str, int]:
        return summarise(self.findings)

    @property
    def score(self) -> int:
        return score_and_grade(self.findings)[0]

    @property
    def grade(self) -> str:
        return score_and_grade(self.findings)[1]

    def as_dict(self, include_data: bool = True) -> Dict[str, object]:
        return {
            "target": self.target,
            "url": self.url,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "preset": self.options.preset,
            "active": self.options.active,
            "score": self.score,
            "grade": self.grade,
            "summary": self.summary,
            "refused": self.refused,
            "refusal": self.refusal,
            "modules": [outcome.as_dict(include_data) for outcome in self.outcomes.values()],
            "findings": [finding.as_dict() for finding in self.findings],
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_scan(options: Options, guard=None, context: Optional[Context] = None) -> ScanResult:
    """Execute the selected modules against one target.

    A target outside the declared scope raises :class:`ScopeRefused` before any
    module runs. A module that is refused mid-scan (a redirect to another host,
    for example) is recorded as ``refused`` and the rest continue.
    """
    from .catalog import ensure_loaded
    ensure_loaded()

    specs = select(options.modules or None, options.preset)
    if not specs:
        raise ValueError("no modules selected")
    if context is not None:
        ctx = context
        guard = context.guard
        guard.require("host", options.target)
    else:
        guard = guard or Guard(options.scope_path)
        guard.require("host", options.target)
        ctx = Context(options, guard)

    result = ScanResult(target=options.target, url=options.url, started_at=_now(),
                        duration_seconds=0.0, options=options)
    started = time.monotonic()
    produced: Dict[str, object] = {}

    for spec in specs:
        outcome = _run_one(spec, ctx, produced, options, result)
        result.outcomes[spec.id] = outcome
        if outcome.status in ("ok", "empty"):
            produced[spec.id] = outcome.data
        ctx.findings_by_module[spec.id] = list(outcome.findings)

    result.duration_seconds = time.monotonic() - started
    return result


def _run_one(spec: ModuleSpec, ctx: Context, produced: Dict[str, object],
             options: Options, result: ScanResult) -> ModuleOutcome:
    outcome = ModuleOutcome(id=spec.id, label=spec.label)
    if spec.active and not options.active:
        outcome.status = "skipped"
        outcome.note = "active check; rerun with --active and a written authorization"
        return outcome
    if result.refused:
        outcome.status = "skipped"
        outcome.note = "the scan was refused before this module ran"
        return outcome
    if ctx.expired():
        outcome.status = "skipped"
        outcome.note = f"the {options.deadline:g}s budget was used by earlier modules"
        return outcome

    started = time.monotonic()
    try:
        value = spec.run(ctx, produced) if spec.needs_results else spec.run(ctx)
        data, findings = split_module_value(value, spec.id)
    except ScopeRefused as exc:
        outcome.status = "refused"
        outcome.error = exc.reason
        result.refused = True
        result.refusal = exc.reason
    except Exception as exc:  # a broken check is a reported error, not a crash
        outcome.status = "error"
        outcome.error = f"{type(exc).__name__}: {exc}"
    else:
        outcome.data = data
        outcome.findings = findings
        if not data and not findings:
            outcome.status = "empty"
    outcome.duration_ms = int((time.monotonic() - started) * 1000)
    return outcome
