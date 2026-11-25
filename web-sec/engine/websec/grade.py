"""Score and grade a scan the way the upstream dashboard did (A+ … F).

Penalties are per finding and capped, so ten copies of one informational note
cannot outweigh a single critical exposure.
"""
from __future__ import annotations

from typing import Iterable, Sequence, Tuple

from .models import Finding

#: Points removed from 100 for the first finding at each severity.
PENALTY = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
#: At most this many findings of one severity per module are counted.
PER_MODULE_CAP = 3

#: (minimum score, grade), highest first.
GRADES: Tuple[Tuple[int, str], ...] = (
    (97, "A+"), (93, "A"), (90, "A-"), (87, "B+"), (83, "B"), (80, "B-"),
    (77, "C+"), (73, "C"), (70, "C-"), (67, "D+"), (63, "D"), (60, "D-"),
)


def penalty(findings: Iterable[Finding]) -> int:
    counts: dict = {}
    total = 0
    for finding in findings:
        key = (finding.module, finding.severity)
        used = counts.get(key, 0)
        if used >= PER_MODULE_CAP:
            continue
        counts[key] = used + 1
        total += PENALTY[finding.severity]
    return min(total, 100)


def score(findings: Sequence[Finding]) -> int:
    return max(0, 100 - penalty(findings))


def grade(value: int) -> str:
    for minimum, label in GRADES:
        if value >= minimum:
            return label
    return "F"


def score_and_grade(findings: Sequence[Finding]) -> Tuple[int, str]:
    value = score(findings)
    return value, grade(value)


def worst(findings: Iterable[Finding]) -> str:
    """The most severe level present, or ``none``."""
    best = None
    for finding in findings:
        if best is None or finding.rank < best.rank:
            best = finding
    return best.severity if best else "none"
