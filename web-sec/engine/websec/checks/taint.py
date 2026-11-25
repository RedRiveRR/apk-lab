"""A static source → sink pass over served JavaScript (DOM-XSS candidates).

Ported from WebAnalyzer's ``TaintFlowTracker`` (MIT, see knowledge/upstream.md).
It reads text the site already serves and never executes or sends anything. A
chain is reported only when all of these hold, which keeps the false-positive
rate of a regex pass tolerable:

1. a named variable (two characters or more, so minified ``e``/``t`` noise is
   skipped) is assigned from a user-controlled source;
2. the same variable appears on the line of a dangerous DOM or eval sink;
3. the assignment is within 50 lines of the sink;
4. the sink line is not a known-safe configuration write.

It is a candidate, not a confirmed bug: the finding says so.
"""
from __future__ import annotations

import re
from typing import Dict, List

SOURCES = (
    r"location\.(?:search|hash|href|pathname)",
    r"document\.(?:referrer|URL|documentURI|baseURI)",
    r"window\.name",
    r"URLSearchParams\s*\([^)]*\)\.get\s*\(",
    r"(?:localStorage|sessionStorage)\.getItem\s*\(",
    r"\.searchParams\.get\s*\(",
)
SINKS = (
    ("innerHTML", r"\.(?:innerHTML|outerHTML)\s*\+?="),
    ("insertAdjacentHTML", r"\.insertAdjacentHTML\s*\("),
    ("document.write", r"document\.write(?:ln)?\s*\("),
    ("eval", r"(?<![A-Za-z0-9_$.])eval\s*\("),
    ("Function", r"new\s+Function\s*\("),
    ("setTimeout(string)", r"set(?:Timeout|Interval)\s*\(\s*[A-Za-z_$][\w$]*\s*[,)]"),
    ("dangerouslySetInnerHTML", r"dangerouslySetInnerHTML"),
    ("bypassSecurityTrust", r"bypassSecurityTrust\w*\s*\("),
)
SAFE_LINES = (r"Drupal\.", r"\.settings\.", r"console\.", r"DOMPurify\.sanitize", r"textContent\s*=")
MAX_LINES = 20_000
MAX_LINE = 4_000
MAX_VARS = 50
MAX_CHAINS = 10
WINDOW = 50

_SOURCE = re.compile("|".join(f"(?:{pattern})" for pattern in SOURCES))
_SINKS = tuple((name, re.compile(pattern)) for name, pattern in SINKS)
_SAFE = re.compile("|".join(SAFE_LINES))
_DECLARE = re.compile(r"(?:var|let|const)\s+([A-Za-z_$][\w$]{1,})\s*=")
_ASSIGN = re.compile(r"([A-Za-z_$][\w$]{1,})\s*=\s*(?:[^=;]{0,80}?)(?=" + _SOURCE.pattern + ")")


def find_taint_chains(text: str) -> List[Dict[str, object]]:
    """Candidate chains, each ``{"line", "source_line", "variable", "sink", "code"}``."""
    lines = (text or "").splitlines()[:MAX_LINES]
    tainted: Dict[str, List[int]] = {}
    for number, raw in enumerate(lines, 1):
        line = raw[:MAX_LINE]
        if not _SOURCE.search(line):
            continue
        for pattern in (_DECLARE, _ASSIGN):
            for match in pattern.finditer(line):
                name = match.group(1)
                if name in ("var", "let", "const", "this", "window", "document", "location"):
                    continue
                if name not in tainted and len(tainted) >= MAX_VARS:
                    continue
                tainted.setdefault(name, []).append(number)
    if not tainted:
        return []
    names = {name: re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])") for name in tainted}
    chains: List[Dict[str, object]] = []
    for number, raw in enumerate(lines, 1):
        line = raw[:MAX_LINE]
        if _SAFE.search(line):
            continue
        for sink, pattern in _SINKS:
            match = pattern.search(line)
            if not match:
                continue
            for name, compiled in names.items():
                near = [source for source in tainted[name] if abs(source - number) <= WINDOW]
                if not near:
                    continue
                # the variable must be on the sink line, after the sink starts or as its value
                if not compiled.search(line):
                    continue
                start = max(0, match.start() - 60)
                chains.append({"line": number, "source_line": near[0], "variable": name, "sink": sink,
                               "code": line[start:match.end() + 120].strip()[:200]})
                if len(chains) >= MAX_CHAINS:
                    return chains
                break
    return chains


__all__ = ["find_taint_chains"]
