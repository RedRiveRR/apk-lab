"""Policy gate for the Windows Apps Lab.

Decides which desktop windows a person or an agent may see, records what agents did and what was
refused, and is the only door the web endpoints and the MCP server use to reach the native
collector in winapps.py. It has no Win32 dependency, so it is testable on any host.

The filter reads process names and window titles only. It is a heuristic, not a guarantee.
"""

from __future__ import annotations

import json
import os
import threading
import time
import unicodedata
from dataclasses import dataclass

POLICY_ENV = "OSLAB_WINAPPS_POLICY"
POLICY_KEYS = ("allowedApps", "restrictedApps", "restrictedTitles")

# Built-in restrictions can be extended by the policy file but never removed.
BUILTIN_RESTRICTED_APPS = frozenset({
    "1password", "bitwarden", "keepass", "keepassxc", "dashlane", "lastpass", "nordpass",
    "enpass", "roboform", "proton pass", "protonpass",
})
BUILTIN_PRIVATE_TITLES = ("inprivate", "incognito", "private browsing", "private window")
BUILTIN_BANKING_TITLES = ("online banking", "internet banking")


class GuardError(Exception):
    """A refusal the caller can show: what failed, a stable code and whether retrying can help."""

    def __init__(self, message: str, code: str, retry: str = "never") -> None:
        super().__init__(message)
        self.code = code
        self.retry = retry


@dataclass(frozen=True)
class Policy:
    allowed: frozenset[str]
    restricted_apps: frozenset[str]
    restricted_titles: tuple[str, ...]
    error: str | None
    path: str
    exists: bool


@dataclass(frozen=True)
class Verdict:
    restricted: bool
    allowed: bool
    reason: str | None


def _norm(value: object) -> str:
    """Case, accent and Turkish dotted/dotless i insensitive form used for every comparison."""
    text = unicodedata.normalize("NFKD", str(value))
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text.casefold().replace("ı", "i").strip()


def _norm_app(value: object) -> str:
    name = _norm(value)
    return name[:-4].strip() if name.endswith(".exe") else name


def _policy_path(root: str) -> str:
    return os.environ.get(POLICY_ENV) or os.path.join(root, "win-lab", "winapps-policy.json")


_POLICY_CACHE: dict[str, tuple[int, int, Policy]] = {}


def _broken(path: str, message: str) -> Policy:
    return Policy(frozenset(), frozenset(), (), message, path, True)


def _parse(path: str, raw: bytes) -> Policy:
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        return _broken(path, "The policy file is not valid JSON")
    if not isinstance(data, dict):
        return _broken(path, "The policy file must be a JSON object")
    lists: dict[str, list[str]] = {}
    for key in POLICY_KEYS:
        value = data.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            return _broken(path, f"{key} must be a list of strings")
        lists[key] = value
    allowed = frozenset(name for name in map(_norm_app, lists["allowedApps"]) if name)
    restricted_apps = frozenset(name for name in map(_norm_app, lists["restrictedApps"]) if name)
    restricted_titles = tuple(hint for hint in map(_norm, lists["restrictedTitles"]) if hint)
    return Policy(allowed, restricted_apps, restricted_titles, None, path, True)


def load_policy(root: str) -> Policy:
    """The current policy; a missing file allows nothing and a broken one fails closed."""
    path = _policy_path(root)
    try:
        stat = os.stat(path)
    except OSError:
        return Policy(frozenset(), frozenset(), (), None, path, False)
    key = (stat.st_mtime_ns, stat.st_size)
    cached = _POLICY_CACHE.get(path)
    if cached and cached[:2] == key:
        return cached[2]
    try:
        with open(path, "rb") as f:
            policy = _parse(path, f.read())
    except OSError:
        policy = _broken(path, "The policy file could not be read")
    _POLICY_CACHE[path] = (key[0], key[1], policy)
    return policy


def classify(window: dict, policy: Policy) -> Verdict:
    """Restricted wins over the allowlist; an app off the allowlist is simply not allowed."""
    app = _norm_app(window.get("app") or "")
    title = _norm(window.get("title") or "")
    if app in BUILTIN_RESTRICTED_APPS:
        return Verdict(True, False, "password-manager")
    if app and app in policy.restricted_apps:
        return Verdict(True, False, "policy-app")
    if any(hint in title for hint in BUILTIN_PRIVATE_TITLES):
        return Verdict(True, False, "private-window")
    if any(hint in title for hint in BUILTIN_BANKING_TITLES):
        return Verdict(True, False, "banking-hint")
    if any(hint in title for hint in policy.restricted_titles):
        return Verdict(True, False, "policy-title")
    if app and app in policy.allowed:
        return Verdict(False, True, None)
    return Verdict(False, False, "not-allowlisted")


def policy_summary(root: str) -> dict:
    """Counts only: the app names stay in the policy file."""
    policy = load_policy(root)
    return {"allowedApps": len(policy.allowed), "restrictedApps": len(policy.restricted_apps),
            "restrictedTitles": len(policy.restricted_titles), "policyError": policy.error,
            "path": policy.path, "exists": policy.exists}


# ── Audit ────────────────────────────────────────────────────────────────────

AUDIT_DIR_ENV = "OSLAB_WINAPPS_AUDIT_DIR"
_AUDIT_MAX = 500
_COALESCE_SECONDS = 60
_AUDIT: list[dict] = []
_AUDIT_SEQ = 0
_AUDIT_LOCK = threading.Lock()


def _reset_audit() -> None:
    global _AUDIT_SEQ
    with _AUDIT_LOCK:
        _AUDIT.clear()
        _AUDIT_SEQ = 0


def audit(root: str | None, kind: str, *, audience: str, app: str | None = None,
          window_id: int | None = None, code: str | None = None, tool: str | None = None) -> None:
    """Record one row. Never raises: auditing must not break the action it describes.

    Titles and pixels cannot be passed in. An identical row (same audience, kind, app, window and
    code) within 60 seconds of the previous one only raises its count, so a panel retrying a
    restricted window every few seconds writes one row a minute.
    """
    global _AUDIT_SEQ
    try:
        now = time.time()
        with _AUDIT_LOCK:
            last = _AUDIT[-1] if _AUDIT else None
            if (last and now - last["time"] <= _COALESCE_SECONDS and last["audience"] == audience
                    and last["kind"] == kind and last["app"] == app and last["windowId"] == window_id
                    and last["code"] == code):
                last["count"] += 1
                return
            _AUDIT_SEQ += 1
            row = {"seq": _AUDIT_SEQ, "time": now, "audience": audience, "kind": kind, "app": app,
                   "windowId": window_id, "code": code, "tool": tool, "count": 1}
            _AUDIT.append(row)
            del _AUDIT[:-_AUDIT_MAX]
            line = json.dumps(row)
        folder = os.environ.get(AUDIT_DIR_ENV) or (os.path.join(root, "win-lab", "artifacts") if root else None)
        if folder:
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, "winapps-audit-%s.jsonl" % time.strftime("%Y%m%d")),
                      "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:  # noqa: BLE001 - the audit trail is best effort by design
        pass


def audit_rows(limit: int = 200) -> dict:
    """The newest rows for the panel and the MCP audit tool."""
    with _AUDIT_LOCK:
        return {"recording": True, "rows": [dict(row) for row in _AUDIT[-max(0, limit):]]}
