"""Policy gate for the Windows Apps Lab.

Decides which desktop windows a person or an agent may see, records what agents did and what was
refused, and is the only door the web endpoints and the MCP server use to reach the native
collector in winapps.py. It has no Win32 dependency, so it is testable on any host.

The filter reads process names and window titles only. It is a heuristic, not a guarantee.
"""

from __future__ import annotations

import json
import os
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
