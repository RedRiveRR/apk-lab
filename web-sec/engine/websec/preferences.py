"""The operator's saved workbench choices, kept across restarts and app updates.

One small JSON file in the private storage folder (``web-sec/storage``, 0700, or
``WEBSEC_STORAGE``), written atomically. It holds *choices*, never commands: the
last target, preset, protocol, an explicit check selection, pacing overrides and
the bulk preset.

Intrusive checks are deliberately not a preference: every active scan is opted in
and confirmed on its own, so a saved choice can never make a scan intrusive.

Update safety follows the Cleanup Lab store: a file written by another version is
read and validated, not discarded; check ids the current catalogue does not list
are kept (a later catalogue may list them again) and only dropped when a scan is
built. Corruption never guesses: the defaults apply and ``configError`` says why.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, Optional

from .config import default_storage

STORE = "preferences.json"
VERSION = 1
PRESETS = ("quick", "standard", "full")
SCHEMES = ("http", "https")
MAX_MODULES = 40
MAX_READ = 64 * 1024
_MODULE_ID = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")


class PreferencesError(ValueError):
    """A preferences object the schema refused; the message says what is wrong."""


def defaults() -> Dict[str, object]:
    return {
        "scan": {"target": "", "preset": "standard", "scheme": "https", "modules": [],
                 "timeout": None, "deadline": None},
        "bulk": {"preset": "quick"},
    }


def _number(value, name: str, low: float, high: float) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PreferencesError(f"{name} must be a number or null")
    if not low <= float(value) <= high:
        raise PreferencesError(f"{name} must be between {low:g} and {high:g} seconds")
    return float(value)


def _keys(value, allowed, name: str) -> Dict[str, object]:
    if not isinstance(value, dict):
        raise PreferencesError(f"{name} must be an object")
    unknown = set(value) - set(allowed)
    if unknown:
        raise PreferencesError(f"Unknown {name} key(s): {', '.join(sorted(unknown))}")
    return value


def validate(value) -> Dict[str, object]:
    """A complete, typed preferences object; missing keys take their defaults."""
    raw = _keys(value, ("scan", "bulk"), "preferences")
    base = defaults()
    scan = _keys(raw.get("scan", {}), base["scan"].keys(), "scan")
    bulk = _keys(raw.get("bulk", {}), base["bulk"].keys(), "bulk")

    target = scan.get("target", "")
    if not isinstance(target, str) or (target and not _TARGET.match(target.strip())):
        raise PreferencesError("target must be a host name or address")
    preset = scan.get("preset", "standard")
    if preset not in PRESETS:
        raise PreferencesError("preset must be quick, standard or full")
    scheme = scan.get("scheme", "https")
    if scheme not in SCHEMES:
        raise PreferencesError("scheme must be http or https")
    modules = scan.get("modules", [])
    if not isinstance(modules, list) or len(modules) > MAX_MODULES:
        raise PreferencesError(f"modules must be a list of at most {MAX_MODULES} check ids")
    if any(not isinstance(item, str) or not _MODULE_ID.match(item) for item in modules):
        raise PreferencesError("each check id must look like dns_records")
    if len(set(modules)) != len(modules):
        raise PreferencesError("modules lists a check twice")
    bulk_preset = bulk.get("preset", "quick")
    if bulk_preset not in PRESETS:
        raise PreferencesError("bulk preset must be quick, standard or full")
    return {
        "scan": {
            "target": target.strip().lower(), "preset": preset, "scheme": scheme,
            "modules": list(modules),
            "timeout": _number(scan.get("timeout"), "timeout", 1, 30),
            "deadline": _number(scan.get("deadline"), "deadline", 10, 600),
        },
        "bulk": {"preset": bulk_preset},
    }


def _path(root: Optional[str] = None) -> str:
    return os.path.join(root or default_storage(), STORE)


def load(root: Optional[str] = None) -> Dict[str, object]:
    """``{"preferences": ..., "configError": str | None, "version": int}``; never raises."""
    payload = {"preferences": defaults(), "configError": None, "version": VERSION}
    try:
        if os.path.getsize(_path(root)) > MAX_READ:
            payload["configError"] = "The preferences file is larger than 64 KiB; defaults apply."
            return payload
        with open(_path(root), encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        return payload
    except (OSError, ValueError) as exc:
        payload["configError"] = f"The preferences file is unreadable: {exc}"
        return payload
    if not isinstance(raw, dict) or not isinstance(raw.get("version"), int) or raw["version"] < 1:
        payload["configError"] = "The preferences file has an unknown shape; defaults apply."
        return payload
    try:
        # Another version is read like any other: unknown keys are refused, known ones kept.
        payload["preferences"] = validate(raw.get("preferences", {}))
    except PreferencesError as exc:
        payload["configError"] = f"The saved preferences are invalid ({exc}); defaults apply."
    return payload


def save(value, root: Optional[str] = None) -> Dict[str, object]:
    """Validate, persist atomically (0600 inside the 0700 storage), return the stored payload."""
    validated = validate(value)
    path = _path(root)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    temporary = f"{path}.tmp-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"version": VERSION, "preferences": validated}, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return {"preferences": validated, "configError": None, "version": VERSION}


__all__ = ["PreferencesError", "defaults", "load", "save", "validate"]
