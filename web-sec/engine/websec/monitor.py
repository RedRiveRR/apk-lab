"""The opt-in posture monitor: recurring passive scans that signal a regression.

Ported in spirit from WebAnalyzer's ``monitor.py`` and ``utils/notify.py`` (MIT, see
knowledge/upstream.md) and shaped like the Cleanup Lab monitor: the console runs
``monitor tick`` on a thread; this module owns the config schema, the private
store (``monitor.json`` in the storage folder, atomic, 0600) and a pure
evaluation over ``(config, state, previous report, new report, now)``.

Monitor scans are always passive, whatever the config says, and every target
still goes through the scope guard. Signals follow the os-lab one-click rules:

* ``warning`` when a run adds a finding at or above ``alertOn`` or the grade drops;
  ``critical`` when a new finding is critical or the grade falls to D/F;
* ``escalated`` when an active warning gets worse; ``reminder`` while it stays
  unresolved (``reminderHours``, 0 turns reminders off); ``recovered`` when every
  flagged finding is gone;
* ``scope-expiring`` / ``scope-expired`` for the authorization record, and
  ``error`` when a target could not be scanned (once per distinct reason).

Notifications are one switch (``notify``), separate from the monitor itself.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import date, datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from .config import default_storage

STORE = "monitor.json"
VERSION = 1
MAX_TARGETS = 10
MAX_EVENTS = 100
MAX_FLAGGED = 50
INTERVALS = (60, 360, 1440, 10080)  # minutes: hourly, every 6 hours, daily, weekly
PRESETS = ("quick", "standard")      # full is not offered for unattended runs
THRESHOLDS = ("critical", "high", "medium", "low")
SEVERITIES = ("critical", "high", "medium", "low", "info")
_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
_GRADE_ORDER = ("A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F")


class MonitorConfigError(ValueError):
    """A config the schema refused; the message says what is wrong."""


def default_config() -> Dict[str, object]:
    return {"enabled": False, "targets": [], "intervalMinutes": 1440, "preset": "quick",
            "alertOn": "high", "notify": True, "reminderHours": 24, "scopeWarnDays": 14}


def validate_config(value) -> Dict[str, object]:
    if not isinstance(value, dict):
        raise MonitorConfigError("config must be an object")
    base = default_config()
    unknown = set(value) - set(base)
    if unknown:
        raise MonitorConfigError(f"Unknown key(s): {', '.join(sorted(unknown))}")
    merged = {**base, **value}
    for key in ("enabled", "notify"):
        if not isinstance(merged[key], bool):
            raise MonitorConfigError(f"{key} must be true or false")
    targets = merged["targets"]
    if not isinstance(targets, list) or len(targets) > MAX_TARGETS:
        raise MonitorConfigError(f"targets must be a list of at most {MAX_TARGETS} hosts")
    cleaned: List[str] = []
    for target in targets:
        if not isinstance(target, str) or not _TARGET.match(target.strip()):
            raise MonitorConfigError("each target must be a host name or address, such as example.test")
        host = target.strip().lower()
        if host not in cleaned:
            cleaned.append(host)
    if merged["enabled"] and not cleaned:
        raise MonitorConfigError("add at least one target before turning the monitor on")
    if merged["intervalMinutes"] not in INTERVALS:
        raise MonitorConfigError("intervalMinutes must be 60, 360, 1440 or 10080")
    if merged["preset"] not in PRESETS:
        raise MonitorConfigError("preset must be quick or standard")
    if merged["alertOn"] not in THRESHOLDS:
        raise MonitorConfigError("alertOn must be critical, high, medium or low")
    for key, low, high in (("reminderHours", 0, 168), ("scopeWarnDays", 1, 60)):
        number = merged[key]
        if isinstance(number, bool) or not isinstance(number, int) or not low <= number <= high:
            raise MonitorConfigError(f"{key} must be a whole number from {low} to {high}")
    return {**merged, "targets": cleaned}


def _fresh_state() -> Dict[str, object]:
    return {"targets": {}, "scope": {"warned": "", "notifiedAt": 0}, "events": []}


def _path(root: Optional[str] = None) -> str:
    return os.path.join(root or default_storage(), STORE)


def load(root: Optional[str] = None) -> Dict[str, object]:
    """``{"config", "state", "configError"}``; never raises."""
    payload = {"config": default_config(), "state": _fresh_state(), "configError": None}
    try:
        with open(_path(root), encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError:
        return payload
    except (OSError, ValueError) as exc:
        payload["configError"] = f"The monitor file is unreadable: {exc}"
        return payload
    if not isinstance(raw, dict) or not isinstance(raw.get("version"), int):
        payload["configError"] = "The monitor file has an unknown shape; defaults apply."
        return payload
    try:
        payload["config"] = validate_config(raw.get("config", {}))
    except MonitorConfigError as exc:
        payload["configError"] = f"The saved monitor config is invalid ({exc}); the monitor is off."
    state = raw.get("state")
    if isinstance(state, dict) and isinstance(state.get("targets"), dict) and isinstance(state.get("events"), list):
        payload["state"] = {**_fresh_state(), **state}
    return payload


def _write(payload: Dict[str, object], root: Optional[str] = None) -> None:
    path = _path(root)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    temporary = f"{path}.tmp-{os.getpid()}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({"version": VERSION, "config": payload["config"], "state": payload["state"]}, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def save_config(value, root: Optional[str] = None) -> Dict[str, object]:
    config = validate_config(value)
    current = load(root)
    state = current["state"]
    # a target that left the list takes its state (and any warning) with it
    state["targets"] = {host: entry for host, entry in state["targets"].items() if host in config["targets"]}
    _write({"config": config, "state": state}, root)
    return {"config": config, "state": state, "configError": None}


# ── evaluation (pure) ────────────────────────────────────────────────────────

def _key(finding: Dict[str, object]) -> str:
    return f"{finding.get('module')}|{finding.get('kind') or finding.get('title')}"


def _at_least(severity: str, threshold: str) -> bool:
    return severity in SEVERITIES and SEVERITIES.index(severity) <= SEVERITIES.index(threshold)


def _grade_rank(grade: str) -> int:
    return _GRADE_ORDER.index(grade) if grade in _GRADE_ORDER else len(_GRADE_ORDER)


def _event(now: float, kind: str, target: str, message: str, **extra) -> Dict[str, object]:
    return {"at": int(now), "kind": kind, "target": target, "message": message[:400], **extra}


def assess(target: str, previous: Optional[Dict[str, object]], current: Dict[str, object],
           entry: Dict[str, object], config: Dict[str, object], now: float) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    """The target's next state entry and the events this run produced."""
    threshold = str(config["alertOn"])
    findings = [f for f in (current.get("findings") or []) if isinstance(f, dict)]
    before = {_key(f) for f in (previous or {}).get("findings") or [] if isinstance(f, dict)}
    present = {_key(f): f for f in findings}
    new = [f for key, f in present.items() if key not in before and _at_least(str(f.get("severity")), threshold)]
    grade_now, grade_before = str(current.get("grade") or ""), str((previous or {}).get("grade") or "")
    dropped = bool(previous) and _grade_rank(grade_now) > _grade_rank(grade_before)
    level = ""
    if new or dropped:
        severe = any(f.get("severity") == "critical" for f in new) or (dropped and grade_now[:1] in ("D", "F"))
        level = "critical" if severe else "warning"

    warning = entry.get("warning") if isinstance(entry.get("warning"), dict) else None
    events: List[Dict[str, object]] = []
    grade_text = f"grade {grade_before} → {grade_now}" if previous else f"grade {grade_now}"
    summary = ", ".join(f"{f.get('severity')}: {f.get('title')}" for f in new[:3])
    message = (f"{len(new)} new finding(s) at or above {threshold}" if new else "The grade dropped")
    message += f"; {grade_text}." + (f" {summary}." if summary else "")
    flagged = sorted({_key(f) for f in new} | set((warning or {}).get("flagged") or []))[:MAX_FLAGGED]
    if level and warning is None:
        events.append(_event(now, level, target, message, new=len(new)))
        warning = {"level": level, "since": int(now), "notifiedAt": int(now), "flagged": flagged,
                   "baseGrade": grade_before or grade_now, "message": message}
    elif level and warning is not None and (new or (level == "critical" and warning.get("level") != "critical")):
        events.append(_event(now, "escalated", target, message, new=len(new)))
        warning = {**warning, "level": "critical" if level == "critical" else warning.get("level", level),
                   "notifiedAt": int(now), "flagged": flagged, "message": message}
    elif warning is not None:
        still = [key for key in warning.get("flagged") or [] if key in present]
        base = str(warning.get("baseGrade") or "")
        grade_back = not base or _grade_rank(grade_now) <= _grade_rank(base)
        if not still and grade_back:
            events.append(_event(now, "recovered", target, f"The flagged findings are resolved; {grade_text}."))
            warning = None
        else:
            warning = {**warning, "flagged": still}
            hours = int(config["reminderHours"])
            if hours and now - float(warning.get("notifiedAt") or 0) >= hours * 3600:
                events.append(_event(now, "reminder", target,
                                     f"{len(still)} flagged finding(s) are still present; {grade_text}."))
                warning["notifiedAt"] = int(now)
    next_entry = {**entry, "lastRun": int(now), "status": "ok", "error": "",
                  "grade": grade_now, "score": current.get("score"), "warning": warning}
    return next_entry, events


def assess_error(target: str, entry: Dict[str, object], reason: str, now: float) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    events = []
    if entry.get("error") != reason:
        events.append(_event(now, "error", target, reason))
    return {**entry, "lastRun": int(now), "status": "error", "error": reason}, events


def assess_scope(scope: Dict[str, object], state: Dict[str, object], config: Dict[str, object],
                 now: float, today: Optional[date] = None) -> List[Dict[str, object]]:
    """Scope-expiry events; updates ``state["scope"]`` in place."""
    record = state.setdefault("scope", {"warned": "", "notifiedAt": 0})
    today = today or datetime.fromtimestamp(now, timezone.utc).date()
    expires = scope.get("expires")
    status = ""
    if not scope.get("valid"):
        status = "scope-expired"
    elif isinstance(expires, str) and expires:
        try:
            days = (date.fromisoformat(expires[:10]) - today).days
        except ValueError:
            days = None
        if days is not None and days <= int(config["scopeWarnDays"]):
            status = "scope-expiring" if days >= 0 else "scope-expired"
    events: List[Dict[str, object]] = []
    hours = int(config["reminderHours"])
    due = hours and now - float(record.get("notifiedAt") or 0) >= hours * 3600
    if status and (status != record.get("warned") or due):
        message = (f"The scope “{scope.get('name') or 'unnamed'}” expires {expires}; renew the written authorization."
                   if status == "scope-expiring" else
                   f"The scope is not usable ({scope.get('reason') or 'expired ' + str(expires)}); monitor scans are refused.")
        events.append(_event(now, status, "", message))
        record.update({"warned": status, "notifiedAt": int(now)})
    elif not status and record.get("warned"):
        record.update({"warned": "", "notifiedAt": 0})
    return events


def due_targets(config: Dict[str, object], state: Dict[str, object], now: float, force: bool = False) -> List[str]:
    if not config.get("enabled") and not force:
        return []
    interval = int(config["intervalMinutes"]) * 60
    targets = state.get("targets") or {}
    due = []
    for host in config["targets"]:
        last = (targets.get(host) or {}).get("lastRun")
        if force or not last or now - float(last) >= interval:  # never run yet: due now
            due.append(host)
    return due


def active_warnings(state: Dict[str, object]) -> List[Dict[str, object]]:
    rows = [{"target": host, **entry["warning"]} for host, entry in (state.get("targets") or {}).items()
            if isinstance(entry, dict) and isinstance(entry.get("warning"), dict)]
    scope = state.get("scope") or {}
    if scope.get("warned"):
        rows.append({"target": "", "level": "critical" if scope["warned"] == "scope-expired" else "warning",
                     "since": scope.get("notifiedAt"), "message": scope["warned"], "flagged": []})
    return rows


def _append(state: Dict[str, object], events: List[Dict[str, object]]) -> None:
    state["events"] = (list(state.get("events") or []) + events)[-MAX_EVENTS:]


# ── the tick (scans + store) ─────────────────────────────────────────────────

def tick(force: bool = False, root: Optional[str] = None, clock: Callable[[], float] = time.time,
         scan: Optional[Callable] = None, scope_status: Optional[Callable] = None,
         notifier: Optional[Callable] = None) -> Dict[str, object]:
    """Scan the due targets passively, store the reports, evaluate and notify."""
    from . import notify as notify_module
    from .history import History
    from .scope import Guard

    loaded = load(root)
    config, state = loaded["config"], loaded["state"]
    now = clock()
    if not (config["enabled"] or force):
        # off: touch nothing, so the console can tick every minute for free
        return {"newEvents": [], "notifications": [], "activeWarnings": active_warnings(state), "scanned": []}
    before = json.dumps(state, sort_keys=True)
    events: List[Dict[str, object]] = []
    events += assess_scope((scope_status or (lambda: Guard().status()))(), state, config, now)
    history = History()
    scanned: List[str] = []
    for host in due_targets(config, state, now, force):
        scanned.append(host)
        entry = dict((state["targets"].get(host) or {}))
        try:
            previous = _previous(history, host, entry)
            document = (scan or _scan)(host, config["preset"])
            stored = history.append(document)
            entry["lastReport"] = stored.get("name", "")
            entry, produced = assess(host, previous, document, entry, config, now)
        except Exception as exc:  # a target that cannot be scanned is an event, never a crash
            reason = str(getattr(exc, "reason", "") or exc) or exc.__class__.__name__
            entry, produced = assess_error(host, entry, reason[:300], now)
        state["targets"][host] = entry
        events += produced
    _append(state, events)
    if json.dumps(state, sort_keys=True) != before:
        _write({"config": config, "state": state}, root)
    deliveries = (notifier or notify_module.send_all)(events, enabled=bool(config["notify"])) if events else []
    return {"newEvents": events, "notifications": deliveries, "activeWarnings": active_warnings(state),
            "scanned": scanned}


def _previous(history, host: str, entry: Dict[str, object]) -> Optional[Dict[str, object]]:
    name = str(entry.get("lastReport") or "")
    if name:
        try:
            return history.load(host, name)
        except (OSError, ValueError):
            pass
    stored = history.reports(host)
    if stored:
        try:
            return history.load(host, stored[0]["name"])
        except (OSError, ValueError):
            return None
    return None


def _scan(host: str, preset: str) -> Dict[str, object]:
    from . import report as report_module
    from .config import Options
    from .runner import run_scan
    options = Options.build(host, preset=preset, active=False, keep_history=False)
    return report_module.build(run_scan(options))


def status(root: Optional[str] = None) -> Dict[str, object]:
    loaded = load(root)
    state = loaded["state"]
    return {"config": loaded["config"], "configError": loaded["configError"],
            "targets": state.get("targets", {}), "activeWarnings": active_warnings(state),
            "events": list(reversed(state.get("events") or []))[:30],
            "intervals": list(INTERVALS)}


__all__ = ["MonitorConfigError", "assess", "assess_error", "assess_scope", "active_warnings", "default_config",
           "due_targets", "load", "save_config", "status", "tick", "validate_config"]
