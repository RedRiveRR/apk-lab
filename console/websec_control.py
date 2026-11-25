"""Web Sec Lab console adapter: readiness and typed action plans.

The engine is a standard-library Python program, so readiness is a short
subprocess probe and any action is a plain command the operator confirms first.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

MAX_STATUS_BYTES = 64 * 1024


def python() -> str:
    return os.environ.get("WEBSEC_PYTHON") or sys.executable


def _version_tuple(text: str):
    parts = str(text or "").split(".")
    if len(parts) < 2 or not all(part.isdigit() for part in parts[:2]):
        return None
    return tuple(int(part) for part in parts[:2])


def readiness(root: str) -> dict:
    """Run ``web-sec/run.py status --json`` in a child process."""
    runner = Path(root) / "web-sec/run.py"
    if not runner.is_file():
        return {"state": "unavailable", "reason": "web-sec/run.py is missing"}
    try:
        result = subprocess.run([python(), str(runner), "status", "--json"],
                                capture_output=True, text=True, timeout=10,
                                cwd=str(root), env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        if len(result.stdout) > MAX_STATUS_BYTES:
            raise ValueError("status output is too large")
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict) or "version" not in payload:
            raise ValueError("status output has an unexpected shape")
        return payload
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {"state": "unavailable", "reason": f"the engine did not report readiness ({exc})"}


def lab_status(root: str, os_name: str) -> dict:
    report = readiness(root) if os_name in ("linux", "macos", "windows") else {}
    installed = (Path(root) / "web-sec/run.py").is_file()
    supported = _version_tuple(report.get("python")) is not None and \
        _version_tuple(report.get("python")) >= (3, 9)
    writable = bool(report.get("storage_writable"))
    scope = report.get("scope") or {}
    scope_ok = bool(scope.get("valid"))
    runnable = installed and supported
    requirements = [
        {"id": "python", "label": "Python 3.9+", "found": supported, "required": True,
         "hint": "Install Python 3.9+ or set WEBSEC_PYTHON to a suitable interpreter."},
        {"id": "storage", "label": "Writable Web Sec Lab storage", "found": writable, "required": True,
         "hint": "Run ./labctl websec setup, or point WEBSEC_STORAGE at a writable folder."},
        {"id": "scope", "label": "Declared test scope", "found": scope_ok, "required": True,
         "hint": "Copy console/scope.example.json to scope.json and list the hosts you own."},
    ]
    state = "unavailable"
    if runnable:
        state = "ready" if (writable and scope_ok) else "needs-setup"
    reasons = [item["hint"] for item in requirements if item["required"] and not item["found"]]
    if not installed:
        reasons.insert(0, "The web-sec lab folder is missing from this checkout.")
    notes = [
        "Every network call is checked against the declared scope before it happens.",
        "The lab needs no VM, Docker, Node or third-party Python packages.",
    ]
    if scope_ok:
        notes.append(f"Scope “{scope.get('name') or 'unnamed'}” covers "
                     f"{scope.get('hosts', 0)} host rule(s) and expires {scope.get('expires') or 'never'}.")
    return {
        "id": "websec", "label": "Web Sec Lab",
        "summary": "Scope-guarded web posture assessment: DNS, TLS, headers, exposure and reports.",
        "provider": "native-python" if runnable else None, "state": state,
        "requirements": requirements, "reasons": reasons[:4], "notes": notes,
        "installed": installed, "version": report.get("version", ""),
        "capabilities": [{"id": "scan", "label": "Scan a target", "detail": "JSON, SARIF, Markdown or HTML report"}]
        if runnable else [],
        "actions": [{"id": action, "label": action.capitalize(), "privileged": False,
                     "description": description} for action, description in (
                        ("status", "Read readiness without touching the network."),
                        ("doctor", "Check Python, storage, scope and plugins."),
                        ("setup", "Create private storage directories; no downloads."))]
        if runnable else [],
    }


def build_plan(root: str, request: dict) -> dict:
    import oslab
    if not isinstance(request, dict) or set(request) - {"lab", "action", "options"}:
        raise oslab.PlanError("Invalid Web Sec Lab request")
    if request.get("lab") != "websec":
        raise oslab.PlanError("Invalid Web Sec Lab request")
    action = request.get("action")
    if action not in ("status", "doctor", "setup"):
        raise oslab.PlanError("Unsupported Web Sec Lab action")
    if request.get("options"):
        raise oslab.PlanError("Web Sec Lab actions take no options")
    args = [str(Path(root) / "web-sec/run.py"), action]
    effects = ["Reads readiness without changing state." if action != "setup"
               else "Creates private storage directories; downloads nothing."]
    return {
        "lab": "websec", "action": action, "provider": "native-python", "workspace": root,
        "program": python(), "args": args, "effects": effects, "timeoutSec": 30,
        "privileged": False, "runnable": True, "manualCommand": None, "setup": None,
        "display": " ".join(oslab._quote(part) for part in [python(), *args]),
    }


def plan(root: str, request: dict) -> dict:
    return build_plan(root, request)
