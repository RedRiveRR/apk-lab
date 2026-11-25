"""Desktop notifications for monitor events (the Cleanup Lab CUX-07 recipe).

Fixed argv with the text passed as arguments, never spliced into a script, so a
host name or a finding title cannot inject anything. Delivery is best effort and
reports what happened: ``sent``, ``skipped`` with a reason, or ``failed``.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

NOTIFIABLE = ("warning", "critical", "escalated", "reminder", "scope-expiring", "scope-expired", "error")
TIMEOUT = 5
_MAC_SCRIPT = ["-e", "on run argv", "-e", "display notification (item 1 of argv) with title (item 2 of argv)",
               "-e", "end run"]


def describe(event: Dict[str, object]) -> Optional[Tuple[str, str]]:
    """(title, message) for one monitor event, or None when it is not notifiable."""
    kind = str(event.get("kind") or "")
    if kind not in NOTIFIABLE:
        return None
    target = str(event.get("target") or "the scope")
    message = str(event.get("message") or "")[:300]
    title = {
        "warning": f"Web Sec Lab: {target} got worse",
        "critical": f"Web Sec Lab: {target} needs attention now",
        "escalated": f"Web Sec Lab: {target} got worse again",
        "reminder": f"Web Sec Lab: {target} is still unresolved",
        "scope-expiring": "Web Sec Lab: the scope expires soon",
        "scope-expired": "Web Sec Lab: the scope has expired",
        "error": f"Web Sec Lab: could not scan {target}",
    }[kind]
    return title, f"{message} Open the Web Sec Lab workbench to review."


def command(title: str, message: str, platform: Optional[str] = None, which=shutil.which) -> Optional[List[str]]:
    platform = platform or sys.platform
    if platform == "darwin":
        return ["osascript", *_MAC_SCRIPT, message, title]
    if platform.startswith("linux") and which("notify-send"):
        return ["notify-send", "--app-name=os-lab", "--", title, message]
    return None


def send(event: Dict[str, object], *, platform: Optional[str] = None, run=subprocess.run,
         which=shutil.which) -> Dict[str, str]:
    described = describe(event)
    if described is None:
        return {"status": "skipped", "reason": "not a notifiable event"}
    argv = command(*described, platform=platform, which=which)
    if argv is None:
        return {"status": "skipped", "reason": "no notifier on this system"}
    try:
        result = run(argv, capture_output=True, timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "failed", "reason": str(exc)}
    if result.returncode != 0:
        return {"status": "failed", "reason": f"the notifier exited with {result.returncode}"}
    return {"status": "sent", "reason": ""}


def send_all(events: List[Dict[str, object]], *, enabled: bool = True, **kwargs) -> List[Dict[str, str]]:
    if not enabled:
        return []
    return [send(event, **kwargs) for event in events if event.get("kind") in NOTIFIABLE]


__all__ = ["NOTIFIABLE", "command", "describe", "send", "send_all"]
