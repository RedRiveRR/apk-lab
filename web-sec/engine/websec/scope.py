"""The scope adapter: refuse a target before any socket is opened.

The lab does not re-implement the project's authorization rule. It loads
``console/scope_guard.py`` from the checkout and asks it about every host it is
about to touch, including each redirect hop and every DNS name it resolves.

Tests inject :class:`AllowAll`, which exists only so offline fixtures can run
without a manifest. Nothing in the CLI, the console or the engine can turn the
real guard off.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from typing import Any, Dict, Optional

GUARD_NAME = "oslab_scope_guard"
MAX_WALK = 8


class ScopeRefused(PermissionError):
    """A target the declared lab scope does not cover."""

    def __init__(self, target: str, reason: str):
        super().__init__(reason)
        self.target = target
        self.reason = reason


def find_guard(root: Optional[str] = None) -> str:
    """Path of ``console/scope_guard.py`` at or above ``root`` (default: this file)."""
    start = os.path.abspath(root or os.path.dirname(__file__))
    directory = start
    for _ in range(MAX_WALK):
        candidate = os.path.join(directory, "console", "scope_guard.py")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent
    raise ScopeRefused("", "console/scope_guard.py was not found; the scope cannot be checked")


def load_guard_module():
    """Import the guard once, under a private module name."""
    if GUARD_NAME in sys.modules:
        return sys.modules[GUARD_NAME]
    path = find_guard()
    spec = importlib.util.spec_from_file_location(GUARD_NAME, path)
    if spec is None or spec.loader is None:
        raise ScopeRefused("", f"the scope guard at {path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[GUARD_NAME] = module
    spec.loader.exec_module(module)
    return module


class Guard:
    """A thin, typed facade over the repository scope guard."""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self._scope = None

    def _module(self):
        return load_guard_module()

    def _manifest(self):
        if self._scope is None:
            module = self._module()
            self._scope = module.load_scope(self.path) if self.path else module.load_scope()
        return self._scope

    def require(self, kind: str, target: str):
        module = self._module()
        try:
            return module.assert_in_scope(kind, target, self._manifest())
        except PermissionError as exc:
            raise ScopeRefused(str(target), str(exc)) from None

    def check(self, kind: str, target: str):
        module = self._module()
        try:
            decision = module.check(kind, target, self._manifest())
        except Exception as exc:
            if isinstance(exc, ValueError):
                return {"allowed": False, "reason": str(exc), "target": str(target), "rule": ""}
            raise
        allowed = getattr(decision, "allowed", None)
        if allowed is None and isinstance(decision, dict):
            allowed = decision.get("allowed")
        return {"allowed": bool(allowed), "reason": getattr(decision, "reason", ""),
                "target": getattr(decision, "target", str(target)),
                "rule": getattr(decision, "rule", "")}

    def status(self) -> Dict[str, Any]:
        """The declared scope summary, or a refusal reason — never a crash."""
        try:
            module = self._module()
            if self.path:
                return dict(module.scope_status(path=self.path))
            return dict(module.scope_status())
        except Exception as exc:
            return {"declared": False, "valid": False, "reason": str(exc), "name": "",
                    "expires": None, "hosts": 0, "paths": 0, "packages": 0, "devices": 0}


class AllowAll:
    """Offline-test stand-in. Never used by the CLI or the console."""

    def require(self, kind: str, target: str):
        return {"allowed": True, "target": target, "rule": "test", "reason": "offline fixture"}

    def check(self, kind: str, target: str):
        return self.require(kind, target)

    def status(self) -> Dict[str, Any]:
        return {"declared": True, "valid": True, "name": "test"}


def describe() -> Dict[str, Any]:
    """Doctor output: is a guard present, and does a manifest exist?"""
    try:
        path = find_guard()
    except ScopeRefused as exc:
        return {"guard": None, "error": exc.reason}
    return {"guard": path, "manifest": os.environ.get("OSLAB_SCOPE_FILE") or "scope.json"}
