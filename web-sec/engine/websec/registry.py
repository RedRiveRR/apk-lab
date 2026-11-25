"""The module registry and plugin discovery.

Ported from ``frkndncr/WebAnalyzer`` (``modules/registry.py``): one place knows
which checks exist, so the CLI, the console API and the dashboard catalogue all
agree. A check is a plain function of a :class:`websec.context.Context` that
returns JSON-serialisable data, optionally with findings.

    from websec.registry import module

    @module("security_txt", label="Security.txt", description="RFC 9116 contact file",
            group="posture", weight="light")
    def security_txt(ctx):
        ...

Set ``active=True`` for a check that sends intrusive traffic. Active checks only
run when the operator passes ``--active`` and the scope guard allows the target.
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

GROUPS = ("recon", "security", "posture", "inventory")
WEIGHTS = ("light", "medium", "heavy")
_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")

#: Presets mirror the upstream scanner's names: cheap, everyday, exhaustive.
PRESETS: Dict[str, Tuple[str, ...]] = {
    "quick": ("domain_info", "dns_records", "geo_analysis"),
    "standard": (
        "domain_info", "dns_records", "geo_analysis", "seo_analysis",
        "web_technologies", "security_analysis", "ssl_san", "security_txt",
        "dns_health", "tls_health", "cookies_cors", "email_security",
        "http_methods", "privacy_trackers", "js_library_vulns", "asset_inventory",
    ),
}


@dataclass(frozen=True)
class ModuleSpec:
    id: str
    label: str
    run: Callable[..., Any]
    description: str = ""
    group: str = "recon"
    weight: str = "light"
    active: bool = False          # sends intrusive traffic; needs --active
    needs_results: bool = False   # run(ctx, results)
    order: int = 100
    upstream: str = ""            # the WebAnalyzer/WebQ module this ports

    def catalogue(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "group": self.group,
            "weight": self.weight,
            "active": self.active,
            "upstream": self.upstream,
        }


_REGISTRY: Dict[str, ModuleSpec] = {}
PLUGIN_ERRORS: List[Tuple[str, str]] = []
PLUGIN_IDS: set = set()


def register(spec: ModuleSpec, replace: bool = False) -> ModuleSpec:
    if not _ID_RE.match(spec.id or ""):
        raise ValueError(f"invalid module id: {spec.id!r}")
    if not spec.label.strip():
        raise ValueError(f"{spec.id}: a label is required")
    if spec.group not in GROUPS:
        raise ValueError(f"{spec.id}: group must be one of {GROUPS}, got {spec.group!r}")
    if spec.weight not in WEIGHTS:
        raise ValueError(f"{spec.id}: weight must be one of {WEIGHTS}, got {spec.weight!r}")
    if not callable(spec.run):
        raise ValueError(f"{spec.id}: run must be callable")
    if spec.id in _REGISTRY and not replace:
        raise ValueError(f"module already registered: {spec.id}")
    _REGISTRY[spec.id] = spec
    return spec


def module(module_id: str, label: str, **options: Any) -> Callable[[Callable], Callable]:
    """Decorator form of :func:`register`; returns the function unchanged."""
    def decorator(fn: Callable) -> Callable:
        register(ModuleSpec(id=module_id, label=label, run=fn, **options))
        return fn
    return decorator


def unregister(module_id: str) -> None:
    _REGISTRY.pop(module_id, None)


def clear() -> None:
    """Drop every registration (tests only; the CLI never calls this)."""
    _REGISTRY.clear()
    PLUGIN_ERRORS.clear()
    PLUGIN_IDS.clear()


def all_modules() -> List[ModuleSpec]:
    return sorted(_REGISTRY.values(), key=lambda item: (item.order, item.id))


def get(module_id: str) -> Optional[ModuleSpec]:
    return _REGISTRY.get(module_id)


def ids() -> Tuple[str, ...]:
    return tuple(spec.id for spec in all_modules())


def catalogue() -> List[Dict[str, Any]]:
    return [spec.catalogue() for spec in all_modules()]


def select(names: Optional[Iterable[str]] = None,
           preset: str = "standard") -> List[ModuleSpec]:
    """Modules for a scan: an explicit list, or a named preset, or everything."""
    chosen = list(names or ())
    if chosen:
        unknown = [name for name in chosen if name not in _REGISTRY]
        if unknown:
            raise ValueError(f"unknown module(s): {', '.join(sorted(unknown))}")
        return [_REGISTRY[name] for name in chosen if name in _REGISTRY]
    if preset == "full":
        return all_modules()
    if preset not in PRESETS:
        raise ValueError(f"unknown preset: {preset!r} (quick, standard, full)")
    return [_REGISTRY[name] for name in PRESETS[preset] if name in _REGISTRY]


# ── plugin discovery ─────────────────────────────────────────────────────────

def plugin_dirs() -> List[str]:
    here = os.path.dirname(os.path.abspath(__file__))
    dirs = [os.path.join(here, "plugins")]
    for extra in (os.environ.get("WEBSEC_PLUGIN_DIRS") or "").split(os.pathsep):
        if extra.strip():
            dirs.append(extra.strip())
    return [directory for directory in dirs if os.path.isdir(directory)]


def discover_plugins(directories: Optional[Sequence[str]] = None) -> List[Tuple[str, Optional[str]]]:
    """Import every ``*.py`` in the plugin folders. Returns ``(name, error)`` pairs.

    A plugin that fails to import is recorded, never fatal: the rest of the lab
    keeps working and ``websec plugins`` shows the reason.
    """
    loaded: List[Tuple[str, Optional[str]]] = []
    for directory in directories if directories is not None else plugin_dirs():
        if not os.path.isdir(directory):
            continue
        for entry in sorted(os.listdir(directory)):
            if not entry.endswith(".py") or entry.startswith("_"):
                continue
            path = os.path.join(directory, entry)
            stem = entry[:-3]
            bundled = os.path.abspath(directory) == os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "plugins")
            name = f"{__package__}.plugins.{stem}" if bundled else f"websec_plugin_{stem}"
            if name in sys.modules:
                loaded.append((name, None))
                continue
            try:
                spec = importlib.util.spec_from_file_location(name, path)
                if spec is None or spec.loader is None:
                    raise ImportError("no loader")
                module_object = importlib.util.module_from_spec(spec)
                sys.modules[name] = module_object
                before = set(_REGISTRY)
                spec.loader.exec_module(module_object)
                PLUGIN_IDS.update(set(_REGISTRY) - before)
                loaded.append((name, None))
            except Exception as exc:  # a broken plugin must not stop the lab
                sys.modules.pop(name, None)
                PLUGIN_ERRORS.append((entry, f"{type(exc).__name__}: {exc}"))
                loaded.append((entry, str(PLUGIN_ERRORS[-1][1])))
    return loaded


def plugin_report() -> Dict[str, Any]:
    return {
        "directories": plugin_dirs(),
        "errors": [{"plugin": name, "error": error} for name, error in PLUGIN_ERRORS],
        "loaded": sorted(PLUGIN_IDS & set(_REGISTRY)),
    }
