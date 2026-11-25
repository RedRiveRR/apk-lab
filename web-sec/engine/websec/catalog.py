"""Load the built-in checks once, then any plugin folders."""
from __future__ import annotations

import threading
from typing import List, Tuple

_LOADED = False
_LOCK = threading.Lock()


def ensure_loaded() -> List[Tuple[str, object]]:
    """Import the built-in checks and discover plugins. Safe to call repeatedly."""
    global _LOADED
    with _LOCK:
        if _LOADED:
            return []
        from . import checks  # noqa: F401  (importing registers the built-ins)
        _LOADED = True
        from .registry import discover_plugins
        return discover_plugins()


def reset() -> None:
    """Tests only: forget that the catalogue was loaded."""
    global _LOADED
    _LOADED = False
