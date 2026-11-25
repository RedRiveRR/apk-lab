"""Web Sec Lab engine.

A scope-guarded, standard-library-only web posture assessment engine. It ports
the assessment capability of ``frkndncr/WebAnalyzer`` (module registry, plugin
discovery, JSON/SARIF/Markdown reports) and the inspection views of
``keyvanarasteh/WebQ`` into os-lab's own contracts.

Every network call goes through :mod:`websec.net`, which asks the repository
scope guard first (``console/scope_guard.py``). Nothing here exploits a target:
the engine profiles what a site exposes and reports how to fix it.
"""
from __future__ import annotations

__all__ = ["__version__"]

from .version import VERSION as __version__
