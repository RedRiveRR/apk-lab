#!/usr/bin/env python3
"""Launcher for the Web Sec Lab engine (called by ``./labctl websec``).

    python3 web-sec/run.py status
    python3 web-sec/run.py scan example.test --preset quick

Standard library only; ``engine/`` is added to ``sys.path`` here so the package
never shadows another lab's modules.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(ROOT, "engine")
if ENGINE not in sys.path:
    sys.path.insert(0, ENGINE)

from websec.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
