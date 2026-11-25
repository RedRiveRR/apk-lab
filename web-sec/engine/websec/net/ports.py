"""TCP connect checks with a short banner read. Active, scope-guarded."""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Optional

from ..scope import ScopeRefused

BANNER_PORTS = frozenset({21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 8080, 9200})
MAX_BANNER = 256


@dataclass
class PortResult:
    port: int
    open: bool = False
    banner: str = ""
    elapsed_ms: int = 0
    error: str = ""


def connect_test(host: str, port: int, guard, timeout: float = 2.0,
                 banner: bool = True) -> PortResult:
    started = time.monotonic()
    try:
        guard.require("host", host)
    except ScopeRefused as exc:
        return PortResult(port=port, error=f"scope refused: {exc.reason}")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            elapsed = int((time.monotonic() - started) * 1000)
            text = ""
            if banner and port in BANNER_PORTS:
                sock.settimeout(min(1.0, timeout))
                try:
                    raw = sock.recv(MAX_BANNER)
                    text = raw.decode("utf-8", "replace").strip()
                except (socket.timeout, OSError):
                    text = ""
            return PortResult(port=port, open=True, banner=" ".join(text.split())[:MAX_BANNER],
                              elapsed_ms=elapsed)
    except (socket.timeout, OSError) as exc:
        return PortResult(port=port, elapsed_ms=int((time.monotonic() - started) * 1000),
                          error=str(exc))
