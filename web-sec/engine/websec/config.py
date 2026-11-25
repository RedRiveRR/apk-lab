"""Typed scan options: every cap the engine honours lives here.

The console and the CLI build these through :meth:`Options.build`, so an
out-of-range number is refused once, with a message, instead of quietly making a
scan heavier than the operator asked for.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple
from urllib.parse import urlsplit

USER_AGENT = "os-lab-websec/0.1 (authorized web assessment; +https://github.com/qline-tech/os-lab)"
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_DNS_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")

DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                 3306, 5432, 6379, 8080, 8443, 9200, 27017)


def _idna(text: str) -> str:
    if text.isascii():
        return text
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"the host cannot be written in punycode ({exc})") from None


def normalize_target(raw: str) -> str:
    """A bare, lower-cased host. Delegates to the repository scope guard when present.

    Accepts ``https://Example.COM/path``, ``example.com:8443`` and IP literals;
    returns just the host. Refuses anything the guard would also refuse, plus
    wildcards, so an operator cannot scan a whole zone with one word.
    """
    text = str(raw or "").strip()
    if not text:
        raise ValueError("a target is required")
    if "://" not in text and "/" not in text:
        candidate = text[1:-1] if text.startswith("[") and text.endswith("]") else text
        try:
            return str(ipaddress.ip_address(candidate)).lower()
        except ValueError:
            pass
    if "://" not in text:
        text = "//" + text
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(text)
        host = parts.hostname or ""
    except ValueError as exc:
        raise ValueError(f"the target cannot be parsed ({exc})") from None
    if not host:
        raise ValueError("no host was found in the target")
    if parts.fragment:
        raise ValueError("a fragment is not part of a target; name one host")
    if parts.username or parts.password:
        raise ValueError("a target carries no user information; name one host")
    host = _idna(host.rstrip("."))
    try:
        return str(ipaddress.ip_address(host)).lower()
    except ValueError:
        pass
    if len(host) > 253 or not all(_LABEL.match(label) for label in host.split(".")):
        raise ValueError("the target is not a valid address or host name")
    return host


def parse_target(raw: str):
    """The bare host and an optional explicit port (``example.test:8443``)."""
    host = normalize_target(raw)
    text = str(raw or "").strip()
    port = None
    if "://" in text:
        try:
            port = urlsplit(text).port
        except ValueError as exc:
            raise ValueError(f"the port is not valid ({exc})") from None
    else:
        authority = text.split("/", 1)[0]
        if authority.startswith("[") and "]:" in authority:
            candidate = authority.rsplit(":", 1)[1]
            port = int(candidate) if candidate.isdigit() else None
        elif authority.count(":") == 1:
            candidate = authority.rsplit(":", 1)[1]
            port = int(candidate) if candidate.isdigit() else None
    if port is not None and not 0 < port < 65536:
        raise ValueError("the port must be between 1 and 65535")
    return host, port


def normalize_scheme(raw: Optional[str]) -> str:
    value = (raw or "https").strip().lower()
    if value not in ("http", "https"):
        raise ValueError(f"scheme must be http or https, not {raw!r}")
    return value


def _number(name: str, value, low: float, high: float, cast=float):
    try:
        number = cast(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number") from None
    if not low <= number <= high:
        raise ValueError(f"{name} must be between {low:g} and {high:g}")
    return number


@dataclass
class Options:
    """Everything one scan needs. Construct through :meth:`build`."""

    target: str
    scheme: str = "https"
    port: Optional[int] = None
    preset: str = "standard"
    modules: Tuple[str, ...] = ()
    active: bool = False
    timeout: float = 6.0
    deadline: float = 60.0
    max_pages: int = 25
    max_bytes: int = 512 * 1024
    cve_lookup: bool = False
    scope_path: Optional[str] = None
    keep_history: bool = True
    user_agent: str = USER_AGENT
    ports: Tuple[int, ...] = DEFAULT_PORTS

    @property
    def url(self) -> str:
        host = f"[{self.target}]" if ":" in self.target else self.target
        authority = f"{host}:{self.port}" if self.port else host
        return f"{self.scheme}://{authority}"

    @classmethod
    def build(cls, target: str, **values) -> "Options":
        host, port = parse_target(target)
        modules = values.pop("modules", ()) or ()
        if isinstance(modules, str):
            modules = tuple(part.strip() for part in modules.split(",") if part.strip())
        options = cls(
            target=host,
            scheme=normalize_scheme(values.pop("scheme", None)),
            port=port,
            preset=str(values.pop("preset", "standard") or "standard"),
            modules=tuple(modules),
            active=bool(values.pop("active", False)),
            timeout=_number("timeout", values.pop("timeout", 6.0), 1, 30),
            deadline=_number("deadline", values.pop("deadline", 60.0), 10, 600),
            max_pages=_number("max_pages", values.pop("max_pages", 25), 1, 100, int),
            max_bytes=_number("max_bytes", values.pop("max_bytes", 512 * 1024), 4096, 2 * 1024 * 1024, int),
            cve_lookup=bool(values.pop("cve_lookup", False)),
            scope_path=values.pop("scope_path", None) or None,
            keep_history=bool(values.pop("keep_history", True)),
            user_agent=str(values.pop("user_agent", USER_AGENT)),
            ports=tuple(int(port) for port in values.pop("ports", DEFAULT_PORTS)),
        )
        if options.preset not in ("quick", "standard", "full"):
            raise ValueError("preset must be quick, standard or full")
        if values:
            raise ValueError(f"unknown option(s): {', '.join(sorted(values))}")
        return options


def default_storage() -> str:
    """``web-sec/storage`` unless ``WEBSEC_STORAGE`` points elsewhere."""
    configured = os.environ.get("WEBSEC_STORAGE")
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "storage")


def ensure_storage(path: Optional[str] = None) -> str:
    """Create the private storage tree (0700) and return its root."""
    root = path or default_storage()
    for child in ("", "history", "reports", "scans"):
        directory = os.path.join(root, child) if child else root
        os.makedirs(directory, mode=0o700, exist_ok=True)
    return root
