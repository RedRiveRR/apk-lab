"""WHOIS over TCP/43: IANA referral first, then the registry that answers."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..scope import ScopeRefused

IANA_SERVER = "whois.iana.org"
MAX_BYTES = 64 * 1024
_FOLDERS = ("status", "remarks", "notify", "changed", "nserver", "domain", "person")


@dataclass
class WhoisResult:
    host: str
    server: str = ""
    raw: str = ""
    fields: Dict[str, List[str]] = field(default_factory=dict)
    error: str = ""

    def first(self, key: str) -> str:
        values = self.fields.get(key.lower()) or []
        return values[0] if values else ""

    def all(self, key: str) -> List[str]:
        return list(self.fields.get(key.lower()) or [])

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.fields)

    def as_dict(self) -> Dict[str, object]:
        keep = ("domain name", "domain", "registrar", "registrar url", "creation date",
                "created", "updated date", "last updated", "registry expiry date",
                "expiry date", "expiration date", "registrant organization",
                "registrant country", "name server", "nserver", "dnssec", "status")
        summary = {}
        for key in keep:
            values = self.fields.get(key)
            if values:
                summary[key] = values[:8]
        return {"host": self.host, "server": self.server, "fields": summary,
                "error": self.error, "bytes": len(self.raw)}


def parse(text: str) -> Dict[str, List[str]]:
    """Parse ``key: value`` lines, keeping repeated keys and folding continuations."""
    fields: Dict[str, List[str]] = {}
    last_key = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("%", "#", ">>>")):
            continue
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = " ".join(key.strip().lower().split())
            value = value.strip()
            if not key or len(key) > 80:
                continue
            if value:
                fields.setdefault(key, []).append(value[:1000])
                last_key = key
            else:
                last_key = ""
        elif last_key and stripped and not stripped.startswith("-"):
            values = fields.get(last_key) or []
            if values and len(values[-1]) < 1000:
                values[-1] = f"{values[-1]} {stripped}"[:1000]
    return fields


def _ask(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii", "replace"))
        chunks = []
        total = 0
        while total < MAX_BYTES:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks)[:MAX_BYTES].decode("utf-8", "replace")


def query(host: str, guard=None, timeout: float = 6.0) -> WhoisResult:
    """Ask IANA, then the referred registry. The assessed host is scope-checked once."""
    result = WhoisResult(host=host)
    if guard is not None:
        try:
            guard.require("host", host)
        except ScopeRefused as exc:
            result.error = f"scope refused: {exc.reason}"
            return result
    try:
        first = parse(_ask(IANA_SERVER, host, timeout))
    except OSError as exc:
        result.error = f"WHOIS lookup failed: {exc}"
        return result
    referral = (first.get("refer") or first.get("whois") or [""])[0].lower()
    text = ""
    server = ""
    if referral and referral != IANA_SERVER and " " not in referral:
        server = referral
        try:
            text = _ask(referral, host, timeout)
        except OSError as exc:
            result.error = f"referral {referral} failed: {exc}"
            text = ""
    if not text:
        text = "\n".join(f"{key}: {value}" for key, values in first.items() for value in values)
    result.server = server or IANA_SERVER
    result.raw = text[:MAX_BYTES]
    result.fields = parse(text)
    if not result.fields and not result.error:
        result.error = "the registry returned no fields"
    return result
