"""Offline fixtures: every transport is a small fake, so no test opens a socket."""
from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional

import pytest

ENGINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ENGINE not in sys.path:
    sys.path.insert(0, ENGINE)

from websec.config import Options                      # noqa: E402
from websec.context import Context                     # noqa: E402
from websec.net.http import Response                   # noqa: E402
from websec.scope import AllowAll                      # noqa: E402
from websec.catalog import ensure_loaded               # noqa: E402

ensure_loaded()

ZONE = "example.test"


def page(body: str = "", status: int = 200, headers: Optional[Dict[str, str]] = None,
         cookies: Optional[List[str]] = None, url: str = f"https://{ZONE}/") -> Response:
    return Response(url=url, status=status, headers=headers or {}, cookies=cookies or [],
                    body=body.encode("utf-8"))


class FakeDns:
    def __init__(self, records: Optional[Dict[object, object]] = None,
                 addresses: Optional[List[str]] = None,
                 chains: Optional[Dict[str, List[str]]] = None,
                 reverse_map: Optional[Dict[str, str]] = None,
                 axfr: Optional[Dict[str, Dict[str, object]]] = None,
                 zone: str = ZONE):
        self.records = records or {}
        self.addresses = addresses if addresses is not None else ["203.0.113.10"]
        self.chains = chains or {}
        self.reverse_map = reverse_map or {}
        self.axfr_results = axfr or {}
        self.zone = zone

    def values(self, name: str, rtype: str):
        key = (name, rtype)
        if key in self.records:
            return list(self.records[key])
        if name.rstrip(".") == self.zone:
            return list(self.records.get(rtype, []))
        return []

    def resolve(self, name: str):
        if name in getattr(self, "addresses_by_name", {}):
            return list(self.addresses_by_name[name])
        return list(self.addresses) if name.rstrip(".") == self.zone else []

    def reverse(self, address: str) -> str:
        return self.reverse_map.get(address, "")

    def cname_chain(self, name: str):
        return list(self.chains.get(name, []))

    def axfr(self, server: str, zone: str, timeout: float = 6.0):
        return self.axfr_results.get(server, {"server": server, "rcode": 5, "records": 0,
                                              "error": "refused"})


class FakeHttp:
    def __init__(self, pages: Optional[Dict[str, Response]] = None):
        self.pages = pages or {}
        self.requests: List[tuple] = []

    def _match(self, key: str):
        if key in self.pages:
            return self.pages[key]
        for pattern, response in self.pages.items():
            if key.endswith(pattern):
                return response
        return Response(url=key.split(" ", 1)[-1], status=404, body=b"")

    def get(self, url: str, **kwargs) -> Response:
        self.requests.append(("GET", url))
        return self._match(url)

    def head(self, url: str, **kwargs) -> Response:
        self.requests.append(("HEAD", url))
        return self._match(url)

    def request(self, url: str, method: str = "GET", headers=None, body=None, **kwargs) -> Response:
        self.requests.append((method.upper(), url))
        return self._match(f"{method.upper()} {url}")


class FakeTls:
    def __init__(self, **values):
        self.host = values.get("host", ZONE)
        self.port = values.get("port", 443)
        self.protocol = values.get("protocol", "TLSv1.3")
        self.cipher = values.get("cipher", "TLS_AES_128_GCM_SHA256")
        self.bits = values.get("bits", 128)
        self.not_before = values.get("not_before", "")
        self.not_after = values.get("not_after", "")
        self.days_left = values.get("days_left", 120)
        self.sans = values.get("sans", [ZONE, f"www.{ZONE}"])
        self.issuer = values.get("issuer", "CN=Test CA, O=Lab")
        self.subject = values.get("subject", f"CN={ZONE}")
        self.serial = values.get("serial", "01")
        self.fingerprint = values.get("fingerprint", "ab" * 32)
        self.verified = values.get("verified", None)
        self.error = values.get("error", "")

    def as_dict(self):
        return {"host": self.host, "port": self.port, "protocol": self.protocol,
                "cipher": self.cipher, "bits": self.bits, "not_before": self.not_before,
                "not_after": self.not_after, "days_left": self.days_left, "sans": self.sans,
                "issuer": self.issuer, "subject": self.subject, "serial": self.serial,
                "fingerprint_sha256": self.fingerprint, "verified": self.verified,
                "error": self.error}


class FakeWhois:
    def __init__(self, fields: Optional[Dict[str, List[str]]] = None, error: str = ""):
        self.host = ZONE
        self.server = "whois.example.test"
        self.fields = fields or {}
        self.error = error
        self.raw = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.fields)

    def first(self, key: str) -> str:
        values = self.fields.get(key.lower()) or []
        return values[0] if values else ""

    def all(self, key: str) -> List[str]:
        return list(self.fields.get(key.lower()) or [])

    def as_dict(self):
        return {"host": self.host, "server": self.server, "fields": self.fields,
                "error": self.error, "bytes": 0}


class FakePort:
    def __init__(self, port: int, open: bool = False, banner: str = ""):
        self.port = port
        self.open = open
        self.banner = banner
        self.elapsed_ms = 1
        self.error = ""


def make_context(options: Optional[Options] = None, dns: Optional[FakeDns] = None,
                 http: Optional[FakeHttp] = None, tls: Optional[FakeTls] = None,
                 whois: Optional[FakeWhois] = None,
                 open_ports: Optional[Dict[int, str]] = None,
                 versions: Optional[List[Dict[str, object]]] = None) -> Context:
    options = options or Options.build(ZONE, preset="full", timeout=2.0, deadline=30.0)
    tls = tls or FakeTls()
    whois = whois or FakeWhois()
    ports = open_ports or {}
    return Context(
        options, AllowAll(), dns=dns or FakeDns(),
        http=http or FakeHttp(),
        tls=lambda host, port=443: tls,
        whois=lambda host=None: whois,
        ports=lambda host, port: FakePort(port, port in ports, ports.get(port, "")),
        tls_versions=lambda host: versions or [
            {"version": "TLSv1_2", "supported": True}, {"version": "TLSv1_3", "supported": True}],
    )


@pytest.fixture
def context() -> Context:
    return make_context()
