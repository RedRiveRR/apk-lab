"""Transport primitives. Every entry point asks the scope guard first."""
from __future__ import annotations

from .dns import DnsError, Resolver
from .http import HttpClient, Response
from .ports import PortResult, connect_test
from .tls import TlsInfo, probe, probe_versions
from .whois import WhoisResult, query as whois_query

__all__ = [
    "DnsError", "Resolver", "HttpClient", "Response", "PortResult", "connect_test",
    "TlsInfo", "probe", "probe_versions", "WhoisResult", "whois_query",
]
