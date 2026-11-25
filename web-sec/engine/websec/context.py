"""A scan context: the target, its budgets, and the transports the checks use.

Checks never open sockets themselves; they call ``ctx.dns``, ``ctx.http``,
``ctx.tls``, ``ctx.whois`` or ``ctx.ports``. That is what makes an offline test
possible: a fixture provides the same attributes and records what was asked.
"""
from __future__ import annotations

import html as html_module
import time
from typing import Dict, List, Optional

from .config import Options
from .net.dns import Resolver
from .net.http import HttpClient, Response
from .net.ports import connect_test
from .net.tls import probe, probe_versions
from .net.whois import query as whois_query
from .scope import Guard, ScopeRefused


INFRA_HOSTS = frozenset({"crt.sh", "web.archive.org", "services.nvd.nist.gov"})


class _InfraGuard:
    """Allow only the three read-only public registries the checks consult.

    The assessed asset is still guarded by the real scope. This adapter exists so
    a certificate-transparency or archive query is a deliberate, listed request
    rather than a silent hole in the guard.
    """

    def require(self, kind: str, target: str):
        host = (target or "").lower()
        if host in INFRA_HOSTS:
            return {"allowed": True, "target": host, "rule": "public registry", "reason": ""}
        raise ScopeRefused(host, f"{host} is not one of the allowlisted public registries")


class Context:
    """Everything one scan shares, including the HTTP response cache."""

    def __init__(self, options: Options, guard, dns=None, http=None, tls=None,
                 whois=None, ports=None, clock=None, tls_versions=None):
        self.options = options
        self.target = options.target
        self.url = options.url
        self.guard = guard
        self.dns = dns if dns is not None else Resolver(timeout=min(3.0, options.timeout))
        self.dns_fast = dns if dns is not None else Resolver(timeout=1.0, attempts=1)
        self.http = http if http is not None else HttpClient(
            guard, timeout=options.timeout, max_bytes=options.max_bytes,
            user_agent=options.user_agent)
        self._tls = tls
        self._tls_versions = tls_versions
        self._whois = whois
        self._ports = ports
        self._cache: Dict[str, Response] = {}
        self._infra = None
        self.findings_by_module: Dict[str, List[object]] = {}
        self._clock = clock or time.monotonic
        self.deadline = self._clock() + options.deadline
        self.pages_fetched = 0

    # ── transports ───────────────────────────────────────────────────────────

    def tls(self, host: Optional[str] = None, port: int = 0):
        target_port = port or self.options.port or 443
        if self._tls is not None:
            return self._tls(host or self.target, target_port)
        return probe(host or self.target, target_port, guard=self.guard, timeout=self.options.timeout)

    def whois(self, host: Optional[str] = None):
        if self._whois is not None:
            return self._whois(host or self.target)
        return whois_query(host or self.target, guard=self.guard, timeout=self.options.timeout)

    def tls_versions(self, host: Optional[str] = None):
        if self._tls_versions is not None:
            return self._tls_versions(host or self.target)
        return probe_versions(host or self.target, self.options.port or 443, guard=self.guard,
                              timeout=min(4.0, self.options.timeout))

    def port(self, port: int, host: Optional[str] = None):
        if self._ports is not None:
            return self._ports(host or self.target, port)
        return connect_test(host or self.target, port, self.guard, timeout=min(2.0, self.options.timeout))

    # ── HTTP helpers ─────────────────────────────────────────────────────────

    def page(self, path: str = "/", scheme: Optional[str] = None) -> Response:
        """Fetch a path on the target, cached by URL."""
        if path.startswith(("http://", "https://")):
            url = path
        else:
            base = self.url if scheme is None else f"{scheme}://{self.target}"
            url = base.rstrip("/") + "/" + path.lstrip("/")
        if url in self._cache:
            return self._cache[url]
        response = self.http.get(url)
        self._cache[url] = response
        self.pages_fetched += 1
        return response

    def html(self) -> str:
        response = self.page("/")
        return response.text if not response.error else ""

    def infra(self, url: str, method: str = "GET") -> Response:
        """A request to an allowlisted public registry (crt.sh, Wayback, NVD)."""
        if self._infra is None:
            self._infra = HttpClient(_InfraGuard(), timeout=max(self.options.timeout, 15.0),
                                     max_bytes=min(2 * 1024 * 1024, self.options.max_bytes * 4),
                                     user_agent=self.options.user_agent, pacing=1.0)
        return self._infra.request(url, method)

    def absolute(self, link: str) -> str:
        from urllib.parse import urljoin
        return urljoin(self.url + "/", link)

    # ── budgets ──────────────────────────────────────────────────────────────

    def expired(self) -> bool:
        return self._clock() >= self.deadline

    def remaining(self) -> float:
        return max(0.0, self.deadline - self._clock())

    def require(self, host: str) -> None:
        self.guard.require("host", host)

    def clean(self, text: str, limit: int = 8192) -> str:
        """Plain text from HTML, bounded — for evidence fields."""
        stripped = html_module.unescape(html_module.unescape(text or ""))
        return " ".join(stripped.split())[:limit]


def build_live(options: Options, guard=None) -> Context:
    guard = guard or Guard(options.scope_path)
    guard.require("host", options.target)
    return Context(options, guard)


__all__ = ["Context", "build_live", "ScopeRefused"]
