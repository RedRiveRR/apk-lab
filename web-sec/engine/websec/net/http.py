"""Bounded HTTP client with manual redirects, so every hop is scope-checked."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Optional

from ..config import USER_AGENT
from ..scope import ScopeRefused


@dataclass
class Response:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    body: bytes = b""
    elapsed_ms: int = 0
    error: str = ""
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400 and not self.error

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def json(self):
        return json.loads(self.body.decode("utf-8", "replace"))


class HttpClient:
    """A small GET/HEAD/POST client: no proxy, no implicit retries, hard caps."""

    def __init__(self, guard, timeout: float = 6.0, max_bytes: int = 512 * 1024,
                 user_agent: str = USER_AGENT, max_redirects: int = 3,
                 pacing: float = 0.25, verify: bool = False):
        self.guard = guard
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.user_agent = user_agent
        self.max_redirects = max_redirects
        self.pacing = pacing
        self._last = 0.0
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        )

    def _pace(self) -> None:
        if self.pacing <= 0:
            return
        wait = self.pacing - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def request(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                body: Optional[bytes] = None, redirects: Optional[int] = None) -> Response:
        current = url
        budget = self.max_redirects if redirects is None else redirects
        for _ in range(budget + 1):
            parts = urllib.parse.urlsplit(current)
            if parts.scheme not in ("http", "https"):
                return Response(url=current, error="only http and https are supported")
            if parts.username or parts.password:
                return Response(url=current, error="a URL carrying credentials is not followed")
            try:
                self.guard.require("host", parts.hostname or "")
            except ScopeRefused as exc:
                return Response(url=current, error=f"scope refused: {exc.reason}")
            response = self._once(current, method, headers, body)
            if response.status in (301, 302, 303, 307, 308) and response.header("location"):
                target = urllib.parse.urljoin(current, response.header("location"))
                if budget <= 0:
                    return response
                budget -= 1
                current = target
                if response.status == 303:
                    method, body = "GET", None
                continue
            return response
        return Response(url=current, error="too many redirects")

    def _once(self, url: str, method: str, headers: Optional[Dict[str, str]],
              body: Optional[bytes]) -> Response:
        self._pace()
        request = urllib.request.Request(url, data=body, method=method.upper())
        request.add_header("User-Agent", self.user_agent)
        request.add_header("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
        request.add_header("Accept-Language", "en")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        started = time.monotonic()
        try:
            with self._opener.open(request, timeout=self.timeout) as reply:
                raw = reply.read(self.max_bytes + 1)
                truncated = len(raw) > self.max_bytes
                payload = raw[: self.max_bytes]
                return Response(
                    url=reply.geturl(),
                    status=int(reply.status),
                    headers={key.lower(): value for key, value in reply.headers.items()},
                    cookies=[str(value) for value in (reply.headers.get_all("Set-Cookie") or [])][:20],
                    body=payload,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    truncated=truncated,
                )
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read(self.max_bytes + 1)
            except OSError:
                raw = b""
            return Response(
                url=url,
                status=int(exc.code),
                headers={key.lower(): value for key, value in (exc.headers or {}).items()},
                cookies=[str(value) for value in ((exc.headers or {}).get_all("Set-Cookie") or [])][:20],
                body=raw[: self.max_bytes],
                elapsed_ms=int((time.monotonic() - started) * 1000),
                truncated=len(raw) > self.max_bytes,
            )
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return Response(url=url, error=str(getattr(exc, "reason", exc)),
                            elapsed_ms=int((time.monotonic() - started) * 1000))

    def get(self, url: str, **kwargs) -> Response:
        return self.request(url, "GET", **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        return self.request(url, "HEAD", **kwargs)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface redirects as responses; the client re-checks scope for each hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
