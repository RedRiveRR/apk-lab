"""Shared parsing, redaction and small helpers for the checks.

Nothing here opens a socket. The HTML parser is deliberately forgiving: a real
page is malformed more often than not, and the checks only need a handful of
signals from it.
"""
from __future__ import annotations

import html as html_module
import ipaddress
import json
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

MAX_SCRIPT = 64 * 1024

SOCIAL_HOSTS = {
    "linkedin.com": "LinkedIn", "twitter.com": "X", "x.com": "X",
    "facebook.com": "Facebook", "instagram.com": "Instagram",
    "github.com": "GitHub", "youtube.com": "YouTube", "tiktok.com": "TikTok",
    "mastodon.social": "Mastodon",
}
FREE_MAIL = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
             "protonmail.com", "yandex.com", "mail.ru"}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
PHONE_RE = re.compile(r"(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?)?\d{3}[\s.\-]?\d{3}[\s.\-]?\d{2,4}")

SECRET_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]", str, str], ...] = (
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "critical",
     "Remove the key from the served asset and rotate it."),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical",
     "Revoke the key in IAM and serve nothing but public configuration."),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high",
     "Restrict the key by referrer and API, then rotate it."),
    ("Stripe live secret", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), "critical",
     "Rotate the secret key; publishable keys only in the client."),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b"), "critical",
     "Revoke the token and move it to a server-side secret store."),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "high",
     "Revoke the token in Slack and rotate the integration."),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "medium", "Move tokens server-side; a JWT in a static asset is public forever."),
    ("Hardcoded password", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"),
     "medium", "Load the credential from the environment, not from a bundled script."),
    ("Basic auth in URL", re.compile(r"https?://[^\s/@:]+:[^\s/@]{6,}@[A-Za-z0-9.\-]+"), "high",
     "Remove the credential from the URL; rotate it."),
)


class Page(HTMLParser):
    """The signals the checks need from one HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.meta: Dict[str, str] = {}
        self.links: List[Dict[str, str]] = []
        self.scripts: List[str] = []
        self.inline: List[str] = []
        self.images: List[Dict[str, str]] = []
        self.headings: List[Tuple[str, str]] = []
        self.anchors: List[str] = []
        self.jsonld: List[str] = []
        self.lang = ""
        self._text: Optional[List[str]] = None
        self._script: Optional[List[str]] = None
        self._script_type = ""
        self._heading: Optional[Tuple[str, List[str]]] = None
        self.text_parts: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag == "html" and values.get("lang"):
            self.lang = values["lang"]
        elif tag == "title":
            self._text = []
        elif tag == "meta":
            key = values.get("name") or values.get("property") or values.get("http-equiv")
            if key and values.get("content"):
                self.meta[key.lower()] = values["content"][:500]
        elif tag == "link":
            if values.get("href"):
                self.links.append({"rel": values.get("rel", "").lower(), "href": values["href"][:1000],
                                   "type": values.get("type", "")[:80]})
        elif tag == "script":
            self._script_type = values.get("type", "").lower()
            if values.get("src"):
                self.scripts.append(values["src"][:1000])
            else:
                self._script = []
        elif tag == "img":
            self.images.append({"src": values.get("src", "")[:500], "alt": values.get("alt", "")[:200]})
        elif tag in ("h1", "h2", "h3"):
            self._heading = (tag, [])
        elif tag == "a" and values.get("href"):
            self.anchors.append(values["href"][:1000])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._text is not None:
            self.title = " ".join(" ".join(self._text).split())[:300]
            self._text = None
        elif tag == "script" and self._script is not None:
            body = "".join(self._script)[:MAX_SCRIPT]
            if self._script_type == "application/ld+json":
                self.jsonld.append(body)
            else:
                self.inline.append(body)
            self._script = None
        elif tag in ("h1", "h2", "h3") and self._heading and tag == self._heading[0]:
            text = " ".join(" ".join(self._heading[1]).split())[:300]
            self.headings.append((tag, text))
            self._heading = None

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script.append(data)
            return
        if self._text is not None:
            self._text.append(data)
        if self._heading is not None:
            self._heading[1].append(data)
        if data.strip():
            self.text_parts.append(data.strip())

    @property
    def text(self) -> str:
        return " ".join(self.text_parts)


def parse_html(markup: str) -> Page:
    page = Page()
    try:
        page.feed(markup or "")
        page.close()
    except Exception:  # a broken page still yields what was parsed
        pass
    return page


def header_map(headers: Dict[str, str]) -> Dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (headers or {}).items()}


def same_host(url: str, host: str) -> bool:
    try:
        candidate = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return candidate == host.lower()


def absolute(url: str, base: str) -> str:
    from urllib.parse import urljoin
    return urljoin(base, url)


def is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (parsed.is_private or parsed.is_loopback or parsed.is_link_local
                or parsed.is_multicast or parsed.is_reserved)


def mask(secret: str) -> str:
    text = secret.strip()
    if len(text) <= 10:
        return text[:2] + "…"
    return f"{text[:4]}…{text[-4:]}"


def find_secrets(text: str, limit: int = 40) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    seen = set()
    for label, pattern, severity, remediation in SECRET_PATTERNS:
        for match in pattern.finditer(text or ""):
            value = match.group(0)
            key = (label, value[:32])
            if key in seen:
                continue
            seen.add(key)
            found.append({"kind": label, "severity": severity, "remediation": remediation,
                          "value": mask(value), "position": min(match.start(), 10 ** 9)})
            if len(found) >= limit:
                return found
    return found


def json_payload(response) -> Any:
    try:
        return json.loads(response.body.decode("utf-8", "replace"))
    except (ValueError, AttributeError):
        return None


def unescape(text: str) -> str:
    return html_module.unescape(text or "")
