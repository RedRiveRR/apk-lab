"""Bounded contact and social discovery (WebAnalyzer ``Contact Spy``)."""
from __future__ import annotations

from collections import OrderedDict
from typing import Dict, List, Set
from urllib.parse import urlsplit

from ..models import Finding
from ..registry import module
from .common import EMAIL_RE, FREE_MAIL, PHONE_RE, SOCIAL_HOSTS, parse_html

MAX_EMAILS = 40


def _digits(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def _social(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    for suffix, label in SOCIAL_HOSTS.items():
        if host == suffix or host.endswith("." + suffix):
            return label
    return ""


@module("contact_spy", label="Contact and social discovery",
        description="Bounded same-host crawl for emails, phone numbers and social profiles",
        group="recon", weight="heavy", order=80, upstream="Contact Spy")
def contact_spy(ctx):
    queue: List[str] = ["/"]
    visited: Set[str] = set()
    pages: List[str] = []
    emails: "OrderedDict[str, str]" = OrderedDict()
    phones: "OrderedDict[str, str]" = OrderedDict()
    socials: "OrderedDict[str, str]" = OrderedDict()
    while queue and len(visited) < ctx.options.max_pages and not ctx.expired():
        path = queue.pop(0)
        if path in visited:
            continue
        visited.add(path)
        response = ctx.page(path)
        if response.error or response.status >= 400:
            continue
        if "html" not in response.header("content-type", "text/html").lower():
            continue
        pages.append(path)
        page = parse_html(response.text)
        for text in (page.text, " ".join(page.anchors)):
            for match in EMAIL_RE.finditer(text):
                address = match.group(0).strip(".").lower()
                if len(emails) < MAX_EMAILS and address not in emails:
                    emails[address] = path
            for match in PHONE_RE.finditer(text):
                digits = _digits(match.group(0))
                if 9 <= len(digits) <= 15 and len(phones) < MAX_EMAILS:
                    phones.setdefault(digits, path)
        for href in page.anchors:
            candidate = ctx.absolute(href)
            label = _social(candidate)
            if label:
                socials.setdefault(label, candidate[:300])
            if href.startswith(("/", "./", "../")) or ctx.target in href:
                target_path = urlsplit(candidate).path or "/"
                if target_path not in visited and len(queue) < 60:
                    queue.append(target_path)
    data = {
        "pages_crawled": len(pages),
        "pages": pages[:25],
        "emails": [{"address": address, "found_on": page} for address, page in emails.items()],
        "phones": [{"number": number, "found_on": page} for number, page in list(phones.items())[:20]],
        "socials": [{"network": network, "url": url} for network, url in socials.items()],
    }
    findings: List[Finding] = []
    free = [address for address in emails if address.rsplit("@", 1)[-1] in FREE_MAIL]
    if free:
        findings.append(Finding(
            module="contact_spy", severity="low",
            title="Personal mailboxes are published on the site",
            detail=f"{len(free)} address(es) use a free mail provider: {', '.join(free[:3])}.",
            remediation="Use role addresses and a contact form; remove personal mailboxes."))
    if len(emails) > 5:
        findings.append(Finding(
            module="contact_spy", severity="info",
            title="Many email addresses are exposed",
            detail=f"{len(emails)} distinct addresses across {len(pages)} page(s).",
            remediation="Confirm each address must be public."))
    return data, findings
