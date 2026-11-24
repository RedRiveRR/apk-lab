"""Third-party requests and tracker categories (upstream plugin ``Privacy & Trackers``)."""
from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlsplit

from ..models import Finding
from ..registry import module
from ..checks.common import parse_html

TRACKERS = {
    "googletagmanager.com": "tag manager", "google-analytics.com": "analytics",
    "doubleclick.net": "advertising", "facebook.net": "advertising", "facebook.com": "social",
    "hotjar.com": "session replay", "segment.com": "analytics", "mixpanel.com": "analytics",
    "clarity.ms": "session replay", "tiktok.com": "advertising", "linkedin.com": "advertising",
    "twitter.com": "social", "x.com": "social", "youtube.com": "video",
    "cdn.jsdelivr.net": "content delivery", "unpkg.com": "content delivery",
    "fonts.googleapis.com": "fonts", "cdnjs.cloudflare.com": "content delivery",
}


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


@module("privacy_trackers", label="Privacy and trackers",
        description="Third-party hosts the page loads, grouped by tracker category",
        group="posture", weight="light", order=270)
def privacy_trackers(ctx):
    response = ctx.page("/")
    if response.error:
        return {"available": False, "reason": response.error}, []
    page = parse_html(response.text)
    sources = list(page.scripts) + [link["href"] for link in page.links] + [image["src"] for image in page.images]
    hosts: Dict[str, str] = {}
    for source in sources[:200]:
        host = _host(source if source.startswith("http") else ctx.absolute(source))
        if host and host != ctx.target and not host.endswith("." + ctx.target):
            hosts.setdefault(host, TRACKERS.get(host, "other"))
    categories: Dict[str, int] = {}
    for category in hosts.values():
        categories[category] = categories.get(category, 0) + 1
    data = {"third_parties": sorted(hosts)[:40], "categories": categories,
            "total": len(hosts)}
    findings: List[Finding] = []
    advertising = sum(count for category, count in categories.items()
                      if category in ("advertising", "session replay"))
    if advertising >= 3:
        findings.append(Finding(
            module="privacy_trackers", severity="low",
            title="The page loads several advertising or session-replay hosts",
            detail=f"{advertising} such hosts are referenced.",
            remediation="Load them only after consent and document them in the privacy notice."))
    return data, findings
