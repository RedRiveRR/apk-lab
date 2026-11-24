"""Framework, CMS and CDN signatures (WebAnalyzer ``Web Technologies``)."""
from __future__ import annotations

from typing import Dict, List, Tuple

from ..models import Finding
from ..registry import module
from .common import parse_html

#: (label, kind, header name, marker in the header value)
HEADER_SIGNATURES = (
    ("Cloudflare", "cdn", "server", "cloudflare"),
    ("Cloudflare", "cdn", "cf-ray", ""),
    ("Akamai", "cdn", "server", "akamai"),
    ("Fastly", "cdn", "x-served-by", "cache-"),
    ("Vercel", "cdn", "x-vercel-id", ""),
    ("AWS CloudFront", "cdn", "x-amz-cf-id", ""),
    ("Amazon S3", "hosting", "server", "amazons3"),
    ("Nginx", "server", "server", "nginx"),
    ("Apache", "server", "server", "apache"),
    ("Caddy", "server", "server", "caddy"),
    ("Microsoft IIS", "server", "server", "microsoft-iis"),
    ("PHP", "language", "x-powered-by", "php"),
    ("ASP.NET", "framework", "x-powered-by", "asp.net"),
    ("Express", "framework", "x-powered-by", "express"),
    ("Next.js", "framework", "x-powered-by", "next.js"),
    ("Nuxt", "framework", "x-powered-by", "nuxt"),
)

HTML_SIGNATURES = (
    ("WordPress", "cms", "wp-content/"), ("WordPress", "cms", "wp-includes/"),
    ("Drupal", "cms", "sites/default/files"), ("Joomla", "cms", "/media/jui/"),
    ("Magento", "cms", "static/version"), ("Shopify", "cms", "cdn.shopify.com"),
    ("Ghost", "cms", "ghost.io"), ("Wix", "cms", "wixstatic"),
    ("Squarespace", "cms", "squarespace.com"), ("Next.js", "framework", "/_next/static/"),
    ("Nuxt", "framework", "__nuxt__"), ("React", "framework", "data-reactroot"),
    ("Vue", "framework", "data-v-"), ("Svelte", "framework", "svelte-"),
    ("Angular", "framework", "ng-version"),
    ("Google Tag Manager", "analytics", "googletagmanager.com"),
    ("Google Analytics", "analytics", "google-analytics.com"),
    ("Segment", "analytics", "segment.com"), ("Hotjar", "analytics", "hotjar.com"),
    ("Plausible", "analytics", "plausible.io"), ("Sentry", "monitoring", "sentry.io"),
    ("Intercom", "support", "intercom.io"), ("jQuery", "library", "jquery"),
    ("Bootstrap", "library", "bootstrap"),
)

GENERATOR_CMS = {
    "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla", "ghost": "Ghost",
    "hugo": "Hugo", "jekyll": "Jekyll", "gatsby": "Gatsby", "wix": "Wix",
    "squarespace": "Squarespace", "shopify": "Shopify", "magento": "Magento",
}

#: (session cookie name, framework it implies). A tuple table, not a mapping:
#: the lab never stores anything that looks like a credential assignment.
COOKIE_FRAMEWORKS: Tuple[Tuple[str, str], ...] = (
    ("phpsessid", "PHP"), ("jsessionid", "Java"), ("asp.net_sessionid", "ASP.NET"),
    ("laravel_session", "Laravel"), ("csrftoken", "Django"),
)


@module("web_technologies", label="Web technologies",
        description="Server, CMS, framework, CDN, analytics and library fingerprints",
        group="recon", weight="medium", order=50, upstream="Web Technologies")
def web_technologies(ctx):
    response = ctx.page("/")
    headers = {str(key).lower(): str(value) for key, value in (response.headers or {}).items()}
    html = response.text if not response.error else ""
    page = parse_html(html)
    found: List[Dict[str, str]] = []
    seen = set()

    def add(label: str, kind: str, evidence: str) -> None:
        key = (label, kind)
        if key in seen:
            return
        seen.add(key)
        found.append({"name": label, "kind": kind, "evidence": evidence[:200]})

    for label, kind, header, marker in HEADER_SIGNATURES:
        value = headers.get(header, "")
        if value and (not marker or marker in value.lower()):
            add(label, kind, f"{header}: {value}")
    generator = page.meta.get("generator", "")
    if generator:
        for marker, label in GENERATOR_CMS.items():
            if marker in generator.lower():
                add(label, "cms", f"meta generator: {generator}")
        if not any(entry["evidence"].startswith("meta generator") for entry in found):
            add(generator.split("(")[0].strip()[:60] or "Generator", "cms",
                f"meta generator: {generator}")
    lowered = html.lower()
    for label, kind, marker in HTML_SIGNATURES:
        if marker in lowered:
            add(label, kind, marker)
    for cookie in response.cookies:
        name = cookie.split("=", 1)[0].strip().lower()
        for cookie_name, framework in COOKIE_FRAMEWORKS:
            if name == cookie_name:
                add(framework, "framework", f"cookie {name}")
    data = {"entries": found[:40], "server": headers.get("server", "")[:200],
            "powered_by": headers.get("x-powered-by", "")[:200], "generator": generator[:200]}
    findings: List[Finding] = []
    server = headers.get("server", "")
    if any(character.isdigit() for character in server) and "/" in server:
        findings.append(Finding(module="web_technologies", kind="server-version", severity="low",
                                title="The Server header discloses a version",
                                detail=f"Server: {server[:120]}",
                                remediation="Reduce the header to the product name, or remove it at the edge."))
    powered = headers.get("x-powered-by", "")
    if powered:
        findings.append(Finding(module="web_technologies", kind="powered-by", severity="low",
                                title="The X-Powered-By header discloses the stack",
                                detail=f"X-Powered-By: {powered[:120]}",
                                remediation="Disable the header; it gives an attacker free reconnaissance."))
    return data, findings
