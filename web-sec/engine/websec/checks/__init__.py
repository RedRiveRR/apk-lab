"""The built-in checks. Importing this package registers every module.

Keep the imports explicit: the catalogue order is the order checks run, and a
missing import is a failing test rather than a silently shorter scan.
"""
from __future__ import annotations

from . import (  # noqa: F401
    archive_spy,
    contact_spy,
    content_scan,
    dns_records,
    domain_info,
    geo_analysis,
    lookalike_domains,
    origin_exposure,
    port_exposure,
    remediation_plan,
    security_analysis,
    seo_analysis,
    ssl_san,
    subdomain_discovery,
    subdomain_takeover,
    web_technologies,
)

__all__ = [
    "archive_spy", "contact_spy", "content_scan", "dns_records", "domain_info",
    "geo_analysis", "lookalike_domains", "origin_exposure", "port_exposure",
    "remediation_plan", "security_analysis", "seo_analysis", "ssl_san",
    "subdomain_discovery", "subdomain_takeover", "web_technologies",
]
