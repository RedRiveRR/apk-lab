"""SecOps guides: short, defensive how-tos tied to the checks that raise them.

The upstream WebQ app opened a "SecOps guide" modal per page. Here the guides are
data on the engine, so the workbench modal, the CLI and the MCP tools read the
same text. Each guide names the check ids it explains; a test keeps every check
in the catalogue covered by exactly one guide. Wording stays short: the guide
says what to fix, the finding says where.
"""
from __future__ import annotations

from typing import Dict, List

GUIDES: List[Dict[str, object]] = [
    {
        "id": "scope",
        "title": "Scope and authorization",
        "checks": [],
        "points": [
            "Scan only hosts listed in scope.json, and only with written permission from their owner.",
            "Intrusive checks need the confirmation on every scan; no saved choice turns them on.",
            "Besides the target, only crt.sh, the Wayback CDX API and NVD are contacted.",
        ],
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    {
        "id": "grade",
        "title": "Reading the grade",
        "checks": ["remediation_plan"],
        "points": [
            "The score starts at 100 and each finding takes points off by severity; grades run from A+ to F.",
            "Fix critical and high findings first; the remediation plan puts them in order.",
            "Compare two runs to confirm a fix landed and nothing regressed.",
        ],
        "refs": [],
    },
    {
        "id": "headers",
        "title": "Security headers and cookies",
        "checks": ["security_analysis", "cookies_cors", "http_methods"],
        "points": [
            "Send Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options and a frame policy on every HTML response.",
            "Mark session cookies Secure, HttpOnly and SameSite.",
            "Allow only the HTTP methods the site uses, and never reflect an arbitrary Origin with credentials.",
        ],
        "refs": ["https://owasp.org/www-project-secure-headers/",
                 "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
    },
    {
        "id": "tls",
        "title": "TLS and certificates",
        "checks": ["tls_health", "ssl_san"],
        "points": [
            "Renew certificates well before they expire, and automate the renewal.",
            "Turn off TLS 1.0 and 1.1 and RSA keys shorter than 2048 bits.",
            "Every name in a certificate is a host to keep patched and in scope.",
        ],
        "refs": ["https://wiki.mozilla.org/Security/Server_Side_TLS"],
    },
    {
        "id": "dns",
        "title": "DNS and email",
        "checks": ["domain_info", "dns_records", "dns_health", "dns_zone_transfer", "email_security"],
        "points": [
            "Run at least two name servers and refuse zone transfers to the public.",
            "Publish SPF, DKIM and a DMARC policy of quarantine or reject.",
            "Add a CAA record so only your certificate authority can issue for the domain.",
        ],
        "refs": ["https://www.rfc-editor.org/rfc/rfc7489", "https://www.rfc-editor.org/rfc/rfc8659"],
    },
    {
        "id": "exposure",
        "title": "Exposure and leaks",
        "checks": ["content_scan", "exposed_files", "archive_spy", "react_exposure",
                   "js_library_vulns", "cloud_storage"],
        "points": [
            "Rotate any secret a scan finds in served code; deleting the file is not enough.",
            "Do not ship source maps or debug data to production.",
            "Upgrade JavaScript libraries with known CVEs and keep a dependency inventory.",
        ],
        "refs": ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
    },
    {
        "id": "surface",
        "title": "Attack surface",
        "checks": ["subdomain_discovery", "subdomain_takeover", "origin_exposure", "port_exposure",
                   "asset_inventory", "geo_analysis", "lookalike_domains"],
        "points": [
            "Remove DNS records that point at cloud services you no longer run.",
            "Keep the origin server reachable only through its CDN or proxy.",
            "Close every port that has no public purpose.",
            "Watch lookalike domains and register the obvious ones.",
        ],
        "refs": ["https://owasp.org/www-project-attack-surface-detector/"],
    },
    {
        "id": "footprint",
        "title": "Public footprint",
        "checks": ["seo_analysis", "web_technologies", "contact_spy", "privacy_trackers", "security_txt"],
        "points": [
            "Publish /.well-known/security.txt with a contact and an expiry date.",
            "Hide version banners that name exact framework releases.",
            "Name every third-party tracker in the privacy policy and ask for consent where the law requires it.",
        ],
        "refs": ["https://www.rfc-editor.org/rfc/rfc9116"],
    },
]


def guides() -> Dict[str, object]:
    """The guide list plus a check id → guide id index."""
    index = {check: str(guide["id"]) for guide in GUIDES for check in guide["checks"]}  # type: ignore[union-attr]
    return {"guides": [dict(guide) for guide in GUIDES], "byCheck": index}


__all__ = ["GUIDES", "guides"]
