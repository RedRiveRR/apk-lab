"""Origin exposure behind a CDN, from public DNS only (WebAnalyzer ``CloudFlare Bypass``).

Upstream scraped history databases for the origin address. This port stays
passive: it maps which names resolve outside the CDN and lets the operator decide
whether one of them is the origin. It never probes an address that is not a name
under the target domain.
"""
from __future__ import annotations

from typing import Dict, List

from ..models import Finding
from ..registry import module

CANDIDATE_LABELS = ("mail", "ftp", "direct", "origin", "cpanel", "webmail", "vpn", "dev",
                    "staging", "api", "smtp", "remote", "server", "host")
CDN_HEADERS = ("cf-ray", "x-vercel-id", "x-amz-cf-id", "x-akamai-transformed", "x-sucuri-id")


def _behind_cdn(headers: Dict[str, str]) -> str:
    for header in CDN_HEADERS:
        if header in headers:
            return header
    server = headers.get("server", "").lower()
    if "cloudflare" in server:
        return "server: cloudflare"
    return ""


@module("origin_exposure", label="Origin exposure",
        description="Names that resolve outside the CDN in front of the site",
        group="security", weight="medium", order=130, upstream="CloudFlare Bypass",
        needs_results=True)
def origin_exposure(ctx, results):
    root = ctx.page("/")
    cdn = _behind_cdn(root.headers or {})
    if not cdn:
        return {"cdn": "", "candidates": [], "note": "the site does not look CDN-fronted"}, []
    discovered = results.get("subdomain_discovery") or {}
    names = [str(name) for name in (discovered.get("names") or [])]
    names += [f"{label}.{ctx.target}" for label in CANDIDATE_LABELS]
    candidates: List[Dict[str, object]] = []
    exposed: List[Dict[str, object]] = []
    for name in dict.fromkeys(names):
        if len(candidates) >= 12 or ctx.expired():
            break
        try:
            addresses = ctx.dns.resolve(name)
        except Exception:
            continue
        if not addresses:
            continue
        response = ctx.http.get(f"https://{name}")
        edge = _behind_cdn(response.headers or {}) if not response.error else ""
        entry = {"name": name, "addresses": addresses[:4], "edge": edge,
                 "status": response.status if not response.error else 0}
        candidates.append(entry)
        if not edge:
            exposed.append(entry)
    data = {"cdn": cdn, "candidates": candidates, "exposed": exposed,
            "note": "a name that is not behind the CDN is a candidate origin, not proof"}
    findings: List[Finding] = []
    if exposed:
        findings.append(Finding(
            module="origin_exposure", severity="medium",
            title="A hostname answers without the CDN in front of it",
            detail=f"{len(exposed)} candidate(s) answered directly; the origin may be reachable by address.",
            evidence=", ".join(f"{entry['name']} → {', '.join(entry['addresses'])}" for entry in exposed[:5]),
            remediation="Firewall the origin to the CDN's published ranges and rotate any exposed address."))
    return data, findings
