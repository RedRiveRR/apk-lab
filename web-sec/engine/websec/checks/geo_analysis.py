"""Address and hosting context (WebAnalyzer ``GEO Analysis``, WebQ IP view)."""
from __future__ import annotations

from typing import Dict, List

from ..models import Finding
from ..net.dns import DnsError
from ..registry import module
from .common import is_public

_HOSTING_HINTS = {
    "amazonaws.com": "AWS", "cloudfront.net": "AWS CloudFront", "azure.com": "Azure",
    "cloudapp.azure.com": "Azure", "googleusercontent.com": "Google Cloud",
    "googlehosted.com": "Google", "cloudflare.com": "Cloudflare", "fastly.net": "Fastly",
    "akamai.net": "Akamai", "digitalocean.com": "DigitalOcean", "ovh.net": "OVH",
    "hetzner.com": "Hetzner", "linode.com": "Linode", "vultr.com": "Vultr",
    "github.io": "GitHub Pages", "netlify.app": "Netlify", "vercel.app": "Vercel",
}


def hosting_hint(name: str) -> str:
    lowered = (name or "").lower()
    for suffix, provider in _HOSTING_HINTS.items():
        if suffix in lowered:
            return provider
    return ""


@module("geo_analysis", label="Address and hosting context",
        description="Resolved addresses, reverse names and hosting hints",
        group="recon", weight="light", order=30, upstream="GEO Analysis")
def geo_analysis(ctx):
    addresses = ctx.dns.resolve(ctx.target)
    entries: List[Dict[str, object]] = []
    hints = set()
    for address in addresses[:8]:
        try:
            reverse = ctx.dns.reverse(address)
        except (DnsError, OSError):
            reverse = ""
        hint = hosting_hint(reverse)
        if hint:
            hints.add(hint)
        entries.append({"address": address, "reverse": reverse, "hosting": hint,
                        "public": is_public(address)})
    data = {"addresses": entries, "hosting": sorted(hints)}
    findings: List[Finding] = []
    if not addresses:
        findings.append(Finding(module="geo_analysis", kind="no-address", severity="high",
                                title="The target does not resolve to any address",
                                detail=f"No A or AAAA answer for {ctx.target}.",
                                remediation="Publish DNS records or correct the target name."))
    elif not any(entry["public"] for entry in entries):
        findings.append(Finding(module="geo_analysis", kind="private-address", severity="info",
                                title="The target resolves only to private or loopback addresses",
                                detail=", ".join(str(entry["address"]) for entry in entries),
                                remediation="Expected for an internal lab target; confirm the exposure you intend to test."))
    return data, findings
