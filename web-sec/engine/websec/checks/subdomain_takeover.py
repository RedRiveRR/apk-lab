"""Dangling CNAME checks against a registry of 36 service fingerprints.

Upstream combined ``subfinder`` output with the same idea; this port reuses the
names discovered by the subdomain module and never enumerates by force.
"""
from __future__ import annotations

from typing import Dict, List

from ..models import Finding
from ..registry import module

#: (CNAME suffix, service name, marker in the service's 404 page)
FINGERPRINTS = (
    ("github.io", "GitHub Pages", "there isn't a github pages site here"),
    ("herokuapp.com", "Heroku", "no such app"),
    ("herokudns.com", "Heroku", "no such app"),
    ("s3.amazonaws.com", "Amazon S3", "nosuchbucket"),
    ("cloudfront.net", "Amazon CloudFront", "bad request"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk", "404 not found"),
    ("azurewebsites.net", "Azure Web Apps", "404 web site not found"),
    ("cloudapp.azure.com", "Azure", ""),
    ("trafficmanager.net", "Azure Traffic Manager", ""),
    ("blob.core.windows.net", "Azure Blob", "blobnotfound"),
    ("netlify.app", "Netlify", "not found - request id"),
    ("netlify.com", "Netlify", "not found - request id"),
    ("vercel.app", "Vercel", "the deployment could not be found"),
    ("now.sh", "Vercel", "the deployment could not be found"),
    ("surge.sh", "Surge", "project not found"),
    ("bitbucket.io", "Bitbucket", "repository not found"),
    ("ghost.io", "Ghost", "domain error"),
    ("readme.io", "ReadMe", "the requested page could not be found"),
    ("tumblr.com", "Tumblr", "there's nothing here"),
    ("wordpress.com", "WordPress.com", "doesn’t exist"),
    ("pantheon.io", "Pantheon", "the gods are wise"),
    ("fastly.net", "Fastly", "fastly error: unknown domain"),
    ("myshopify.com", "Shopify", "sorry, this shop is currently unavailable"),
    ("webflow.io", "Webflow", "the page you are looking for doesn't exist"),
    ("cargocollective.com", "Cargo", "404 not found"),
    ("statuspage.io", "Statuspage", "better status page"),
    ("helpscoutdocs.com", "Help Scout", "no settings were found"),
    ("zendesk.com", "Zendesk", "help center closed"),
    ("uservoice.com", "UserVoice", "this uservoice subdomain is not active"),
    ("freshdesk.com", "Freshdesk", "not found"),
    ("ngrok.io", "ngrok", "tunnel not found"),
    ("ngrok-free.app", "ngrok", "tunnel not found"),
    ("fly.dev", "Fly.io", "not found"),
    ("railway.app", "Railway", "application not found"),
    ("render.com", "Render", "not found"),
    ("pages.dev", "Cloudflare Pages", "not found"),
    ("workers.dev", "Cloudflare Workers", "not found"),
)
MAX_CANDIDATES = 60


def _fingerprint(target: str):
    lowered = target.lower().rstrip(".")
    for suffix, service, marker in FINGERPRINTS:
        if lowered == suffix or lowered.endswith("." + suffix):
            return service, marker
    return None, ""


@module("subdomain_takeover", label="Subdomain takeover",
        description="Dangling CNAMEs pointing at unclaimed hosting services",
        group="security", weight="heavy", order=120, upstream="Subdomain Takeover",
        needs_results=True)
def subdomain_takeover(ctx, results):
    discovered = results.get("subdomain_discovery") or {}
    names = [str(name) for name in (discovered.get("names") or [])][:MAX_CANDIDATES]
    if ctx.target not in names:
        names.insert(0, ctx.target)
    checked: List[Dict[str, object]] = []
    dangling: List[Dict[str, object]] = []
    confirmed: List[Dict[str, object]] = []
    for name in names:
        if ctx.expired():
            break
        try:
            chain = ctx.dns.cname_chain(name)
        except Exception as exc:
            checked.append({"name": name, "error": str(exc)})
            continue
        if not chain:
            continue
        endpoint = chain[-1]
        service, marker = _fingerprint(endpoint)
        if not service:
            continue
        entry = {"name": name, "chain": chain, "service": service}
        try:
            addresses = ctx.dns.resolve(endpoint)
        except Exception:
            addresses = []
        if not addresses:
            entry["evidence"] = f"{endpoint} does not resolve"
            dangling.append(entry)
            checked.append(entry)
            continue
        response = ctx.http.get(f"https://{name}")
        body = response.text.lower() if not response.error else ""
        if marker and marker in body:
            entry["evidence"] = f"matched the {service} takeover page"
            confirmed.append(entry)
        checked.append(entry)
    data = {"checked": checked[:40], "dangling": dangling, "confirmed": confirmed,
            "candidates": len(names), "services": len(FINGERPRINTS)}
    findings: List[Finding] = []
    for entry in confirmed:
        findings.append(Finding(
            module="subdomain_takeover", kind="claim-possible", severity="high",
            title=f"{entry['service']} claim appears possible for {entry['name']}",
            detail=f"CNAME chain: {' → '.join(entry['chain'])}",
            evidence=str(entry.get("evidence", "")),
            remediation="Remove the DNS record or claim the resource; do not leave a dangling CNAME."))
    for entry in dangling:
        findings.append(Finding(
            module="subdomain_takeover", kind="dangling-cname", severity="medium",
            title=f"Dangling CNAME to {entry['service']} for {entry['name']}",
            detail=f"CNAME chain: {' → '.join(entry['chain'])}",
            evidence=str(entry.get("evidence", "")),
            remediation="Delete the record or re-create the service, then re-check."))
    return data, findings
