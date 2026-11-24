"""Security posture: headers, TLS, cookies and the A+ … F grade.

The upstream dashboard graded a domain from its WAF, CORS and TLS results; this
check computes the same kind of grade from the headers and transport it can
actually observe, and pairs every deduction with a fix.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..grade import grade as letter_grade
from ..models import Finding
from ..registry import module

PENALTY = {"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}
SESSION_HINT = ("sess", "token", "auth", "jwt", "sid", "login", "remember")


def parse_cookie(raw: str) -> Dict[str, object]:
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    lowered = raw.lower()
    same_site = ""
    for part in parts[1:]:
        key, _, value = part.partition("=")
        if key.strip().lower() == "samesite":
            same_site = value.strip().lower()
    return {
        "name": name,
        "secure": "secure" in lowered,
        "httponly": "httponly" in lowered,
        "samesite": same_site,
        "session": any(hint in name.lower() for hint in SESSION_HINT),
    }


def _findings_for(headers: Dict[str, str], cookies: List[Dict[str, object]],
                  tls, https_redirect: Optional[bool]) -> List[Finding]:
    found: List[Finding] = []

    def add(kind: str, severity: str, title: str, detail: str, remediation: str, evidence: str = "") -> None:
        found.append(Finding(module="security_analysis", severity=severity, title=title,
                             detail=detail, remediation=remediation, evidence=evidence, kind=kind))

    hsts = headers.get("strict-transport-security", "")
    if not hsts:
        add("hsts-missing", "medium", "Strict-Transport-Security is missing",
            "A browser that reaches the site over plain HTTP will not be upgraded on later visits.",
            "Send Strict-Transport-Security: max-age=31536000; includeSubDomains over HTTPS.")
    else:
        max_age = 0
        for part in hsts.split(";"):
            key, _, value = part.strip().partition("=")
            if key.lower() == "max-age":
                try:
                    max_age = int(value)
                except ValueError:
                    max_age = 0
        if max_age < 15552000:
            add("hsts-max-age", "low", "HSTS max-age is shorter than 180 days",
                f"max-age={max_age} seconds.", "Raise max-age to at least 15552000.")
        if "includesubdomains" not in hsts.lower():
            add("hsts-subdomains", "info", "HSTS does not cover subdomains",
                "includeSubDomains is absent.", "Add includeSubDomains once every subdomain is HTTPS-only.")

    csp = headers.get("content-security-policy", "")
    if not csp:
        add("csp-missing", "medium", "Content-Security-Policy is missing",
            "Nothing limits which scripts, frames or connections the page may load.",
            "Start with a report-only policy, then enforce script-src 'self' and object-src 'none'.")
    else:
        lowered = csp.lower()
        if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
            add("csp-inline", "low", "The CSP allows inline or evaluated script",
                "'unsafe-inline' or 'unsafe-eval' is present, which weakens XSS protection.",
                "Move inline handlers to files and use nonces or hashes.")
        if "*" in lowered and "default-src *" in lowered:
            add("csp-wildcard", "high", "The CSP allows any origin",
                "default-src * makes the policy close to decorative.",
                "Replace the wildcard with the origins the page actually uses.")

    frame_options = headers.get("x-frame-options", "").lower()
    if "frame-ancestors" not in csp.lower() and frame_options not in ("deny", "sameorigin"):
        add("clickjacking-missing", "medium", "Clickjacking protection is missing",
            "Neither X-Frame-Options nor CSP frame-ancestors restricts framing.",
            "Send X-Frame-Options: DENY, or frame-ancestors 'none' in the CSP.")

    if headers.get("x-content-type-options", "").lower() != "nosniff":
        add("nosniff-missing", "low", "X-Content-Type-Options is not nosniff",
            "Browsers may guess a content type and execute an uploaded file as script.",
            "Send X-Content-Type-Options: nosniff.")

    referrer = headers.get("referrer-policy", "").lower()
    if not referrer:
        add("referrer-missing", "low", "Referrer-Policy is missing",
            "Full URLs, including query strings, may leak to third parties.",
            "Send Referrer-Policy: strict-origin-when-cross-origin.")
    elif referrer in ("unsafe-url", "no-referrer-when-downgrade"):
        add("referrer-leaks", "low", "Referrer-Policy leaks cross-origin URLs",
            f"Policy: {referrer}.", "Use strict-origin-when-cross-origin.")

    if not headers.get("permissions-policy"):
        add("permissions-policy-missing", "info", "Permissions-Policy is missing",
            "Camera, microphone and geolocation remain available to any embedded frame.",
            "Send a Permissions-Policy that disables features the page does not use.")

    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower()
    if allow_origin == "*" and allow_credentials == "true":
        add("cors-wildcard-credentials", "high", "CORS allows any origin with credentials",
            "Access-Control-Allow-Origin: * together with credentials lets any site read responses.",
            "Echo only known origins from an allowlist and never combine * with credentials.")
    elif allow_origin == "*":
        add("cors-wildcard", "low", "CORS allows any origin",
            "Access-Control-Allow-Origin: * exposes the response to every site.",
            "Restrict the origin if the response is not meant to be public.")

    for cookie in cookies:
        name = str(cookie["name"])
        if not cookie["secure"]:
            add("cookie-secure", "medium" if cookie["session"] else "low", f"Cookie {name} is sent without Secure",
                "It can travel over plain HTTP.", "Add the Secure attribute.")
        if not cookie["httponly"]:
            add("cookie-httponly", "medium" if cookie["session"] else "low", f"Cookie {name} is readable from JavaScript",
                "The HttpOnly attribute is missing.", "Add HttpOnly to session cookies.")
        if str(cookie["samesite"]) == "none" and not cookie["secure"]:
            add("cookie-samesite-none", "high", f"Cookie {name} uses SameSite=None without Secure",
                "Browsers reject the cookie, and it is exposed on plain HTTP.",
                "Set Secure whenever SameSite=None is used.")
        elif not cookie["samesite"]:
            add("cookie-samesite-absent", "low", f"Cookie {name} has no SameSite attribute",
                "The browser default varies.", "Set SameSite=Lax or Strict.")

    if tls is None or getattr(tls, "error", ""):
        add("tls-uninspected", "medium", "TLS could not be inspected",
            f"{(getattr(tls, 'error', '') if tls is not None else 'no handshake')}",
            "Confirm the certificate chain and that 443 answers.")
    else:
        protocol = getattr(tls, "protocol", "") or ""
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            add("tls-obsolete", "high", "The endpoint negotiated an obsolete TLS version",
                f"Negotiated {protocol}.", "Require TLS 1.2 or newer.")
        days_left = getattr(tls, "days_left", None)
        if days_left is not None and days_left < 0:
            add("cert-expired", "critical", "The TLS certificate has expired",
                f"Expired {abs(int(days_left))} days ago.", "Renew the certificate and automate renewal.")
        elif days_left is not None and days_left <= 14:
            add("cert-expiring", "high", "The TLS certificate expires within 14 days",
                f"{int(days_left)} days left.", "Renew now and monitor expiry.")
        elif days_left is not None and days_left <= 30:
            add("cert-expiring", "medium", "The TLS certificate expires within 30 days",
                f"{int(days_left)} days left.", "Renew before the next release window.")
        if getattr(tls, "issuer", "") and getattr(tls, "issuer", "") == getattr(tls, "subject", ""):
            add("cert-self-signed", "medium", "The certificate is self-signed",
                "No public CA vouches for this certificate.", "Use a certificate from a trusted CA.")

    if https_redirect is False:
        add("no-https-redirect", "medium", "Plain HTTP is served without a redirect to HTTPS",
            "The first request can be intercepted before any HSTS policy applies.",
            "Redirect 80/tcp to https:// with a 301 and keep HSTS enabled.")
    return found


def _waf(headers: Dict[str, str]) -> str:
    for header, label in (("cf-ray", "Cloudflare"), ("x-sucuri-id", "Sucuri"),
                          ("x-akamai-transformed", "Akamai"), ("x-iinfo", "Imperva"),
                          ("x-amzn-waf-action", "AWS WAF"), ("server", "cloudflare")):
        value = headers.get(header, "")
        if value and (header != "server" or "cloudflare" in value.lower()):
            return label
    return ""


@module("security_analysis", label="Security posture",
        description="Header grade, TLS version and expiry, cookie flags, CORS and WAF hints",
        group="security", weight="medium", order=60, upstream="Security Analysis")
def security_analysis(ctx):
    response = ctx.page("/")
    headers = {str(key).lower(): str(value) for key, value in (response.headers or {}).items()}
    cookies = [parse_cookie(raw) for raw in response.cookies][:20]
    tls = ctx.tls()
    https_redirect = None
    if ctx.options.scheme == "https" and ctx.options.port in (None, 443):
        plain = ctx.page("/", scheme="http")
        if plain.error:
            https_redirect = None
        else:
            location = plain.header("location")
            https_redirect = bool(location.startswith("https://") or plain.url.startswith("https://"))
    findings = _findings_for(headers, cookies, tls if ctx.options.scheme == "https" else None, https_redirect)
    if ctx.options.scheme != "https":
        findings = [finding for finding in findings if not finding.title.startswith("TLS")]
    penalty = min(100, sum(PENALTY[finding.severity] for finding in findings))
    score = max(0, 100 - penalty)
    data = {
        "score": score,
        "grade": letter_grade(score),
        "headers": {key: value[:300] for key, value in headers.items()
                    if key in ("strict-transport-security", "content-security-policy",
                               "x-frame-options", "x-content-type-options", "referrer-policy",
                               "permissions-policy", "access-control-allow-origin",
                               "cross-origin-opener-policy", "cross-origin-resource-policy")},
        "cookies": cookies,
        "tls": tls.as_dict() if hasattr(tls, "as_dict") else {},
        "https_redirect": https_redirect,
        "waf": _waf(headers),
        "checks": [{"severity": finding.severity, "title": finding.title} for finding in findings],
    }
    return data, findings
