"""Map a finding to a CWE and an OWASP Top 10 (2021) category.

Ported from WebAnalyzer's ``utils/taxonomy.py`` (MIT, see knowledge/upstream.md)
and kept as conservative: a finding is classified only when its kind, title or
detail clearly matches, then by a small per-check fallback; anything else stays
unclassified rather than guessed. The first match wins.
"""
from __future__ import annotations

import re
from typing import Dict, Optional

# (pattern over "kind title detail", CWE id, CWE name, OWASP 2021 category)
_RULES = (
    (r"strict-transport-security|\bhsts\b|plain http|unencrypted|cleartext|https redirect|no_https",
     319, "Cleartext Transmission of Sensitive Information", "A02:2021 Cryptographic Failures"),
    (r"\bssl\b|\btls\b|certificate|cipher|weak protocol|key size|rsa key",
     326, "Inadequate Encryption Strength", "A02:2021 Cryptographic Failures"),
    (r"x-frame-options|clickjack|frame-ancestors",
     1021, "Improper Restriction of Rendered UI Layers or Frames", "A05:2021 Security Misconfiguration"),
    (r"content-security-policy|\bcsp\b|x-content-type-options|nosniff|referrer-policy|permissions-policy",
     693, "Protection Mechanism Failure", "A05:2021 Security Misconfiguration"),
    (r"\bcors\b|access-control-allow-origin",
     942, "Permissive Cross-domain Policy with Untrusted Domains", "A05:2021 Security Misconfiguration"),
    (r"cookie",
     614, "Sensitive Cookie Without 'Secure' Attribute", "A05:2021 Security Misconfiguration"),
    (r"\bxss\b|cross-site scripting|innerhtml|dom sink|document\.write",
     79, "Cross-site Scripting", "A03:2021 Injection"),
    (r"open redirect",
     601, "URL Redirection to Untrusted Site", "A01:2021 Broken Access Control"),
    (r"takeover|dangling",
     284, "Improper Access Control", "A05:2021 Security Misconfiguration"),
    (r"api[ _-]?key|secret|password|credential|private key|access key|\btoken\b",
     798, "Use of Hard-coded Credentials", "A07:2021 Identification and Authentication Failures"),
    (r"directory listing|index of /",
     548, "Exposure of Information Through Directory Listing", "A05:2021 Security Misconfiguration"),
    (r"source map|exposed (file|endpoint|admin)|\.git\b|\.env\b|backup|sensitive file|public bucket|listable",
     538, "Insertion of Sensitive Information into Externally-Accessible File or Directory",
     "A05:2021 Security Misconfiguration"),
    (r"outdated|vulnerable (component|library|version)|known vulnerab|end[- ]of[- ]life|cve-\d{4}",
     1104, "Use of Unmaintained Third Party Components", "A06:2021 Vulnerable and Outdated Components"),
    (r"information disclosure|server header|version (disclosure|banner)|x-powered-by|stack trace|debug",
     200, "Exposure of Sensitive Information to an Unauthorized Actor", "A05:2021 Security Misconfiguration"),
    (r"zone transfer|axfr",
     200, "Exposure of Sensitive Information to an Unauthorized Actor", "A05:2021 Security Misconfiguration"),
    (r"\bspf\b|dmarc|dkim|mta-sts|look-?alike|phishing|typosquat",
     290, "Authentication Bypass by Spoofing", "A07:2021 Identification and Authentication Failures"),
    (r"open port|exposed (port|service)|origin (ip|address|exposure)",
     668, "Exposure of Resource to Wrong Sphere", "A05:2021 Security Misconfiguration"),
    (r"\btrace\b|risky method|http method",
     749, "Exposed Dangerous Method or Function", "A05:2021 Security Misconfiguration"),
)
_COMPILED = tuple((re.compile(pattern, re.I), cwe, name, owasp) for pattern, cwe, name, owasp in _RULES)

# Fallback by check id, used only when no text rule matched.
_BY_MODULE: Dict[str, tuple] = {
    "port_exposure": (668, "Exposure of Resource to Wrong Sphere", "A05:2021 Security Misconfiguration"),
    "origin_exposure": (668, "Exposure of Resource to Wrong Sphere", "A05:2021 Security Misconfiguration"),
    "email_security": (290, "Authentication Bypass by Spoofing", "A07:2021 Identification and Authentication Failures"),
    "lookalike_domains": (290, "Authentication Bypass by Spoofing", "A07:2021 Identification and Authentication Failures"),
    "js_library_vulns": (1104, "Use of Unmaintained Third Party Components", "A06:2021 Vulnerable and Outdated Components"),
    "tls_health": (326, "Inadequate Encryption Strength", "A02:2021 Cryptographic Failures"),
    "subdomain_takeover": (284, "Improper Access Control", "A05:2021 Security Misconfiguration"),
    "exposed_files": (538, "Insertion of Sensitive Information into Externally-Accessible File or Directory",
                      "A05:2021 Security Misconfiguration"),
}


def classify(module: str, kind: str = "", title: str = "", detail: str = "") -> Optional[Dict[str, str]]:
    """``{"cwe": "CWE-319", "cwe_name": ..., "owasp": ...}``, or None when nothing matches clearly."""
    text = f"{kind.replace('_', ' ')} {title} {detail}"
    for pattern, cwe, name, owasp in _COMPILED:
        if pattern.search(text):
            return {"cwe": f"CWE-{cwe}", "cwe_name": name, "owasp": owasp}
    fallback = _BY_MODULE.get(module)
    if fallback:
        return {"cwe": f"CWE-{fallback[0]}", "cwe_name": fallback[1], "owasp": fallback[2]}
    return None


def annotate(finding: Dict[str, object]) -> Dict[str, object]:
    """The finding dict with ``cwe``/``cwe_name``/``owasp`` filled (empty strings when unclassified)."""
    label = classify(str(finding.get("module") or ""), str(finding.get("kind") or ""),
                     str(finding.get("title") or ""), str(finding.get("detail") or ""))
    finding.update(label or {"cwe": "", "cwe_name": "", "owasp": ""})
    return finding


__all__ = ["annotate", "classify"]
