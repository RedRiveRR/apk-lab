"""Exposed services on a bounded port list (WebAnalyzer ``Nmap Zero Day Scan``).

Upstream piped Nmap XML into NVD. This port uses the same connect-and-banner
idea over 20 declared ports, and only asks NVD for a CVE when the operator opts
in with ``--cve-lookup``.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

from ..models import Finding
from ..registry import module

DATABASES = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
             9200: "Elasticsearch", 1433: "MSSQL", 5984: "CouchDB", 11211: "Memcached"}
PLAINTEXT = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 25: "SMTP", 53: "DNS"}
ADMIN_PORTS = {8080: "HTTP alternate", 8443: "HTTPS alternate", 3389: "RDP"}
MAX_PORTS = 20
_VERSION = re.compile(r"([A-Za-z][A-Za-z0-9._-]{2,30})[/ ]([0-9]+(?:\.[0-9]+){0,3})")


def _service(port: int, banner: str) -> str:
    lowered = banner.lower()
    for marker, name in (("ssh-", "OpenSSH"), ("mysql", "MySQL"), ("postgres", "PostgreSQL"),
                         ("redis", "Redis"), ("elastic", "Elasticsearch"), ("http", "HTTP"),
                         ("smtp", "SMTP"), ("ftp", "FTP")):
        if marker in lowered:
            return name
    return DATABASES.get(port) or PLAINTEXT.get(port) or ADMIN_PORTS.get(port) or ""


def _nvd(ctx, service: str, version: str) -> List[Dict[str, str]]:
    keyword = f"{service} {version}".strip()
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
           + keyword.replace(" ", "%20") + "&resultsPerPage=3")
    response = ctx.infra(url)
    if response.error or response.status != 200:
        return []
    try:
        payload = json.loads(response.body.decode("utf-8", "replace"))
    except ValueError:
        return []
    found = []
    for entry in (payload.get("vulnerabilities") or [])[:3]:
        cve = entry.get("cve") or {}
        identifier = cve.get("id")
        if not identifier:
            continue
        description = ""
        for item in cve.get("descriptions") or []:
            if item.get("lang") == "en":
                description = str(item.get("value", ""))[:500]
                break
        found.append({"id": str(identifier), "description": description})
    return found


@module("port_exposure", label="Port exposure",
        description="Bounded TCP connect check on 20 declared ports, with optional NVD lookup",
        group="security", weight="heavy", order=140, active=True,
        upstream="Nmap Zero Day Scan")
def port_exposure(ctx):
    ports = list(dict.fromkeys(ctx.options.ports))[:MAX_PORTS]
    entries: List[Dict[str, object]] = []
    findings: List[Finding] = []
    for port in ports:
        if ctx.expired():
            break
        result = ctx.port(port)
        if not result.open:
            continue
        service = _service(port, result.banner)
        entries.append({"port": port, "service": service, "banner": result.banner[:200]})
        if port in DATABASES:
            findings.append(Finding(
                module="port_exposure", severity="high",
                title=f"{DATABASES[port]} is reachable on port {port}",
                detail="A datastore should not answer on the public edge.",
                evidence=result.banner[:200],
                remediation=f"Bind {DATABASES[port]} to loopback or a private network and require authentication."))
        elif port in PLAINTEXT:
            severity = "high" if port in (21, 23) else "medium"
            findings.append(Finding(
                module="port_exposure", severity=severity,
                title=f"{PLAINTEXT[port]} is reachable on port {port}",
                detail="Credentials and contents can cross the network in clear text.",
                evidence=result.banner[:200],
                remediation=f"Disable {PLAINTEXT[port]} or move it behind TLS and a VPN."))
        elif port in ADMIN_PORTS:
            findings.append(Finding(
                module="port_exposure", severity="medium",
                title=f"{ADMIN_PORTS[port]} answers on port {port}",
                detail="An administrative interface is exposed to the internet.",
                evidence=result.banner[:200],
                remediation="Restrict the port to an allowlist or a VPN."))
        elif port == 22:
            findings.append(Finding(module="port_exposure", severity="info",
                                    title="SSH is reachable on port 22",
                                    detail="Expose it only to the addresses that administer the host.",
                                    remediation="Restrict SSH to an allowlist and disable password auth."))
    cves: List[Dict[str, object]] = []
    if ctx.options.cve_lookup:
        for entry in entries[:3]:
            banner = str(entry.get("banner", ""))
            match = _VERSION.search(banner)
            if not match:
                continue
            for cve in _nvd(ctx, str(entry.get("service") or match.group(1)), match.group(2)):
                cves.append({"port": entry["port"], **cve})
    data = {"ports": entries, "scanned": len(ports), "cves": cves,
            "cve_lookup": bool(ctx.options.cve_lookup)}
    for cve in cves:
        findings.append(Finding(
            module="port_exposure", severity="low",
            title=f"{cve['id']} matches the service on port {cve['port']}",
            detail=str(cve["description"])[:600],
            remediation="Confirm the version, then patch or upgrade the service.",
            refs=(f"https://nvd.nist.gov/vuln/detail/{cve['id']}",)))
    return data, findings
