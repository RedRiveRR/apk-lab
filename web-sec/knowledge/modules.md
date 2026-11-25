# Checks

29 checks. The engine registers them in `websec/registry.py`; `websec modules`
prints the same list, and `websec modules --json` is what the dashboard renders,
so this page and the product cannot drift far apart.

Groups: `recon` (what the site is), `security` (how it is configured), `posture`
(hygiene around it), `inventory` (what the scan found).

## Built-in modules (16)

| id | group | traffic | what it does | upstream |
|---|---|---|---|---|
| `domain_info` | recon | passive | WHOIS: registrar, dates, nameservers, registry status; flags expiry and suspension | Domain Information |
| `dns_records` | recon | passive | A, AAAA, MX, TXT, NS, CNAME, SOA, CAA through the stdlib resolver | DNS Records |
| `geo_analysis` | recon | passive | resolved addresses, reverse names, hosting hints, public/private class | GEO Analysis |
| `seo_analysis` | recon | passive | title, description, canonical, Open Graph, headings, alt text, robots, sitemap | SEO Analysis |
| `web_technologies` | recon | passive | server, CMS, framework, CDN, analytics and library fingerprints | Web Technologies |
| `contact_spy` | recon | passive | bounded same-host crawl for emails, phones and social profiles | Contact Spy |
| `subdomain_discovery` | recon | passive | certificate-transparency names from crt.sh; flags staging/dev/admin | Subdomain Discovery |
| `security_analysis` | security | passive | header grade A+–F, TLS version and expiry, cookie flags, CORS, WAF hints | Security Analysis |
| `content_scan` | security | passive | 25 secret patterns with an entropy floor (cloud, AI, VCS, payment, database URLs, generic high-entropy assignments), DOM-XSS source→sink candidates, source-map exposure, framework data | Advanced Content Scan |
| `archive_spy` | security | passive | Wayback CDX URLs whose names suggest config, backups or secrets | Web Archive Spy |
| `ssl_san` | security | passive | certificate SANs, wildcards, names outside the domain | SSL SAN Association |
| `subdomain_takeover` | security | passive | dangling CNAMEs against a 36-service fingerprint table | Subdomain Takeover |
| `origin_exposure` | security | passive | names that answer outside the CDN in front of the site | CloudFlare Bypass |
| `port_exposure` | security | **active** | 20 declared ports, banner read, optional NVD lookup | Nmap Zero Day Scan |
| `lookalike_domains` | security | passive | typosquat/homoglyph variants that already resolve | Phishing Domain Protection |
| `remediation_plan` | posture | none | findings ordered into a fix list, highest severity first | Attack Path Planner |

## Plugins (13)

| id | group | traffic | what it does | upstream plugin |
|---|---|---|---|---|
| `security_txt` | posture | passive | `/.well-known/security.txt`: contacts, expiry, RFC 9116 fields | Security.txt |
| `dns_health` | posture | passive | nameserver count, CAA, DNSSEC delegation, SOA | DNS Health |
| `dns_zone_transfer` | security | **active** | AXFR against each nameserver; an answered transfer is critical | DNS Zone Transfer |
| `email_security` | posture | passive | SPF policy, DMARC policy, DKIM selectors, MTA-STS, BIMI | Email Security |
| `tls_health` | security | **active** | accepted TLS versions; obsolete versions are high | TLS Health |
| `http_methods` | security | **active** | `OPTIONS` Allow list, TRACE echo | HTTP Methods |
| `cookies_cors` | security | **active** | CORS origin reflection with a harmless probe origin | Cookies & CORS |
| `privacy_trackers` | posture | passive | third-party hosts grouped into tracker categories | Privacy & Trackers |
| `js_library_vulns` | posture | passive | library versions against a bundled advisory table | JS Library Vulnerabilities |
| `exposed_files` | security | **active** | ten well-known paths, one request each | Exposed Files |
| `cloud_storage` | inventory | passive | bucket names referenced by the page, not probed | Cloud Storage |
| `asset_inventory` | inventory | none | hosts, addresses, certificate names and technologies in one table | Asset Inventory |
| `react_exposure` | security | passive | development bundles and sensitive `__NEXT_DATA__` keys | WebQ React source view |

## Intrusive checks

`port_exposure`, `dns_zone_transfer`, `tls_health`, `http_methods`,
`cookies_cors` and `exposed_files` send traffic a passive observer would notice.
They run only when the operator passes `--active` **and** the scope covers the
target. `websec doctor` and the dashboard list them with an `(active)` marker.

## Adding a check

```python
from websec.registry import module

@module("security_txt", label="Security.txt", description="RFC 9116 file",
        group="posture", weight="light", order=200)
def security_txt(ctx):
    response = ctx.page("/.well-known/security.txt")
    if response.error:
        return {"present": False}, []
    return {"present": True}, []
```

A check returns a JSON-serialisable mapping, optionally with `(data, findings)`.
It must not open its own sockets: use `ctx.dns`, `ctx.http`, `ctx.tls`,
`ctx.whois` or `ctx.port`, which enforce the scope. Mark `active=True` for
intrusive traffic and `needs_results=True` to receive earlier results.
