"""Check behaviour against scripted transports, plus runner semantics."""
from __future__ import annotations

import time

import pytest

from conftest import ZONE, FakeDns, FakeHttp, FakeTls, FakeWhois, make_context, page
from websec import registry
from websec.config import Options
from websec.models import Finding
from websec.runner import run_scan
from websec.scope import ScopeRefused

LONG_TITLE = "Example test page with a descriptive title for search results"


def _call(module_id: str, ctx, results=None):
    spec = registry.get(module_id)
    assert spec is not None, module_id
    return spec.run(ctx, results or {}) if spec.needs_results else spec.run(ctx)


# ── recon ────────────────────────────────────────────────────────────────────

def test_domain_info_flags_an_expiring_registration():
    whois = FakeWhois({"registrar": ["Example Registrar"], "expiry date": ["2026-12-01"],
                       "name server": ["ns1.example.test", "ns2.example.test"]})
    ctx = make_context(whois=whois)
    data, findings = _call("domain_info", ctx)
    assert data["available"] is True
    assert any(finding.severity in ("high", "medium") for finding in findings)


def test_domain_info_without_whois_is_data_not_an_error():
    ctx = make_context(whois=FakeWhois({}, error="no registry answer"))
    data, findings = _call("domain_info", ctx)
    assert data["available"] is False
    assert findings == []


def test_dns_records_reports_an_unresolved_host():
    ctx = make_context(dns=FakeDns({}, addresses=[]))
    data, findings = _call("dns_records", ctx)
    assert data["addresses"] == []
    assert any(finding.severity == "high" for finding in findings)


def test_geo_and_inventory_use_the_resolved_address():
    dns = FakeDns(addresses=["203.0.113.10"], reverse_map={"203.0.113.10": "ec2.example.amazonaws.com"})
    ctx = make_context(dns=dns)
    data, _ = _call("geo_analysis", ctx)
    assert data["addresses"][0]["hosting"] == "AWS"
    inventory, _ = _call("asset_inventory", ctx, {"dns_records": {"records": {"A": ["203.0.113.10"]}},
                                                  "geo_analysis": data})
    assert inventory["counts"]["addresses"] == 1


def test_seo_flags_missing_metadata_and_alt_text():
    body = "<html><body><img src='a.png'><h2>Only a subheading</h2></body></html>"
    ctx = make_context(http=FakeHttp({f"https://{ZONE}/": page(body)}))
    data, findings = _call("seo_analysis", ctx)
    titles = {finding.title for finding in findings}
    assert "The page has no title element" in titles
    assert "Images without alternative text" in titles
    assert data["images_missing_alt"] == 1


def test_seo_good_page_has_no_high_findings():
    body = (f"<html lang='en'><head><title>{LONG_TITLE}</title>"
            "<meta name='description' content='" + "x" * 70 + "'>"
            "<link rel='canonical' href='https://example.test/'></head>"
            "<body><h1>Example</h1><p>" + "word " * 320 + "</p></body></html>")
    ctx = make_context(http=FakeHttp({
        f"https://{ZONE}/": page(body),
        f"https://{ZONE}/robots.txt": page("User-agent: *"),
        f"https://{ZONE}/sitemap.xml": page("<urlset/>"),
    }))
    _, findings = _call("seo_analysis", ctx)
    assert all(finding.severity in ("low", "info") for finding in findings)


def test_technologies_detect_cms_and_disclose_versions():
    body = ("<html><head><meta name='generator' content='WordPress 5.8'></head>"
            "<body><script src='/wp-content/a.js'></script></body></html>")
    ctx = make_context(http=FakeHttp({f"https://{ZONE}/": page(
        body, headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"})}))
    data, findings = _call("web_technologies", ctx)
    names = {entry["name"] for entry in data["entries"]}
    assert "WordPress" in names and "Nginx" in names
    assert {finding.title for finding in findings} >= {
        "The Server header discloses a version",
        "The X-Powered-By header discloses the stack"}


def test_contact_spy_stays_on_the_host_and_collects_contacts():
    body = ("<html><body><a href='/team'>Team</a>"
            "<a href='https://linkedin.com/company/example'>LinkedIn</a>"
            "<p>write to security@example.test or call +90 555 111 22 33</p></body></html>")
    http = FakeHttp({f"https://{ZONE}/": page(body), f"https://{ZONE}/team": page("<p>team</p>")})
    ctx = make_context(http=http)
    ctx.options.max_pages = 5
    data, _ = _call("contact_spy", ctx)
    assert data["pages_crawled"] == 2
    assert data["emails"][0]["address"] == "security@example.test"
    assert any(entry["network"] == "LinkedIn" for entry in data["socials"])


# ── security ─────────────────────────────────────────────────────────────────

def test_security_analysis_grades_an_unhardened_site_low():
    ctx = make_context(http=FakeHttp({f"https://{ZONE}/": page("<html></html>")}))
    data, findings = _call("security_analysis", ctx)
    assert data["grade"] in ("C", "C-", "D+", "D", "D-", "F")
    titles = {finding.title for finding in findings}
    assert "Content-Security-Policy is missing" in titles
    assert "Strict-Transport-Security is missing" in titles


def test_security_analysis_passes_a_hardened_site():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    }
    ctx = make_context(http=FakeHttp({
        f"https://{ZONE}/": page("<html></html>", headers=headers),
        f"http://{ZONE}/": page("", status=301, headers={"Location": f"https://{ZONE}/"}),
    }))
    data, findings = _call("security_analysis", ctx)
    assert data["grade"] in ("A+", "A", "A-")
    assert all(finding.severity == "info" for finding in findings)


def test_security_analysis_flags_cookie_and_cors_mistakes():
    headers = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    ctx = make_context(http=FakeHttp({f"https://{ZONE}/": page(
        "<html></html>", headers=headers, cookies=["sessionid=abc; Path=/; SameSite=None"])}))
    _, findings = _call("security_analysis", ctx)
    titles = {finding.title for finding in findings}
    assert "CORS allows any origin with credentials" in titles
    assert any("sessionid" in title for title in titles)


def test_content_scan_masks_a_secret_and_reports_one_finding_per_kind():
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    body = (f"<html><script>const k='{key}'; const j='{key}';</script>"
            "<script src='/app.js'></script></html>")
    ctx = make_context(http=FakeHttp({
        f"https://{ZONE}/": page(body),
        f"https://{ZONE}/app.js": page("var t='ghp_" + "a" * 36 + "';"),
    }))
    data, findings = _call("content_scan", ctx)
    kinds = {entry["kind"] for entry in data["secrets"]}
    assert "AWS access key id" in kinds and "GitHub token" in kinds
    assert len([f for f in findings if f.title == "AWS access key id appears in served content"]) == 1
    assert all(key not in f.evidence for f in findings)


def test_security_txt_reports_an_expired_file():
    body = "Contact: mailto:security@example.test\nExpires: 2020-01-01T00:00:00Z\n"
    ctx = make_context(http=FakeHttp({f"https://{ZONE}/.well-known/security.txt": page(body)}))
    data, findings = _call("security_txt", ctx)
    assert data["present"] is True
    assert any("expired" in finding.title for finding in findings)


def test_email_security_flags_missing_dmarc_and_open_spf():
    dns = FakeDns({(ZONE, "TXT"): ["v=spf1 +all"], (f"_dmarc.{ZONE}", "TXT"): []})
    ctx = make_context(dns=dns)
    data, findings = _call("email_security", ctx)
    titles = {finding.title for finding in findings}
    assert "SPF allows every sender" in titles
    assert "No DMARC record is published" in titles
    assert data["dmarc_policy"] == ""


def test_js_library_vulns_compares_versions():
    body = "<html><script src='https://code.jquery.com/jquery-1.12.4.min.js'></script></html>"
    ctx = make_context(http=FakeHttp({f"https://{ZONE}/": page(body)}))
    data, findings = _call("js_library_vulns", ctx)
    assert data["libraries"][0]["library"] == "jQuery"
    assert findings[0].severity == "medium"


def test_port_exposure_flags_a_public_database():
    ctx = make_context(open_ports={6379: "-NOAUTH Authentication required\r\n",
                                  22: "SSH-2.0-OpenSSH_8.9"})
    data, findings = _call("port_exposure", ctx)
    assert [entry["port"] for entry in data["ports"]] == [22, 6379]
    assert any(finding.title.startswith("Redis is reachable") for finding in findings)


def test_exposed_files_reports_a_served_env_file_only_when_it_looks_like_one():
    http = FakeHttp({
        f"GET https://{ZONE}/.env": page("APP_ENV=production\nDEBUG=false\n"),
        f"GET https://{ZONE}/.git/HEAD": page("<html>not git</html>"),
    })
    ctx = make_context(http=http)
    data, findings = _call("exposed_files", ctx)
    assert data["paths"] == ["/.env"]
    assert findings[0].severity == "high"


def test_subdomain_takeover_separates_dangling_from_confirmed():
    dns = FakeDns(chains={"old.example.test": ["myapp.herokuapp.com"],
                          "shop.example.test": ["shop.myshopify.com"]})
    dns.addresses_by_name = {"shop.myshopify.com": ["198.51.100.5"]}
    http = FakeHttp({f"https://shop.example.test": page("Sorry, this shop is currently unavailable.")})
    ctx = make_context(dns=dns, http=http)
    data, findings = _call("subdomain_takeover", ctx,
                           {"subdomain_discovery": {"names": ["old.example.test",
                                                             "shop.example.test"]}})
    assert [entry["name"] for entry in data["dangling"]] == ["old.example.test"]
    assert [entry["name"] for entry in data["confirmed"]] == ["shop.example.test"]
    assert {finding.severity for finding in findings} == {"high", "medium"}


def test_lookalike_domains_reports_registered_variants():
    dns = FakeDns()
    dns.addresses_by_name = {f"examp1e.{ZONE.rsplit('.', 1)[-1]}": ["198.51.100.9"]}
    ctx = make_context(dns=dns)
    data, findings = _call("lookalike_domains", ctx)
    assert data["registered"]
    assert findings[0].severity == "medium"


def test_remediation_plan_orders_by_severity():
    ctx = make_context()
    ctx.findings_by_module = {
        "a": [Finding(module="a", severity="low", title="Low", remediation="fix low")],
        "b": [Finding(module="b", severity="critical", title="Critical", remediation="fix now")],
    }
    data, findings = _call("remediation_plan", ctx, {})
    assert [item["severity"] for item in data["items"]] == ["critical", "low"]
    assert data["top_actions"][0] == "fix now"
    assert findings == []


# ── runner ───────────────────────────────────────────────────────────────────

def test_runner_skips_active_checks_without_the_flag():
    result = run_scan(Options.build(ZONE, modules="port_exposure"), context=make_context())
    outcome = result.outcomes["port_exposure"]
    assert outcome.status == "skipped"
    assert "--active" in outcome.note


def test_runner_records_an_error_without_stopping_the_scan():
    @registry.module("boom", label="Boom", group="inventory")
    def boom(ctx):
        raise RuntimeError("kaboom")

    try:
        result = run_scan(Options.build(ZONE, modules="security_txt,boom"),
                          context=make_context())
    finally:
        registry.unregister("boom")
    assert result.outcomes["security_txt"].status in ("ok", "empty")
    assert result.outcomes["boom"].status == "error"
    assert "kaboom" in result.outcomes["boom"].error


def test_runner_stops_after_a_scope_refusal():
    @registry.module("refuser", label="Refuser", group="inventory")
    def refuser(ctx):
        raise ScopeRefused("other.example", "outside the declared scope")

    try:
        result = run_scan(Options.build(ZONE, modules="refuser,security_txt"),
                          context=make_context())
    finally:
        registry.unregister("refuser")
    assert result.refused is True
    assert result.outcomes["refuser"].status == "refused"
    assert result.outcomes["security_txt"].status == "skipped"


def test_runner_honours_an_expired_budget():
    ctx = make_context()
    ctx.deadline = time.monotonic() - 1
    result = run_scan(Options.build(ZONE, modules="security_txt"), context=ctx)
    assert result.outcomes["security_txt"].status == "skipped"
    assert "budget" in result.outcomes["security_txt"].note


def test_port_exposure_names_a_bannerless_known_port():
    ctx = make_context(open_ports={443: ""})
    data, _ = _call("port_exposure", ctx)
    assert data["ports"][0]["service"] == "HTTPS"


def test_content_scan_follows_imported_chunks_one_level():
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    http = FakeHttp({
        f"https://{ZONE}/": page("<html><script src='/app.js'></script></html>"),
        f"https://{ZONE}/app.js": page("import { probe } from './chunk.js';"),
        f"https://{ZONE}/chunk.js": page(f"const key='{key}';"),
    })
    ctx = make_context(http=http)
    data, _ = _call("content_scan", ctx)
    assert ("GET", f"https://{ZONE}/chunk.js") in http.requests
    assert any(entry["kind"] == "AWS access key id" for entry in data["secrets"])


def test_origin_exposure_recognises_cdn_ranges():
    from websec.checks.origin_exposure import _cdn_for_address
    assert _cdn_for_address("104.16.132.229") == "Cloudflare"
    assert _cdn_for_address("151.101.1.140") == "Fastly"
    assert _cdn_for_address("203.0.113.7") == ""
