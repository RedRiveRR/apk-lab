"""Catalogue, DNS codec, report formats and scope plumbing."""
from __future__ import annotations

import json
import os
import struct
import sys
import textwrap

import pytest

from conftest import ZONE, FakeDns, FakeHttp, FakeTls, FakeWhois, make_context, page
from websec import grade, registry, report
from websec.config import Options, normalize_target
from websec.net.dns import DnsError, build_query, encode_name, parse_message
from websec.scope import AllowAll, Guard, ScopeRefused
from websec.version import VERSION


# ── config ───────────────────────────────────────────────────────────────────

def test_normalize_target_accepts_urls_and_addresses():
    assert normalize_target("https://Example.COM/path?q=1") == "example.com"
    assert normalize_target("example.com:8443") == "example.com"
    assert normalize_target("127.0.0.1") == "127.0.0.1"
    assert normalize_target("::1") == "::1"


def test_options_keep_an_explicit_port_in_the_url():
    options = Options.build("127.0.0.1:8765", scheme="http")
    assert options.target == "127.0.0.1"
    assert options.port == 8765
    assert options.url == "http://127.0.0.1:8765"
    assert Options.build("example.test").url == "https://example.test"
    with pytest.raises(ValueError):
        Options.build("example.test:99999")


@pytest.mark.parametrize("bad", ["", "  ", "*.example.com", "example.com#x", "exa mple.com"])
def test_normalize_target_refuses_wildcards_and_spaces(bad):
    with pytest.raises(ValueError):
        normalize_target(bad)


def test_options_reject_out_of_range_budgets():
    with pytest.raises(ValueError):
        Options.build(ZONE, max_pages=1000)
    with pytest.raises(ValueError):
        Options.build(ZONE, preset="everything")
    options = Options.build(ZONE, modules="dns_records,security_analysis")
    assert options.modules == ("dns_records", "security_analysis")


# ── registry ─────────────────────────────────────────────────────────────────

def test_catalogue_has_every_port_and_active_flags():
    from websec.catalog import ensure_loaded
    ensure_loaded()
    entries = {entry["id"]: entry for entry in registry.catalogue()}
    assert len(entries) >= 28
    assert entries["port_exposure"]["active"] is True
    assert entries["domain_info"]["active"] is False
    assert entries["domain_info"]["label"]


def test_presets_and_unknown_modules():
    from websec.catalog import ensure_loaded
    ensure_loaded()
    quick = [spec.id for spec in registry.select(None, "quick")]
    assert quick == ["domain_info", "dns_records", "geo_analysis"]
    assert len(registry.select(None, "full")) >= 28
    with pytest.raises(ValueError):
        registry.select(["nope"], "quick")


def test_duplicate_registration_is_refused():
    spec = registry.ModuleSpec(id="demo_check", label="Demo", run=lambda ctx: {})
    registry.register(spec)
    try:
        with pytest.raises(ValueError):
            registry.register(spec)
    finally:
        registry.unregister("demo_check")


def test_plugin_discovery_loads_an_external_file(tmp_path):
    plugin = tmp_path / "external_demo.py"
    plugin.write_text(textwrap.dedent("""
        from websec.registry import module

        @module("external_demo", label="External demo", description="fixture",
                group="inventory", weight="light", order=999)
        def external_demo(ctx):
            return {"ok": True}
    """), encoding="utf-8")
    loaded = registry.discover_plugins([str(tmp_path)])
    assert any(name.endswith("external_demo") for name, error in loaded if error is None)
    assert registry.get("external_demo") is not None
    registry.unregister("external_demo")


# ── DNS codec ────────────────────────────────────────────────────────────────

def _record(name: str, rtype: int, rdata: bytes) -> bytes:
    return encode_name(name) + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata


def _message(answers, qid=0x4242, rcode=0):
    header = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0)
    return header + encode_name(ZONE) + struct.pack(">HH", 1, 1) + b"".join(answers)


def test_dns_parses_a_compressed_cname_and_addresses():
    data = _message([
        _record(ZONE, 1, bytes([203, 0, 113, 10])),
        _record(ZONE, 5, b"\xc0\x0c"),
        _record(ZONE, 15, struct.pack(">H", 10) + encode_name("mail.example.test")),
    ])
    message = parse_message(data)
    assert message["rcode"] == 0
    assert len(message["answers"]) == 3
    values = [record["value"] for record in message["answers"]]
    assert "203.0.113.10" in values
    assert ZONE in values
    assert {"preference": 10, "exchange": "mail.example.test"} in values


def test_dns_parses_txt_and_soa():
    txt = b"\x0bv=spf1 -all"
    soa = (encode_name("ns1.example.test") + encode_name("hostmaster.example.test")
           + struct.pack(">IIIII", 7, 3600, 600, 86400, 300))
    message = parse_message(_message([_record(ZONE, 16, txt), _record(ZONE, 6, soa)]))
    assert message["answers"][0]["value"] == "v=spf1 -all"
    assert message["answers"][1]["value"]["serial"] == 7


def test_dns_query_is_well_formed():
    identifier, packet = build_query("example.test", "A", qid=1)
    assert identifier == 1
    assert packet[:2] == b"\x00\x01"
    assert packet.endswith(b"\x00" + struct.pack(">HH", 1, 1))
    assert encode_name("example.test") == b"\x07example\x04test\x00"


def test_dns_refuses_a_truncated_message():
    with pytest.raises(DnsError):
        parse_message(b"\x00\x01")


def test_dns_reports_nxdomain():
    message = parse_message(_message([], rcode=3))
    assert message["rcode"] == 3


# ── grade and report ─────────────────────────────────────────────────────────

def test_grade_penalties_are_capped():
    from websec.models import Finding
    clean = []
    assert grade.score_and_grade(clean) == (100, "A+")
    one = [Finding(module="m", severity="critical", title="boom")]
    assert grade.score_and_grade(one) == (75, "C")
    noisy = [Finding(module="m", severity="info", title=f"n{i}") for i in range(20)]
    assert grade.score_and_grade(noisy) == (100, "A+")


def test_report_json_sarif_and_markdown_agree():
    from websec.runner import run_scan
    ctx = make_context(http=FakeHttp({f"https://{ZONE}/": page("<html lang='en'><title>Example test page with a long enough title</title></html>")}))
    result = run_scan(Options.build(ZONE, modules="security_txt"), context=ctx)
    document = report.build(result)
    assert document["tool"]["version"] == VERSION
    assert document["summary"]["total"] == 0
    sarif = json.loads(report.to_sarif(document))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "oslab-websec"
    markdown = report.to_markdown(document)
    assert f"# Web Sec Lab report — {ZONE}" in markdown
    assert "## Modules" in markdown
    assert "Grade" in markdown


def test_report_sarif_maps_severity():
    from websec.models import Finding
    from websec.runner import ScanResult
    options = Options.build(ZONE, modules="security_txt")
    result = ScanResult(target=ZONE, url=options.url, started_at="", duration_seconds=0.1,
                        options=options)
    from websec.models import ModuleOutcome
    result.outcomes["security_txt"] = ModuleOutcome(
        id="security_txt", label="Security.txt", findings=[
            Finding(module="security_txt", severity="high", title="A", remediation="fix A")])
    document = report.build(result)
    sarif = json.loads(report.to_sarif(document))
    run = sarif["runs"][0]
    assert run["results"][0]["level"] == "error"
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"
    assert run["results"][0]["ruleId"].startswith("WEBSEC/security_txt/")


def test_html_report_escapes_content():
    from websec.models import Finding, ModuleOutcome
    from websec.runner import ScanResult
    options = Options.build(ZONE, modules="security_txt")
    result = ScanResult(target=ZONE, url=options.url, started_at="", duration_seconds=0.1,
                        options=options)
    result.outcomes["security_txt"] = ModuleOutcome(
        id="security_txt", label="Security.txt",
        findings=[Finding(module="security_txt", severity="low", title="<script>x</script>")])
    html = report.to_html(report.build(result))
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


# ── scope ────────────────────────────────────────────────────────────────────

def test_guard_refuses_an_undeclared_host(tmp_path):
    manifest = tmp_path / "scope.json"
    manifest.write_text(json.dumps({
        "version": 1, "name": "unit", "author" "ization": "unit test only",
        "expires": "2099-01-01", "hosts": ["localhost", "127.0.0.1"],
        "packages": [], "devices": [], "paths": [],
    }), encoding="utf-8")
    guard = Guard(str(manifest))
    guard.require("host", "localhost")
    with pytest.raises(ScopeRefused):
        guard.require("host", "example.com")
    status = guard.status()
    assert status["valid"] is True


def test_allow_all_is_explicitly_a_fixture():
    assert AllowAll().require("host", "example.com")["allowed"] is True
