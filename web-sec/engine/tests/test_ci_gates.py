"""CI contracts: severity gates, baselines, job summaries, report covers and CWE/OWASP labels."""
from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

from test_cli import _fake_scan_result, run
from websec import cli as websec_cli
from websec import report as report_module
from websec.history import History
from websec.taxonomy import classify


@pytest.fixture
def scanned(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    monkeypatch.setattr(websec_cli, "run_scan", lambda options, progress=None: _fake_scan_result())
    return tmp_path


@pytest.mark.parametrize("threshold, code", [("none", 0), ("high", 0), ("medium", 4), ("low", 4), ("info", 4)])
def test_fail_on_gates_the_exit_code(scanned, threshold, code):
    result, _, err = run(["scan", "example.test", "--no-history", "--json", "--fail-on", threshold])
    assert result == code
    assert ("gate:" in err) is (code == 4)


def test_baseline_counts_only_new_findings(scanned):
    baseline = scanned / "baseline.json"
    code, out, _ = run(["scan", "example.test", "--no-history", "--json"])
    baseline.write_text(out, encoding="utf-8")
    code, _, err = run(["scan", "example.test", "--no-history", "--json", "--fail-on", "medium",
                        "--baseline", str(baseline)])
    assert code == 0, err
    assert "0 new finding(s) since the baseline" in err
    # a baseline without the CSP finding makes it new, so the gate fails
    document = json.loads(baseline.read_text(encoding="utf-8"))
    document["findings"] = []
    baseline.write_text(json.dumps(document), encoding="utf-8")
    code, _, err = run(["scan", "example.test", "--no-history", "--json", "--fail-on", "medium",
                        "--baseline", str(baseline)])
    assert code == 4 and "1 new finding(s)" in err


def test_baseline_can_be_a_stored_report_name_and_must_match_the_target(scanned):
    code, _, _ = run(["scan", "example.test", "--json"])
    name = History().list("example.test")[0]["name"]
    code, _, err = run(["scan", "example.test", "--no-history", "--json", "--baseline", name, "--fail-on", "low"])
    assert code == 0, err
    other = scanned / "other.json"
    other.write_text(json.dumps({"target": "other.test", "findings": []}), encoding="utf-8")
    code, _, err = run(["scan", "example.test", "--no-history", "--baseline", str(other)])
    assert code == 2 and "another target" in err


def test_summary_is_appended_for_the_ci_job(scanned):
    summary = scanned / "summary.md"
    summary.write_text("earlier step\n", encoding="utf-8")
    run(["scan", "example.test", "--no-history", "--json", "--summary", str(summary), "--fail-on", "medium"])
    text = summary.read_text(encoding="utf-8")
    assert text.startswith("earlier step\n")
    assert "grade A (90/100)" in text
    assert "Content-Security-Policy is missing" in text and "CWE-693" in text
    assert "**failed** (1)" in text


def test_cover_reaches_html_and_markdown(scanned):
    code, out, _ = run(["scan", "example.test", "--no-history", "--format", "html",
                        "--client", "Acme <Ltd>", "--author", "Blue team", "--title", "Quarterly review"])
    assert code == 0
    assert "<h1>Quarterly review</h1>" in out
    assert "Prepared for Acme &lt;Ltd&gt;" in out and "by Blue team" in out
    code, out, _ = run(["scan", "example.test", "--no-history", "--format", "markdown", "--client", "Acme"])
    assert out.startswith("# Web Sec Lab report — example.test") or "Prepared for Acme" in out


def test_findings_carry_cwe_and_owasp_into_sarif(scanned):
    code, out, _ = run(["scan", "example.test", "--no-history", "--format", "sarif"])
    sarif = json.loads(out)
    rule = sarif["runs"][0]["rules"][0] if "rules" in sarif["runs"][0] else sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "external/cwe/cwe-693" in rule["properties"]["tags"]
    assert any(tag.startswith("owasp/A05") for tag in rule["properties"]["tags"])
    assert sarif["runs"][0]["results"][0]["properties"]["cwe"] == "CWE-693"


@pytest.mark.parametrize("module, kind, title, cwe", [
    ("security_analysis", "hsts_missing", "Strict-Transport-Security is missing", "CWE-319"),
    ("cookies_cors", "", "CORS reflects any Origin with credentials", "CWE-942"),
    ("cookies_cors", "", "Session cookie without HttpOnly", "CWE-614"),
    ("content_scan", "", "AWS access key id in a served script", "CWE-798"),
    ("email_security", "", "No DMARC record", "CWE-290"),
    ("port_exposure", "", "Redis answers on 6379", "CWE-668"),
    ("dns_zone_transfer", "", "Open AXFR on ns1", "CWE-200"),
])
def test_taxonomy_classifies_conservatively(module, kind, title, cwe):
    assert classify(module, kind, title)["cwe"] == cwe


def test_taxonomy_leaves_unclear_findings_unclassified():
    assert classify("seo_analysis", "", "The page has no meta description") is None


def test_stored_reports_from_before_the_mapping_are_labelled_on_read(scanned):
    old = {"target": "example.test", "url": "https://example.test", "started_at": "x", "duration_seconds": 1,
           "preset": "quick", "active": False, "score": 90, "grade": "A", "refused": False, "refusal": "",
           "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total": 1},
           "modules": [], "findings": [{"module": "security_analysis", "severity": "medium",
                                        "title": "Content-Security-Policy is missing", "detail": "",
                                        "evidence": "", "remediation": "", "refs": [], "kind": ""}]}
    labelled = report_module.with_taxonomy(old)
    assert labelled["findings"][0]["cwe"] == "CWE-693"
    assert "cwe" not in old["findings"][0]  # the stored document is not mutated


def test_compare_fail_on_new(scanned):
    folder = History().reports_dir("example.test")
    for name, findings in (("20261101T000000Z-95.json", []),
                           ("20261124T000000Z-90.json", [{"module": "m", "kind": "k", "severity": "high", "title": "t"}])):
        with open(f"{folder}/{name}", "w", encoding="utf-8") as handle:
            json.dump({"target": "example.test", "score": 90, "grade": "A", "summary": {}, "findings": findings,
                       "modules": []}, handle)
    argv = ["compare", "--target", "example.test", "--old", "20261101T000000Z-95.json",
            "--new", "20261124T000000Z-90.json", "--json"]
    code, out, _ = run(argv + ["--fail-on-new", "high"])
    assert code == 4 and json.loads(out)["gate"] == {"threshold": "high", "failed": 1}
    code, _, _ = run(argv + ["--fail-on-new", "critical"])
    assert code == 0


def test_bulk_reads_stdin_and_honours_concurrency(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    seen = []
    monkeypatch.setattr(websec_cli, "run_scan",
                        lambda options: seen.append(options.target) or SimpleNamespace(score=96, grade="A", summary={"total": 0}))
    monkeypatch.setattr("sys.stdin", io.StringIO("# hosts\none.test\ntwo.test\n"))
    code, out, _ = run(["bulk", "-", "--json", "--concurrency", "1"])
    assert code == 0 and sorted(seen) == ["one.test", "two.test"]
    assert json.loads(out)["count"] == 2
    code, out, _ = run(["bulk", "-", "--concurrency", "99"])
    assert code == 2 and "concurrency" in out


def test_the_github_action_only_uses_flags_the_scan_command_has():
    import os
    import re
    action = os.path.join(os.path.dirname(__file__), "..", "..", "action.yml")
    with open(action, encoding="utf-8") as handle:
        text = handle.read()
    used = set(re.findall(r"(--[a-z][a-z-]+)", text))
    scan_parser = websec_cli.build_parser()._subparsers._group_actions[0].choices["scan"]
    known = {flag for action_ in scan_parser._actions for flag in action_.option_strings}
    assert used and used <= known, used - known
    assert "OSLAB_SCOPE_FILE" in text and "--no-history" in text
