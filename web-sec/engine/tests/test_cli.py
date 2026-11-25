"""CLI contracts: status, catalogue, and a refusal before any network call."""
from __future__ import annotations

import contextlib
import io
import json
from types import SimpleNamespace

import pytest

from websec import cli as websec_cli
from websec.cli import main
from websec.history import History
from websec.models import Finding
from websec.scope import ScopeRefused


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def test_status_json_reports_the_catalogue(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    code, out, _ = run(["status", "--json"])
    assert code == 0
    payload = json.loads(out)
    assert payload["version"]
    assert payload["modules"] >= 28
    assert payload["plugins"] >= 13
    assert payload["storage"] == str(tmp_path / "storage")


def test_modules_json_marks_the_intrusive_checks(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    code, out, _ = run(["modules", "--json"])
    assert code == 0
    entries = {entry["id"]: entry for entry in json.loads(out)["modules"]}
    assert entries["port_exposure"]["active"] is True
    assert entries["dns_records"]["active"] is False
    assert entries["security_txt"]["label"]


def test_scan_refuses_before_any_network_call(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({
        "version": 1, "name": "cli test", "author" "ization": "unit test only",
        "expires": "2099-01-01", "hosts": ["localhost"], "packages": [], "devices": [], "paths": [],
    }), encoding="utf-8")
    monkeypatch.delenv("OSLAB_SCOPE_FILE", raising=False)
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    code, out, err = run(["scan", "example.com", "--preset", "quick", "--scope", str(scope)])
    assert code == 1
    assert out == ""
    assert "refused" in err.lower()
    assert "example.com" in err


def test_setup_creates_private_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    code, out, _ = run(["setup"])
    assert code == 0
    assert (tmp_path / "storage" / "history").is_dir()
    assert "storage ready" in out


def test_history_entries_carry_the_report_name(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    history = History()
    document = {"target": "example.test", "generated_at": "2026-11-24T00:00:00+00:00",
                "score": 90, "grade": "A", "summary": {"total": 0},
                "preset": "quick", "active": False, "refused": False}
    paths = history.append(document)
    assert paths["name"].endswith("-90.json")
    entries = history.list("example.test")
    assert entries[0]["name"] == paths["name"]
    assert history.load("example.test", paths["name"])["target"] == "example.test"
    code, out, _ = run(["history", "--target", "example.test", "--json"])
    assert code == 0
    assert json.loads(out)["entries"][0]["name"] == paths["name"]


def test_bulk_csv_and_worst_grade_exit_code(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    targets = tmp_path / "targets.txt"
    targets.write_text("a.test\nb.test\nc.test\n", encoding="utf-8")
    grades = {"a.test": (96, "A"), "b.test": (72, "C")}

    def fake_run_scan(options):
        if options.target == "c.test":
            raise ScopeRefused("c.test", "the target is outside the declared scope")
        score, grade = grades[options.target]
        return SimpleNamespace(score=score, grade=grade, summary={"total": 1})

    monkeypatch.setattr(websec_cli, "run_scan", fake_run_scan)
    code, out, _ = run(["bulk", str(targets), "--csv", "--preset", "quick"])
    assert code == 3
    lines = out.strip().splitlines()
    assert lines[0] == "target,grade,score,critical,high,medium,low,info,total,error"
    assert "a.test,A,96,0,0,0,0,0,1," in out
    assert "b.test,C,72,0,0,0,0,0,1," in out
    assert "c.test,,,0,0,0,0,0,0,the target is outside the declared scope" in out
    code, out, _ = run(["bulk", str(targets), "--preset", "quick"])
    assert code == 3


def _fake_scan_result(score=90, grade="A", medium=1):
    finding = Finding(module="security_analysis", severity="medium",
                      title="Content-Security-Policy is missing",
                      remediation="Enforce script-src 'self'.", kind="csp-missing")
    summary = {"critical": 0, "high": 0, "medium": medium, "low": 0, "info": 0, "total": medium}
    return SimpleNamespace(
        target="example.test", url="https://example.test",
        started_at="2026-11-24T00:00:00+00:00", duration_seconds=1.2,
        score=score, grade=grade, summary=summary, refused=False, refusal="",
        options=SimpleNamespace(preset="standard", active=False, keep_history=True),
        as_dict=lambda include_data=True: {
            "target": "example.test", "url": "https://example.test",
            "started_at": "2026-11-24T00:00:00+00:00", "duration_seconds": 1.2,
            "preset": "standard", "active": False, "score": score, "grade": grade,
            "summary": dict(summary), "refused": False, "refusal": "",
            "modules": [{"id": "security_analysis", "label": "Security posture", "status": "ok",
                         "duration_ms": 10, "findings": medium, "error": "", "note": "", "data": {}}],
            "findings": [finding.as_dict()],
        })


def _previous_document(score=95):
    return {
        "tool": {"name": "Web Sec Lab", "version": "0.1.0", "uri": "", "schema_version": 1},
        "generated_at": "2026-11-23T00:00:00+00:00", "target": "example.test",
        "url": "https://example.test", "started_at": "2026-11-23T00:00:00+00:00",
        "duration_seconds": 2.0, "preset": "standard", "active": False, "score": score,
        "grade": "A", "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
        "refused": False, "refusal": "", "modules": [], "findings": [],
    }


def test_scan_diff_against_a_stored_report(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    previous = History().append(_previous_document())
    monkeypatch.setattr(websec_cli, "run_scan", lambda options, progress=None: _fake_scan_result())
    code, out, _ = run(["scan", "example.test", "--preset", "standard",
                        "--diff", previous["name"], "--json"])
    assert code == 0
    diff = json.loads(out)
    assert diff["score"]["delta"] == -5
    assert [item["title"] for item in diff["new"]] == ["Content-Security-Policy is missing"]
    assert diff["resolved"] == []


def test_scan_diff_without_json_renders_lines(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    previous = History().append(_previous_document())
    monkeypatch.setattr(websec_cli, "run_scan", lambda options, progress=None: _fake_scan_result())
    code, out, _ = run(["scan", "example.test", "--diff", previous["name"]])
    assert code == 0
    assert "95 → 90" in out
    assert "new findings: 1" in out


def test_scan_diff_refuses_a_missing_report(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    monkeypatch.setattr(websec_cli, "run_scan", lambda options, progress=None: _fake_scan_result())
    code, out, err = run(["scan", "example.test", "--diff", "20990101T000000Z-99.json", "--json"])
    assert code == 2
    assert "cannot read the previous report" in err


@pytest.mark.parametrize("argv", [["scan"], ["nonsense"]])
def test_bad_usage_exits_without_tracebacks(argv):
    with pytest.raises(SystemExit):
        run(argv)


def test_no_command_prints_help_and_returns_2():
    code, out, _ = run([])
    assert code == 2
    assert "usage" in out.lower()
