"""CLI contracts: status, catalogue, and a refusal before any network call."""
from __future__ import annotations

import contextlib
import io
import json

import pytest

from websec.cli import main


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


@pytest.mark.parametrize("argv", [["scan"], ["nonsense"]])
def test_bad_usage_exits_without_tracebacks(argv):
    with pytest.raises(SystemExit):
        run(argv)


def test_no_command_prints_help_and_returns_2():
    code, out, _ = run([])
    assert code == 2
    assert "usage" in out.lower()
