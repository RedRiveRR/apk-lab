"""Workbench contracts: saved choices, the no-network plan, stored-report compare, guides."""
from __future__ import annotations

import contextlib
import io
import json
import os
import stat

import pytest

from websec import preferences
from websec.cli import main
from websec.guides import GUIDES, guides
from websec.history import History
from websec.registry import catalogue


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def storage(tmp_path, monkeypatch):
    root = tmp_path / "storage"
    monkeypatch.setenv("WEBSEC_STORAGE", str(root))
    return root


# ── preferences ──────────────────────────────────────────────────────────────

def test_preferences_default_when_nothing_is_stored(storage):
    loaded = preferences.load()
    assert loaded["configError"] is None
    assert loaded["preferences"]["scan"]["preset"] == "standard"
    assert loaded["preferences"]["bulk"]["preset"] == "quick"


def test_preferences_round_trip_privately_and_keep_unknown_check_ids(storage):
    saved = preferences.save({"scan": {"target": "Example.TEST", "preset": "quick", "scheme": "http",
                                       "modules": ["dns_records", "a_future_check"], "timeout": 12,
                                       "deadline": None},
                              "bulk": {"preset": "full"}})
    assert saved["preferences"]["scan"]["target"] == "example.test"
    loaded = preferences.load()
    assert loaded["preferences"] == saved["preferences"]
    # a later catalogue may list the id again, so it is kept, not deleted
    assert "a_future_check" in loaded["preferences"]["scan"]["modules"]
    mode = stat.S_IMODE(os.stat(storage / "preferences.json").st_mode)
    assert mode & 0o077 == 0


@pytest.mark.parametrize("value, message", [
    ({"scan": {"preset": "loud"}}, "preset"),
    ({"scan": {"timeout": 99}}, "timeout"),
    ({"scan": {"active": True}}, "Unknown scan key"),
    ({"scan": {"modules": ["Bad Id"]}}, "check id"),
    ({"extra": {}}, "Unknown preferences key"),
])
def test_preferences_refuse_bad_values_and_never_store_intrusive_mode(storage, value, message):
    with pytest.raises(preferences.PreferencesError, match=message):
        preferences.save(value)


def test_preferences_from_another_version_are_read_and_corruption_falls_back(storage):
    storage.mkdir(parents=True)
    path = storage / "preferences.json"
    path.write_text(json.dumps({"version": 7, "preferences": {"scan": {"preset": "full"}}}), encoding="utf-8")
    assert preferences.load()["preferences"]["scan"]["preset"] == "full"
    path.write_text("{not json", encoding="utf-8")
    broken = preferences.load()
    assert broken["preferences"] == preferences.defaults()
    assert "unreadable" in broken["configError"]


def test_prefs_cli_saves_and_refuses(storage):
    code, out, _ = run(["prefs", "--save", json.dumps({"scan": {"preset": "full"}}), "--json"])
    assert code == 0 and json.loads(out)["preferences"]["scan"]["preset"] == "full"
    code, out, _ = run(["prefs", "--json"])
    assert json.loads(out)["preferences"]["scan"]["preset"] == "full"
    code, _, err = run(["prefs", "--save", json.dumps({"scan": {"preset": "loud"}})])
    assert code == 2 and "preset" in err


# ── plan ─────────────────────────────────────────────────────────────────────

def _scope(tmp_path, hosts):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({
        "version": 1, "name": "plan test", "author" "ization": "unit test only",
        "expires": "2099-01-01", "hosts": hosts, "packages": [], "devices": [], "paths": [],
    }), encoding="utf-8")
    return str(path)


def test_plan_lists_checks_without_network_and_holds_back_intrusive_ones(tmp_path, storage, monkeypatch):
    monkeypatch.delenv("OSLAB_SCOPE_FILE", raising=False)
    scope = _scope(tmp_path, ["localhost"])
    code, out, _ = run(["plan", "localhost", "--preset", "full", "--scope", scope, "--json"])
    assert code == 0
    plan = json.loads(out)
    assert plan["scope"]["allowed"] is True
    by_id = {entry["id"]: entry for entry in plan["checks"]}
    assert by_id["port_exposure"]["runs"] is False
    assert "intrusive" in by_id["port_exposure"]["note"]
    assert by_id["dns_records"]["runs"] is True
    assert plan["intrusive"] == []
    assert "port_exposure" in plan["available_intrusive"]

    code, out, _ = run(["plan", "localhost", "--preset", "full", "--active", "--scope", scope, "--json"])
    assert "port_exposure" in json.loads(out)["intrusive"]


def test_plan_refuses_a_target_outside_the_scope(tmp_path, storage, monkeypatch):
    monkeypatch.delenv("OSLAB_SCOPE_FILE", raising=False)
    code, out, _ = run(["plan", "example.com", "--scope", _scope(tmp_path, ["localhost"]), "--json"])
    assert code == 1
    plan = json.loads(out)
    assert plan["scope"]["allowed"] is False
    assert plan["runs"] == 0


def test_plan_refuses_an_unknown_check(storage):
    code, _, err = run(["plan", "localhost", "--modules", "no_such_check"])
    assert code == 2 and "no_such_check" in err


# ── compare ──────────────────────────────────────────────────────────────────

def _store(name, document):
    history = History()
    path = os.path.join(history.reports_dir(document["target"]), name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle)


def _doc(score, grade, findings, modules=()):
    return {"target": "example.test", "started_at": "2026-11-24T00:00:00+00:00", "preset": "standard",
            "score": score, "grade": grade, "summary": {"total": len(findings)},
            "findings": findings, "modules": list(modules)}


def test_compare_reports_new_and_resolved_findings(storage):
    csp = {"module": "security_analysis", "kind": "csp_missing", "severity": "medium", "title": "CSP is missing"}
    hsts = {"module": "security_analysis", "kind": "hsts_missing", "severity": "high", "title": "HSTS is missing"}
    _store("20261101T000000Z-80.json", _doc(80, "B", [csp, hsts], [{"id": "tls_health", "status": "ok"}]))
    _store("20261124T000000Z-90.json", _doc(90, "A", [{**csp, "title": "CSP is still missing"}],
                                            [{"id": "tls_health", "status": "error"}]))
    code, out, _ = run(["compare", "--target", "example.test", "--old", "20261101T000000Z-80.json",
                        "--new", "20261124T000000Z-90.json", "--json"])
    assert code == 0
    diff = json.loads(out)
    assert diff["score"] == {"current": 90, "previous": 80, "delta": 10}
    assert diff["grade"] == {"current": "A", "previous": "B"}
    assert diff["new"] == []  # a reworded finding is the same finding
    assert [item["title"] for item in diff["resolved"]] == ["HSTS is missing"]
    assert diff["modules"] == [{"id": "tls_health", "previous": "ok", "current": "error"}]
    assert diff["from"]["name"] == "20261101T000000Z-80.json"


def test_compare_refuses_names_outside_the_report_folder(storage):
    code, _, err = run(["compare", "--target", "example.test", "--old", "../x.json", "--new", "y.json"])
    assert code == 2 and "cannot read" in err


# ── guides ───────────────────────────────────────────────────────────────────

def test_every_check_has_exactly_one_guide():
    ids = [entry["id"] for entry in catalogue()]
    covered = [check for guide in GUIDES for check in guide["checks"]]
    assert sorted(covered) == sorted(set(covered)), "a check is in two guides"
    assert sorted(set(ids) - set(covered)) == [], "a check has no guide"
    assert sorted(set(covered) - set(ids)) == [], "a guide names a check the catalogue lacks"
    assert guides()["byCheck"]["tls_health"] == "tls"


def test_guides_cli_lists_every_guide(storage):
    code, out, _ = run(["guides", "--json"])
    assert code == 0
    assert len(json.loads(out)["guides"]) == len(GUIDES)


def test_modules_json_lists_preset_membership(storage):
    code, out, _ = run(["modules", "--json"])
    presets = json.loads(out)["presets"]
    assert presets["quick"] == ["domain_info", "dns_records", "geo_analysis"]
    assert "port_exposure" not in presets["standard"] and "port_exposure" in presets["full"]


def test_guides_carry_reference_tables_from_the_checks():
    from websec.config import DEFAULT_PORTS
    ref = guides()["reference"]
    assert [row["port"] for row in ref["ports"]] == list(DEFAULT_PORTS)
    assert {row["kind"] for row in ref["ports"]} <= {"database", "plaintext", "admin", "service"}
    assert next(row for row in ref["ports"] if row["port"] == 6379) == {"port": 6379, "service": "Redis", "kind": "database"}
    assert ref["headers"][0]["header"] == "Strict-Transport-Security"
