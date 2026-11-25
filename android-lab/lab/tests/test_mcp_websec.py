"""Web Sec Lab MCP tools run the same console API, engine and scope guard as the workbench."""
import json
import os
import sys

import pytest

REPO_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "console"))
sys.path.insert(0, os.path.dirname(__file__))

import mcp_server  # noqa: E402
from test_websec_console import forbid_scans  # noqa: E402
import websec_api  # noqa: E402

EXPECTED = {"websec_status", "websec_catalogue", "websec_guides", "websec_preferences", "websec_history",
            "websec_reports", "websec_report", "websec_compare", "websec_job", "websec_review", "websec_scan",
            "websec_scan_cancel", "websec_bulk", "websec_preferences_save", "websec_monitor",
            "websec_monitor_config", "websec_monitor_run", "websec_stats", "websec_favourite",
            "websec_delete_runs", "websec_clear_history"}


def rpc(name, args=None, key="arguments"):
    reply = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": name, key: args or {}}})
    return reply["result"]["isError"], json.loads(reply["result"]["content"][0]["text"])


@pytest.fixture
def lab(tmp_path, monkeypatch):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({
        "version": 1, "name": "mcp test", "author" "ization": "unit test only",
        "expires": "2099-01-01", "hosts": ["localhost"], "packages": [], "devices": [], "paths": [],
    }), encoding="utf-8")
    monkeypatch.setenv("OSLAB_SCOPE_FILE", str(scope))
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    api = websec_api.api_for(REPO_ROOT)
    monkeypatch.setattr(api, "storage", tmp_path / "storage")
    monkeypatch.setattr(api, "jobs", {})
    return api


def test_every_websec_ability_is_a_listed_tool_with_a_schema():
    listed = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
    names = {tool["name"] for tool in listed}
    assert EXPECTED <= names
    assert "cleanup_review" in names and "macos_stop" in names  # the other tools are still there
    for tool in listed:
        if tool["name"].startswith("websec_"):
            assert tool["inputSchema"]["type"] == "object"
            assert tool["inputSchema"]["additionalProperties"] is False


def test_read_only_tools_answer_from_the_engine(lab):
    failed, catalogue = rpc("websec_catalogue")
    assert not failed
    by_id = {module["id"]: module for module in catalogue["modules"]}
    assert by_id["port_exposure"]["active"] is True and by_id["tls_health"]["guide"] == "tls"
    failed, guides = rpc("websec_guides")
    assert not failed and guides["guides"]
    failed, prefs = rpc("websec_preferences")
    assert not failed and prefs["preferences"]["scan"]["preset"] == "standard"
    failed, saved = rpc("websec_preferences_save", {"preferences": {"scan": {"preset": "quick"}}})
    assert not failed and saved["preferences"]["scan"]["preset"] == "quick"
    # the legacy "args" key still works
    failed, prefs = rpc("websec_preferences", key="args")
    assert not failed and prefs["preferences"]["scan"]["preset"] == "quick"


def test_review_never_scans_and_an_active_scan_needs_confirmation(lab, monkeypatch):
    forbid_scans(monkeypatch, websec_api)
    failed, plan = rpc("websec_review", {"target": "localhost", "preset": "full", "active": True})
    assert not failed
    assert "port_exposure" in plan["intrusive"] and "confirm: true" in plan["next"]
    failed, refusal = rpc("websec_scan", {"target": "localhost", "active": True})
    assert failed and refusal["code"] == "CONFIRM_REQUIRED"
    failed, refusal = rpc("websec_scan", {"target": "localhost", "active": True, "confirm": False})
    assert failed and refusal["code"] == "CONFIRM_REQUIRED"
    assert lab.jobs == {}


def test_scan_waits_for_the_job_and_returns_a_graded_summary(lab, monkeypatch):
    report = {"target": "localhost", "grade": "B", "score": 84, "summary": {"total": 1}, "refused": False,
              "refusal": "", "modules": [{"id": "dns_records", "status": "ok", "findings": 1, "data": {"big": "x"}}],
              "findings": [{"severity": "medium", "module": "dns_records", "title": "No CAA record",
                            "remediation": "Add a CAA record.", "evidence": "..."}]}
    sent = {}

    def start(payload):
        sent.update(payload)
        return {"id": "j1", "state": "running", "kind": "scan", "target": "localhost",
                "preset": "quick", "active": False, "started": 1}

    monkeypatch.setattr(lab, "start_scan", start)
    monkeypatch.setattr(lab, "job", lambda job_id: {"id": job_id, "state": "done", "kind": "scan",
                                                     "target": "localhost", "preset": "quick", "active": False,
                                                     "started": 1, "report": report})
    failed, result = rpc("websec_scan", {"target": "localhost", "preset": "quick", "timeoutSeconds": 5})
    assert not failed
    assert sent == {"target": "localhost", "preset": "quick", "active": False}
    assert result["report"]["grade"] == "B"
    assert result["report"]["findings"] == [{"severity": "medium", "module": "dns_records",
                                             "title": "No CAA record", "remediation": "Add a CAA record."}]
    assert "data" not in result["report"]["modules"][0]


def test_tools_refuse_unknown_arguments_paths_and_out_of_scope_targets(lab, monkeypatch):
    forbid_scans(monkeypatch, websec_api)
    for name, args in (("websec_status", {"path": "/"}), ("websec_scan", {"target": "localhost", "command": "nmap"}),
                       ("websec_report", {"target": "localhost", "name": "../../etc/passwd"}),
                       ("websec_scan", {"target": "localhost", "timeoutSeconds": 0}),
                       ("websec_history", {"limit": "all"}), ("websec_job", {})):
        failed, payload = rpc(name, args)
        assert failed, (name, args)
        assert payload["code"] in ("INVALID_ARGS", "WEBSEC_400"), payload
    failed, payload = rpc("websec_scan", {"target": "example.com"})
    assert failed and payload["code"] == "WEBSEC_403"


def test_compare_defaults_to_the_latest_two_runs(lab, tmp_path):
    folder = tmp_path / "storage" / "reports" / "localhost"
    folder.mkdir(parents=True)
    for name, score, grade in (("20261101T000000Z-80.json", 80, "B"), ("20261124T000000Z-96.json", 96, "A+")):
        (folder / name).write_text(json.dumps({"target": "localhost", "score": score, "grade": grade,
                                               "summary": {}, "findings": [], "modules": []}), encoding="utf-8")
        os.utime(folder / name, (int(name[:8]), int(name[:8])))
    failed, diff = rpc("websec_compare", {"target": "localhost"})
    assert not failed, diff
    assert diff["grade"] == {"current": "A+", "previous": "B"}
    failed, payload = rpc("websec_compare", {"target": "nothing.here"})
    assert failed


def test_monitor_tools_configure_and_run_through_the_engine(lab, monkeypatch):
    forbid_scans(monkeypatch, websec_api)
    failed, status = rpc("websec_monitor")
    assert not failed and status["config"]["enabled"] is False and status["runner"]["alive"] is False
    failed, refusal = rpc("websec_monitor_config", {"config": {"enabled": True, "targets": ["localhost"], "preset": "full"}})
    assert failed and refusal["code"] == "WEBSEC_400"
    failed, saved = rpc("websec_monitor_config", {"config": {"enabled": False, "targets": ["localhost"]}})
    assert not failed and saved["config"]["targets"] == ["localhost"]
    # a check now with the monitor off still runs a forced tick (the scan itself is the engine's)
    monkeypatch.setattr(lab, "_run", lambda args, timeout=20.0: type("R", (), {
        "returncode": 0, "stdout": json.dumps({"newEvents": [], "scanned": ["localhost"]}), "stderr": ""})())
    failed, ran = rpc("websec_monitor_run")
    assert not failed and ran["queued"] is False and ran["lastTick"]["scanned"] == 1


def test_run_management_needs_confirmation_to_delete(lab, tmp_path):
    folder = tmp_path / "storage" / "reports" / "localhost"
    folder.mkdir(parents=True)
    (folder / "20261124T000000Z-96.json").write_text(json.dumps({"target": "localhost", "findings": []}), encoding="utf-8")
    failed, stats = rpc("websec_stats")
    assert not failed and "runs" in stats
    failed, marked = rpc("websec_favourite", {"target": "localhost", "name": "20261124T000000Z-96.json"})
    assert not failed and marked["favourite"] is True
    for name, args in (("websec_delete_runs", {"target": "localhost", "names": ["20261124T000000Z-96.json"]}),
                       ("websec_clear_history", {"all": True, "confirm": False})):
        failed, refusal = rpc(name, args)
        assert failed and refusal["code"] in ("CONFIRM_REQUIRED", "INVALID_ARGS")
    assert (folder / "20261124T000000Z-96.json").exists()
    failed, done = rpc("websec_delete_runs", {"target": "localhost", "names": ["20261124T000000Z-96.json"], "confirm": True})
    assert not failed and done["deleted"] == 1
    failed, refusal = rpc("websec_clear_history", {"confirm": True})
    assert failed and refusal["code"] == "WEBSEC_400"
