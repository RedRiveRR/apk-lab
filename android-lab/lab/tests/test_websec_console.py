"""Web Sec Lab console contracts: readiness, typed plans and API validation."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
CONSOLE = ROOT / "console"
if str(CONSOLE) not in sys.path:
    sys.path.insert(0, str(CONSOLE))

import oslab  # noqa: E402
import websec_api  # noqa: E402
import websec_control  # noqa: E402

READY = {"version": "0.1.0", "python": "3.9.6", "storage": "/tmp/websec",
         "storage_writable": True, "modules": 29, "plugins": 13, "ready": True,
         "scope": {"valid": True, "name": "unit", "hosts": 1, "expires": "2099-01-01"}}


def test_lab_status_is_ready_with_storage_and_scope(monkeypatch):
    monkeypatch.setattr(websec_control, "readiness", lambda root: dict(READY))
    status = websec_control.lab_status(str(ROOT), "macos")
    assert status["state"] == "ready"
    assert status["provider"] == "native-python"
    assert [action["id"] for action in status["actions"]] == ["status", "doctor", "setup"]
    assert all(item["found"] for item in status["requirements"])


def test_lab_status_needs_a_scope(monkeypatch):
    payload = dict(READY, scope={"valid": False, "reason": "no scope declared"})
    monkeypatch.setattr(websec_control, "readiness", lambda root: payload)
    status = websec_control.lab_status(str(ROOT), "linux")
    assert status["state"] == "needs-setup"
    assert any("scope" in reason.lower() for reason in status["reasons"])


def test_lab_status_is_unavailable_without_the_lab(tmp_path, monkeypatch):
    monkeypatch.setattr(websec_control, "readiness", lambda root: {})
    status = websec_control.lab_status(str(tmp_path), "linux")
    assert status["state"] == "unavailable"
    assert status["provider"] is None


def test_build_plan_returns_a_typed_command():
    plan = websec_control.build_plan(str(ROOT), {"lab": "websec", "action": "doctor"})
    assert plan["program"]
    assert plan["args"][0].endswith("web-sec/run.py")
    assert plan["args"][1] == "doctor"
    assert plan["privileged"] is False
    assert "doctor" in plan["display"]


def test_build_plan_refuses_unknown_actions_and_options():
    with pytest.raises(oslab.PlanError):
        websec_control.build_plan(str(ROOT), {"lab": "websec", "action": "scan"})
    with pytest.raises(oslab.PlanError):
        websec_control.build_plan(str(ROOT), {"lab": "websec", "action": "status",
                                              "options": {"target": "example.test"}})
    with pytest.raises(oslab.PlanError):
        websec_control.build_plan(str(ROOT), {"lab": "other", "action": "status"})


def test_api_validates_a_scan_payload(tmp_path):
    api = websec_api.WebSecAPI(str(tmp_path))
    options = api._validate({"target": "Example.test", "preset": "quick",
                             "modules": ["dns_records"], "scheme": "http"})
    assert options["target"] == "example.test"
    assert options["preset"] == "quick"
    with pytest.raises(websec_api.WebSecError):
        api._validate({"target": "example.test", "extra": True})
    with pytest.raises(websec_api.WebSecError):
        api._validate({"target": "-oops"})
    with pytest.raises(websec_api.WebSecError):
        api._validate({"target": "example.test", "preset": "everything"})
    with pytest.raises(websec_api.WebSecError):
        api._validate({"target": "example.test", "modules": ["../etc/passwd"]})


def test_api_refuses_a_second_scan_and_unknown_routes(tmp_path):
    api = websec_api.WebSecAPI(str(tmp_path))
    api.jobs["running"] = {"id": "running", "state": "running", "target": "example.test",
                           "started": 0.0, "process": None}
    with pytest.raises(websec_api.WebSecError) as conflict:
        api.start_scan({"target": "example.test"})
    assert conflict.value.status == 409
    with pytest.raises(websec_api.WebSecError) as missing:
        api.get("/api/websec/unknown", {})
    assert missing.value.status == 404
    with pytest.raises(websec_api.WebSecError):
        api.job("nope")


def test_api_refuses_report_name_traversal(tmp_path):
    api = websec_api.WebSecAPI(str(tmp_path))
    with pytest.raises(websec_api.WebSecError):
        api.report("example.test", "../../secret.json", "json")
    with pytest.raises(websec_api.WebSecError):
        api.report("example.test", "20260101T000000Z-90.json", "exe")


def test_api_for_is_one_object_per_checkout(tmp_path):
    first = websec_api.api_for(str(tmp_path))
    second = websec_api.api_for(str(tmp_path))
    assert first is second
    assert first.jobs is second.jobs


def test_api_validates_pacing_overrides(tmp_path):
    api = websec_api.WebSecAPI(str(tmp_path))
    options = api._validate({"target": "example.test", "timeout": 12, "deadline": "120"})
    assert options["timeout"] == 12.0
    assert options["deadline"] == 120.0
    with pytest.raises(websec_api.WebSecError):
        api._validate({"target": "example.test", "timeout": 0.5})
    with pytest.raises(websec_api.WebSecError):
        api._validate({"target": "example.test", "timeout": "soon"})
    with pytest.raises(websec_api.WebSecError):
        api._validate({"target": "example.test", "deadline": 900})


def test_start_scan_passes_pacing_to_the_engine(tmp_path, monkeypatch):
    api = websec_api.WebSecAPI(str(tmp_path))
    api.runner = tmp_path / "run.py"
    api.runner.write_text("", encoding="utf-8")
    api.storage = tmp_path / "storage"
    seen = {}

    class FakeProcess:
        pid = 4242

        def poll(self):
            return None

    def fake_popen(args, **kwargs):
        seen["args"] = args
        return FakeProcess()

    monkeypatch.setattr(websec_api.subprocess, "Popen", fake_popen)
    job = api.start_scan({"target": "example.test", "timeout": 12, "deadline": 120})
    assert job["state"] == "running"
    args = seen["args"]
    assert args[args.index("--timeout") + 1] == "12.0"
    assert args[args.index("--deadline") + 1] == "120.0"


def test_start_scan_refuses_an_out_of_scope_target_before_spawning(tmp_path, monkeypatch):
    api = websec_api.WebSecAPI(str(tmp_path))
    monkeypatch.setattr(api, "_scope_refusal", lambda target: "Refused: host is outside the lab scope")
    with pytest.raises(websec_api.WebSecError) as refused:
        api.start_scan({"target": "example.test"})
    assert refused.value.status == 403
    assert "outside the lab scope" in str(refused.value)
    assert api.jobs == {}


def test_api_status_reports_the_console_view(tmp_path, monkeypatch):
    monkeypatch.setattr(websec_api, "lab_status",
                        lambda root, platform: {"state": "needs-setup", "provider": None,
                                                "requirements": [], "reasons": ["declare a scope"],
                                                "notes": [], "version": "0.1.0"})
    api = websec_api.WebSecAPI(str(tmp_path))
    status = api.status()
    assert status["state"] == "needs-setup"
    assert status["reasons"] == ["declare a scope"]
    assert status["storage"].endswith("web-sec/storage")


def test_oslab_registers_the_lab():
    assert "websec" in oslab.LABS
    assert oslab.LABS["websec"]["dir"] == "web-sec"
    assert oslab.provider_for("websec", "linux") == "native-python"
    assert oslab.provider_for("websec", "windows") == "native-python"
    assert oslab.provider_for("websec", "android") is None


def test_oslab_dispatches_readiness_and_plans(monkeypatch):
    monkeypatch.setattr(websec_control, "lab_status",
                        lambda root, os_name: {"id": "websec", "state": "ready"})
    monkeypatch.setattr(websec_control, "plan",
                        lambda root, request: {"lab": "websec", "action": request["action"]})
    host = {"root": str(ROOT), "os": "linux", "arch": "x86_64", "tools": [],
            "runtime": False, "kvm": {"usable": False}}
    assert oslab.lab_status("websec", host)["state"] == "ready"
    assert oslab.plan(str(ROOT), {"lab": "websec", "action": "status"}, host)["action"] == "status"


def test_api_validates_a_bulk_payload(tmp_path):
    api = websec_api.WebSecAPI(str(tmp_path))
    options = api._validate_bulk({"targets": ["Example.test", "example.test", "other.test"],
                                  "preset": "quick"})
    assert options["targets"] == ["example.test", "other.test"]
    assert options["preset"] == "quick"
    with pytest.raises(websec_api.WebSecError):
        api._validate_bulk({"targets": []})
    with pytest.raises(websec_api.WebSecError):
        api._validate_bulk({"targets": ["-oops"]})
    with pytest.raises(websec_api.WebSecError):
        api._validate_bulk({"targets": ["example.test"], "preset": "everything"})
    with pytest.raises(websec_api.WebSecError):
        api._validate_bulk({"targets": ["example.test"], "extra": True})
    with pytest.raises(websec_api.WebSecError):
        api._validate_bulk({"targets": ["example.test"] * (websec_api.MAX_BULK + 1)})


def test_start_bulk_shares_the_one_running_job_slot(tmp_path):
    api = websec_api.WebSecAPI(str(tmp_path))
    api.jobs["running"] = {"id": "running", "state": "running", "target": "example.test",
                           "preset": "quick", "started": 0.0, "process": None}
    with pytest.raises(websec_api.WebSecError) as conflict:
        api.start_bulk({"targets": ["example.test"]})
    assert conflict.value.status == 409


def test_job_view_distinguishes_bulk_results_from_scan_reports(tmp_path):
    api = websec_api.WebSecAPI(str(tmp_path))
    api.jobs["b1"] = {"id": "b1", "state": "done", "kind": "bulk", "target": "",
                      "preset": "quick", "active": False, "started": 0.0, "process": None,
                      "results": {"targets": [], "count": 0}}
    view = api.job("b1")
    assert view["kind"] == "bulk"
    assert "results" in view
    assert "report" not in view
