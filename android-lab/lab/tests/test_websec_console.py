"""Web Sec Lab console contracts: readiness, typed plans and API validation."""
import json
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


def test_running_job_reports_module_progress(tmp_path, monkeypatch):
    api = websec_api.WebSecAPI(str(tmp_path))
    api.runner = tmp_path / "run.py"
    api.runner.write_text("", encoding="utf-8")
    api.storage = tmp_path / "storage"

    class FakeProcess:
        pid = 4243

        def poll(self):
            return None

    monkeypatch.setattr(websec_api.subprocess, "Popen", lambda args, **kwargs: FakeProcess())
    job = api.start_scan({"target": "example.test"})
    progress_path = api.storage / "jobs" / job["id"] / "progress.jsonl"
    progress_path.write_text(
        json.dumps({"modules": ["dns_records", "security_analysis"]}) + "\n"
        + json.dumps({"id": "dns_records", "status": "ok", "duration_ms": 5}) + "\n",
        encoding="utf-8")
    view = api.job(job["id"])
    assert view["progress"]["modules"] == [
        {"id": "dns_records", "status": "ok"},
        {"id": "security_analysis", "status": None},
    ]


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


def forbid_scans(monkeypatch, module):
    """Let readiness/plan subprocesses run, but fail on any spawned scan or bulk job."""
    real = module.subprocess.Popen

    def guarded(args, *rest, **kwargs):
        if isinstance(args, (list, tuple)) and len(args) > 2 and args[2] in ("scan", "bulk"):
            pytest.fail("this path must never start a scan")
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(module.subprocess, "Popen", guarded)


# ── workbench endpoints: saved choices, review plan, compare, guides ─────────

def _engine_api(tmp_path, monkeypatch, hosts=("localhost",)):
    """A console API over the real engine, with private storage and a test scope."""
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({
        "version": 1, "name": "console test", "author" "ization": "unit test only",
        "expires": "2099-01-01", "hosts": list(hosts), "packages": [], "devices": [], "paths": [],
    }), encoding="utf-8")
    monkeypatch.setenv("OSLAB_SCOPE_FILE", str(scope))
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    return websec_api.WebSecAPI(str(ROOT))


def test_preferences_round_trip_through_the_engine(tmp_path, monkeypatch):
    api = _engine_api(tmp_path, monkeypatch)
    assert api.get("/api/websec/preferences", {})["preferences"]["scan"]["preset"] == "standard"
    saved = api.post("/api/websec/preferences", {"scan": {"target": "localhost", "preset": "quick",
                                                          "modules": ["dns_records"]}})
    assert saved["preferences"]["scan"]["preset"] == "quick"
    assert api.get("/api/websec/preferences", {})["preferences"]["scan"]["modules"] == ["dns_records"]
    assert (tmp_path / "storage" / "preferences.json").is_file()
    with pytest.raises(websec_api.WebSecError) as refused:
        api.post("/api/websec/preferences", {"scan": {"preset": "loud"}})
    assert refused.value.status == 400 and "preset" in str(refused.value)
    with pytest.raises(websec_api.WebSecError) as refused:
        api.post("/api/websec/preferences", {"scan": {"active": True}})
    assert refused.value.status == 400
    with pytest.raises(websec_api.WebSecError):
        api.post("/api/websec/preferences", {"monitor": {}})


def test_plan_reviews_without_scanning_and_reports_a_refusal(tmp_path, monkeypatch):
    api = _engine_api(tmp_path, monkeypatch)
    forbid_scans(monkeypatch, websec_api)
    plan = api.post("/api/websec/plan", {"target": "localhost", "preset": "full"})
    assert plan["scope"]["allowed"] is True
    assert plan["intrusive"] == [] and "port_exposure" in plan["available_intrusive"]
    active = api.post("/api/websec/plan", {"target": "localhost", "preset": "full", "active": True})
    assert "port_exposure" in active["intrusive"]
    outside = api.post("/api/websec/plan", {"target": "example.com"})
    assert outside["scope"]["allowed"] is False and outside["runs"] == 0
    with pytest.raises(websec_api.WebSecError) as refused:
        api.post("/api/websec/plan", {"target": "localhost", "modules": ["no_such_check"]})
    assert refused.value.status == 400
    assert api.jobs == {}


def _store_report(tmp_path, name, score, grade, findings):
    folder = tmp_path / "storage" / "reports" / "localhost"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(json.dumps({
        "target": "localhost", "started_at": "2026-11-24T00:00:00+00:00", "preset": "quick",
        "score": score, "grade": grade, "summary": {"total": len(findings)}, "findings": findings,
        "modules": []}), encoding="utf-8")


def test_compare_diffs_two_stored_runs(tmp_path, monkeypatch):
    api = _engine_api(tmp_path, monkeypatch)
    hsts = {"module": "security_analysis", "kind": "hsts", "severity": "high", "title": "HSTS is missing"}
    _store_report(tmp_path, "20261101T000000Z-80.json", 80, "B", [hsts])
    _store_report(tmp_path, "20261124T000000Z-96.json", 96, "A+", [])
    diff = api.get("/api/websec/compare", {"target": ["localhost"], "old": ["20261101T000000Z-80.json"],
                                           "new": ["20261124T000000Z-96.json"]})
    assert diff["score"]["delta"] == 16
    assert [item["title"] for item in diff["resolved"]] == ["HSTS is missing"]
    for query in ({"target": ["localhost"], "old": ["../x.json"], "new": ["y.json"]},
                  {"target": ["localhost"], "old": ["a.json"], "new": ["a.json"]},
                  {"target": ["-x"], "old": ["a.json"], "new": ["b.json"]}):
        with pytest.raises(websec_api.WebSecError) as refused:
            api.get("/api/websec/compare", query)
        assert refused.value.status == 400


def test_guides_come_from_the_engine(tmp_path, monkeypatch):
    api = _engine_api(tmp_path, monkeypatch)
    payload = api.get("/api/websec/guides", {})
    assert {guide["id"] for guide in payload["guides"]} >= {"scope", "headers", "tls", "dns"}
    assert payload["byCheck"]["security_analysis"] == "headers"
