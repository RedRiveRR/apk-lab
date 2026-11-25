"""Monitor contracts: config schema, warning lifecycle, scope expiry, the tick and notifications."""
from __future__ import annotations

import json
import os
import stat
from datetime import date

import pytest

from test_cli import run
from websec import monitor, notify

HOUR = 3600
CONFIG = {**monitor.default_config(), "enabled": True, "targets": ["example.test"], "reminderHours": 24}


def doc(grade="A", score=95, findings=()):
    return {"target": "example.test", "grade": grade, "score": score, "findings": list(findings),
            "summary": {}, "modules": []}


CSP = {"module": "security_analysis", "kind": "csp", "severity": "medium", "title": "CSP is missing"}
HSTS = {"module": "security_analysis", "kind": "hsts", "severity": "high", "title": "HSTS is missing"}
KEY = {"module": "content_scan", "kind": "aws", "severity": "critical", "title": "AWS key in a script"}


@pytest.fixture
def storage(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    return tmp_path / "storage"


# ── config ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value, message", [
    ({"enabled": True}, "at least one target"),
    ({"targets": ["bad host"]}, "host name"),
    ({"targets": [f"h{i}.test" for i in range(11)]}, "at most 10"),
    ({"intervalMinutes": 5}, "intervalMinutes"),
    ({"preset": "full"}, "quick or standard"),
    ({"alertOn": "info"}, "alertOn"),
    ({"reminderHours": 500}, "reminderHours"),
    ({"active": True}, "Unknown key"),
])
def test_config_refuses_unsafe_or_invalid_values(value, message):
    with pytest.raises(monitor.MonitorConfigError, match=message):
        monitor.validate_config(value)


def test_config_round_trips_privately_and_drops_state_of_removed_targets(storage):
    monitor.save_config({**CONFIG, "targets": ["Example.TEST", "two.test"]})
    loaded = monitor.load()
    assert loaded["config"]["targets"] == ["example.test", "two.test"]
    assert stat.S_IMODE(os.stat(storage / "monitor.json").st_mode) & 0o077 == 0
    loaded["state"]["targets"]["two.test"] = {"lastRun": 1}
    monitor._write({"config": loaded["config"], "state": loaded["state"]})
    monitor.save_config({**CONFIG, "targets": ["example.test"]})
    assert "two.test" not in monitor.load()["state"]["targets"]


def test_a_corrupt_store_turns_the_monitor_off_with_a_reason(storage):
    storage.mkdir(parents=True)
    (storage / "monitor.json").write_text("{nope", encoding="utf-8")
    loaded = monitor.load()
    assert loaded["config"]["enabled"] is False and "unreadable" in loaded["configError"]


# ── warning lifecycle ────────────────────────────────────────────────────────

def test_a_new_high_finding_warns_then_escalates_reminds_and_recovers():
    entry, events = monitor.assess("example.test", doc(), doc(findings=[HSTS]), {}, CONFIG, 1000)
    assert [e["kind"] for e in events] == ["warning"]
    assert entry["warning"]["level"] == "warning"
    # a new critical finding escalates the same warning
    entry, events = monitor.assess("example.test", doc(findings=[HSTS]), doc(findings=[HSTS, KEY]), entry, CONFIG, 2000)
    assert [e["kind"] for e in events] == ["escalated"] and entry["warning"]["level"] == "critical"
    # nothing new, not yet due: silent; a day later: a reminder
    same = doc(findings=[HSTS, KEY])
    entry, events = monitor.assess("example.test", same, same, entry, CONFIG, 2000 + HOUR)
    assert events == []
    entry, events = monitor.assess("example.test", same, same, entry, CONFIG, 2000 + 25 * HOUR)
    assert [e["kind"] for e in events] == ["reminder"]
    # both flagged findings fixed: recovered, warning cleared
    entry, events = monitor.assess("example.test", same, doc(findings=[CSP]), entry, CONFIG, 3000 + 25 * HOUR)
    assert [e["kind"] for e in events] == ["recovered"] and entry["warning"] is None


def test_findings_below_the_threshold_and_standing_ones_stay_quiet():
    entry, events = monitor.assess("example.test", doc(findings=[HSTS]), doc(findings=[HSTS, CSP]), {}, CONFIG, 1)
    assert events == [] and entry["warning"] is None


def test_a_grade_drop_to_d_is_critical_and_recovers_when_the_grade_returns():
    entry, events = monitor.assess("example.test", doc("A", 95), doc("D", 62), {}, CONFIG, 1)
    assert [e["kind"] for e in events] == ["critical"]
    entry, events = monitor.assess("example.test", doc("D", 62), doc("A", 95), entry, CONFIG, 2)
    assert [e["kind"] for e in events] == ["recovered"]


def test_reminders_can_be_switched_off():
    config = {**CONFIG, "reminderHours": 0}
    entry, _ = monitor.assess("example.test", doc(), doc(findings=[HSTS]), {}, config, 0)
    entry, events = monitor.assess("example.test", doc(findings=[HSTS]), doc(findings=[HSTS]), entry, config, 99 * HOUR)
    assert events == []


def test_errors_are_reported_once_per_reason():
    entry, events = monitor.assess_error("example.test", {}, "refused: outside the scope", 1)
    assert [e["kind"] for e in events] == ["error"]
    entry, events = monitor.assess_error("example.test", entry, "refused: outside the scope", 2)
    assert events == []


def test_scope_expiry_warns_ahead_and_when_expired():
    state = {"scope": {"warned": "", "notifiedAt": 0}}
    events = monitor.assess_scope({"valid": True, "expires": "2026-12-01", "name": "lab"}, state, CONFIG, 1,
                                  today=date(2026, 11, 25))
    assert [e["kind"] for e in events] == ["scope-expiring"]
    assert monitor.assess_scope({"valid": True, "expires": "2026-12-01"}, state, CONFIG, 2, today=date(2026, 11, 26)) == []
    events = monitor.assess_scope({"valid": False, "reason": "expired"}, state, CONFIG, 3, today=date(2026, 12, 2))
    assert [e["kind"] for e in events] == ["scope-expired"]
    assert monitor.assess_scope({"valid": True, "expires": "2027-12-01"}, state, CONFIG, 4, today=date(2026, 12, 3)) == []
    assert state["scope"]["warned"] == ""


# ── the tick ─────────────────────────────────────────────────────────────────

def test_tick_scans_due_targets_stores_reports_and_notifies(storage):
    monitor.save_config(CONFIG)
    sent = []
    reports = iter([doc(), doc(findings=[HSTS])])
    common = dict(scan=lambda host, preset: next(reports), notifier=lambda events, enabled: sent.append((events, enabled)) or [],
                  scope_status=lambda: {"valid": True, "expires": "2099-01-01"})
    first = monitor.tick(clock=lambda: 10_000, **common)
    assert first["scanned"] == ["example.test"] and first["newEvents"] == []
    # not due yet: nothing scanned
    assert monitor.tick(clock=lambda: 10_100, **common)["scanned"] == []
    second = monitor.tick(clock=lambda: 10_000 + 1441 * 60, **common)
    assert [e["kind"] for e in second["newEvents"]] == ["warning"]
    assert sent[-1][1] is True and sent[-1][0][0]["target"] == "example.test"
    status = monitor.status()
    assert status["activeWarnings"][0]["target"] == "example.test"
    assert status["targets"]["example.test"]["lastReport"].endswith(".json")


def test_tick_is_idle_while_off_and_records_scan_failures(storage):
    monitor.save_config({**CONFIG, "enabled": False})
    assert monitor.tick(scan=lambda h, p: pytest.fail("off means no scans"))["scanned"] == []

    def refuse(host, preset):
        raise ValueError("the target is outside the declared scope")

    result = monitor.tick(force=True, scan=refuse, notifier=lambda events, enabled: [],
                          scope_status=lambda: {"valid": True, "expires": None})
    assert [e["kind"] for e in result["newEvents"]] == ["error"]
    assert monitor.status()["targets"]["example.test"]["status"] == "error"


def test_monitor_cli_saves_and_refuses(storage):
    code, out, _ = run(["monitor", "config", "--save", json.dumps(CONFIG), "--json"])
    assert code == 0 and json.loads(out)["config"]["enabled"] is True
    code, _, err = run(["monitor", "config", "--save", json.dumps({"preset": "full"})])
    assert code == 2 and "quick or standard" in err
    code, out, _ = run(["monitor", "status"])
    assert "monitor on" in out


# ── notifications ────────────────────────────────────────────────────────────

def test_notifications_use_fixed_argv_and_skip_quiet_events():
    event = {"kind": "warning", "target": "example.test", "message": '"; do shell script "rm -rf ~"'}
    title, message = notify.describe(event)
    argv = notify.command(title, message, platform="darwin")
    assert argv[0] == "osascript" and argv[-1] == title and argv[-2] == message  # text is an argument
    assert notify.describe({"kind": "recovered"}) is None
    calls = []
    results = notify.send_all([event, {"kind": "recovered"}], platform="linux",
                              which=lambda name: "/usr/bin/notify-send",
                              run=lambda argv, **kw: calls.append(argv) or type("R", (), {"returncode": 0})())
    assert [r["status"] for r in results] == ["sent"] and calls[0][:3] == ["notify-send", "--app-name=os-lab", "--"]
    assert notify.send_all([event], enabled=False) == []
