"""Contracts for the Windows Apps Lab policy gate (console/winapps_guard.py).

The guard has no Win32 dependency, so these run the same on any host.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "console")))

import winapps_guard as guard


def write_policy(tmp_path, monkeypatch, data=None, raw=None):
    path = tmp_path / "policy.json"
    path.write_bytes(raw if raw is not None else json.dumps(data).encode("utf-8"))
    monkeypatch.setenv("OSLAB_WINAPPS_POLICY", str(path))
    return path


def win(app, title="Untitled"):
    return {"windowId": 7, "app": app, "title": title}


def verdict(tmp_path, monkeypatch, window, **policy):
    write_policy(tmp_path, monkeypatch, policy)
    return guard.classify(window, guard.load_policy(str(tmp_path)))


# ── Task 1: policy and classification ────────────────────────────────────────

def test_missing_policy_means_nothing_is_allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("OSLAB_WINAPPS_POLICY", str(tmp_path / "absent.json"))
    policy = guard.load_policy(str(tmp_path))
    assert policy.exists is False and policy.error is None
    assert policy.allowed == frozenset()


def test_allowlist_matches_case_insensitively_and_ignores_exe_and_spaces(tmp_path, monkeypatch):
    v = verdict(tmp_path, monkeypatch, win(" notepad.EXE "), allowedApps=["Notepad"])
    assert v.allowed is True and v.restricted is False and v.reason is None


def test_unlisted_app_is_not_allowlisted(tmp_path, monkeypatch):
    v = verdict(tmp_path, monkeypatch, win("Calc"), allowedApps=["Notepad"])
    assert (v.restricted, v.allowed, v.reason) == (False, False, "not-allowlisted")


def test_blank_entries_never_match_blank_apps(tmp_path, monkeypatch):
    v = verdict(tmp_path, monkeypatch, win(""), allowedApps=["", "  ", ".exe"])
    assert v.allowed is False


def test_builtin_password_managers_are_restricted_even_if_allowlisted(tmp_path, monkeypatch):
    v = verdict(tmp_path, monkeypatch, win("1Password"), allowedApps=["1Password"])
    assert (v.restricted, v.allowed, v.reason) == (True, False, "password-manager")


@pytest.mark.parametrize("title,reason", [
    ("New tab - [InPrivate] - Edge", "private-window"),
    ("New Incognito tab - Chrome", "private-window"),
    ("Mozilla Firefox Private Browsing", "private-window"),
    ("Brave Private Window", "private-window"),
    ("My Online Banking", "banking-hint"),
    ("Internet Banking login", "banking-hint"),
])
def test_builtin_sensitive_titles_are_restricted(tmp_path, monkeypatch, title, reason):
    v = verdict(tmp_path, monkeypatch, win("msedge", title), allowedApps=["msedge"])
    assert (v.restricted, v.allowed, v.reason) == (True, False, reason)


def test_policy_can_add_restrictions_but_not_remove_defaults(tmp_path, monkeypatch):
    policy = dict(allowedApps=["MyVault", "msedge", "1Password"], restrictedApps=["MyVault"],
                  restrictedTitles=["secret"])
    assert verdict(tmp_path, monkeypatch, win("MyVault"), **policy).reason == "policy-app"
    assert verdict(tmp_path, monkeypatch, win("msedge", "my SECRET plan"), **policy).reason == "policy-title"
    assert verdict(tmp_path, monkeypatch, win("1Password"), **policy).reason == "password-manager"


@pytest.mark.parametrize("title", ["İNTERNET BANKACILIĞI", "Internet Bankacılığı", "internet bankaciligi"])
def test_turkish_dotted_capital_i_matches_title_hints(tmp_path, monkeypatch, title):
    v = verdict(tmp_path, monkeypatch, win("msedge", title), restrictedTitles=["internet bankacılığı"])
    assert v.restricted is True and v.reason == "policy-title"


@pytest.mark.parametrize("raw", [
    b"not json",
    json.dumps({"allowedApps": "Notepad"}).encode(),
    json.dumps({"allowedApps": [1, None, ["x"]]}).encode(),
    json.dumps({"restrictedTitles": {"a": 1}}).encode(),
    json.dumps([]).encode(),
])
def test_malformed_policy_fails_closed_with_policy_error(tmp_path, monkeypatch, raw):
    write_policy(tmp_path, monkeypatch, raw=raw)
    policy = guard.load_policy(str(tmp_path))
    assert policy.allowed == frozenset() and policy.error
    assert guard.classify(win("Notepad"), policy).allowed is False


def test_a_utf8_bom_policy_still_loads(tmp_path, monkeypatch):
    write_policy(tmp_path, monkeypatch, raw=b"\xef\xbb\xbf" + json.dumps({"allowedApps": ["Notepad"]}).encode())
    policy = guard.load_policy(str(tmp_path))
    assert policy.error is None and policy.allowed == frozenset({"notepad"})


def test_ten_thousand_allowlist_entries_load(tmp_path, monkeypatch):
    write_policy(tmp_path, monkeypatch, {"allowedApps": [f"app{i}" for i in range(10_000)]})
    policy = guard.load_policy(str(tmp_path))
    assert policy.error is None and len(policy.allowed) == 10_000


def test_policy_is_reloaded_when_the_file_changes(tmp_path, monkeypatch):
    path = write_policy(tmp_path, monkeypatch, {"allowedApps": ["a"]})
    assert guard.load_policy(str(tmp_path)).allowed == frozenset({"a"})
    path.write_text(json.dumps({"allowedApps": ["b"]}))
    later = path.stat().st_mtime + 10
    os.utime(path, (later, later))
    assert guard.load_policy(str(tmp_path)).allowed == frozenset({"b"})


def test_policy_summary_reports_counts_without_names(tmp_path, monkeypatch):
    path = write_policy(tmp_path, monkeypatch, {"allowedApps": ["Notepad", "Calc"], "restrictedApps": ["V"],
                                                "restrictedTitles": ["x", "y", "z"]})
    summary = guard.policy_summary(str(tmp_path))
    assert summary == {"allowedApps": 2, "restrictedApps": 1, "restrictedTitles": 3,
                       "policyError": None, "path": str(path), "exists": True}
    assert "Notepad" not in json.dumps(summary)


# ── Task 2: audit ─────────────────────────────────────────────────────────────

import threading


@pytest.fixture
def audit_dir(tmp_path, monkeypatch):
    folder = tmp_path / "audit"
    monkeypatch.setenv("OSLAB_WINAPPS_AUDIT_DIR", str(folder))
    guard._reset_audit()
    yield folder
    guard._reset_audit()


def rows(limit=500):
    return guard.audit_rows(limit)["rows"]


def test_audit_row_has_seq_time_and_no_title_or_pixels(audit_dir):
    guard.audit(None, "list", audience="agent", app="Notepad", window_id=1, tool="winapps_apps")
    row = rows()[-1]
    assert set(row) == {"seq", "time", "audience", "kind", "app", "windowId", "code", "tool", "count"}
    assert row["seq"] == 1 and row["count"] == 1 and row["windowId"] == 1
    with pytest.raises(TypeError):
        guard.audit(None, "list", audience="agent", title="secret")  # titles cannot be passed at all


def test_identical_rows_within_60_seconds_coalesce_with_count(audit_dir, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(guard.time, "time", lambda: now[0])
    for _ in range(20):
        guard.audit(None, "refused", audience="human", app="1Password", window_id=5, code="RESTRICTED_WINDOW")
        now[0] += 1
    assert len(rows()) == 1 and rows()[0]["count"] == 20
    now[0] = 1061.5
    guard.audit(None, "refused", audience="human", app="1Password", window_id=5, code="RESTRICTED_WINDOW")
    assert len(rows()) == 2


def test_ring_never_exceeds_500_rows(audit_dir):
    for i in range(650):
        guard.audit(None, "list", audience="agent", window_id=i)
    assert len(rows(10_000)) == 500 and rows(10_000)[-1]["windowId"] == 649


def test_audit_writes_one_jsonl_line_per_new_row_under_the_audit_dir(audit_dir, tmp_path):
    guard.audit(str(tmp_path), "list", audience="agent", window_id=1)
    guard.audit(str(tmp_path), "screenshot", audience="agent", window_id=1)
    files = list(audit_dir.glob("winapps-audit-*.jsonl"))
    assert len(files) == 1
    lines = [json.loads(line) for line in files[0].read_text(encoding="utf-8").splitlines()]
    assert [line["kind"] for line in lines] == ["list", "screenshot"]


def test_audit_never_raises_when_the_directory_is_unwritable(tmp_path, monkeypatch):
    blocker = tmp_path / "a-file"
    blocker.write_text("not a folder")
    monkeypatch.setenv("OSLAB_WINAPPS_AUDIT_DIR", str(blocker))
    guard._reset_audit()
    guard.audit(str(tmp_path), "list", audience="agent", window_id=1)
    assert len(rows()) == 1


def test_concurrent_audit_keeps_unique_consecutive_seq(audit_dir):
    def work(base):
        for i in range(50):
            guard.audit(None, "list", audience="agent", window_id=base * 1000 + i)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(row["seq"] for row in rows()) == list(range(1, 401))
