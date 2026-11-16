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
