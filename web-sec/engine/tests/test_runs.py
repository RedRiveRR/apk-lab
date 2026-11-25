"""Stored-run management: favourites survive pruning, delete, clear and statistics."""
from __future__ import annotations

import json
import os

import pytest

from test_cli import run
from websec import history as history_module
from websec.history import History


@pytest.fixture
def stored(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSEC_STORAGE", str(tmp_path / "storage"))
    history = History()
    names = []
    for index, (score, grade, total) in enumerate(((80, "B", 3), (90, "A", 1), (96, "A+", 0))):
        document = {"target": "example.test", "generated_at": f"2026-11-2{index}T00:00:00+00:00", "score": score,
                    "grade": grade, "summary": {"total": total, "high": total}, "preset": "quick",
                    "active": False, "refused": False, "findings": []}
        monkeypatch.setattr(history_module.time, "strftime", lambda fmt, _=None, index=index: f"2026112{index}T000000Z")
        names.append(history.append(document)["name"])
    other = {"target": "other.test", "generated_at": "2026-11-25T00:00:00+00:00", "score": 60, "grade": "D",
             "summary": {"total": 5, "critical": 1}, "preset": "quick", "active": False, "refused": False, "findings": []}
    history.append(other)
    return history, names


def test_favourites_are_marked_and_survive_pruning(stored, monkeypatch):
    history, names = stored
    history.set_favourite("example.test", names[0])
    assert [entry["favourite"] for entry in history.list("example.test")] == [False, False, True]
    monkeypatch.setattr(history_module, "MAX_REPORTS", 2)
    history._prune(history.reports_dir("example.test"), {names[0]})
    left = {entry["name"] for entry in history.reports("example.test")}
    assert names[0] in left and len(left) == 2
    history.set_favourite("example.test", names[0], on=False)
    assert not any(entry["favourite"] for entry in history.list("example.test"))
    with pytest.raises(ValueError):
        history.set_favourite("example.test", "../../x.json")


def test_delete_removes_reports_lines_and_favourites(stored):
    history, names = stored
    history.set_favourite("example.test", names[1])
    result = history.delete("example.test", [names[0], names[1]])
    assert result["deleted"] == 2
    assert [entry["name"] for entry in history.list("example.test")] == [names[2]]
    assert history.favourites() == {}
    with pytest.raises(ValueError):
        history.delete("example.test", ["../escape.json"])


def test_stats_cover_the_latest_run_of_each_target(stored):
    history, _ = stored
    stats = history.stats()
    assert stats["targets"] == 2 and stats["runs"] == 4 and stats["reports"] == 4
    assert stats["grades"] == {"A": 1, "D": 1}
    assert stats["latestFindings"]["critical"] == 1
    assert stats["latest"][0]["target"] == "other.test"


def test_clear_one_target_or_everything(stored):
    history, _ = stored
    assert history.clear("other.test")["deleted"] == 1
    assert history.targets() == ["example.test"]
    assert history.clear()["deleted"] == 3
    assert history.targets() == [] and history.stats()["runs"] == 0


def test_runs_cli(stored):
    _, names = stored
    code, out, _ = run(["runs", "stats", "--json"])
    assert code == 0 and json.loads(out)["targets"] == 2
    code, out, _ = run(["runs", "favourite", "--target", "example.test", "--name", names[2], "--json"])
    assert code == 0 and json.loads(out)["favourite"] is True
    code, _, err = run(["runs", "clear"])
    assert code == 2 and "--all" in err
    code, out, _ = run(["runs", "delete", "--target", "example.test", "--name", names[0], "--name", names[1], "--json"])
    assert json.loads(out)["deleted"] == 2
    code, out, _ = run(["runs", "clear", "--all", "--json"])
    assert json.loads(out)["deleted"] == 2
