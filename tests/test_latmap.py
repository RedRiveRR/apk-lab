from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.analysis import latmap

FIXTURES = Path(__file__).parent / "fixtures" / "latmap"


def test_demo_session_generates_valid_graph_and_wiki_links() -> None:
    raw = latmap.build_demo_session()
    session = latmap.normalize_session(raw)
    report = latmap.validate_graph(session)
    md = latmap.render_lat_markdown(session, report)

    assert report["status"] == "OK"
    assert "[[lat.md/session-brain-map.md#avelium-dmz-waf|avelium-dmz-waf]]" in md
    assert "#Targets#" not in md


def test_valid_fixture_cli_exit_zero(capsys: pytest.CaptureFixture[str]) -> None:
    rc = latmap.main(["--session", str(FIXTURES / "valid_session.json"), "--check"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "lms-waf-node" in captured.out


def test_orphan_fixture_warns_and_strict_mode_fails(capsys: pytest.CaptureFixture[str]) -> None:
    rc_normal = latmap.main(["--session", str(FIXTURES / "orphan_warning.json"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc_normal == 0
    assert payload["validation"]["status"] == "WARN"
    assert "forgotten-host" in payload["validation"]["orphan_nodes"]

    rc_strict = latmap.main(["--session", str(FIXTURES / "orphan_warning.json"), "--strict"])
    assert rc_strict == 1


def test_broken_links_fixture_check_flag_controls_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    rc_no_check = latmap.main(["--session", str(FIXTURES / "broken_links.json"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc_no_check == 0
    assert payload["validation"]["status"] == "FAIL"
    assert len(payload["validation"]["dangling_links"]) == 2

    rc_check = latmap.main(["--session", str(FIXTURES / "broken_links.json"), "--check"])
    assert rc_check == 1


def test_sanitize_strips_all_ansi_and_control_chars() -> None:
    dirty = "Target\x1b[31m-Host\x1b]0;title\x07\x00"
    assert latmap.sanitize_text(dirty) == "Target-Host"


def test_unverified_target_defaults_not_authorized() -> None:
    session = latmap.normalize_session({"targets": [{"id": "host-a"}]})
    target = session["targets"][0]
    assert target["scope"] == "unverified"
    assert "not verified" in target["notes"].lower()


def test_colliding_and_missing_ids_raise_error() -> None:
    with pytest.raises(ValueError, match="missing a usable identifier"):
        latmap.normalize_session({"targets": [{}]})

    with pytest.raises(ValueError, match="Duplicate or colliding"):
        latmap.normalize_session({"targets": [{"id": "web_1"}, {"id": "web-1"}]})


def test_string_list_rejected_and_duplicate_targets_deduplicated() -> None:
    with pytest.raises(ValueError, match="must be a list"):
        latmap.normalize_session({"scripts": [{"id": "s1", "targets": "abc"}]})

    session = latmap.normalize_session(
        {
            "targets": [{"id": "t1"}],
            "scripts": [{"id": "s1", "targets": ["t1", "t1"]}],
        }
    )
    assert session["scripts"][0]["targets"] == ["t1"]


def test_single_disconnected_node_reported_as_orphan() -> None:
    session = latmap.normalize_session({"targets": [{"id": "lone-host"}]})
    report = latmap.validate_graph(session)
    assert report["status"] == "WARN"
    assert report["orphan_nodes"] == ["lone-host"]


def test_markdown_escapes_html_and_frontmatter() -> None:
    session = latmap.normalize_session(
        {
            "session_id": 'sec "quoted" \\ id',
            "targets": [{"id": "t1", "name": "<script>alert(1)</script>"}],
        }
    )
    report = latmap.validate_graph(session)
    md = latmap.render_lat_markdown(session, report)
    assert 'id: "sec \\"quoted\\" \\\\ id"' in md
    assert "<script>" not in md
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in md


def test_output_same_as_session_rejected_and_revision_protected(tmp_path: Path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps(latmap.build_demo_session()), encoding="utf-8")
    assert latmap.main(["--session", str(session_file), "--output", str(session_file)]) == 1

    out_file = tmp_path / "brain-map.md"
    rc = latmap.main(["--demo", "--output", str(out_file)])
    assert rc == 0
    content = out_file.read_text(encoding="utf-8")
    assert f"[[{out_file.as_posix()}#avelium-dmz-waf|avelium-dmz-waf]]" in content

    # Newer revision succeeds, older revision is rejected
    latmap.atomic_write_text(out_file, "---\nrevision: 5\n---\n", revision=5)
    with pytest.raises(ValueError, match="Refusing to overwrite newer map"):
        latmap.atomic_write_text(out_file, "---\nrevision: 2\n---\n", revision=2)
