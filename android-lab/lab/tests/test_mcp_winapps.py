"""Contracts for the read-only Windows Apps Lab tools on the stdio MCP server."""

import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "console")))

import mcp_server
import winapps
import winapps_guard

WIN_TOOL_NAMES = {"winapps_apps", "winapps_screenshot", "winapps_capabilities", "winapps_doctor", "winapps_audit"}


def rpc(method, params=None):
    return mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})["result"]


def call(name, args=None):
    return rpc("tools/call", {"name": name, "args": args or {}})


def payload(result):
    return json.loads(result["content"][0]["text"])


@pytest.fixture
def on_windows(monkeypatch):
    monkeypatch.setattr(mcp_server.sys, "platform", "win32")


def test_win_tools_are_listed_only_on_windows(monkeypatch):
    monkeypatch.setattr(mcp_server.sys, "platform", "win32")
    assert WIN_TOOL_NAMES <= {tool["name"] for tool in rpc("tools/list")["tools"]}
    monkeypatch.setattr(mcp_server.sys, "platform", "linux")
    listed = rpc("tools/list")["tools"]
    assert not any(tool["name"].startswith("winapps_") for tool in listed)
    assert listed == mcp_server.TOOLS


def test_there_is_no_arm_or_input_tool(on_windows):
    names = {tool["name"] for tool in rpc("tools/list")["tools"] if tool["name"].startswith("winapps_")}
    assert names == WIN_TOOL_NAMES
    for name in names:
        assert not any(word in name for word in ("arm", "click", "type", "key", "paste", "scroll", "set", "perform"))


def test_winapps_apps_is_agent_filtered(on_windows, monkeypatch):
    seen = {}

    def fake(root, audience, *, tool=None):
        seen.update(audience=audience, tool=tool)
        return {"available": True, "reason": None, "windows": [], "withheld": 2}

    monkeypatch.setattr(winapps_guard, "list_windows", fake)
    result = call("winapps_apps")
    assert result["isError"] is False and payload(result)["withheld"] == 2
    assert seen == {"audience": "agent", "tool": "winapps_apps"}


def test_winapps_screenshot_returns_image_content(on_windows, monkeypatch):
    png = b"\x89PNG\r\n\x1a\nxx"
    seen = {}

    def fake(root, window_id, audience, *, tool=None):
        seen.update(window_id=window_id, audience=audience, tool=tool)
        return png

    monkeypatch.setattr(winapps_guard, "screenshot", fake)
    result = call("winapps_screenshot", {"windowId": 12})
    assert result["isError"] is False
    assert result["content"] == [{"type": "image", "data": base64.b64encode(png).decode(), "mimeType": "image/png"}]
    assert seen == {"window_id": 12, "audience": "agent", "tool": "winapps_screenshot"}


def test_guard_and_collector_errors_become_is_error_with_code(on_windows, monkeypatch):
    def refuse(root, window_id, audience, *, tool=None):
        raise winapps_guard.GuardError("restricted", "RESTRICTED_WINDOW")

    monkeypatch.setattr(winapps_guard, "screenshot", refuse)
    refused = call("winapps_screenshot", {"windowId": 3})
    assert refused["isError"] is True
    assert payload(refused) == {"error": "restricted", "code": "RESTRICTED_WINDOW", "retry": "never"}

    def broken(root, audience, *, tool=None):
        raise winapps.WinAppError("enumeration failed")

    monkeypatch.setattr(winapps_guard, "list_windows", broken)
    failed = call("winapps_apps")
    assert failed["isError"] is True and payload(failed) == {"error": "enumeration failed", "code": "CAPTURE_FAILED"}


def test_winapps_capabilities_reports_policy_summary_and_input_unsupported(on_windows, monkeypatch, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"allowedApps": ["Notepad", "Calc"], "restrictedApps": ["Vault"]}))
    monkeypatch.setenv("OSLAB_WINAPPS_POLICY", str(policy))
    result = call("winapps_capabilities")
    assert payload(result) == {"allowedApps": 2, "restrictedApps": 1, "restrictedTitles": 0, "policyError": None,
                               "exists": True, "audience": "agent", "inputSupported": False}
    assert "Notepad" not in result["content"][0]["text"]


def test_winapps_doctor_and_audit_use_the_agent_audience(on_windows, monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(winapps_guard, "doctor", lambda root, audience="agent", *, tool=None:
                        seen.update(audience=audience, tool=tool) or {"capture": True})
    assert payload(call("winapps_doctor")) == {"capture": True}
    assert seen == {"audience": "agent", "tool": "winapps_doctor"}
    monkeypatch.setenv("OSLAB_WINAPPS_AUDIT_DIR", str(tmp_path / "audit"))
    winapps_guard._reset_audit()
    winapps_guard.audit(None, "list", audience="agent", tool="winapps_apps")
    assert [row["kind"] for row in payload(call("winapps_audit"))["rows"]] == ["list"]
    winapps_guard._reset_audit()


def test_winapps_tool_on_a_non_windows_host_is_a_clean_error(monkeypatch):
    monkeypatch.setattr(mcp_server.sys, "platform", "linux")
    result = call("winapps_apps")
    assert result["isError"] is True and payload(result)["code"] == "NOT_SUPPORTED"


@pytest.mark.parametrize("platform,name", [("win32", "os-lab-windows"), ("linux", "os-lab-macos"),
                                           ("darwin", "os-lab-macos")])
def test_server_name_depends_on_platform(monkeypatch, platform, name):
    monkeypatch.setattr(mcp_server.sys, "platform", platform)
    assert rpc("initialize")["serverInfo"]["name"] == name
