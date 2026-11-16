# Windows Apps Lab agent safety layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate what agents and the panel may see of Windows desktop windows (allowlist, restricted windows, audit) and expose read-only MCP tools behind that gate.

**Architecture:** A new pure-Python module `console/winapps_guard.py` owns policy, classification, audit and the only facade (`list_windows`, `screenshot`, `doctor`) that `web_ui.py` and `mcp_server.py` call. `console/winapps.py` stays the raw ctypes collector and gains only a coded error, a public single-window lookup and an optional probe filter in `doctor`.

**Tech Stack:** Python standard library, pytest, existing stdio MCP server, React/Astro dashboard, Playwright.

**Spec:** `docs/superpowers/specs/2026-11-16-winapps-agent-safety-design.md`

## Global Constraints

- Standard library only; the guard imports no ctypes and is testable on any OS.
- Agent audience: allowlist only, empty or missing or broken policy = sees nothing (fail closed).
- Restricted beats the allowlist; built-in restrictions can be extended by the policy file, never removed.
- Audit rows never contain window titles or pixels; `audit()` never raises.
- No arm tool and no input tool anywhere; MCP winapps tools register only when `sys.platform == "win32"`.
- Paths relative to the lab root with env overrides `OSLAB_WINAPPS_POLICY` and `OSLAB_WINAPPS_AUDIT_DIR`.
- Dashboard strings in all 7 locales (`npm run test:i18n`); locale JSON keeps master's key order (insert after the alphabetical predecessor, never re-sort); `dashboard/dist` is rebuilt, never hand-merged.
- Commits are Conventional Commits and carry no AI attribution lines.

## Review Focus

1. Turkish dotted capital `İ` and mixed case: title `İNTERNET BANKACILIĞI` must match the hint `internet bankacılığı`; app `" notepad.EXE "` matches allowlist `Notepad`. (Task 1)
2. Policy JSON of the wrong shape (string instead of list, numbers, null, nested lists, a UTF-8 BOM, 10,000 entries): no crash, agent sees nothing, `policyError` set. (Task 1)
3. `windowId` that is a bool, float, negative, `"12abc"` or huge: `INVALID_WINDOW`, never an unhandled exception. (Task 3)
4. Audit directory unwritable, a file instead of a folder, or 8 threads writing at once: no exception, ring stays at most 500 rows, no lost or duplicated seq numbers. (Task 2)
5. A window whose title becomes restricted between the check and the capture: the PNG is discarded and the refusal audited. (Task 3)

---

### Task 1: Policy and classification

**Files:**
- Create: `console/winapps_guard.py`, `win-lab/winapps-policy.example.json`
- Test: `android-lab/lab/tests/test_winapps_guard.py`
- Modify: `.gitignore` (add `win-lab/winapps-policy.json`)

**Interfaces:**
- Produces:
  - `@dataclass(frozen=True) Policy(allowed: frozenset[str], restricted_apps: frozenset[str], restricted_titles: tuple[str, ...], error: str | None, path: str, exists: bool)`
  - `@dataclass(frozen=True) Verdict(restricted: bool, allowed: bool, reason: str | None)`
  - `class GuardError(Exception)` with `__init__(self, message: str, code: str, retry: str = "never")` and attributes `code`, `retry`
  - `load_policy(root: str) -> Policy`, `classify(window: dict, policy: Policy) -> Verdict`, `policy_summary(root: str) -> dict`

- [ ] **Step 1: Write failing tests** in `test_winapps_guard.py` (use `tmp_path` and `OSLAB_WINAPPS_POLICY`):
  `test_missing_policy_means_nothing_is_allowed` (`exists is False`, `allowed == frozenset()`, `error is None`);
  `test_allowlist_matches_case_insensitively_and_ignores_exe_and_spaces` (`" notepad.EXE "` vs `["Notepad"]` gives `allowed=True`);
  `test_unlisted_app_is_not_allowlisted` (`reason == "not-allowlisted"`, `restricted is False`);
  `test_builtin_password_managers_are_restricted_even_if_allowlisted` (`1Password` in `allowedApps` still `restricted=True, allowed=False, reason="password-manager"`);
  `test_builtin_private_window_titles_are_restricted` (`InPrivate`, `Incognito`, `Private Browsing`, `Private Window` give `reason="private-window"`; built-in `online banking` / `internet banking` give `reason="banking-hint"`);
  `test_policy_can_add_restrictions_but_not_remove_defaults` (`restrictedApps: ["MyVault"]` gives `policy-app`, `restrictedTitles: ["secret"]` gives `policy-title`);
  `test_turkish_dotted_capital_i_matches_title_hints` (Review Focus 1);
  `test_malformed_policy_fails_closed_with_policy_error` parametrised over: `"not json"`, `{"allowedApps": "Notepad"}`, `{"allowedApps": [1, null, ["x"]]}`, `[]`, a BOM-prefixed valid file (BOM must still parse), and 10,000 entries (loads, no crash) — assert no exception and for the invalid ones `allowed == frozenset()` and `error` set (Review Focus 2);
  `test_policy_is_reloaded_when_the_file_changes` (rewrite file, bump mtime, new allowlist seen);
  `test_policy_summary_reports_counts_without_names` (keys `allowedApps`, `restrictedApps`, `restrictedTitles` as ints, `policyError`, `path`, `exists`).

- [ ] **Step 2: Run** `python -m pytest android-lab/lab/tests/test_winapps_guard.py -q`; expect FAIL (module missing).

- [ ] **Step 3: Implement** `load_policy`, `classify`, `policy_summary`, `GuardError` in `console/winapps_guard.py`. Normalise every name and title with one helper: NFKD, drop combining marks, `casefold()`, strip, drop a trailing `.exe` for app names. Cache the parsed policy by (path, mtime). Built-in lists are exactly those in the spec. `classify` order: restricted app (built-in then policy) → restricted title (built-in private/banking, then policy) → allowlist. Add the example policy file with two allowed apps and empty restriction lists; add the `.gitignore` line.

- [ ] **Step 4: Run** the test file; expect all PASS.
- [ ] **Step 5: Commit** `feat(winapps): policy file and window classification`

### Task 2: Audit

**Files:** Modify `console/winapps_guard.py`; Test `android-lab/lab/tests/test_winapps_guard.py` (audit section).

**Interfaces:**
- Consumes: `GuardError` (Task 1).
- Produces: `audit(root: str | None, kind: str, *, audience: str, app: str | None = None, window_id: int | None = None, code: str | None = None, tool: str | None = None) -> None`; `audit_rows(limit: int = 200) -> dict` returning `{"recording": True, "rows": [...]}`; test helper `_reset_audit()`.

- [ ] **Step 1: Write failing tests:**
  `test_audit_row_has_seq_time_and_no_title_or_pixels` (passing extra keyword `title=` is not accepted; row keys are exactly `seq,time,audience,kind,app,windowId,code,tool,count`);
  `test_identical_rows_within_60_seconds_coalesce_with_count` (monkeypatch `winapps_guard.time.time`; 20 calls give one row with `count == 20`; a call 61 s later gives a second row);
  `test_ring_never_exceeds_500_rows`;
  `test_audit_writes_one_jsonl_line_per_new_row_under_the_audit_dir` (`OSLAB_WINAPPS_AUDIT_DIR=tmp_path`, file `winapps-audit-YYYYMMDD.jsonl`);
  `test_audit_never_raises_when_the_directory_is_unwritable` (audit dir is an existing regular file; Review Focus 4);
  `test_concurrent_audit_keeps_unique_consecutive_seq` (8 threads x 50 distinct rows give seq set of size 400).

- [ ] **Step 2: Run**; expect FAIL.
- [ ] **Step 3: Implement** `audit` and `audit_rows`: module lock, `_AUDIT_MAX = 500`, coalescing key `(audience, kind, app, window_id, code)` within 60 s (update `count` and `time` on the existing row; the JSONL file receives only the first occurrence), JSONL append inside `try/except Exception` that swallows everything.
- [ ] **Step 4: Run**; expect PASS.
- [ ] **Step 5: Commit** `feat(winapps): audit log with coalescing`

### Task 3: Guarded facade and collector hooks

**Files:**
- Modify: `console/winapps.py` (error code, `window_info`, `doctor(can_probe)`), `console/winapps_guard.py`
- Test: `android-lab/lab/tests/test_winapps_guard.py`, `android-lab/lab/tests/test_winapps.py`

**Interfaces:**
- Consumes: `Policy`, `classify`, `audit`, `GuardError`.
- Produces:
  - `winapps.WinAppError(message: str, code: str = "CAPTURE_FAILED")`; `"INVALID_WINDOW"` at the invalid-id raises, `"WINDOW_GONE"` at the stale raises
  - `winapps.window_info(window_id: int) -> dict | None` (same filters and root check as the screenshot path; `None` when gone)
  - `winapps.doctor(can_probe: Callable[[dict], bool] | None = None) -> dict`
  - `winapps_guard.list_windows(root: str, audience: str, *, tool: str | None = None) -> dict`
  - `winapps_guard.screenshot(root: str, window_id: int | str, audience: str, *, tool: str | None = None) -> bytes`
  - `winapps_guard.doctor(root: str, audience: str = "agent", *, tool: str | None = None) -> dict`
  - GuardError codes `RESTRICTED_WINDOW`, `APP_NOT_ALLOWED`, `WINDOW_GONE`, `INVALID_WINDOW`, `CAPTURE_FAILED`

- [ ] **Step 1: Write failing tests** (monkeypatch `winapps.winapps_windows`, `winapps.window_info`, `winapps.winapps_window_screenshot`):
  `test_agent_list_returns_only_allowlisted_unrestricted_windows_and_a_withheld_count`;
  `test_agent_list_with_empty_policy_returns_nothing_and_counts_all_as_withheld`;
  `test_human_list_keeps_restricted_windows_but_redacts_title_and_flags_them` (`restricted: True`, `reason`, `title == "(restricted)"`, `app` kept);
  `test_screenshot_refuses_restricted_windows_for_everyone` (human and agent get `RESTRICTED_WINDOW`; collector screenshot never called);
  `test_screenshot_refuses_non_allowlisted_apps_for_agents_only`;
  `test_screenshot_discards_pixels_if_the_title_turns_restricted_during_capture` (`window_info` returns a clean dict first, a restricted one second; expect `RESTRICTED_WINDOW`, an audit row with `code`; Review Focus 5);
  `test_screenshot_rejects_bad_window_ids` parametrised over `True`, `1.5`, `-3`, `"12abc"`, `10**30`, `None` giving `INVALID_WINDOW` (Review Focus 3);
  `test_gone_window_maps_to_window_gone`;
  `test_doctor_probe_skips_restricted_windows` (collector `doctor` receives a `can_probe` that is false for a restricted window);
  `test_every_refusal_and_every_agent_call_is_audited_but_human_success_is_not`.
  In `test_winapps.py`: `test_window_info_returns_none_for_a_stale_id`, `test_doctor_honours_can_probe`, `test_errors_carry_codes`.

- [ ] **Step 2: Run** both files; expect FAIL.
- [ ] **Step 3: Implement.** In `winapps.py` add the three hooks without changing existing messages. In the guard, `list_windows` transforms `winapps.winapps_windows()` per the spec (agent adds `withheld`); `screenshot` runs `window_info` → `classify` → refuse or capture → `window_info` + `classify` again → return PNG or refuse, converting `WinAppError.code` to `GuardError`; every refusal audits `kind="refused"`, every agent call audits its own kind (`list`, `screenshot`, `doctor`), human successes are not audited.
- [ ] **Step 4: Run** both files plus `test_web_ui.py`; expect PASS (the one pre-existing `test_lab_start_requires_a_previewed_plan` failure is unrelated).
- [ ] **Step 5: Commit** `feat(winapps): guarded facade for listing, capture and doctor`

### Task 4: Web endpoints through the guard

**Files:** Modify `android-lab/lab/web_ui.py`; Test `android-lab/lab/tests/test_web_ui.py`, `android-lab/lab/tests/test_winapps_guard.py`.

**Interfaces:**
- Consumes: `winapps_guard.list_windows/screenshot/doctor/policy_summary/audit_rows`, `GuardError`.
- Produces: `GET /api/labs/winapps/apps`, `.../apps/<id>/screenshot`, `.../doctor` (all audience `human`), new `GET /api/labs/winapps/policy` and `GET /api/labs/winapps/audit`. Status mapping: `RESTRICTED_WINDOW` 403, `INVALID_WINDOW`/`WINDOW_GONE`/`CAPTURE_FAILED` 400, guard module missing 501.

- [ ] **Step 1: Write failing tests:** `test_winapps_screenshot_of_a_restricted_window_is_403_with_code`; `test_winapps_policy_endpoint_serves_counts_only`; `test_winapps_audit_endpoint_serves_rows`; `test_winapps_endpoints_are_501_without_the_guard_module`; and in the guard test file `test_web_ui_and_mcp_never_call_the_raw_screenshot_directly` (read both source files, assert the text `winapps.winapps_window_screenshot` is absent). Update the existing winapps tests in `test_web_ui.py` that monkeypatch `web_ui.winapps` to patch the guard instead.
- [ ] **Step 2: Run**; expect FAIL.
- [ ] **Step 3: Implement** routing in the existing `_lab_get` branch, importing `winapps_guard` with the same `try/except ImportError` pattern as `winapps`.
- [ ] **Step 4: Run** `pytest android-lab/lab/tests -q`; expect only the known pre-existing failure.
- [ ] **Step 5: Commit** `feat(winapps): route web endpoints through the guard`

### Task 5: Read-only MCP tools

**Files:** Modify `console/mcp_server.py`; Create `android-lab/lab/tests/test_mcp_winapps.py`.

**Interfaces:**
- Consumes: `winapps_guard.*`, `GuardError`, `winapps.WinAppError`, existing `handle`, `tool_call`, `TOOLS`.
- Produces: `WIN_TOOLS` list with `winapps_apps`, `winapps_screenshot` (required integer `windowId`), `winapps_capabilities`, `winapps_doctor`, `winapps_audit`; `tools/list` returns `TOOLS + WIN_TOOLS` only when `sys.platform == "win32"`; `serverInfo.name` is `os-lab-windows` on win32, `os-lab-macos` otherwise; `isError` results carry `error`, `code`, `retry`.

- [ ] **Step 1: Write failing tests** (call `mcp_server.handle` with monkeypatched `sys.platform`): `test_win_tools_are_listed_only_on_windows`; `test_there_is_no_arm_or_input_tool` (no name contains `arm`, `click`, `type`, `key`, `paste`, `scroll`, `set`, `perform` in the winapps set); `test_winapps_apps_is_agent_filtered`; `test_winapps_screenshot_returns_image_content`; `test_guard_error_becomes_is_error_with_code`; `test_winapps_capabilities_reports_policy_summary_and_input_unsupported`; `test_winapps_tool_on_a_non_windows_host_is_a_clean_error`; `test_server_name_depends_on_platform`.
- [ ] **Step 2: Run**; expect FAIL.
- [ ] **Step 3: Implement** following the existing macOS tool pattern; extend the `handle` exception clause to `GuardError` and `winapps.WinAppError`. Update the module docstring to state the Windows tools are read-only with no arm tool.
- [ ] **Step 4: Run** `test_mcp_winapps.py`; expect PASS.
- [ ] **Step 5: Commit** `feat(winapps): read-only MCP tools behind the guard`

### Task 6: Panel marks restricted windows

**Files:** Modify `dashboard/src/lib/api.ts`, `dashboard/src/views/winapps-app-mirror.tsx`, `dashboard/src/i18n/generated/*.json` (7 files), `dashboard/e2e/winapps.spec.ts`; rebuild `dashboard/dist`.

**Interfaces:** `WinApp` gains optional `restricted?: boolean` and `reason?: string`; `WinAppsInfo` gains optional `withheld?: number`.

- [ ] **Step 1: Write failing E2E** `a restricted window is listed but disabled and never captured` (inventory with one normal and one `restricted: true` window; the restricted `<option>` is disabled, no screenshot request is made for it, the hint text `Some windows are restricted and cannot be mirrored.` is visible).
- [ ] **Step 2: Run** `npx playwright test winapps.spec.ts`; expect FAIL.
- [ ] **Step 3: Implement** the disabled option (label `{app} (restricted)`), skip selection of restricted windows, show the hint once when any exist; add that one key to all 7 locales by script, keeping master order.
- [ ] **Step 4: Run** `npm run check`, `npm run test:i18n`, `npm run build`, then `npx playwright test winapps.spec.ts`; expect all PASS.
- [ ] **Step 5: Commit** `feat(winapps): mark restricted windows in the panel`

### Task 7: Capabilities, docs, bundle lists and real-host proof

**Files:** Modify `console/capabilities.json`, `docs/legal/PRIVACY.md`, `lat.md/win-lab.md`, `app/scripts/stage-runtime.mjs`, `app/src-tauri/src/runtime.rs`, `win-lab/VERIFY.md`, `android-lab/lab/tests/test_oslab_console.py` if it enumerates labs.

- [ ] **Step 1: Write failing test** in `test_oslab_console.py`: `test_capabilities_include_the_windows_apps_lab` (item `lab-winapps`, `lab: "winapps"`, Windows `full`, macOS and Linux `none`); then add the item beside `lab-macos`.
- [ ] **Step 2: Run** `pytest android-lab/lab/tests/test_oslab_console.py -q`; expect PASS after the edit.
- [ ] **Step 3: Docs and bundle:** PRIVACY.md rows for the policy file and the audit log (no titles stored, folder and env override); a `lat.md/win-lab.md` section on the gate, policy, audit and the honest limits from the spec (use `[[console/winapps_guard.py]]` links only to files that exist); add `console/winapps_guard.py` once to `stage-runtime.mjs` REQUIRED and once to `runtime.rs` BUNDLE_FILES; run `cd app && npm run test:stage`.
- [ ] **Step 4: Real-host proof** on this Windows machine and record observed output in `VERIFY.md`: write a policy allowing one running app; run `python console/mcp_server.py` as a subprocess and send `initialize`, `tools/list`, `tools/call winapps_apps`, `tools/call winapps_screenshot` for an allowlisted and for a non-allowlisted window id; confirm exactly the allowlisted app is listed, the other is refused with `APP_NOT_ALLOWED`, and the audit rows appear without titles. State what was not verified.
- [ ] **Step 5: Full verification and commit:** `python -m pytest android-lab/lab/tests -q`, `npm run check && npm run test:i18n && npm run build`, `npx playwright test winapps.spec.ts`; commit `docs(winapps): capabilities, privacy, bundle lists and verification for the agent safety layer`.
