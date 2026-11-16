# Windows Apps Lab: agent safety layer and read-only MCP tools

Status: draft for approval. Tracks #288 items WINMIR-11f, 11d, 06, 12a and 12b.

## Intent

The Windows Apps Lab (#225/#287) can list and screenshot every visible desktop window. That is fine
for a person looking at their own dashboard, and it is not fine for an agent: today a password
manager, a private browser window or an online-banking tab is listed and captured like any other.

The instructor's goal is agents that operate real applications, with a security layer that makes
that acceptable. This change builds the part that needs no input control: a policy gate that decides
what may be seen, an audit trail of what agents did and what was refused, and read-only MCP tools
behind that gate. Input (`SendInput`), UI Automation and streaming are later phases and will reuse
the same gate.

## Goals

- An agent sees only windows of applications on an explicit allowlist. Empty or missing allowlist
  means the agent sees nothing (default deny). Chosen by the user over "allowlist guards input only".
- Windows that look sensitive (password managers, private/incognito browsing, user-listed banking
  hints) are never captured for anyone, and are marked restricted for the human panel. Restricted
  beats the allowlist: allowlisting a restricted app does not expose it.
- Every agent action and every refusal leaves an audit row. Auditing never raises.
- Read-only MCP tools on the existing `console/mcp_server.py`, with deliberately no arm tool and no
  input tool.
- `console/capabilities.json` gains the Windows Apps Lab entry; PRIVACY.md and `lat.md` describe the
  new policy and audit files.

## Non-goals

- No input of any kind, no arm/disarm, no panic stop (they belong to the input phase, WINMIR-11a/b/c/e).
- No UI Automation, element tree, streaming or multi-monitor work.
- No content-based detection: the filter reads process names and window titles only. It is a
  heuristic and the docs must say so; it is not a guarantee.
- No dashboard parity work beyond marking restricted windows in the existing picker.

## Anti-goals (a failure even if the tests pass)

- An agent ever receives pixels or a title of a restricted window, including through `doctor`.
- A broken or unreadable policy file widens access. It must fail closed for agents.
- The audit log stores window titles or pixels, or grows without bound.
- The panel's 3-second polling floods the audit log.

## Approaches considered

1. **Separate policy module `console/winapps_guard.py` (chosen).** Policy, classification, the
   facade used by both the web endpoints and MCP, and audit live in one module with no Win32
   dependency, so it is testable on any OS and reusable by future input. Cost: one more module.
2. All inside `console/winapps.py`. Fewer files, but ctypes and policy mix and the file roughly
   doubles. Rejected.
3. In `console/oslab.py` like the macOS lab. Matches the macOS pattern but `oslab.py` is already
   over 3000 lines of module-level macOS state, and the Windows lab was deliberately kept standalone.
   Rejected.

## Design

### Policy file

`win-lab/winapps-policy.json` (git-ignored; `win-lab/winapps-policy.example.json` is committed).
Override path with `OSLAB_WINAPPS_POLICY`.

```json
{ "allowedApps": ["Notepad", "WindowsTerminal"],
  "restrictedApps": ["MyVault"],
  "restrictedTitles": ["internet bankacılığı"] }
```

- App names are process base names, case-insensitive, `.exe` ignored. Titles are case-insensitive
  substrings.
- `restrictedApps` / `restrictedTitles` only add to the built-in defaults; defaults cannot be removed.
- Built-in restricted apps: 1Password, Bitwarden, KeePass, KeePassXC, Dashlane, LastPass, NordPass,
  Enpass, RoboForm, Proton Pass. Built-in restricted title hints: `InPrivate`, `Incognito`,
  `Private Browsing`, `Private Window`, `online banking`, `internet banking`.
- Loaded with an mtime cache. Missing file = empty allowlist. Malformed JSON, wrong types or
  unreadable file = empty allowlist for agents plus a `policyError` string; the human panel keeps
  working under the built-in restrictions only.

### `console/winapps_guard.py`

Pure Python, no ctypes. Public surface (the only way web_ui and MCP reach the collector):

- `load_policy(root) -> Policy`
- `classify(window, policy) -> Verdict(restricted, reason, allowed)` where `reason` is
  `password-manager | private-window | policy-app | policy-title | not-allowlisted`.
- `list_windows(root, audience)`: audience `human` returns every window; restricted ones keep
  `app`, lose their title (`"(restricted)"`) and carry `restricted: true` and `reason`. Audience
  `agent` returns only allowlisted, unrestricted windows plus `withheld: <count>` (a number, no
  names).
- `screenshot(root, window_id, audience)`: re-reads the window fresh at call time (a title can
  change between list and capture), refuses restricted windows for everyone and non-allowlisted
  windows for agents, otherwise returns the PNG.
- `doctor(root)`: calls `winapps.doctor` with a probe predicate so the capture probe skips restricted
  windows. This needs one small change in `winapps.doctor` (optional `can_probe` argument).
- `GuardError(code, retry)` with codes `RESTRICTED_WINDOW`, `APP_NOT_ALLOWED`, `WINDOW_GONE`,
  `INVALID_WINDOW`.
- Audit (below).

A source-level test asserts that `web_ui.py` and `mcp_server.py` never call
`winapps.winapps_window_screenshot` directly, so a future caller cannot bypass the gate by accident.

### Audit

- In-memory ring of the last 500 rows plus one JSONL file per day at
  `win-lab/artifacts/winapps-audit-YYYYMMDD.jsonl` (already git-ignored through `**/artifacts/*`);
  override the folder with `OSLAB_WINAPPS_AUDIT_DIR`. Same convention as the macOS audit and
  `scope.json`: paths are relative to the lab root, with an environment override.
- Row: `seq`, `time`, `audience` (`agent|human`), `kind` (`list`, `screenshot`, `doctor`, `refused`),
  `app`, `windowId`, `code`, `tool`, `count`. No titles, no pixels.
- Audited: every agent (MCP) call and every refusal for any audience. Not audited: ordinary
  successful human panel polling.
- Identical consecutive rows (same kind, app, windowId, code, audience) within 60 seconds are
  coalesced into one row with `count`, so a panel retrying a restricted window every 3 s writes one
  row per minute, not twenty.
- `audit()` swallows every exception, including disk errors.
- `GET /api/labs/winapps/audit` returns the last 200 in-memory rows.

### Web endpoints

Existing endpoints route through the guard with audience `human`. New read-only endpoints:
`GET /api/labs/winapps/policy` (counts, source path, `policyError`; never the app list contents
beyond counts) and `GET /api/labs/winapps/audit`. A refused screenshot returns 403 with
`{error, code}`; a stale window keeps 400. The panel shows restricted windows as disabled options
labelled with the app and "(restricted)".

### MCP tools (only registered when `sys.platform == "win32"`)

`winapps_apps`, `winapps_screenshot`, `winapps_capabilities`, `winapps_doctor`, `winapps_audit`.
All use audience `agent`. There is no arm tool and no input tool, stated in the server docstring and
asserted by a test over the tool list. `GuardError` becomes an `isError` result with `error`,
`code`, `retry`, like `PlanError`. `serverInfo.name` becomes `os-lab-windows` on Windows and stays
`os-lab-macos` elsewhere. `winapps_capabilities` reports the policy summary (allowlisted count,
restricted count, `policyError`, `inputSupported: false`) so an agent can tell why it sees nothing.

### Other files

- `console/capabilities.json`: a `lab-winapps` item beside `lab-macos`; Windows `full`, others `none`.
- `docs/legal/PRIVACY.md`: rows for the policy file and the audit log (titles never stored).
- `lat.md/win-lab.md`: a section on the gate, policy, audit and the honest limits.
- `console/winapps_guard.py` added once each to `stage-runtime.mjs` REQUIRED and `runtime.rs`
  BUNDLE_FILES; the example policy file is bundled by the existing `win-lab` include.
- `win-lab/VERIFY.md`: a section with observed results.

## Constraints

- Standard library only; works on Windows, with the guard importable and testable on any OS.
- Dashboard strings need all 7 locales (`npm run test:i18n`); `dashboard/dist` is rebuilt, not hand-merged.
- Windows host used for acceptance is one machine, standard user.

## Testing

- Guard unit tests with fake windows and temp policy files: default deny, allowlist match
  (case, `.exe`), restricted beats allowlist, malformed policy fails closed, title change between
  list and capture, `withheld` count, doctor probe skips restricted windows.
- Audit tests: no titles stored, coalescing, ring bound, never raises when the disk write fails.
- MCP tests (the server has none today): tool list on win32 vs other platforms, no arm/input tool,
  `GuardError` to `isError`, a stdio round trip.
- web_ui tests for 403/400/200 and the new endpoints; E2E for the disabled restricted option.
- Real-host check on the Windows 11 machine: a policy allowing one app, an MCP stdio session that
  lists exactly that app and refuses another, and the audit rows produced.

## Left to the builder

Exact restricted-title wording beyond the defaults above, JSON field naming inside audit rows
beyond those listed, and the panel label copy.

## Honest limits to document

The filter sees names and titles only, so a banking page titled "Welcome" is not caught unless the
user adds a hint. A windowed app can change its title after a capture decision is made. In a packaged install the lab
root may be read-only; then the policy path and audit folder must be pointed at a writable place
with the two environment variables, and until then the audit stays in memory only (macOS has the
same limitation). Elevated
windows still cannot be captured by a standard-user console (unchanged). The allowlist is a local
file the same user can edit; this is a guard against agent mistakes, not against a hostile local user.
