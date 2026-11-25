# Web Sec Lab

A scope-guarded web posture assessment lab. It profiles a site you own or are
authorized to test — DNS, WHOIS, TLS, headers, cookies, exposure, archived URLs —
and produces a graded report with fixes. Standard library only: no VM, Docker,
Node or third-party Python package is needed.

It ports the assessment capability of two upstream projects into os-lab's own
contracts. See [knowledge/upstream.md](knowledge/upstream.md) for the mapping and
the parts that were deliberately not ported.

## Quick start

```bash
./labctl websec status          # readiness: Python, storage, declared scope
./labctl websec doctor          # the same, with every requirement spelled out
./labctl websec setup           # create web-sec/storage (0700), no downloads

# A scope is required before any network call:
cp console/scope.example.json scope.json     # then list the hosts you own

./labctl websec scan example.test --preset quick --format text
./labctl websec scan example.test --format sarif --out report.sarif
./labctl websec scan example.test --diff 20260101T000000Z-95.json   # what changed since the last run
./labctl websec bulk targets.txt --csv                             # one row per target; exits with the worst grade
./labctl websec history --limit 10
./labctl websec report --target example.test --list
./labctl websec plan example.test --preset full --json             # what a scan would run; sends nothing
./labctl websec compare --target example.test --old A.json --new B.json --fail-on-new high
./labctl websec scan example.test --fail-on high --baseline A.json --summary "$GITHUB_STEP_SUMMARY"
./labctl websec prefs --json                                       # the workbench's saved choices
./labctl websec guides                                             # the SecOps guides
./labctl websec runs stats                                         # totals and each target's latest grade
./labctl websec monitor status                                     # the opt-in passive monitor
```

`./labctl websec` is `python3 web-sec/run.py`. The same commands work directly
from this folder with `python3 run.py …` or `make status|doctor|scan`.

## Checks

29 checks: 16 built-in modules and 13 plugins, in four groups (`recon`,
`security`, `posture`, `inventory`). `websec modules` prints the catalogue;
[knowledge/modules.md](knowledge/modules.md) explains each one and marks the
intrusive ones.

Presets:

- `quick` — domain registration, DNS records, address context.
- `standard` — the passive everyday set, plus email, TLS, cookie and CORS hygiene.
- `full` — everything, including intrusive modules when `--active` is passed.

Intrusive modules (port checks, zone-transfer audit, method/TRACE checks, CORS
probe, standard-file checks, TLS-version probing) are skipped unless `--active`
is given **and** the scope covers the target.

## Reports

JSON, SARIF 2.1.0, Markdown, text and a self-contained HTML page. Rule ids are
`WEBSEC/<module>/<kind>` — the stable kind each check declares — so a reworded
finding does not become a new rule, and `security-severity` follows the usual
9.5 → 0.5 mapping, so the SARIF drops straight into GitHub code scanning or any
SARIF viewer. Findings carry a CWE and OWASP Top 10 label when the match is clear.
`--client`, `--author` and `--title` put a cover on the HTML and Markdown report.
The schema, the CI gates and the exit codes are in
[knowledge/report-schema.md](knowledge/report-schema.md).

## CI and agents

[`action.yml`](action.yml) runs one scope-checked scan in GitHub Actions: SARIF
(optionally uploaded to code scanning), a job summary and a `fail-on` gate. The scope
file in the repository is the authorization record.

The os-lab MCP server (`console/mcp_server.py`) carries the workbench as `websec_*`
tools ([console/mcp_websec.py](../console/mcp_websec.py)): read-only status,
catalogue, guides, history, reports and compare; `websec_review`, which sends
nothing; `websec_scan` as a job, where intrusive checks need `confirm: true`.

## State and privacy

- History and reports live under `web-sec/storage` (mode 0700, 600 files), pruned
  to the last 50 history lines and 20 reports per target.
- The engine opens sockets only to the target (scope-checked) and to three
  allowlisted public registries: `crt.sh`, `web.archive.org` and
  `services.nvd.nist.gov`. Nothing else.
- Nothing is executed from a target; the lab reads responses and reports.

## Tests

```bash
cd engine && python3 -m pytest -q
```

The suite runs offline: DNS messages, HTTP responses, WHOIS text, TLS
certificates and scan modules are exercised through fake transports.

## Authorization

The lab is defensive and authorization-only. The scope guard refuses a target
that is not listed in `scope.json` (or `$OSLAB_SCOPE_FILE`), and it refuses
before the first socket is opened. Do not use it against systems you do not own
or have written permission to test.
