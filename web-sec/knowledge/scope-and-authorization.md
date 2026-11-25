# Scope and authorization

The lab is an authorization-only tool. This page records exactly what that means
in code, so an operator can see the boundary instead of trusting a paragraph.

## The guard

`websec/scope.py` loads `console/scope_guard.py` from the checkout and asks it
about every host before a socket is opened. The guard is not re-implemented here,
so a change to the project's scope rules applies to this lab automatically.

- `build_live()` checks the target before the first module runs.
- `Context.require()` and every transport (`dns`, `http`, `tls`, `whois`, `ports`)
  check again, including each HTTP redirect hop.
- A refusal raises `ScopeRefused`. The runner records the module as `refused`,
  stops the scan, and the console answers 4xx rather than pretending to work.
- Tests inject `AllowAll`, which exists only for offline fixtures. The CLI and the
  console have no switch that disables the real guard.

The manifest is `scope.json` in the checkout, or `$OSLAB_SCOPE_FILE`. Start from
`console/scope.example.json`. A manifest that does not name its targets, has
expired, or uses a wildcard TLD is refused by the guard itself.

## What the lab never does

- No exploitation, injection payloads, brute force, credential guessing or DoS.
  The upstream `payloads/` wordlists and React RCE probes were not ported.
- No path brute force. `exposed_files` asks for ten well-known names once.
- No execution of anything served by the target. Scripts are scanned as text.
- No third-party endpoint beyond the three listed below.

## The three public registries

Some checks need public data that the target cannot provide:

| Endpoint | Used by | Why |
|---|---|---|
| `crt.sh` | `subdomain_discovery` | certificate-transparency names |
| `web.archive.org` | `archive_spy` | archived URL index (CDX) |
| `services.nvd.nist.gov` | `port_exposure --cve-lookup` | CVE details for a banner |

`Context.infra()` builds a separate client whose guard allows those three hosts
and nothing else. The assessed host stays under the real scope; the registries
are read-only queries, and the operator triggers each one by choosing the module.

## Traffic budget

- 60 s default deadline, 512 KiB per response, 2 MiB for a registry response.
- 25 pages per crawl, 5 scripts per content scan, 20 ports, 24 lookalike lookups,
  60 takeover candidates, 12 origin candidates.
- 250 ms pacing between requests to the target; 1 s between registry requests.

## Operator checklist

1. Written authorization for the host and the date range.
2. `scope.json` lists exactly those hosts; `./labctl websec status` says `ready`.
3. Start with `--preset quick`, read the findings, then widen.
4. Add `--active` only for the intrusive checks the authorization covers.
5. Keep reports in `web-sec/storage` or export them deliberately; they contain
   hostnames and evidence.
