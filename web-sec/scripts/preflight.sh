#!/usr/bin/env bash
# Read-only readiness check for the Web Sec Lab. Exits 0 only when a scan could run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${WEBSEC_PYTHON:-python3}"
status=0

say() { printf '%s\n' "$*"; }

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  say "[fail] python   $PYTHON is not installed (3.9+ required)"
  exit 2
fi

version="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
if "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
  say "[ok]   python   $version"
else
  say "[fail] python   $version is older than 3.9"
  status=1
fi

if [ -w "$ROOT/storage" ] || [ -w "$ROOT/.." ]; then
  say "[ok]   storage  $ROOT/storage"
else
  say "[fail] storage  $ROOT is not writable"
  status=1
fi

if [ -f "$ROOT/../console/scope_guard.py" ]; then
  say "[ok]   guard    console/scope_guard.py"
else
  say "[fail] guard    console/scope_guard.py is missing from this checkout"
  status=1
fi

report="$("$PYTHON" "$ROOT/run.py" status --json 2>/dev/null || true)"
if [ -n "$report" ]; then
  scope="$("$PYTHON" -c 'import json,sys; d=json.load(sys.stdin); print("valid" if d.get("scope",{}).get("valid") else d.get("scope",{}).get("reason","not declared"))' <<<"$report" 2>/dev/null || echo "unreadable")"
  if [ "$scope" = "valid" ]; then
    say "[ok]   scope    declared"
  else
    say "[warn] scope    $scope"
    say "       declare a scope before scanning (console/scope.example.json)"
  fi
else
  say "[fail] engine   websec/run.py status did not answer"
  status=1
fi

exit "$status"
