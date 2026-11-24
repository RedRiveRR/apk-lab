#!/usr/bin/env bash
# Create the Web Sec Lab's private storage. Downloads nothing, changes nothing else.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${WEBSEC_PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "web-sec setup: $PYTHON is not installed (Python 3.9+ is required)" >&2
  exit 2
fi

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
  echo "web-sec setup: $("$PYTHON" -V 2>&1) is older than 3.9" >&2
  exit 2
fi

"$PYTHON" "$ROOT/run.py" setup

SCOPE="${OSLAB_SCOPE_FILE:-$ROOT/../scope.json}"
if [ ! -f "$SCOPE" ]; then
  echo
  echo "No scope manifest found. Before scanning, copy console/scope.example.json to"
  echo "scope.json in the checkout and list the hosts you are authorized to test."
fi
