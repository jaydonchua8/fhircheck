#!/usr/bin/env bash
# Run the unit tests, then the live suite against the servers in servers.json.
# Usage: ./run.sh [--only hapi-r4] [--perf-n 10] [--no-write]
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "python3 not found" >&2; exit 2; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "need Python 3.9+" >&2; exit 2; }

echo "== unit tests"
"$PY" -m unittest -q

BASELINE_ARGS=()
if [[ -f baseline.json ]]; then BASELINE_ARGS=(--baseline baseline.json); fi

echo "== live suite"
set +e
"$PY" fhircheck.py --out results "${BASELINE_ARGS[@]}" "$@"
status=$?
set -e

report="results/report-$("$PY" -c 'import sys; print(sys.platform)').md"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -f "$report" ]]; then cat "$report" >> "$GITHUB_STEP_SUMMARY"; fi
exit $status
