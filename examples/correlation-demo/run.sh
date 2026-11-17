#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEMO_DIR="$PROJECT_ROOT/examples/correlation-demo"

run_cli() {
    if command -v cvevident >/dev/null 2>&1; then
        cvevident "$@"
    else
        PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" python -m cvevident.cli "$@"
    fi
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cvevident-correlation-demo.XXXXXX")"
if [[ "${KEEP_DEMO_OUTPUT:-0}" == "1" ]]; then
    KEEP_OUTPUT=1
else
    KEEP_OUTPUT=0
fi

cleanup() {
    if [[ "$KEEP_OUTPUT" == "1" ]]; then
        printf 'Demo output kept at: %s\n' "$WORK_DIR"
    else
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

DB="$WORK_DIR/demo.sqlite3"
MATCH_REPORT="$WORK_DIR/match.json"
MISMATCH_REPORT="$WORK_DIR/environment-mismatch.json"
NO_ENVIRONMENT_REPORT="$WORK_DIR/no-environment.json"

printf '\n%s\n' "[1/6] Initialize a clean database"
run_cli --db "$DB" init-db

printf '\n%s\n' "[2/6] Import the synthetic NVD record"
run_cli --db "$DB" import-nvd "$DEMO_DIR/nvd-demo.json"

printf '\n%s\n' "[3/6] Import the synthetic parser evidence rule"
run_cli --db "$DB" import-evidence-rules "$DEMO_DIR/evidence-rules.json"

printf '\n%s\n' "[4/6] Analyze with a matching environment CPE"
run_cli --db "$DB" analyze "$DEMO_DIR/sample.rtf" \
    --environment-cpe 'cpe:2.3:a:acme:reader:2.4:*:*:*:*:*:*:*' \
    --format json --output "$MATCH_REPORT"

printf '\n%s\n' "[5/6] Analyze with a non-matching environment CPE"
run_cli --db "$DB" analyze "$DEMO_DIR/sample.rtf" \
    --environment-cpe 'cpe:2.3:a:acme:reader:3.0:*:*:*:*:*:*:*' \
    --format json --output "$MISMATCH_REPORT"

printf '\n%s\n' "[6/6] Analyze without environment context"
run_cli --db "$DB" analyze "$DEMO_DIR/sample.rtf" \
    --format json --output "$NO_ENVIRONMENT_REPORT"

python - "$MATCH_REPORT" "$MISMATCH_REPORT" "$NO_ENVIRONMENT_REPORT" <<'PY'
import json
import sys

reports = []
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as stream:
        reports.append(json.load(stream))

def result_status(report):
    rows = report.get("cve_associations", [])
    for row in rows:
        if row.get("cve_id") == "CVE-2099-12345":
            return row.get("correlation_status")
    return None

statuses = [result_status(report) for report in reports]
expected = ("MATCH", "NO_MATCH", "PARTIAL")
labels = ("matching environment", "non-matching environment", "missing environment")
for label, actual, wanted in zip(labels, statuses, expected):
    print(f"{label}: expected {wanted}, received {actual}")
    if actual != wanted:
        raise SystemExit(1)

print("Correlation demo: PASS")
PY

printf '\n%s\n' "All correlation demo checks passed."
