#!/usr/bin/env bash
# Runs the standard ForensicTrace demo sequence (for recording or dry run).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DEMO="/tmp/forensictrace_demo"
BIN="$ROOT/forensictrace"

step() {
    echo ""
    echo "=========================================="
    echo "  $1"
    echo "=========================================="
    echo ""
}

step "1/7 — Build"
make clean
make

step "2/7 — Acceptance tests (expect 13 passed)"
./tests/run_tests.sh

step "3/7 — CLI help"
"$BIN" --help

step "4/7 — Trace /bin/ls (Config B)"
mkdir -p "$DEMO"
"$BIN" --config B --output "$DEMO/ls.json" -- /bin/ls "$DEMO"

step "5/7 — Integrity check + timeline viewer"
sha256sum -c "$DEMO/ls.json.sha256"
python3 scripts/view_timeline.py "$DEMO/ls.json" | head -15

step "6/7 — Compare Config A vs B"
"$BIN" --config A --output "$DEMO/a.json" -- /bin/ls /tmp >/dev/null
"$BIN" --config B --output "$DEMO/b.json" -- /bin/ls /tmp >/dev/null
python3 -c "
import json
for k in 'AB':
    d = json.load(open('$DEMO/' + k.lower() + '.json'))
    f = sum(1 for e in d['events'] if e['type'] == 'file')
    print(f'Config {k}: events={d[\"event_count\"]} file={f}')
"

step "7/7 — Scenario 4 (file corruption)"
"$BIN" --config B --output "$DEMO/scenario4.json" -- bash scenarios/scenario04_file_corruption.sh
python3 scripts/view_timeline.py "$DEMO/scenario4.json" | grep -E 'write|unlink|open' | head -10 || true

echo ""
echo "Demo complete. Output files: $DEMO/"
