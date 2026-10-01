#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

echo 'echo "scenario03 run"' > served.txt

python3 -m http.server 8766 >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT
sleep 0.5

curl -sf -o fetched.txt "http://127.0.0.1:8766/served.txt"
cat fetched.txt > runme.sh
chmod +x runme.sh
./runme.sh

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
