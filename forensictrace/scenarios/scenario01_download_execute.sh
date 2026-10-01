#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

cd "$WORKDIR"

cat > payload.sh <<'PAYLOAD'
#!/bin/sh
echo "scenario01 payload executed"
PAYLOAD

python3 -m http.server 8765 >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT
sleep 0.5

curl -sf -o downloaded.sh "http://127.0.0.1:8765/payload.sh"
chmod +x downloaded.sh
./downloaded.sh

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
