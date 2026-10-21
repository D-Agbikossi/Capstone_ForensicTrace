#!/usr/bin/env bash
# Scenario 1: Download -> chmod -> execute
set -e

WORKDIR="/tmp/ft_scenario01"
rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"; cd "$WORKDIR"

cat > payload.sh <<'EOF'
#!/bin/sh
echo "payload executed at $(date)"
sleep 0.2
EOF

python3 -m http.server 8765 --directory "$WORKDIR" >/dev/null 2>&1 &
SERVER=$!
sleep 0.5

# Ground truth actions:
curl -s -o downloaded.sh "http://127.0.0.1:8765/payload.sh"
chmod +x downloaded.sh
./downloaded.sh

kill $SERVER 2>/dev/null || true
wait $SERVER 2>/dev/null || true
