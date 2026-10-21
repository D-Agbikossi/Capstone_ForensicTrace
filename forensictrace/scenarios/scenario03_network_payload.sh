#!/usr/bin/env bash
# Scenario 3: Network fetch -> write payload -> execute
set -e

WORKDIR="/tmp/ft_scenario03"
rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"; cd "$WORKDIR"

echo "hello from server" > served.txt
python3 -m http.server 8766 --directory "$WORKDIR" >/dev/null 2>&1 &
SERVER=$!
sleep 0.5

curl -s "http://127.0.0.1:8766/served.txt" > fetched.txt

cat > runme.sh <<'EOF'
#!/bin/sh
echo "network payload executed"
EOF
chmod +x runme.sh
./runme.sh

kill $SERVER 2>/dev/null || true
wait $SERVER 2>/dev/null || true
