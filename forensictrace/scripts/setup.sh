#!/usr/bin/env bash
# One-command lab setup for ForensicTrace (Ubuntu/Debian).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Installing OS packages (may prompt for sudo)..."
sudo apt update
sudo apt install -y build-essential libssl-dev python3 curl

echo "==> Building ForensicTrace..."
make clean
make

echo "==> Making scripts executable..."
chmod +x tests/run_tests.sh scenarios/*.sh scripts/*.sh

echo "==> Running acceptance tests..."
./tests/run_tests.sh

echo ""
echo "Setup complete. Try:"
echo "  ./forensictrace --config B --output /tmp/run.json -- /bin/ls /tmp"
