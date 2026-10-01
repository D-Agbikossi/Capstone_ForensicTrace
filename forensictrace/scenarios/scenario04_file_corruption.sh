#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

echo "important data" > important.txt
echo "CORRUPTED" > important.txt
rm -f important.txt
