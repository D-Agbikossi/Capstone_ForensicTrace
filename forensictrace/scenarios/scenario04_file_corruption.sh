#!/usr/bin/env bash
# Scenario 4: Deliberate file corruption (integrity scenario)
set -e

WORKDIR="/tmp/ft_scenario04"
rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"; cd "$WORKDIR"

echo "IMPORTANT DATA: this file must not be changed" > important.txt
echo "--- original ---"
cat important.txt

echo "CORRUPTED" > important.txt

echo "--- after corruption ---"
cat important.txt

rm -f important.txt
