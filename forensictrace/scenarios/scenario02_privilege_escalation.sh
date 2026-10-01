#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

FAKE="$WORKDIR/fake_passwd_entry"

python3 -c "open('/etc/shadow','rb').read(1)" 2>/dev/null || true
echo "fake:x:1000:1000:Fake:/tmp:/bin/false" > "$FAKE"
rm -f "$FAKE"
