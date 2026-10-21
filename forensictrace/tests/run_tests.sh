#!/usr/bin/env bash
# ForensicTrace MVP acceptance tests. Exit 0 if all pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BIN="$ROOT/forensictrace"
TMP="$ROOT/.test_out"
PASS=0
FAIL=0

mkdir -p "$TMP"

pass() { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

json_count() {
  python3 - "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("event_count", 0))
PY
}

json_type_count() {
  python3 - "$1" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
t = sys.argv[2]
print(sum(1 for e in d["events"] if e["type"] == t))
PY
}

parent_linked() {
  python3 - "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(1 if any(e.get("parent_event", -1) >= 0 for e in d["events"]) else 0)
PY
}

echo "=== ForensicTrace test suite ==="

# --- 1–3: build, CLI, validation ---
# 1 Build
BUILD_LOG="$TMP/build.log"
if ! make clean >/dev/null 2>&1 || ! make >"$BUILD_LOG" 2>&1; then
  fail "binary builds"
elif grep -qi warning "$BUILD_LOG"; then
  fail "binary builds (compiler warnings)"
else
  pass "binary builds"
fi

# 2 Help
if "$BIN" --help 2>&1 | grep -q "Usage:"; then
  pass "--help works"
else
  fail "--help works"
fi

# 3 Invalid config
rm -f "$TMP/bad.json"
if "$BIN" --config Z --output "$TMP/bad.json" -- /bin/true >/dev/null 2>&1; then
  fail "invalid config rejected"
elif [[ -f "$TMP/bad.json" ]]; then
  fail "invalid config rejected (file created)"
else
  pass "invalid config rejected"
fi

# --- 4–8: evidence configurations A–D ---
# 4 Config A valid JSON
"$BIN" --config A --output "$TMP/a.json" -- /bin/true >/dev/null 2>&1
if python3 -c "import json; json.load(open('$TMP/a.json'))"; then
  pass "Config A produces valid JSON"
else
  fail "Config A produces valid JSON"
fi

# 5 Config A excludes file events
fc=$(json_type_count "$TMP/a.json" file)
if [[ "$fc" -eq 0 ]]; then
  pass "Config A excludes file events"
else
  fail "Config A excludes file events (file_count=$fc)"
fi

# 6 Config B includes file events
"$BIN" --config B --output "$TMP/b.json" -- /bin/ls /tmp >/dev/null 2>&1
fc=$(json_type_count "$TMP/b.json" file)
if [[ "$fc" -gt 0 ]]; then
  pass "Config B includes file events"
else
  fail "Config B includes file events"
fi

# 7 Config C includes network events
if command -v curl >/dev/null 2>&1; then
  "$BIN" --config C --output "$TMP/c.json" -- curl -s -o /dev/null http://127.0.0.1:1/ >/dev/null 2>&1 || true
  nc=$(json_type_count "$TMP/c.json" network)
  if [[ "$nc" -gt 0 ]]; then
    pass "Config C includes network events"
  else
    fail "Config C includes network events"
  fi
else
  echo "[SKIP] Config C network test (curl not installed)"
fi

# 8 Config D > Config A
"$BIN" --config D --output "$TMP/d.json" -- /bin/true >/dev/null 2>&1
ca=$(json_count "$TMP/a.json")
cd=$(json_count "$TMP/d.json")
if [[ "$cd" -gt "$ca" ]]; then
  pass "Config D > Config A"
else
  fail "Config D > Config A ($cd vs $ca)"
fi

# --- 9–12: correlation, integrity, helpers ---
# 9 Correlation links events
if [[ "$(parent_linked "$TMP/b.json")" -eq 1 ]]; then
  pass "Correlation links events"
else
  fail "Correlation links events"
fi

# 10 Sidecar verifies
"$BIN" --config A --output "$TMP/int.json" -- /bin/true >/dev/null 2>&1
if sha256sum -c "$TMP/int.json.sha256" >/dev/null 2>&1; then
  pass "Sidecar verifies"
else
  fail "Sidecar verifies"
fi

# 11 Tamper detection
echo " " >> "$TMP/int.json"
if sha256sum -c "$TMP/int.json.sha256" >/dev/null 2>&1; then
  fail "Tamper detection"
else
  pass "Tamper detection"
fi

# 12 Timeline viewer
if python3 "$ROOT/scripts/view_timeline.py" "$TMP/b.json" >/dev/null 2>&1; then
  pass "Timeline viewer runs"
else
  fail "Timeline viewer runs"
fi

# --- 13: controlled scenario under ptrace ---
# 13 Scenario 1 end-to-end
if [[ -x "$ROOT/scenarios/scenario01_download_execute.sh" ]]; then
  SC_OUT="$TMP/scenario01.json"
  rm -f "$SC_OUT" "$SC_OUT.sha256"
  "$BIN" --config C --output "$SC_OUT" -- bash "$ROOT/scenarios/scenario01_download_execute.sh" >/dev/null 2>&1 || true
  ex=$(python3 - "$SC_OUT" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print(0)
    raise SystemExit
print(sum(1 for e in d["events"] if e["syscall"] == "execve"))
PY
)
  if [[ "$ex" -ge 2 ]]; then
    pass "Scenario 1 end-to-end"
  else
    fail "Scenario 1 end-to-end (execve count=$ex)"
  fi
else
  fail "Scenario 1 script missing"
fi

# --- 14–16: output path, truncated flag, cross-process correlation ---
# 14 Nested output directory (mkdir -p + non-empty JSON)
NEST="$TMP/nested/out.json"
rm -rf "$TMP/nested"
"$BIN" --config A --output "$NEST" -- /bin/echo hi >/dev/null 2>&1
if [[ -f "$NEST" ]] && [[ "$(stat -c%s "$NEST" 2>/dev/null || echo 0)" -gt 0 ]]; then
  pass "Output creates nested directory"
else
  fail "Output creates nested directory"
fi

# 15 truncated field in JSON schema
if python3 - "$NEST" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert "truncated" in d
assert d["truncated"] is False
PY
then
  pass "JSON includes truncated flag"
else
  fail "JSON includes truncated flag"
fi

# 16 Cross-process parent_event (child PID linked to parent clone/fork)
"$BIN" --config A --output "$TMP/fork.json" -- /bin/sh -c '/bin/true & wait' >/dev/null 2>&1
if python3 - "$TMP/fork.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
events = d["events"]
for i, e in enumerate(events):
    pe = e.get("parent_event", -1)
    if pe < 0:
        continue
    parent = events[pe]
    if parent["pid"] != e["pid"]:
        raise SystemExit(0)
raise SystemExit(1)
PY
then
  pass "Cross-process correlation"
else
  fail "Cross-process correlation"
fi

echo "=== Results: $PASS passed, $FAIL failed ==="
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
