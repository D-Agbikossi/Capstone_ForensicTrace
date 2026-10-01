#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/experiments"
BIN="$ROOT/forensictrace"
CONFIGS=(A B C D)
SCENARIOS=(
  "scenario01_download_execute.sh"
  "scenario02_privilege_escalation.sh"
  "scenario03_network_payload.sh"
  "scenario04_file_corruption.sh"
)
REPS=4

mkdir -p "$OUT"
MANIFEST="$OUT/manifest.csv"
echo "run_id,scenario,config,rep,json_path,sha256_path,event_count" > "$MANIFEST"

run_id=0
for sc in "${SCENARIOS[@]}"; do
  for cfg in "${CONFIGS[@]}"; do
    for rep in $(seq 1 "$REPS"); do
      run_id=$((run_id + 1))
      base="${sc%.sh}_${cfg}_r${rep}"
      json="$OUT/${base}.json"
      "$BIN" --config "$cfg" --output "$json" -- bash "$ROOT/scenarios/$sc" >/dev/null 2>&1 || true
      count=$(python3 - "$json" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("event_count", 0))
except Exception:
    print(0)
PY
)
      echo "${run_id},${sc},${cfg},${rep},${json},${json}.sha256,${count}" >> "$MANIFEST"
    done
  done
done

echo "Wrote $run_id experiments under $OUT"
echo "Manifest: $MANIFEST"
