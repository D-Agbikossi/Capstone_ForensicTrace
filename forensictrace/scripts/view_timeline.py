#!/usr/bin/env python3
"""Render a ForensicTrace experiment JSON as a simple timeline."""

import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: view_timeline.py <experiment.json>", file=sys.stderr)
        return 1

    with open(sys.argv[1], encoding="utf-8") as fh:
        data = json.load(fh)

    events = data.get("events", [])
    config = data.get("config", "?")
    duration_ns = data.get("duration_ns", 0)
    duration_ms = duration_ns / 1e6 if duration_ns else 0.0

    print("=== ForensicTrace JSON Timeline ===")
    print(f"Config: {config} | Events: {len(events)} | Duration: {duration_ms:.3f} ms\n")

    if not events:
        print("(no events)")
        return 0

    base = events[0].get("ts_ns", 0)
    print(f"{'#':<5} {'Delta(ms)':<10} {'Type':<9} {'PID':<8} {'Syscall':<12} Target")
    print("-" * 72)
    for ev in events:
        ts = ev.get("ts_ns", base)
        delta = (ts - base) / 1e6
        target = ev.get("target") or ev.get("detail") or ""
        print(
            f"{ev.get('id', 0):<5} {delta:<10.3f} {ev.get('type', ''):<9} "
            f"{ev.get('pid', 0):<8} {ev.get('syscall', ''):<12} {target}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
