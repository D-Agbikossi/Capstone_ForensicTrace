#!/usr/bin/env python3
"""View a ForensicTrace experiment JSON file as a timeline."""
import json
import sys


def main(path):
    with open(path) as f:
        data = json.load(f)

    print("\n=== ForensicTrace Experiment ===")
    print(f"Config      : {data.get('config')}")
    print(f"Event count : {data.get('event_count')}")
    print(f"Duration    : {data.get('duration_ns', 0) / 1e6:.3f} ms")
    print("=================================\n")

    events = data.get("events", [])
    if not events:
        print("No events recorded.")
        return

    base = events[0]["ts_ns"]

    print(f"{'#':<5} {'Delta(ms)':<10} {'Type':<9} "
          f"{'PID':<8} {'PPID':<8} {'Syscall':<12} Target")
    print("-" * 90)

    for e in events:
        delta = (e["ts_ns"] - base) / 1e6
        print(f"{e['id']:<5} {delta:<10.3f} {e['type']:<9} "
              f"{e['pid']:<8} {e['ppid']:<8} {e['syscall']:<12} "
              f"{e.get('target','')}")

    print("-" * 90)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <experiment.json>")
        sys.exit(1)
    main(sys.argv[1])
    