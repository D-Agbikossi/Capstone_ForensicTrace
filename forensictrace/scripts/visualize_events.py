#!/usr/bin/env python3
"""Summarise event counts by type; optional PNG bar chart (needs matplotlib)."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter


def main() -> int:
    parser = argparse.ArgumentParser(description="Visualize ForensicTrace event types")
    parser.add_argument("json_path", help="Path to experiment JSON")
    parser.add_argument(
        "-o",
        "--output",
        help="Write PNG chart to this path (requires matplotlib)",
    )
    args = parser.parse_args()

    with open(args.json_path, encoding="utf-8") as fh:
        data = json.load(fh)

    events = data.get("events", [])
    counts = Counter(e.get("type", "unknown") for e in events)
    config = data.get("config", "?")

    print(f"Config: {config} | Total events: {len(events)}")
    for kind in sorted(counts):
        print(f"  {kind:10} {counts[kind]}")

    if not args.output:
        return 0

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print(
            "matplotlib not installed; text summary only. "
            "Install: sudo apt install python3-matplotlib",
            file=sys.stderr,
        )
        return 1

    labels = list(counts.keys())
    values = [counts[k] for k in labels]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(labels, values, color=["#2563eb", "#16a34a", "#ea580c", "#64748b"][: len(labels)])
    ax.set_title(f"ForensicTrace events by type (config {config})")
    ax.set_ylabel("Count")
    ax.set_xlabel("Event type")
    fig.tight_layout()
    fig.savefig(args.output, dpi=120)
    print(f"Wrote chart to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
