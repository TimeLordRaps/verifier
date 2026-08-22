#!/usr/bin/env python3
"""Deterministic word-frequency computation used by the VSTD generic-run example.

Pure standard library, no randomness, no floating point, and no wall-clock
dependence in its *output* — timing is recorded separately by the VSTD
receipt as execution metadata, not baked into these artifacts. That is what
lets this example legitimately declare ``determinism_declared: DETERMINISTIC``
in manifest.json.
"""
from __future__ import annotations

import json
import sys
from collections import Counter


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: compute.py <input.txt> <output.json> <metrics.json>", file=sys.stderr)
        return 2
    input_path, output_path, metrics_path = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(input_path, "r", encoding="utf-8") as f:
        text = f.read()

    tokens = text.split()
    counts = Counter(tokens)
    # Sort by (descending count, ascending token) so output order is fully
    # deterministic regardless of Python's dict/Counter iteration order.
    frequency_table = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"frequency_table": frequency_table}, f, indent=2, sort_keys=True)
        f.write("\n")

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump({"total_tokens": len(tokens), "unique_tokens": len(counts)}, f, indent=2, sort_keys=True)
        f.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
