#!/usr/bin/env python3
"""Run the complete validation suite for this experiment.

Uses the standard library only, so it runs without pytest. When pytest is present,
``python -m pytest experiments/zizk_vstd/zero_identity/tests -q`` runs the same
fixtures plus the inference-blocking assertions.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from evaluate import evaluate  # noqa: E402


def main() -> int:
    failures: list[str] = []
    fixtures = sorted((HERE / "fixtures").glob("*.json"))
    if not fixtures:
        print("no fixtures found")
        return 1
    for path in fixtures:
        fixture = json.loads(path.read_text(encoding="utf-8"))
        outcome = evaluate(fixture["record"])
        expected = fixture["expected"]
        if outcome.verdict != expected["verdict"]:
            failures.append(
                f"{path.name}: verdict {outcome.verdict} != {expected['verdict']}"
            )
        for name, want in expected["properties"].items():
            got = outcome.properties.get(name)
            if got != want:
                failures.append(f"{path.name}: {name} {got} != {want}")
        print(f"{outcome.verdict:<17} {path.stem}")
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{len(fixtures)} fixtures, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
