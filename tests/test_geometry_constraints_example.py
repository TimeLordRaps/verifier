"""Executable Verifier Standard (VSTD) geometry constraint teaching path.

Boolean satisfiability problem (SAT); unsatisfiable (UNSAT); JavaScript Object
Notation (JSON). These outcomes never replace unresolved geometry judgments.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_geometry_constraint_example_source_only() -> None:
    environment = {key: os.environ[key] for key in ("SystemRoot", "TEMP", "TMP") if key in os.environ}
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-u", "-B", "-S", "examples/geometry_constraints/demo.py"],
        cwd=ROOT, env=environment,
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    cases = report["cases"]
    assert [case["status"] for case in cases] == ["SAT", "UNSAT", "UNKNOWN"]
    assert [case["rechecked_status"] for case in cases] == ["SAT", "UNSAT", "UNKNOWN"]
    assert len({case["problem_digest"] for case in cases}) == 3
    assert cases[0]["model"] is not None and cases[0]["certificate"] is None
    assert dict(cases[0]["model"]) == {"compact": True, "icons": True}
    assert cases[1]["model"] is None and cases[1]["certificate"]["proof"][-1] == []
    assert cases[2]["model"] is None and cases[2]["certificate"] is None
    assert report["coordinate_statuses"] == ["INDETERMINATE", "INDETERMINATE"]
    assert "No geometry hole is discharged" in report["claim_boundary"]
