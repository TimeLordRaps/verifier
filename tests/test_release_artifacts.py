"""The public source archive must bind exact, publicly resolvable Git bytes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "release_artifacts.py"


def test_source_release_manifest_binds_head_and_exact_archive_bytes(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(REPO_ROOT),
            "source",
            "--ref",
            "HEAD",
            "--release",
            "test",
            "--output-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    manifest_path = tmp_path / "verifier-standard-test.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
    ).strip()
    assert manifest["source"]["commit"] == expected_commit
    assert manifest["source"]["ref"] == "HEAD"
    assert "RELEASE-MANIFEST.json" not in manifest["files"]
    assert manifest["source"]["byte_semantics"] == (
        "exact Git blob bytes as emitted by git archive"
    )

    verify = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(REPO_ROOT),
            "verify",
            str(manifest_path),
        ],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stderr
