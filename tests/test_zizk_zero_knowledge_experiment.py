from __future__ import annotations

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments" / "zizk_vstd" / "zero_knowledge"


def test_zero_knowledge_experiment_is_optional_and_pinned() -> None:
    host_manifest = (EXPERIMENT / "host" / "Cargo.toml").read_text(encoding="utf-8")
    guest_manifest = (
        EXPERIMENT / "methods" / "guest" / "Cargo.toml"
    ).read_text(encoding="utf-8")
    methods_manifest = (EXPERIMENT / "methods" / "Cargo.toml").read_text(
        encoding="utf-8"
    )

    assert 'version = "=3.0.6"' in host_manifest
    assert 'features = ["disable-dev-mode"]' in host_manifest
    assert 'version = "=3.0.6"' in guest_manifest
    assert 'version = "=3.0.6"' in methods_manifest
    assert "zizk" not in (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()


def test_zero_knowledge_claim_boundary_is_explicit() -> None:
    boundary = (EXPERIMENT / "CLAIM_BOUNDARY.md").read_text(encoding="utf-8")
    assert "does not prove" in boundary
    assert "optional experiment" in boundary
    assert "UNKNOWN" in boundary
    assert "CONFLICTED" in boundary


def test_private_and_generated_artifacts_are_not_versioned() -> None:
    ignore = (EXPERIMENT / ".gitignore").read_text(encoding="utf-8")
    assert "private-*.json" in ignore
    assert "local-artifacts/" in ignore
    tracked = subprocess.run(
        ["git", "ls-files", "--", "experiments/zizk_vstd/zero_knowledge"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert not any(path.endswith(".msgpack") for path in tracked)
    assert not any("private-" in path and path.endswith(".json") for path in tracked)
