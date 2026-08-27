"""Terminology: Request for Comments (RFC); Verifier Standard (VSTD).

Installed specification resources must match the public normative files exactly."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_packaged_specification_bytes_match_normative_sources() -> None:
    normative_files = sorted((REPO_ROOT / "standard").glob("*.md"))
    packaged_dir = REPO_ROOT / "src" / "verifier" / "specifications"
    assert {path.name for path in packaged_dir.glob("*.md")} == {
        path.name for path in normative_files
    }
    for normative in normative_files:
        assert (packaged_dir / normative.name).read_bytes() == normative.read_bytes(), (
            normative.name
        )


def test_ladder_fixes_causal_provenance_directions_without_actor_trust() -> None:
    ladder = (REPO_ROOT / "standard" / "LADDER.md").read_text(encoding="utf-8")
    assert "ancestor artifact --bounded positive support--> descendant" in ladder
    assert "descendant Rust   --memetic causal backtrace--> recorded ancestor states" in ladder
    assert "Memetic propagation" in ladder
    assert "RFC 2119" in ladder
    assert "RFC 8174" in ladder
    assert "not computable conformance results" in ladder
    assert "current VSTD runtime emits or validates either transfer" in ladder
    assert "MUST NOT strengthen an artifact-bound result" in ladder
    assert "They do not cancel, form one\nscalar score" in ladder
