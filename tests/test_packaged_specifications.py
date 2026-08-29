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
    assert "ancestor artifact --TRUST through a checked transformation--> descendant" in ladder
    assert "recorded TRUST    --ROT under typed current-state evidence--> reassessment" in ladder
    assert "descendant deviation --RUST memetic causal backtrace--> ancestor candidates" in ladder
    assert "Memetic propagation" in ladder
    assert "RFC 2119" in ladder
    assert "RFC 8174" in ladder
    assert "not serialized receipt values or\ncomputable conformance results" in ladder
    assert "current VSTD runtime emits or validates a TRUST, ROT, or\nRUST transfer" in ladder
    assert "MUST NOT strengthen an artifact-bound\nresult" in ladder
    assert "TRUST and RUST never cancel" in ladder
    assert "whether an actor is good, bad, reputable, or worthy of trust" in ladder
    assert "zero unevidenced knowledge is presumed" in ladder
    assert "cryptographic zero knowledge" in ladder
