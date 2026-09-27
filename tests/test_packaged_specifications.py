"""Terminology: Request for Comments (RFC); Verifier Standard (VSTD).

The packaged specification resources are the normative files."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_ladder_fixes_causal_provenance_directions_without_actor_trust() -> None:
    ladder = (REPO_ROOT / "src" / "verifier" / "standard" / "LADDER.md").read_text(encoding="utf-8")
    assert "ancestor artifact --TRUST through a checked transformation--> descendant" in ladder
    assert "recorded TRUST    --ROT under typed current-state evidence--> reassessment" in ladder
    assert "descendant deviation --RUST memetic causal backtrace--> ancestor candidates" in ladder
    assert "Memetic propagation" in ladder
    assert "RFC 2119" in ladder
    assert "RFC 8174" in ladder
    assert "serialize as typed event kinds only in the non-receipt\n`verifier-graph-assurance-1` mechanism log" in ladder
    assert "`AssuranceLedger` implements mechanism-earned forward TRUST" in ladder
    assert "`recheck_assurance_log` reconstructs the historical Graph" in ladder
    assert "MUST NOT strengthen an artifact-bound\nresult" in ladder
    assert "TRUST and RUST never cancel" in ladder
    assert "whether an actor is good, bad, reputable, or worthy of trust" in ladder
    assert "zero unevidenced knowledge is presumed" in ladder
    assert "cryptographic zero knowledge" in ladder
