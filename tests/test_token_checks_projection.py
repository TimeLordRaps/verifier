from __future__ import annotations

import copy
from pathlib import Path

import pytest

from verifier.domains.contracts import token_checks, token_checks_projection


def _candidate(check: str) -> dict[str, object]:
    pin = token_checks_projection.accepted_projection(check)
    return {
        "check": check, "object_kind": "TOKEN", "tier": pin["tier"],
        "member_id": pin["member_id"], "scope": pin["scope"], "source_rows": pin["source_rows"],
        "route_instance_id": pin["route_instance_id"], "union_ref_id": pin["union_ref_id"],
        "claim_text": token_checks.registration(check)["proposition"],
        "claim_sha256": pin["union_claim_digest"], "source": pin["source"],
        "source_map_digest": pin["source_map_digest"],
        "producer_source_coordinate_digest": pin["producer_source_coordinate_digest"],
        "candidate_input_digest": pin["candidate_input_digest"],
        "contribution_index": pin["contribution_index"], "row_index": pin["row_index"],
    }


def test_exact_three_token_projections_preserve_disjoint_exclusions() -> None:
    assert token_checks_projection.MAPPED_CHECKS == ("tenure", "windows", "delegation")
    assert token_checks_projection.EXCLUDED_DISJOINT_MEMBERS == ("TOKEN-1.1", "TOKEN-5.1")
    for check in token_checks_projection.MAPPED_CHECKS:
        result = token_checks_projection.project_registration(
            check, token_checks.registration(check), _candidate(check)
        )
        assert result["status"] == "STRUCTURAL_PROJECTION_ONLY"
        assert result["excluded_disjoint_members"] == ["TOKEN-1.1", "TOKEN-5.1"]
        assert result["release_admissible"] is False


def test_token_unreviewed_reverse_and_source_row_substitution_are_refused() -> None:
    with pytest.raises(token_checks_projection.TokenChecksProjectionRefusal):
        token_checks_projection.accepted_projection("inventory")
    with pytest.raises(token_checks_projection.TokenChecksProjectionRefusal):
        token_checks_projection.project_registration(
            "tenure", token_checks.registration("tenure"), _candidate("tenure"),
            direction="UNION_TO_ROUTE",
        )
    candidate = copy.deepcopy(_candidate("tenure"))
    candidate["source_rows"] = []
    with pytest.raises(token_checks_projection.TokenChecksProjectionRefusal):
        token_checks_projection.project_registration(
            "tenure", token_checks.registration("tenure"), candidate
        )


def test_token_sources_and_note_are_successor_bound() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Path(token_checks_projection.__file__).resolve() == (
        root / "src/verifier/domains/contracts/token_checks_projection.py"
    ).resolve()
    assert token_checks_projection.bounded_accounting()["remaining_after"] == 86
    note = " ".join(
        (root / "src/verifier/standard/CURRENT_TOKEN_CHECK_PROJECTIONS.md")
        .read_text(encoding="utf-8").split()
    )
    assert "TOKEN-1.1 and TOKEN-5.1 remain excluded" in note
    assert "no duplicate credit" in note
