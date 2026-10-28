from __future__ import annotations

import copy
from pathlib import Path

import pytest

from verifier.domains.contracts import bench_checks, bench_checks_projection


def _candidate(check: str) -> dict[str, object]:
    pin = bench_checks_projection.accepted_projection(check)
    return {
        "check": check, "object_kind": "BENCH", "tier": pin["tier"],
        "member_id": pin["member_id"], "scope": pin["scope"],
        "route_instance_id": pin["route_instance_id"], "union_ref_id": pin["union_ref_id"],
        "claim_text": bench_checks.registration(check)["proposition"],
        "claim_sha256": pin["union_claim_digest"], "source": pin["source"],
        "source_map_digest": pin["source_map_digest"],
        "producer_source_coordinate_digest": pin["producer_source_coordinate_digest"],
        "candidate_input_digest": pin["candidate_input_digest"],
        "contribution_index": pin["contribution_index"], "row_index": pin["row_index"],
    }


def test_exact_four_bench_projections_exclude_bench_attempts() -> None:
    assert bench_checks_projection.MAPPED_CHECKS == (
        "problems", "oracles", "budgets", "coverage"
    )
    assert bench_checks_projection.EXCLUDED_DISJOINT_MEMBER == "BENCH-2.1"
    for check in bench_checks_projection.MAPPED_CHECKS:
        result = bench_checks_projection.project_registration(
            check, bench_checks.registration(check), _candidate(check)
        )
        assert result["status"] == "STRUCTURAL_PROJECTION_ONLY"
        assert result["excluded_disjoint_members"] == ["BENCH-2.1"]
        assert result["release_admissible"] is False


def test_bench_unreviewed_reverse_and_substitution_are_refused() -> None:
    with pytest.raises(bench_checks_projection.BenchChecksProjectionRefusal):
        bench_checks_projection.accepted_projection("attempts")
    with pytest.raises(bench_checks_projection.BenchChecksProjectionRefusal):
        bench_checks_projection.project_registration(
            "problems", bench_checks.registration("problems"), _candidate("problems"),
            direction="UNION_TO_ROUTE",
        )
    candidate = copy.deepcopy(_candidate("problems"))
    candidate["member_id"] = "BENCH-2.1"
    with pytest.raises(bench_checks_projection.BenchChecksProjectionRefusal):
        bench_checks_projection.project_registration(
            "problems", bench_checks.registration("problems"), candidate
        )


def test_bench_sources_and_note_are_successor_bound() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Path(bench_checks_projection.__file__).resolve() == (
        root / "src/verifier/domains/contracts/bench_checks_projection.py"
    ).resolve()
    assert bench_checks_projection.bounded_accounting()["remaining_after"] == 89
    note = " ".join(
        (root / "src/verifier/standard/CURRENT_BENCH_CHECK_PROJECTIONS.md")
        .read_text(encoding="utf-8").split()
    )
    assert "BENCH-2.1 remains excluded" in note
    assert "separate bench-attempts mechanism" in note
