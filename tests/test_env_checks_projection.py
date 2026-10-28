from __future__ import annotations

import copy
from pathlib import Path

import pytest

from verifier.domains.contracts import env_checks, env_checks_projection


def _candidate(check: str) -> dict[str, object]:
    pin = env_checks_projection.accepted_projection(check)
    return {
        "check": check, "object_kind": "ENV", "tier": pin["tier"],
        "member_id": pin["member_id"], "scope": pin["scope"],
        "route_instance_id": pin["route_instance_id"], "union_ref_id": pin["union_ref_id"],
        "claim_text": env_checks.registration(check)["proposition"],
        "claim_sha256": pin["union_claim_digest"], "source": pin["source"],
        "source_map_digest": pin["source_map_digest"],
        "producer_source_coordinate_digest": pin["producer_source_coordinate_digest"],
        "candidate_input_digest": pin["candidate_input_digest"],
        "contribution_index": pin["contribution_index"], "row_index": pin["row_index"],
    }


def test_exact_four_env_projections_are_bounded_and_zero_credit() -> None:
    assert env_checks_projection.MAPPED_CHECKS == (
        "closure", "configuration", "reproduction", "resources"
    )
    for check in env_checks_projection.MAPPED_CHECKS:
        result = env_checks_projection.project_registration(
            check, env_checks.registration(check), _candidate(check)
        )
        assert result["status"] == "STRUCTURAL_PROJECTION_ONLY"
        assert result["acceptance_mechanism"]["identifier"] == (
            "verifier.domains.contracts.env_checks.recheck_env_checks_certificate"
        )
        assert result["release_admissible"] is False
        assert result["test_credit"] == "NONE"


def test_env_unreviewed_reverse_and_substitution_are_refused() -> None:
    with pytest.raises(env_checks_projection.EnvChecksProjectionRefusal):
        env_checks_projection.accepted_projection("future")
    with pytest.raises(env_checks_projection.EnvChecksProjectionRefusal):
        env_checks_projection.project_registration(
            "closure", env_checks.registration("closure"), _candidate("closure"),
            direction="UNION_TO_ROUTE",
        )
    candidate = copy.deepcopy(_candidate("closure"))
    candidate["source_map_digest"] = "sha256:" + "0" * 64
    with pytest.raises(env_checks_projection.EnvChecksProjectionRefusal):
        env_checks_projection.project_registration(
            "closure", env_checks.registration("closure"), candidate
        )


def test_env_sources_and_note_are_successor_bound() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Path(env_checks_projection.__file__).resolve() == (
        root / "src/verifier/domains/contracts/env_checks_projection.py"
    ).resolve()
    assert env_checks_projection.bounded_accounting()["remaining_after"] == 93
    note = " ".join(
        (root / "src/verifier/standard/CURRENT_ENV_CHECK_PROJECTIONS.md")
        .read_text(encoding="utf-8").split()
    )
    assert "four fixed ENV mappings" in note
    assert "zero evidence, authority, package, installed-mechanism, test, profile, completeness, and release credit" in note
