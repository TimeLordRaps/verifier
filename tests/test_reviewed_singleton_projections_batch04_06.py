from __future__ import annotations

import copy
import importlib
from pathlib import Path

import pytest

from verifier.domains.contracts import reviewed_singleton_projections_batch04_06 as projections


def _registration(pin: dict[str, object]) -> dict[str, object]:
    module_name = str(pin["module_path"])[4:-3].replace("/", ".")
    module = importlib.import_module(module_name)
    factory = getattr(module, "registration", None)
    return factory() if callable(factory) else dict(module.PROPOSITION)


def _candidate(pin: dict[str, object], registration: dict[str, object]) -> dict[str, object]:
    return {
        "member_id": pin["member_id"],
        "object_kind": pin["object_kind"],
        "tier": pin["tier"],
        "scope": pin["scope"],
        "route_instance_id": pin["route_instance_id"],
        "union_ref_id": pin["union_ref_id"],
        "claim_text": registration["proposition"],
        "claim_sha256": pin["union_claim_digest"],
        "source": {"uri": pin["source_uri"], "sha256": pin["source_sha256"]},
        "source_map_digest": pin["source_map_digest"],
        "producer_source_coordinate_digest": pin["producer_source_coordinate_digest"],
        "candidate_input_digest": pin["candidate_input_digest"],
        "contribution_index": pin["contribution_index"],
        "row_index": pin["row_index"],
    }


@pytest.mark.parametrize("member_id", projections.MAPPED_MEMBERS)
def test_exact_twenty_reviewed_singleton_projections_are_structural(member_id: str) -> None:
    pin = projections.accepted_projection(member_id)
    registration = _registration(pin)
    result = projections.project_registration(member_id, registration, _candidate(pin, registration))
    assert result["status"] == "STRUCTURAL_PROJECTION_ONLY"
    assert result["acceptance_mechanism"]["identifier"] == pin["mechanism"]
    assert result["dependency_binding_status"] == "UNKNOWN"
    assert result["dependency_discharged_by_mapping"] is False
    assert result["test_credit"] == "NONE"
    assert result["release_admissible"] is False


def test_fixed_set_and_reviewed_refusals_are_exact() -> None:
    assert len(projections.MAPPED_MEMBERS) == len(set(projections.MAPPED_MEMBERS)) == 20
    assert projections.EXCLUDED_MEMBERS == (
        "OBJECT-1.1", "SIM-5.1", "EVENT-2.1", "EVENT-3.1", "EVENT-4.1",
        "OWNER-2.6", "OWNER-4.3", "SPACE-2.1", "SPACE-3.1", "SPACE-4.1",
    )
    for member_id in projections.EXCLUDED_MEMBERS:
        with pytest.raises(projections.ReviewedSingletonBatch0406Refusal):
            projections.accepted_projection(member_id)
    with pytest.raises(projections.ReviewedSingletonBatch0406Refusal):
        projections.accepted_projection("UNREVIEWED-99.99")


def test_reverse_and_coordinate_substitution_are_refused() -> None:
    pin = projections.accepted_projection("OBJECT-2.1")
    registration = _registration(pin)
    candidate = _candidate(pin, registration)
    with pytest.raises(projections.ReviewedSingletonBatch0406Refusal, match="ROUTE_TO_UNION"):
        projections.project_registration(
            "OBJECT-2.1", registration, candidate, direction="UNION_TO_ROUTE"
        )
    substituted = copy.deepcopy(candidate)
    substituted["source_map_digest"] = "sha256:" + "0" * 64
    with pytest.raises(projections.ReviewedSingletonBatch0406Refusal, match="substituted"):
        projections.project_registration("OBJECT-2.1", registration, substituted)


def test_all_declared_dependency_edges_remain_unresolved() -> None:
    assert len(projections.DECLARED_DEPENDENCY_EDGES) == 27
    assert all(len(edge) == 3 for edge in projections.DECLARED_DEPENDENCY_EDGES)
    accounting = projections.bounded_accounting()
    assert accounting == {
        "uninspected_before": 56,
        "processed": 30,
        "mapped": 20,
        "reviewed_refusals": 10,
        "uninspected_after": 26,
        "mapped_credit": 0,
        "dependency_edges_unresolved": 27,
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
    }


def test_source_and_boundary_note_are_successor_bound() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Path(projections.__file__).resolve() == (
        root / "src/verifier/domains/contracts/reviewed_singleton_projections_batch04_06.py"
    ).resolve()
    note = " ".join(
        (root / "src/verifier/standard/CURRENT_REVIEWED_SINGLETON_PROJECTIONS_BATCH04_06.md")
        .read_text(encoding="utf-8").split()
    )
    for phrase in (
        "exactly 20 accepted singleton mappings",
        "10 exact reviewed refusals",
        "no mechanism-family fallback",
        "27 declared dependency relations remain unresolved",
        "26 rows remain uninspected",
        "zero evidence, authority, package, installed-mechanism, test, profile, completeness, or release credit",
    ):
        assert phrase in note
