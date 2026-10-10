from __future__ import annotations

import copy
import importlib
from pathlib import Path

import pytest

from verifier.domains.contracts import reviewed_singleton_projections as projections


def _registration(pin: dict[str, object]) -> dict[str, object]:
    module_name = str(pin["module_path"])[4:-3].replace("/", ".")
    module = importlib.import_module(module_name)
    registration = getattr(module, "registration", None)
    return registration() if callable(registration) else dict(module.PROPOSITION)


def _candidate(pin: dict[str, object], registration: dict[str, object]) -> dict[str, object]:
    return {
        "member_id": pin["member_id"], "object_kind": pin["object_kind"], "tier": pin["tier"],
        "scope": pin["scope"], "route_instance_id": pin["route_instance_id"],
        "union_ref_id": pin["union_ref_id"], "claim_text": registration["proposition"],
        "claim_sha256": pin["union_claim_digest"],
        "source": {"uri": pin["source_uri"], "sha256": pin["source_sha256"]},
        "source_map_digest": pin["source_map_digest"],
        "producer_source_coordinate_digest": pin["producer_source_coordinate_digest"],
        "candidate_input_digest": pin["candidate_input_digest"],
        "contribution_index": pin["contribution_index"], "row_index": pin["row_index"],
    }


def test_exact_thirty_reviewed_singletons_are_structural_only() -> None:
    assert len(projections.MAPPED_MEMBERS) == 30
    assert len(set(projections.MAPPED_MEMBERS)) == 30
    for member in projections.MAPPED_MEMBERS:
        pin = projections.accepted_projection(member)
        registration = _registration(pin)
        result = projections.project_registration(member, registration, _candidate(pin, registration))
        assert result["status"] == "STRUCTURAL_PROJECTION_ONLY"
        assert result["acceptance_mechanism"]["identifier"] == pin["mechanism"]
        assert result["dependency_discharged_by_mapping"] is False
        assert result["release_admissible"] is False


def test_no_unreviewed_family_or_reverse_fallback_exists() -> None:
    with pytest.raises(projections.ReviewedSingletonProjectionRefusal, match="outside"):
        projections.accepted_projection("SIM-99.99")
    pin = projections.accepted_projection("ACTOR-2.7")
    registration = _registration(pin)
    with pytest.raises(projections.ReviewedSingletonProjectionRefusal, match="ROUTE_TO_UNION"):
        projections.project_registration(
            "ACTOR-2.7", registration, _candidate(pin, registration), direction="UNION_TO_ROUTE"
        )


@pytest.mark.parametrize("field", [
    "object_kind", "tier", "scope", "route_instance_id", "union_ref_id",
    "claim_sha256", "source", "source_map_digest", "producer_source_coordinate_digest",
    "candidate_input_digest", "contribution_index", "row_index",
])
def test_singleton_coordinate_substitution_is_refused(field: str) -> None:
    pin = projections.accepted_projection("ACTOR-2.7")
    registration = _registration(pin)
    candidate = copy.deepcopy(_candidate(pin, registration))
    candidate[field] = None
    with pytest.raises(projections.ReviewedSingletonProjectionRefusal, match="substituted"):
        projections.project_registration("ACTOR-2.7", registration, candidate)


def test_four_dependency_edges_remain_unresolved() -> None:
    assert projections.DEPENDENCY_EDGES == (
        {"dependent": "ARCH-2.1", "prerequisite": "ARCH-3.1"},
        {"dependent": "COLLECTIVE-2.1", "prerequisite": "COLLECTIVE-3.1"},
        {"dependent": "GRAPH-2.1", "prerequisite": "GRAPH-3.1"},
        {"dependent": "IDENTITY-2.1", "prerequisite": "IDENTITY-3.1"},
    )
    accounting = projections.bounded_accounting()
    assert accounting["remaining_after"] == 56
    assert accounting["dependency_edges_unresolved"] == list(projections.DEPENDENCY_EDGES)


def test_source_and_boundary_note_are_successor_bound() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Path(projections.__file__).resolve() == (
        root / "src/verifier/domains/contracts/reviewed_singleton_projections.py"
    ).resolve()
    note = " ".join(
        (root / "src/verifier/standard/CURRENT_REVIEWED_SINGLETON_PROJECTIONS.md")
        .read_text(encoding="utf-8").split()
    )
    for phrase in (
        "exactly 30 reviewed singleton mappings", "no mechanism-family fallback",
        "ARCH, COLLECTIVE, GRAPH, and IDENTITY", "56 rows remain unresolved",
        "zero evidence, authority, package, installed-mechanism, test, profile, completeness, or release credit",
    ):
        assert phrase in note
