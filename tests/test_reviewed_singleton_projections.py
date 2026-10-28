from __future__ import annotations

import copy
from pathlib import Path

import pytest

from verifier.domains.contracts import (
    actor_closure, actor_decision_record, actor_replay, arch_resolution,
    arch_schedule, arch_shapes, bench_attempts, collective_closure,
    collective_constraints, collective_lifecycle, data_distribution,
    env_configuration_surface, env_executable, env_pin_closure, graph_closure,
    graph_order, graph_statics, hardware_capacity, hardware_inventory,
    hardware_inventory_closure, hardware_measurements,
    hardware_substrate_observations, hardware_topology, human_no_composition,
    human_population_declaration, human_template_irreversibility,
    identity_lifecycle, identity_presentation, identity_scope,
    object_address_closure, reviewed_singleton_projections as projections,
)


# The reviewed pins admit exactly these source modules. A literal map keeps the
# test closed over that finite set instead of turning a manifest path into code.
_MODULES = {
    "src/verifier/domains/contracts/actor_closure.py": actor_closure,
    "src/verifier/domains/contracts/actor_decision_record.py": actor_decision_record,
    "src/verifier/domains/contracts/actor_replay.py": actor_replay,
    "src/verifier/domains/contracts/arch_resolution.py": arch_resolution,
    "src/verifier/domains/contracts/arch_schedule.py": arch_schedule,
    "src/verifier/domains/contracts/arch_shapes.py": arch_shapes,
    "src/verifier/domains/contracts/bench_attempts.py": bench_attempts,
    "src/verifier/domains/contracts/collective_closure.py": collective_closure,
    "src/verifier/domains/contracts/collective_constraints.py": collective_constraints,
    "src/verifier/domains/contracts/collective_lifecycle.py": collective_lifecycle,
    "src/verifier/domains/contracts/data_distribution.py": data_distribution,
    "src/verifier/domains/contracts/env_configuration_surface.py": env_configuration_surface,
    "src/verifier/domains/contracts/env_executable.py": env_executable,
    "src/verifier/domains/contracts/env_pin_closure.py": env_pin_closure,
    "src/verifier/domains/contracts/graph_closure.py": graph_closure,
    "src/verifier/domains/contracts/graph_order.py": graph_order,
    "src/verifier/domains/contracts/graph_statics.py": graph_statics,
    "src/verifier/domains/contracts/hardware_capacity.py": hardware_capacity,
    "src/verifier/domains/contracts/hardware_inventory.py": hardware_inventory,
    "src/verifier/domains/contracts/hardware_inventory_closure.py": hardware_inventory_closure,
    "src/verifier/domains/contracts/hardware_measurements.py": hardware_measurements,
    "src/verifier/domains/contracts/hardware_substrate_observations.py": hardware_substrate_observations,
    "src/verifier/domains/contracts/hardware_topology.py": hardware_topology,
    "src/verifier/domains/contracts/human_no_composition.py": human_no_composition,
    "src/verifier/domains/contracts/human_population_declaration.py": human_population_declaration,
    "src/verifier/domains/contracts/human_template_irreversibility.py": human_template_irreversibility,
    "src/verifier/domains/contracts/identity_lifecycle.py": identity_lifecycle,
    "src/verifier/domains/contracts/identity_presentation.py": identity_presentation,
    "src/verifier/domains/contracts/identity_scope.py": identity_scope,
    "src/verifier/domains/contracts/object_address_closure.py": object_address_closure,
}


def _registration(pin: dict[str, object]) -> dict[str, object]:
    module = _MODULES[str(pin["module_path"])]
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
