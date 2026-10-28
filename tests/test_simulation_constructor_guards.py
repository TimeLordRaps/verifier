"""Terminology: Secure Hash Algorithm 256-bit (SHA-256); simulation (SIM).

Constructor guards of the abstract simulation specification: each malformed frame, manifest or
snapshot is refused when it is built, for the stated reason, and the values on the accepted side
of each boundary stay accepted.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from verifier.corrigibility import (
    AbstractSimulationManifest,
    CausalOrderingKind,
    SecondOrderHyperOntology,
    SimulationError,
    SimulationTier,
    StateSnapshot,
    StateTopologyType,
    compute_state_digest,
)

DIGEST_REASON = "is not a valid sha256 digest"

MALFORMED_DIGESTS = (
    pytest.param("", id="empty"),
    pytest.param("sha256:", id="prefix-only"),
    pytest.param("a" * 64, id="no-prefix"),
    pytest.param("sha256:" + "a" * 63, id="one-digit-short"),
    pytest.param("sha256:" + "a" * 65, id="one-digit-long"),
    pytest.param("sha256:" + "A" * 64, id="uppercase-hex"),
    pytest.param("SHA256:" + "a" * 64, id="uppercase-prefix"),
    pytest.param("md5:" + "a" * 64, id="other-algorithm"),
    pytest.param("sha256:" + "g" * 64, id="non-hex-digit"),
)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _ontology(**overrides: Any) -> SecondOrderHyperOntology:
    fields: dict[str, Any] = {
        "frame_id": "frame:guards",
        "state_topology": StateTopologyType.DISCRETE_LATTICE,
        "causal_ordering": CausalOrderingKind.DISCRETE_STEPS,
        "initial_seed": 7,
        "entropy_stream_digest": _digest("entropy"),
        "declared_invariants": ("bounded_memory",),
    }
    fields.update(overrides)
    return SecondOrderHyperOntology(**fields)


def _manifest(**overrides: Any) -> AbstractSimulationManifest:
    fields: dict[str, Any] = {
        "simulation_id": "sim:guards",
        "generator_name": "generator:guards",
        "target_tier": SimulationTier.SIM_1_TRACE_REPLAY,
        "ontology": _ontology(),
        "initial_state_digest": _digest("state-0"),
        "trajectory_length": 3,
    }
    fields.update(overrides)
    return AbstractSimulationManifest(**fields)


def _snapshot(**overrides: Any) -> StateSnapshot:
    fields: dict[str, Any] = {
        "step_index": 0,
        "causal_time": 0.0,
        "state_payload": {"cell": 1},
        "state_digest": compute_state_digest({"cell": 1}),
    }
    fields.update(overrides)
    return StateSnapshot(**fields)


def test_well_formed_values_are_accepted() -> None:
    ontology = _ontology()
    manifest = _manifest(ontology=ontology)
    snapshot = _snapshot()
    assert ontology.frame_id == "frame:guards"
    assert manifest.ontology is ontology
    assert manifest.trajectory_length == 3
    assert snapshot.state_digest == compute_state_digest({"cell": 1})
    assert StateSnapshot.create(0, 0.0, {"cell": 1}).state_digest == snapshot.state_digest


def test_an_empty_frame_id_is_refused() -> None:
    with pytest.raises(SimulationError, match="frame_id cannot be empty"):
        _ontology(frame_id="")


@pytest.mark.parametrize("malformed", MALFORMED_DIGESTS)
def test_a_malformed_entropy_stream_digest_is_refused(malformed: str) -> None:
    with pytest.raises(SimulationError, match=f"entropy_stream_digest .* {DIGEST_REASON}"):
        _ontology(entropy_stream_digest=malformed)


def test_an_empty_simulation_id_is_refused() -> None:
    with pytest.raises(SimulationError, match="simulation_id cannot be empty"):
        _manifest(simulation_id="")


def test_an_empty_generator_name_is_refused() -> None:
    with pytest.raises(SimulationError, match="generator_name cannot be empty"):
        _manifest(generator_name="")


@pytest.mark.parametrize("length", (-1, -1000))
def test_a_negative_trajectory_length_is_refused(length: int) -> None:
    with pytest.raises(SimulationError, match="trajectory_length cannot be negative"):
        _manifest(trajectory_length=length)


def test_a_zero_length_trajectory_is_accepted() -> None:
    assert _manifest(trajectory_length=0).trajectory_length == 0


@pytest.mark.parametrize("malformed", MALFORMED_DIGESTS)
def test_a_malformed_initial_state_digest_is_refused(malformed: str) -> None:
    with pytest.raises(SimulationError, match=f"initial_state_digest .* {DIGEST_REASON}"):
        _manifest(initial_state_digest=malformed)


def test_a_negative_step_index_is_refused() -> None:
    with pytest.raises(SimulationError, match="step_index cannot be negative"):
        _snapshot(step_index=-1)


def test_step_index_zero_is_accepted() -> None:
    assert _snapshot(step_index=0).step_index == 0


@pytest.mark.parametrize("malformed", MALFORMED_DIGESTS)
def test_a_malformed_state_digest_is_refused(malformed: str) -> None:
    with pytest.raises(SimulationError, match=f"state_digest .* {DIGEST_REASON}"):
        _snapshot(state_digest=malformed)


def test_a_snapshot_rebuilt_from_a_dictionary_is_held_to_the_same_guard() -> None:
    data = _snapshot().to_dict()
    data["state_digest"] = "sha256:" + "A" * 64
    with pytest.raises(SimulationError, match=f"state_digest .* {DIGEST_REASON}"):
        StateSnapshot.from_dict(data)
