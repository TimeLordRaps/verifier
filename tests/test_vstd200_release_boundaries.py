"""Verifier Standard (VSTD) candidate regressions for unevidenced success."""

from __future__ import annotations

from dataclasses import replace
import json
import math
from pathlib import Path

import pytest

from verifier.corrigibility import (
    AbstractSimulationManifest, CausalOrderingKind, SecondOrderHyperOntology,
    SimulationTier, SimulationVerdict, StateSnapshot, StateTopologyType,
    compute_state_digest, evaluate_vstd_sim_receipt, verify_sim1_trace_replay,
    verify_sim3_bisimulation_abstraction, verify_sim4_agent_parity_contained,
    verify_sim5_distributed_sharded,
)


def _case(tier: SimulationTier = SimulationTier.SIM_1_TRACE_REPLAY):
    state = {"x": 0}
    ontology = SecondOrderHyperOntology(
        "frame", StateTopologyType.DISCRETE_LATTICE,
        CausalOrderingKind.DISCRETE_STEPS, 0, compute_state_digest([1]), ("bounded",),
    )
    manifest = AbstractSimulationManifest(
        "sim", "increment", tier, ontology, compute_state_digest(state), 2,
    )
    trajectory = [StateSnapshot.create(0, 0.0, state), StateSnapshot.create(1, 1.0, {"x": 1})]
    return manifest, trajectory, state


@pytest.mark.parametrize("tier", list(SimulationTier))
def test_missing_mechanisms_never_verify(tier: SimulationTier) -> None:
    manifest, trajectory, state = _case(tier)
    receipt = evaluate_vstd_sim_receipt(manifest, trajectory, state, [1])
    assert receipt.verdict == SimulationVerdict.NOT_ESTABLISHED
    assert receipt.invariants_checked == ()
    assert receipt.shards_verified == ()


@pytest.mark.parametrize("tier", list(SimulationTier)[1:])
def test_replay_alone_cannot_establish_higher_profile(tier: SimulationTier) -> None:
    manifest, trajectory, state = _case(tier)
    receipt = evaluate_vstd_sim_receipt(
        manifest, trajectory, state, [1], generator_step_fn=lambda s, e: {"x": s["x"] + e},
    )
    assert receipt.verdict == SimulationVerdict.NOT_ESTABLISHED


def test_payload_digest_mismatch_is_detected_at_check_time() -> None:
    manifest, trajectory, state = _case()
    trajectory[1].state_payload["x"] = 999
    assert not verify_sim1_trace_replay(manifest, state, [1], lambda s, e: {"x": s["x"] + e}, trajectory)[0]


def test_noncontiguous_steps_are_rejected() -> None:
    manifest, trajectory, state = _case()
    trajectory[1] = replace(trajectory[1], step_index=4)
    assert not verify_sim1_trace_replay(manifest, state, [1], lambda s, e: {"x": s["x"] + e}, trajectory)[0]


@pytest.mark.parametrize("distance", [math.nan, math.inf, -1.0, True])
def test_invalid_distance_cannot_pass(distance: float) -> None:
    _, trajectory, _ = _case()
    assert not verify_sim3_bisimulation_abstraction(trajectory, trajectory, dict, lambda a, b: distance, 0.1)[0]


@pytest.mark.parametrize("value", ["escape", {}, True, math.nan, math.inf])
def test_nonfinite_or_nonnumeric_actions_cannot_pass(value: object) -> None:
    _, trajectory, _ = _case()
    observations = [s.state_payload for s in trajectory]
    assert not verify_sim4_agent_parity_contained(
        trajectory, dict, observations, [{"throttle": value}] * 2, {"throttle": (0.0, 1.0)},
    )[0]


def test_missing_action_trace_cannot_pass() -> None:
    _, trajectory, _ = _case()
    assert not verify_sim4_agent_parity_contained(
        trajectory, dict, [s.state_payload for s in trajectory], [], {},
    )[0]


def test_arbitrary_signature_strings_do_not_authenticate_witnesses() -> None:
    a = StateSnapshot.create(0, 0.0, {"x": 0}, "a", "made-up")
    b = StateSnapshot.create(0, 0.0, {"x": 0}, "b", "made-up")
    passed, message, findings = verify_sim5_distributed_sharded({"a": [a], "b": [b]}, lambda *args: True)
    assert not passed
    assert "authentication" in message.lower()


def test_failure_receipt_with_unbounded_distance_remains_serializable() -> None:
    manifest, trajectory, state = _case(SimulationTier.SIM_3_BISIMULATION_ABSTRACTION)
    receipt = evaluate_vstd_sim_receipt(
        manifest, trajectory, state, [1], lambda s, e: {"x": s["x"] + e},
        {"bounded": lambda s: True}, macro_trajectory=[], abstraction_morphism=dict,
        distance_metric=lambda a, b: 0.0,
    )
    assert receipt.verdict == SimulationVerdict.VIOLATION_DETECTED
    assert receipt.to_dict()["canonical_digest"].startswith("sha256:")
    import jsonschema
    root = Path(__file__).resolve().parents[1]
    schema_bytes = (root / "standard/schemas/vstd-sim-1.schema.json").read_bytes()
    assert schema_bytes == (root / "src/verifier/schemas/vstd-sim-1.schema.json").read_bytes()
    jsonschema.Draft202012Validator(json.loads(schema_bytes)).validate(receipt.to_dict())
