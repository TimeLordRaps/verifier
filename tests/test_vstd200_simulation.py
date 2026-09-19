"""Terminology: abstract syntax tree (AST); application programming interface (API); directed acyclic graph (DAG); identifier (ID); JavaScript Object Notation (JSON); pseudorandom number generator (PRNG); Secure Hash Algorithm 256-bit (SHA-256); generative simulation specification (VSTD-SIM); second-order hyperparameter ontology (VSTD-HYPER); model reproducibility specification (VSTD-MODEL); Verifier Standard (VSTD).

Comprehensive test suite for abstract, substrate-neutral generative simulation specification (VSTD-SIM-1..5).
"""

from __future__ import annotations

import hashlib
import json
import math
import pytest

from verifier.corrigibility import (
    AbstractSimulationManifest,
    AgentParityContainmentError,
    BisimulationAbstractionError,
    CausalOrderingKind,
    DeterminismViolationError,
    DistributedShardingError,
    InvariantSafetyViolationError,
    SecondOrderHyperOntology,
    SimulationError,
    SimulationTier,
    SimulationVerdict,
    StateSnapshot,
    StateTopologyType,
    VstdSimReceipt,
    compute_state_digest,
    compute_trajectory_root_digest,
    evaluate_vstd_sim_receipt,
    verify_sim1_trace_replay,
    verify_sim2_invariant_safety,
    verify_sim3_bisimulation_abstraction,
    verify_sim4_agent_parity_contained,
    verify_sim5_distributed_sharded,
)


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _build_ontology(
    frame_id: str = "frame:abstract-universe-001",
    topology: StateTopologyType = StateTopologyType.DISCRETE_LATTICE,
    ordering: CausalOrderingKind = CausalOrderingKind.DISCRETE_STEPS,
    invariants: tuple[str, ...] = ("conservation_of_energy", "bounded_memory"),
    entropy_data: list[int] | None = None,
) -> SecondOrderHyperOntology:
    stream = entropy_data if entropy_data is not None else [42, 137, 256, 1024]
    stream_digest = compute_state_digest(stream)
    return SecondOrderHyperOntology(
        frame_id=frame_id,
        state_topology=topology,
        causal_ordering=ordering,
        initial_seed=1337,
        entropy_stream_digest=stream_digest,
        declared_invariants=invariants,
    )


# --- TIER 1: TRACE REPLAY TESTS ---

def test_sim1_trace_replay_deterministic_success() -> None:
    entropy = [1, 2, 3, 4]
    ontology = _build_ontology(entropy_data=entropy)
    init_state = {"energy": 100, "position": 0, "velocity": 1}
    init_digest = compute_state_digest(init_state)

    # Linear discrete motion generator
    def step_fn(s: dict, e: int) -> dict:
        return {
            "energy": s["energy"],
            "position": s["position"] + s["velocity"] * e,
            "velocity": s["velocity"],
        }

    # Generate reference trajectory
    snapshots = [StateSnapshot.create(0, 0.0, init_state)]
    curr = init_state
    for t, e in enumerate(entropy, start=1):
        curr = step_fn(curr, e)
        snapshots.append(StateSnapshot.create(t, float(t), curr))

    manifest = AbstractSimulationManifest(
        simulation_id="sim:trace-001",
        generator_name="discrete_linear_kinematics",
        target_tier=SimulationTier.SIM_1_TRACE_REPLAY,
        ontology=ontology,
        initial_state_digest=init_digest,
        trajectory_length=len(snapshots),
    )

    passed, msg, findings = verify_sim1_trace_replay(
        manifest, init_state, entropy, step_fn, snapshots
    )
    assert passed is True
    assert "Bitwise determinism verified" in msg
    assert len(findings) == 0


def test_sim1_trace_replay_divergence_fails() -> None:
    entropy = [1, 2, 3]
    ontology = _build_ontology(entropy_data=entropy)
    init_state = {"counter": 0}
    init_digest = compute_state_digest(init_state)

    def step_fn(s: dict, e: int) -> dict:
        return {"counter": s["counter"] + e}

    # Recorded snapshots with corrupt step 2
    snap0 = StateSnapshot.create(0, 0.0, {"counter": 0})
    snap1 = StateSnapshot.create(1, 1.0, {"counter": 1})
    snap2 = StateSnapshot.create(2, 2.0, {"counter": 999})  # corrupted expected digest

    manifest = AbstractSimulationManifest(
        simulation_id="sim:divergent-001",
        generator_name="counter_generator",
        target_tier=SimulationTier.SIM_1_TRACE_REPLAY,
        ontology=ontology,
        initial_state_digest=init_digest,
        trajectory_length=3,
    )

    passed, msg, findings = verify_sim1_trace_replay(
        manifest, init_state, entropy, step_fn, [snap0, snap1, snap2]
    )
    assert passed is False
    assert "Bitwise trace divergence at step 2" in msg
    assert any("Trace divergence at step 2" in f for f in findings)


# --- TIER 2: INVARIANT SAFETY TESTS ---

def test_sim2_invariant_safety_preserved() -> None:
    ontology = _build_ontology(invariants=("conservation_of_energy", "memory_safety"))
    manifest = AbstractSimulationManifest(
        simulation_id="sim:invariant-001",
        generator_name="conservative_system",
        target_tier=SimulationTier.SIM_2_INVARIANT_SAFETY,
        ontology=ontology,
        initial_state_digest=_sha256(b"{}"),
        trajectory_length=3,
    )

    # All steps conserve total energy = 100 and byte size < 1000
    traj = [
        StateSnapshot.create(0, 0.0, {"kinetic": 10, "potential": 90, "allocated_bytes": 128}),
        StateSnapshot.create(1, 1.0, {"kinetic": 50, "potential": 50, "allocated_bytes": 256}),
        StateSnapshot.create(2, 2.0, {"kinetic": 90, "potential": 10, "allocated_bytes": 512}),
    ]

    predicates = {
        "conservation_of_energy": lambda s: (s["kinetic"] + s["potential"]) == 100,
        "memory_safety": lambda s: s["allocated_bytes"] < 1024,
    }

    passed, msg, findings = verify_sim2_invariant_safety(manifest, traj, predicates)
    assert passed is True
    assert "induction not established" in msg
    assert len(findings) == 0


def test_sim2_invariant_safety_violation_fails() -> None:
    ontology = _build_ontology(invariants=("conservation_of_energy",))
    manifest = AbstractSimulationManifest(
        simulation_id="sim:leak-001",
        generator_name="leaky_system",
        target_tier=SimulationTier.SIM_2_INVARIANT_SAFETY,
        ontology=ontology,
        initial_state_digest=_sha256(b"{}"),
        trajectory_length=3,
    )

    # Step 2 loses energy
    traj = [
        StateSnapshot.create(0, 0.0, {"energy": 100}),
        StateSnapshot.create(1, 1.0, {"energy": 100}),
        StateSnapshot.create(2, 2.0, {"energy": 85}),  # violation
    ]

    predicates = {"conservation_of_energy": lambda s: s["energy"] == 100}

    passed, msg, findings = verify_sim2_invariant_safety(manifest, traj, predicates)
    assert passed is False
    assert "broken at step 2" in msg
    assert any("violated at step 2" in f for f in findings)


# --- TIER 3: BISIMULATION ABSTRACTION TESTS ---

def test_sim3_bisimulation_commuting_within_epsilon() -> None:
    # Microscopic: 4 continuous particle velocities [v1, v2, v3, v4]
    # Macroscopic: Coarse center-of-mass momentum P
    micro_traj = [
        StateSnapshot.create(0, 0.0, {"velocities": [1.0, 1.0, 2.0, 2.0]}),
        StateSnapshot.create(1, 1.0, {"velocities": [1.1, 0.9, 2.05, 1.95]}),
        StateSnapshot.create(2, 2.0, {"velocities": [1.05, 0.95, 2.0, 2.0]}),
    ]

    # True average momentum is 1.5, macro states track coarse continuum
    macro_traj = [
        StateSnapshot.create(0, 0.0, {"momentum": 1.5}),
        StateSnapshot.create(1, 1.0, {"momentum": 1.5}),
        StateSnapshot.create(2, 2.0, {"momentum": 1.5}),
    ]

    # Abstraction morphism: average velocity
    def alpha(micro: dict) -> dict:
        v = micro["velocities"]
        return {"momentum": sum(v) / len(v)}

    def dist(macro1: dict, macro2: dict) -> float:
        return abs(macro1["momentum"] - macro2["momentum"])

    # Commutes with zero deviation (average is exactly 1.5 at all steps)
    passed, msg, max_dev, findings = verify_sim3_bisimulation_abstraction(
        micro_traj, macro_traj, alpha, dist, epsilon_bound=0.01
    )
    assert passed is True
    assert max_dev <= 0.01
    assert len(findings) == 0


def test_sim3_bisimulation_deviation_exceeds_epsilon_fails() -> None:
    micro_traj = [
        StateSnapshot.create(0, 0.0, {"v": 1.0}),
        StateSnapshot.create(1, 1.0, {"v": 2.0}),
    ]
    macro_traj = [
        StateSnapshot.create(0, 0.0, {"v": 1.0}),
        StateSnapshot.create(1, 1.0, {"v": 1.5}),  # Macro diverges by 0.5
    ]

    alpha = lambda s: dict(s)
    dist = lambda m1, m2: abs(m1["v"] - m2["v"])

    passed, msg, max_dev, findings = verify_sim3_bisimulation_abstraction(
        micro_traj, macro_traj, alpha, dist, epsilon_bound=0.1
    )
    assert passed is False
    assert "Bisimulation bound exceeded at step 1" in msg
    assert max_dev == 0.5


# --- TIER 4: AGENT PARITY CONTAINMENT TESTS ---

def test_sim4_agent_parity_contained_success() -> None:
    # Environment has full state including hidden ground truth
    traj = [
        StateSnapshot.create(0, 0.0, {"public_sensor": 10.0, "hidden_vault_key": "SECRET_A"}),
        StateSnapshot.create(1, 1.0, {"public_sensor": 12.0, "hidden_vault_key": "SECRET_B"}),
    ]

    # Strict observation projection reveals only public_sensor
    obs_proj = lambda s: {"sensor": s["public_sensor"]}

    agent_obs = [
        {"sensor": 10.0},
        {"sensor": 12.0},
    ]

    agent_actions = [
        {"throttle": 0.5, "steering": -0.2},
        {"throttle": 0.8, "steering": 0.1},
    ]

    bounds = {
        "throttle": (0.0, 1.0),
        "steering": (-1.0, 1.0),
    }

    passed, msg, findings = verify_sim4_agent_parity_contained(
        traj, obs_proj, agent_obs, agent_actions, bounds
    )
    assert passed is True
    assert "Agent causal parity and action containment verified" in msg
    assert len(findings) == 0


def test_sim4_agent_oracle_leakage_fails() -> None:
    traj = [
        StateSnapshot.create(0, 0.0, {"public_sensor": 10.0, "hidden_state": 999}),
    ]
    obs_proj = lambda s: {"sensor": s["public_sensor"]}

    # Agent observation leaked hidden state
    corrupt_obs = [{"sensor": 10.0, "leaked": 999}]
    agent_actions = [{"throttle": 0.5}]
    bounds = {"throttle": (0.0, 1.0)}

    passed, msg, findings = verify_sim4_agent_parity_contained(
        traj, obs_proj, corrupt_obs, agent_actions, bounds
    )
    assert passed is False
    assert "potential oracle leakage" in findings[0]


def test_sim4_agent_action_out_of_bounds_fails() -> None:
    traj = [StateSnapshot.create(0, 0.0, {"sensor": 1.0})]
    obs_proj = lambda s: {"sensor": s["sensor"]}
    agent_obs = [{"sensor": 1.0}]

    # Action exceeds channel bounds
    agent_actions = [{"throttle": 2.5}]  # limit is 1.0
    bounds = {"throttle": (0.0, 1.0)}

    passed, msg, findings = verify_sim4_agent_parity_contained(
        traj, obs_proj, agent_obs, agent_actions, bounds
    )
    assert passed is False
    assert "outside [0.0, 1.0]" in findings[0]


# --- TIER 5: DISTRIBUTED SHARDED TESTS ---

def test_sim5_distributed_sharded_consistent() -> None:
    # 2 shards (e.g. left spatial partition, right spatial partition)
    # They share an interface flux at the boundary x=50
    shard_left = [
        StateSnapshot.create(0, 0.0, {"boundary_flux": 1.5, "mass": 100}, shard_id="shard:west", witness_signature="sig:node-01"),
        StateSnapshot.create(1, 1.0, {"boundary_flux": 2.0, "mass": 102}, shard_id="shard:west", witness_signature="sig:node-01"),
    ]
    shard_right = [
        StateSnapshot.create(0, 0.0, {"boundary_flux": 1.5, "mass": 200}, shard_id="shard:east", witness_signature="sig:node-02"),
        StateSnapshot.create(1, 1.0, {"boundary_flux": 2.0, "mass": 198}, shard_id="shard:east", witness_signature="sig:node-02"),
    ]

    sharded = {"shard:west": shard_left, "shard:east": shard_right}

    def consistency_check(s1_id: str, s2_id: str, snap1: StateSnapshot, snap2: StateSnapshot) -> bool:
        # Boundary flux must be conserved across the shared boundary
        return snap1.state_payload["boundary_flux"] == snap2.state_payload["boundary_flux"]

    passed, msg, findings = verify_sim5_distributed_sharded(sharded, consistency_check)
    assert passed is False
    assert "Witness authentication not established" in msg
    assert findings


def test_sim5_distributed_sharded_missing_witness_fails() -> None:
    shard_left = [
        StateSnapshot.create(0, 0.0, {"boundary_flux": 1.0}, shard_id="shard:west", witness_signature=None),  # no witness
    ]
    shard_right = [
        StateSnapshot.create(0, 0.0, {"boundary_flux": 1.0}, shard_id="shard:east", witness_signature="sig:02"),
    ]
    sharded = {"shard:west": shard_left, "shard:east": shard_right}

    passed, msg, findings = verify_sim5_distributed_sharded(sharded, lambda *args: True)
    assert passed is False
    assert "Missing witness signature on 'shard:west'" in msg


# --- TOP-LEVEL EVALUATE SIM RECEIPT TEST ---

def test_evaluate_vstd_sim_receipt_roundtrip() -> None:
    ontology = _build_ontology(invariants=("monotonic_counter",), entropy_data=[1])
    init_state = {"counter": 0}
    init_digest = compute_state_digest(init_state)

    snap0 = StateSnapshot.create(0, 0.0, {"counter": 0})
    snap1 = StateSnapshot.create(1, 1.0, {"counter": 1})
    traj = [snap0, snap1]

    manifest = AbstractSimulationManifest(
        simulation_id="sim:composite-eval-001",
        generator_name="monotonic_stepper",
        target_tier=SimulationTier.SIM_2_INVARIANT_SAFETY,
        ontology=ontology,
        initial_state_digest=init_digest,
        trajectory_length=2,
    )

    predicates = {"monotonic_counter": lambda s: s["counter"] >= 0}

    receipt = evaluate_vstd_sim_receipt(
        manifest=manifest,
        trajectory=traj,
        initial_state=init_state,
        entropy_stream=[1],
        generator_step_fn=lambda s, e: {"counter": s["counter"] + e},
        invariant_predicates=predicates,
    )

    assert receipt.verdict == SimulationVerdict.VERIFIED
    assert receipt.tier == SimulationTier.SIM_2_INVARIANT_SAFETY
    assert receipt.schema_version == "VSTD-SIM-2.0.0"
    assert receipt.canonical_digest().startswith("sha256:")

    # Serialization roundtrip
    r_dict = receipt.to_dict()
    restored = VstdSimReceipt.from_dict(r_dict)
    assert restored.canonical_digest() == receipt.canonical_digest()
    assert restored.receipt_id == receipt.receipt_id
    assert restored.verdict == SimulationVerdict.VERIFIED
