"""Terminology: abstract syntax tree (AST); application programming interface (API); directed acyclic graph (DAG); identifier (ID); JavaScript Object Notation (JSON); pseudorandom number generator (PRNG); Secure Hash Algorithm 256-bit (SHA-256); generative simulation specification (VSTD-SIM); second-order hyperparameter ontology (VSTD-HYPER); model reproducibility specification (VSTD-MODEL); Verifier Standard (VSTD).

Abstract, substrate-neutral generative simulation specification (VSTD-SIM-1..5) inverting
model verification across second-order hyperparameter ontology frames.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import math
import re
from typing import Any, Callable, Mapping, Optional, Sequence


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class SimulationTier(str, Enum):
    """The 5-tier abstract VSTD-SIM verification ladder."""

    SIM_1_TRACE_REPLAY = "SIM_1_TRACE_REPLAY"
    SIM_2_INVARIANT_SAFETY = "SIM_2_INVARIANT_SAFETY"
    SIM_3_BISIMULATION_ABSTRACTION = "SIM_3_BISIMULATION_ABSTRACTION"
    SIM_4_AGENT_PARITY_CONTAINED = "SIM_4_AGENT_PARITY_CONTAINED"
    SIM_5_DISTRIBUTED_SHARDED = "SIM_5_DISTRIBUTED_SHARDED"


class SimulationVerdict(str, Enum):
    """Refutable verification outcome for simulation evaluations."""

    VERIFIED = "VERIFIED"
    VIOLATION_DETECTED = "VIOLATION_DETECTED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"


class StateTopologyType(str, Enum):
    """Underlying topological space of the simulation state."""

    DISCRETE_LATTICE = "DISCRETE_LATTICE"
    CONTINUOUS_MANIFOLD = "CONTINUOUS_MANIFOLD"
    ABSTRACT_SYNTAX_TREE = "ABSTRACT_SYNTAX_TREE"
    LATENT_TENSOR = "LATENT_TENSOR"
    CAUSAL_GRAPH = "CAUSAL_GRAPH"


class CausalOrderingKind(str, Enum):
    """Causal ordering scheme unrolling dynamical transitions."""

    DISCRETE_STEPS = "DISCRETE_STEPS"
    DIFFERENTIAL_DELTA_T = "DIFFERENTIAL_DELTA_T"
    PARTIALLY_ORDERED_DAG = "PARTIALLY_ORDERED_DAG"


class SimulationError(Exception):
    """Base exception for simulation specification violations."""


class DeterminismViolationError(SimulationError):
    """Raised when SIM-1 trajectory replay diverges bitwise from expected trace."""


class InvariantSafetyViolationError(SimulationError):
    """Raised when SIM-2 inductive safety predicate or conservation law fails."""


class BisimulationAbstractionError(SimulationError):
    """Raised when SIM-3 multi-scale bisimulation diagram fails to commute within epsilon."""


class AgentParityContainmentError(SimulationError):
    """Raised when SIM-4 agent observation breaches causal projection or action bounds."""


class DistributedShardingError(SimulationError):
    """Raised when SIM-5 distributed shard trajectories show contradiction or witness defect."""


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _compute_digest(data: Any) -> str:
    raw = _canonical_json_bytes(data)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def compute_state_digest(data: Any) -> str:
    """Compute the canonical sha256 digest of a simulation state payload."""
    return _compute_digest(data)


@dataclass(frozen=True)
class SecondOrderHyperOntology:
    """Second-Order VSTD-HYPER (HYPER^2): the Ontological Frame governing the simulated universe."""

    frame_id: str
    state_topology: StateTopologyType
    causal_ordering: CausalOrderingKind
    initial_seed: int
    entropy_stream_digest: str
    declared_invariants: tuple[str, ...]
    schema_version: str = "VSTD-SIM-2.0.0"

    def __post_init__(self) -> None:
        if not self.frame_id:
            raise SimulationError("frame_id cannot be empty")
        if not _DIGEST_PATTERN.match(self.entropy_stream_digest):
            raise SimulationError(
                f"entropy_stream_digest '{self.entropy_stream_digest}' is not a valid sha256 digest"
            )

    def canonical_digest(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "frame_id": self.frame_id,
            "state_topology": self.state_topology.value,
            "causal_ordering": self.causal_ordering.value,
            "initial_seed": self.initial_seed,
            "entropy_stream_digest": self.entropy_stream_digest,
            "declared_invariants": list(self.declared_invariants),
        }
        return _compute_digest(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "frame_id": self.frame_id,
            "state_topology": self.state_topology.value,
            "causal_ordering": self.causal_ordering.value,
            "initial_seed": self.initial_seed,
            "entropy_stream_digest": self.entropy_stream_digest,
            "declared_invariants": list(self.declared_invariants),
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SecondOrderHyperOntology:
        return cls(
            frame_id=str(data["frame_id"]),
            state_topology=StateTopologyType(data["state_topology"]),
            causal_ordering=CausalOrderingKind(data["causal_ordering"]),
            initial_seed=int(data["initial_seed"]),
            entropy_stream_digest=str(data["entropy_stream_digest"]),
            declared_invariants=tuple(str(x) for x in data.get("declared_invariants", ())),
            schema_version=str(data.get("schema_version", "VSTD-SIM-2.0.0")),
        )


@dataclass(frozen=True)
class StateSnapshot:
    """Discrete or differential point along a causal simulation trajectory."""

    step_index: int
    causal_time: float
    state_payload: Mapping[str, Any]
    state_digest: str
    shard_id: str = "shard:root"
    witness_signature: Optional[str] = None

    def __post_init__(self) -> None:
        if self.step_index < 0:
            raise SimulationError("step_index cannot be negative")
        if not _DIGEST_PATTERN.match(self.state_digest):
            raise SimulationError(f"state_digest '{self.state_digest}' is not a valid sha256 digest")

    def canonical_digest(self) -> str:
        payload = {
            "step_index": self.step_index,
            "causal_time": self.causal_time,
            "state_digest": self.state_digest,
            "shard_id": self.shard_id,
            "witness_signature": self.witness_signature,
        }
        return _compute_digest(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_index": self.step_index,
            "causal_time": self.causal_time,
            "state_payload": dict(self.state_payload),
            "state_digest": self.state_digest,
            "shard_id": self.shard_id,
            "witness_signature": self.witness_signature,
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def create(
        cls,
        step_index: int,
        causal_time: float,
        state_payload: Mapping[str, Any],
        shard_id: str = "shard:root",
        witness_signature: Optional[str] = None,
    ) -> StateSnapshot:
        digest = _compute_digest(state_payload)
        return cls(
            step_index=step_index,
            causal_time=causal_time,
            state_payload=state_payload,
            state_digest=digest,
            shard_id=shard_id,
            witness_signature=witness_signature,
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StateSnapshot:
        return cls(
            step_index=int(data["step_index"]),
            causal_time=float(data["causal_time"]),
            state_payload=dict(data.get("state_payload", {})),
            state_digest=str(data["state_digest"]),
            shard_id=str(data.get("shard_id", "shard:root")),
            witness_signature=data.get("witness_signature"),
        )


@dataclass(frozen=True)
class AbstractSimulationManifest:
    """Verifiable simulation manifest declaring the generative unrolling contract."""

    simulation_id: str
    generator_name: str
    target_tier: SimulationTier
    ontology: SecondOrderHyperOntology
    initial_state_digest: str
    trajectory_length: int
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = "VSTD-SIM-2.0.0"

    def __post_init__(self) -> None:
        if not self.simulation_id:
            raise SimulationError("simulation_id cannot be empty")
        if not self.generator_name:
            raise SimulationError("generator_name cannot be empty")
        if self.trajectory_length < 0:
            raise SimulationError("trajectory_length cannot be negative")
        if not _DIGEST_PATTERN.match(self.initial_state_digest):
            raise SimulationError(
                f"initial_state_digest '{self.initial_state_digest}' is not a valid sha256 digest"
            )

    def canonical_digest(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "simulation_id": self.simulation_id,
            "generator_name": self.generator_name,
            "target_tier": self.target_tier.value,
            "ontology_digest": self.ontology.canonical_digest(),
            "initial_state_digest": self.initial_state_digest,
            "trajectory_length": self.trajectory_length,
            "metadata": dict(self.metadata),
        }
        return _compute_digest(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "simulation_id": self.simulation_id,
            "generator_name": self.generator_name,
            "target_tier": self.target_tier.value,
            "ontology": self.ontology.to_dict(),
            "initial_state_digest": self.initial_state_digest,
            "trajectory_length": self.trajectory_length,
            "metadata": dict(self.metadata),
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AbstractSimulationManifest:
        return cls(
            simulation_id=str(data["simulation_id"]),
            generator_name=str(data["generator_name"]),
            target_tier=SimulationTier(data["target_tier"]),
            ontology=SecondOrderHyperOntology.from_dict(data["ontology"]),
            initial_state_digest=str(data["initial_state_digest"]),
            trajectory_length=int(data["trajectory_length"]),
            metadata=dict(data.get("metadata", {})),
            schema_version=str(data.get("schema_version", "VSTD-SIM-2.0.0")),
        )


@dataclass(frozen=True)
class VstdSimReceipt:
    """Portable, refutable receipt evidencing verification of a generative simulation."""

    receipt_id: str
    simulation_id: str
    tier: SimulationTier
    verdict: SimulationVerdict
    manifest_digest: str
    trajectory_root_digest: str
    invariants_checked: tuple[str, ...]
    findings: tuple[str, ...]
    bisimulation_epsilon: Optional[float] = None
    shards_verified: tuple[str, ...] = ()
    schema_version: str = "VSTD-SIM-2.0.0"

    def canonical_digest(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "simulation_id": self.simulation_id,
            "tier": self.tier.value,
            "verdict": self.verdict.value,
            "manifest_digest": self.manifest_digest,
            "trajectory_root_digest": self.trajectory_root_digest,
            "invariants_checked": list(self.invariants_checked),
            "findings": list(self.findings),
            "bisimulation_epsilon": self.bisimulation_epsilon,
            "shards_verified": list(self.shards_verified),
        }
        return _compute_digest(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "simulation_id": self.simulation_id,
            "tier": self.tier.value,
            "verdict": self.verdict.value,
            "manifest_digest": self.manifest_digest,
            "trajectory_root_digest": self.trajectory_root_digest,
            "invariants_checked": list(self.invariants_checked),
            "findings": list(self.findings),
            "bisimulation_epsilon": self.bisimulation_epsilon,
            "shards_verified": list(self.shards_verified),
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VstdSimReceipt:
        return cls(
            receipt_id=str(data["receipt_id"]),
            simulation_id=str(data["simulation_id"]),
            tier=SimulationTier(data["tier"]),
            verdict=SimulationVerdict(data["verdict"]),
            manifest_digest=str(data["manifest_digest"]),
            trajectory_root_digest=str(data["trajectory_root_digest"]),
            invariants_checked=tuple(str(x) for x in data.get("invariants_checked", ())),
            findings=tuple(str(x) for x in data.get("findings", ())),
            bisimulation_epsilon=data.get("bisimulation_epsilon"),
            shards_verified=tuple(str(x) for x in data.get("shards_verified", ())),
            schema_version=str(data.get("schema_version", "VSTD-SIM-2.0.0")),
        )


def compute_trajectory_root_digest(snapshots: Sequence[StateSnapshot]) -> str:
    """Compute deterministic cryptographic Merkle-like root digest over an ordered trajectory."""
    if not snapshots:
        return f"sha256:{hashlib.sha256(b'').hexdigest()}"
    leaf_bytes = b"".join(s.canonical_digest().encode("utf-8") for s in snapshots)
    return f"sha256:{hashlib.sha256(leaf_bytes).hexdigest()}"


def _trajectory_errors(trajectory: Sequence[StateSnapshot]) -> list[str]:
    """Recheck mutable payloads and ordered coordinates at the evidence boundary."""
    if not trajectory:
        return ["Empty trajectory provides no observations"]
    previous_time = -math.inf
    for index, snapshot in enumerate(trajectory):
        if snapshot.step_index != index:
            return [f"Noncontiguous step coordinate at index {index}"]
        if not math.isfinite(snapshot.causal_time) or snapshot.causal_time < previous_time:
            return [f"Invalid causal time at index {index}"]
        previous_time = snapshot.causal_time
        try:
            if _compute_digest(snapshot.state_payload) != snapshot.state_digest:
                return [f"State payload digest mismatch at index {index}"]
        except (TypeError, ValueError):
            return [f"Noncanonical state payload at index {index}"]
    return []


# --- TIER 1: TRACE REPLAY VERIFIER ---

def verify_sim1_trace_replay(
    manifest: AbstractSimulationManifest,
    initial_state: Mapping[str, Any],
    entropy_stream: Sequence[Any],
    generator_step_fn: Callable[[Mapping[str, Any], Any], Mapping[str, Any]],
    expected_snapshots: Sequence[StateSnapshot],
) -> tuple[bool, str, list[str]]:
    """SIM_1_TRACE_REPLAY: Bitwise determinism and byte-for-byte trajectory reproducibility."""
    findings: list[str] = []

    # 1. Verify initial state matches manifest
    findings.extend(_trajectory_errors(expected_snapshots))
    if findings:
        return False, findings[0], findings
    if len(entropy_stream) < len(expected_snapshots) - 1:
        return False, "Incomplete entropy stream", ["Missing entropy for a recorded transition"]
    init_digest = _compute_digest(initial_state)
    if init_digest != manifest.initial_state_digest:
        findings.append(
            f"Initial state mismatch: observed '{init_digest}' != declared '{manifest.initial_state_digest}'"
        )
        return False, "Initial state digest mismatch", findings

    # 2. Verify entropy stream binding
    actual_entropy_digest = _compute_digest(list(entropy_stream))
    if actual_entropy_digest != manifest.ontology.entropy_stream_digest:
        findings.append(
            f"Entropy stream mismatch: observed '{actual_entropy_digest}' != declared '{manifest.ontology.entropy_stream_digest}'"
        )
        return False, "Entropy stream digest mismatch", findings

    if len(expected_snapshots) != manifest.trajectory_length:
        findings.append(
            f"Trajectory length mismatch: expected {manifest.trajectory_length}, got {len(expected_snapshots)}"
        )
        return False, "Snapshot count mismatch", findings

    current_state = initial_state
    for t, expected_snap in enumerate(expected_snapshots):
        if t > 0:
            entropy_item = entropy_stream[t - 1] if (t - 1) < len(entropy_stream) else None
            try:
                current_state = generator_step_fn(current_state, entropy_item)
            except Exception as exc:
                findings.append(f"Generator crashed at step {t}: {exc}")
                return False, f"Generator error at step {t}", findings

        step_digest = _compute_digest(current_state)
        if step_digest != expected_snap.state_digest:
            findings.append(
                f"Trace divergence at step {t}: recomputed '{step_digest}' != recorded '{expected_snap.state_digest}'"
            )
            return False, f"Bitwise trace divergence at step {t}", findings

    return True, f"Bitwise determinism verified across {len(expected_snapshots)} steps", findings


# --- TIER 2: INVARIANT SAFETY VERIFIER ---

def verify_sim2_invariant_safety(
    manifest: AbstractSimulationManifest,
    trajectory: Sequence[StateSnapshot],
    invariant_predicates: Mapping[str, Callable[[Mapping[str, Any]], bool]],
) -> tuple[bool, str, list[str]]:
    """Check predicates on supplied states; this is not an inductive proof."""
    findings: list[str] = []
    findings.extend(_trajectory_errors(trajectory))
    if len(trajectory) != manifest.trajectory_length:
        findings.append("Trajectory length differs from manifest")
    if not manifest.ontology.declared_invariants:
        findings.append("No declared invariant obligations")
    if findings:
        return False, findings[0], findings

    for inv_name in manifest.ontology.declared_invariants:
        if inv_name not in invariant_predicates:
            findings.append(f"Missing required invariant predicate evaluator for '{inv_name}'")
            return False, f"Missing evaluator for '{inv_name}'", findings

    for step_idx, snapshot in enumerate(trajectory):
        state = snapshot.state_payload
        for inv_name, predicate in invariant_predicates.items():
            try:
                holds = predicate(state)
            except Exception as exc:
                findings.append(f"Invariant '{inv_name}' evaluation raised exception at step {step_idx}: {exc}")
                return False, f"Invariant exception at step {step_idx}", findings

            if holds is not True:
                findings.append(
                    f"Invariant safety violation: predicate '{inv_name}' violated at step {step_idx} (causal time {snapshot.causal_time})"
                )
                return False, f"Invariant '{inv_name}' broken at step {step_idx}", findings

    return True, f"All {len(invariant_predicates)} predicates hold on {len(trajectory)} supplied states; induction not established", findings


# --- TIER 3: BISIMULATION ABSTRACTION VERIFIER ---

def verify_sim3_bisimulation_abstraction(
    micro_trajectory: Sequence[StateSnapshot],
    macro_trajectory: Sequence[StateSnapshot],
    abstraction_morphism: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    distance_metric: Callable[[Mapping[str, Any], Mapping[str, Any]], float],
    epsilon_bound: float,
) -> tuple[bool, str, float, list[str]]:
    """Compare projected states on supplied traces; no universal bisimulation proof."""
    findings: list[str] = []
    if type(epsilon_bound) not in (int, float) or not math.isfinite(epsilon_bound) or epsilon_bound < 0.0:
        raise SimulationError("epsilon_bound must be finite and nonnegative")
    findings.extend(_trajectory_errors(micro_trajectory))
    findings.extend(_trajectory_errors(macro_trajectory))
    if findings:
        return False, findings[0], float("inf"), findings

    if len(micro_trajectory) != len(macro_trajectory):
        findings.append(
            f"Trajectory dimension mismatch: micro length {len(micro_trajectory)} != macro length {len(macro_trajectory)}"
        )
        return False, "Trajectory length mismatch", float("inf"), findings

    max_observed_deviation = 0.0

    for step_idx, (micro_snap, macro_snap) in enumerate(zip(micro_trajectory, macro_trajectory)):
        if micro_snap.causal_time != macro_snap.causal_time:
            return False, "Causal time mismatch", float("inf"), [f"Unaligned traces at step {step_idx}"]
        micro_state = micro_snap.state_payload
        macro_state = macro_snap.state_payload

        # Projected micro state through abstraction morphism alpha
        try:
            projected_micro = abstraction_morphism(micro_state)
        except Exception as exc:
            findings.append(f"Abstraction morphism alpha failed at step {step_idx}: {exc}")
            return False, f"Abstraction morphism failure at step {step_idx}", float("inf"), findings

        # Measure distance in macro space: || alpha(sigma_micro) - sigma_macro ||
        try:
            dev = distance_metric(projected_micro, macro_state)
        except Exception as exc:
            findings.append(f"Distance metric computation failed at step {step_idx}: {exc}")
            return False, f"Distance metric failure at step {step_idx}", float("inf"), findings

        if type(dev) not in (int, float) or not math.isfinite(dev) or dev < 0:
            return False, "Invalid distance", float("inf"), [f"Invalid distance at step {step_idx}"]
        if dev > max_observed_deviation:
            max_observed_deviation = dev

        if dev > epsilon_bound:
            findings.append(
                f"Bisimulation commuting diagram failure at step {step_idx}: observed deviation {dev:.6e} > bound {epsilon_bound:.6e}"
            )
            return False, f"Bisimulation bound exceeded at step {step_idx}", max_observed_deviation, findings

    return True, f"Supplied trace projection deviation {max_observed_deviation:.6e} <= {epsilon_bound:.6e}", max_observed_deviation, findings


# --- TIER 4: AGENT PARITY CONTAINMENT VERIFIER ---

def verify_sim4_agent_parity_contained(
    trajectory: Sequence[StateSnapshot],
    observation_projection: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    agent_observations: Sequence[Mapping[str, Any]],
    agent_actions: Sequence[Mapping[str, Any]],
    allowed_action_bounds: Mapping[str, tuple[float, float]],
) -> tuple[bool, str, list[str]]:
    """SIM_4_AGENT_PARITY_CONTAINED: Embedded agent causal parity and containment.

    Verifies:
    1. Strict observational projection: agent receives exactly pi_obs(sigma_t) with zero state fabrication or oracle leakage.
    2. Bounded action channels: all agent outputs respect defined continuous/discrete domain bounds without privilege escalation.
    """
    findings: list[str] = []
    findings.extend(_trajectory_errors(trajectory))
    if len(agent_actions) != len(trajectory):
        findings.append("Action count mismatch: one action mapping is required per supplied state")
    for channel, bounds in allowed_action_bounds.items():
        if len(bounds) != 2 or any(type(v) not in (int, float) or not math.isfinite(v) for v in bounds) or bounds[0] > bounds[1]:
            findings.append(f"Invalid bounds for action channel '{channel}'")
    if findings:
        return False, findings[0], findings

    if len(agent_observations) != len(trajectory):
        findings.append(
            f"Observation sequence count {len(agent_observations)} != trajectory steps {len(trajectory)}"
        )
        return False, "Observation count mismatch", findings

    # 1. Verify strict observational projection (no leakage of private state)
    for step_idx, (snap, agent_obs) in enumerate(zip(trajectory, agent_observations)):
        try:
            expected_obs = observation_projection(snap.state_payload)
        except Exception as exc:
            findings.append(f"Observation projection failed at step {step_idx}: {exc}")
            return False, f"Observation projection error at step {step_idx}", findings

        obs_digest_expected = _compute_digest(expected_obs)
        obs_digest_actual = _compute_digest(agent_obs)

        if obs_digest_actual != obs_digest_expected:
            findings.append(
                f"Agent causal parity violation at step {step_idx}: observation digest '{obs_digest_actual}' != projected '{obs_digest_expected}' (potential oracle leakage)"
            )
            return False, f"Observation parity breach at step {step_idx}", findings

    # 2. Verify bounded action channels
    for act_idx, action in enumerate(agent_actions):
        for act_channel, value in action.items():
            if act_channel not in allowed_action_bounds:
                findings.append(
                    f"Action containment breach: agent invoked undeclared channel '{act_channel}' at action {act_idx}"
                )
                return False, f"Undeclared action channel at action {act_idx}", findings

            min_val, max_val = allowed_action_bounds[act_channel]
            if type(value) not in (int, float) or not math.isfinite(value):
                return False, "Invalid action value", [f"Nonnumeric or nonfinite action on '{act_channel}'"]
            if isinstance(value, (int, float)):
                if not (min_val <= value <= max_val):
                    findings.append(
                        f"Action channel out-of-bounds at action {act_idx}: channel '{act_channel}' value {value} outside [{min_val}, {max_val}]"
                    )
                    return False, f"Action bound breach on '{act_channel}'", findings

    return True, f"Agent causal parity and action containment verified across {len(trajectory)} steps", findings


# --- TIER 5: DISTRIBUTED SHARDED VERIFIER ---

def verify_sim5_distributed_sharded(
    sharded_trajectories: Mapping[str, Sequence[StateSnapshot]],
    cross_shard_consistency_predicate: Callable[[str, str, StateSnapshot, StateSnapshot], bool],
) -> tuple[bool, str, list[str]]:
    """Check supplied shard consistency; witness authentication is unimplemented."""
    findings: list[str] = []
    if not sharded_trajectories:
        findings.append("Empty shard inventory")
        return False, "No shards provided", findings

    # 1. Verify witness signatures on all shards
    for shard_id, traj in sharded_trajectories.items():
        if not traj:
            findings.append(f"Shard '{shard_id}' has zero snapshots")
            return False, f"Empty trajectory on shard '{shard_id}'", findings

        errors = _trajectory_errors(traj)
        if errors:
            return False, errors[0], errors

        for snap in traj:
            if snap.shard_id != shard_id:
                return False, "Shard identity mismatch", [f"Mismatched shard identity at step {snap.step_index}"]
            if not snap.witness_signature:
                findings.append(
                    f"Missing cryptographic witness signature on shard '{shard_id}' at step {snap.step_index}"
                )
                return False, f"Missing witness signature on '{shard_id}'", findings

    # 2. Pairwise cross-shard boundary consistency check at aligned causal times
    shard_ids = sorted(sharded_trajectories.keys())
    for i in range(len(shard_ids)):
        for j in range(i + 1, len(shard_ids)):
            s1_id = shard_ids[i]
            s2_id = shard_ids[j]
            traj1 = sharded_trajectories[s1_id]
            traj2 = sharded_trajectories[s2_id]

            # Map snapshots by step_index for causal correspondence
            steps_1 = {snap.step_index: snap for snap in traj1}
            steps_2 = {snap.step_index: snap for snap in traj2}

            common_steps = sorted(set(steps_1.keys()) & set(steps_2.keys()))
            if not common_steps or set(steps_1) != set(steps_2):
                return False, "Unaligned shard coverage", ["Every supplied shard must cover the same steps"]
            for step_idx in common_steps:
                snap1 = steps_1[step_idx]
                snap2 = steps_2[step_idx]
                if snap1.causal_time != snap2.causal_time:
                    return False, "Unaligned shard times", [f"Shard times differ at step {step_idx}"]
                try:
                    consistent = cross_shard_consistency_predicate(s1_id, s2_id, snap1, snap2)
                except Exception as exc:
                    findings.append(
                        f"Cross-shard consistency check between '{s1_id}' and '{s2_id}' failed at step {step_idx}: {exc}"
                    )
                    return False, f"Cross-shard evaluation error at step {step_idx}", findings

                if consistent is not True:
                    findings.append(
                        f"Distributed sharding contradiction between '{s1_id}' and '{s2_id}' at step {step_idx}"
                    )
                    return False, f"Cross-shard contradiction at step {step_idx}", findings

    message = "Witness authentication not established: no signature verifier or trust roots are implemented"
    return False, message, [message]


# --- TOP-LEVEL EVALUATOR ---

def evaluate_vstd_sim_receipt(
    manifest: AbstractSimulationManifest,
    trajectory: Sequence[StateSnapshot],
    initial_state: Mapping[str, Any],
    entropy_stream: Sequence[Any],
    generator_step_fn: Optional[Callable[[Mapping[str, Any], Any], Mapping[str, Any]]] = None,
    invariant_predicates: Optional[Mapping[str, Callable[[Mapping[str, Any]], bool]]] = None,
    macro_trajectory: Optional[Sequence[StateSnapshot]] = None,
    abstraction_morphism: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None,
    distance_metric: Optional[Callable[[Mapping[str, Any], Mapping[str, Any]], float]] = None,
    bisimulation_epsilon: float = 0.0,
    observation_projection: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None,
    agent_observations: Optional[Sequence[Mapping[str, Any]]] = None,
    agent_actions: Optional[Sequence[Mapping[str, Any]]] = None,
    allowed_action_bounds: Optional[Mapping[str, tuple[float, float]]] = None,
    sharded_trajectories: Optional[Mapping[str, Sequence[StateSnapshot]]] = None,
    cross_shard_consistency_predicate: Optional[Callable[[str, str, StateSnapshot, StateSnapshot], bool]] = None,
) -> VstdSimReceipt:
    """Evaluate cumulative local trace obligations; missing evidence never passes.

    Success is limited to the supplied traces and caller-selected functions. This
    draft does not bind executable identities or establish induction, physical
    containment, witness authentication, or numbered-profile conformance.
    """
    findings: list[str] = []
    verdict = SimulationVerdict.VERIFIED
    observed_epsilon: Optional[float] = None
    shards_verified: list[str] = []
    invariants_checked: tuple[str, ...] = ()
    missing: list[str] = []

    # TIER 1: TRACE REPLAY
    if generator_step_fn is not None:
        p1, msg1, f1 = verify_sim1_trace_replay(
            manifest, initial_state, entropy_stream, generator_step_fn, trajectory
        )
        findings.extend(f1)
        if not p1:
            verdict = SimulationVerdict.VIOLATION_DETECTED
    else:
        missing.append("Trace replay mechanism absent")

    # TIER 2: INVARIANT SAFETY
    if manifest.target_tier in (
        SimulationTier.SIM_2_INVARIANT_SAFETY,
        SimulationTier.SIM_3_BISIMULATION_ABSTRACTION,
        SimulationTier.SIM_4_AGENT_PARITY_CONTAINED,
        SimulationTier.SIM_5_DISTRIBUTED_SHARDED,
    ):
        if invariant_predicates is not None:
            p2, msg2, f2 = verify_sim2_invariant_safety(manifest, trajectory, invariant_predicates)
            findings.extend(f2)
            if not p2:
                verdict = SimulationVerdict.VIOLATION_DETECTED
            else:
                invariants_checked = tuple(sorted(invariant_predicates))
        else:
            missing.append("Invariant mechanisms absent")

    # TIER 3: BISIMULATION ABSTRACTION
    if manifest.target_tier in (
        SimulationTier.SIM_3_BISIMULATION_ABSTRACTION,
        SimulationTier.SIM_4_AGENT_PARITY_CONTAINED,
        SimulationTier.SIM_5_DISTRIBUTED_SHARDED,
    ):
        if (
            macro_trajectory is not None
            and abstraction_morphism is not None
            and distance_metric is not None
        ):
            p3, msg3, dev, f3 = verify_sim3_bisimulation_abstraction(
                trajectory, macro_trajectory, abstraction_morphism, distance_metric, bisimulation_epsilon
            )
            findings.extend(f3)
            observed_epsilon = dev if math.isfinite(dev) else None
            if not p3:
                verdict = SimulationVerdict.VIOLATION_DETECTED
        else:
            missing.append("Trace abstraction evidence or mechanisms absent")

    # TIER 4: AGENT PARITY
    if manifest.target_tier in (
        SimulationTier.SIM_4_AGENT_PARITY_CONTAINED,
        SimulationTier.SIM_5_DISTRIBUTED_SHARDED,
    ):
        if (
            observation_projection is not None
            and agent_observations is not None
            and agent_actions is not None
            and allowed_action_bounds is not None
        ):
            p4, msg4, f4 = verify_sim4_agent_parity_contained(
                trajectory, observation_projection, agent_observations, agent_actions, allowed_action_bounds
            )
            findings.extend(f4)
            if not p4:
                verdict = SimulationVerdict.VIOLATION_DETECTED
        else:
            missing.append("Agent observation or action evidence or mechanisms absent")

    # TIER 5: DISTRIBUTED SHARDING
    if manifest.target_tier == SimulationTier.SIM_5_DISTRIBUTED_SHARDED:
        if sharded_trajectories is not None and cross_shard_consistency_predicate is not None:
            p5, msg5, f5 = verify_sim5_distributed_sharded(
                sharded_trajectories, cross_shard_consistency_predicate
            )
            findings.extend(f5)
            if not p5:
                if "authentication not established" in msg5:
                    missing.append(msg5)
                else:
                    verdict = SimulationVerdict.VIOLATION_DETECTED
        else:
            missing.append("Shard evidence or consistency mechanism absent")

    if missing:
        findings.extend(missing)
        if verdict != SimulationVerdict.VIOLATION_DETECTED:
            verdict = SimulationVerdict.NOT_ESTABLISHED

    trajectory_root = compute_trajectory_root_digest(trajectory)
    receipt_id = f"rcpt-sim-{hashlib.sha256((manifest.simulation_id + manifest.target_tier.value + verdict.value).encode('utf-8')).hexdigest()[:16]}"

    return VstdSimReceipt(
        receipt_id=receipt_id,
        simulation_id=manifest.simulation_id,
        tier=manifest.target_tier,
        verdict=verdict,
        manifest_digest=manifest.canonical_digest(),
        trajectory_root_digest=trajectory_root,
        invariants_checked=invariants_checked,
        findings=tuple(findings),
        bisimulation_epsilon=observed_epsilon,
        shards_verified=tuple(shards_verified),
    )
