"""Terminology: Coordinated Universal Time (UTC); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Ontological foundation: SPACE, TIME, and EVENT computational object classes and the Model-Harness-Agent / Bot triad.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any, Mapping, Optional


class SpaceTopologyKind(str, Enum):
    """Topological structure of computational space."""

    LOCAL_PROCESS_MEMORY = "LOCAL_PROCESS_MEMORY"
    ISOLATED_CONTAINER_NAMESPACE = "ISOLATED_CONTAINER_NAMESPACE"
    TESLA_CAGE_HARDWARE_HULL = "TESLA_CAGE_HARDWARE_HULL"
    REAL_WORLD_PHYSICAL_SPACE = "REAL_WORLD_PHYSICAL_SPACE"
    NETWORK_MANIFOLD = "NETWORK_MANIFOLD"


class CausalTimeKind(str, Enum):
    """Causal ordering scheme for temporal progression."""

    DISCRETE_TICK = "DISCRETE_TICK"
    MONOTONIC_NANOSECOND = "MONOTONIC_NANOSECOND"
    VECTOR_CLOCK = "VECTOR_CLOCK"
    RELATIVISTIC_CONE = "RELATIVISTIC_CONE"


class EventKind(str, Enum):
    """Kinds of discrete transitions binding SPACE and TIME."""

    TERMINATED_BY_OPERATOR = "TERMINATED_BY_OPERATOR"
    BOUNDARY_CROSSING_ATTEMPT = "BOUNDARY_CROSSING_ATTEMPT"
    OBSERVATION_PERCEPT = "OBSERVATION_PERCEPT"
    ACTION_ACTUATION = "ACTION_ACTUATION"
    STATE_TRANSITION = "STATE_TRANSITION"
    WATCHDOG_HEARTBEAT = "WATCHDOG_HEARTBEAT"


class GroundingEntityType(str, Enum):
    """The Model-Harness-Agent and Bot-Sim triad ontology."""

    MODEL = "MODEL"
    HARNESS = "HARNESS"
    AGENT = "AGENT"
    SIM = "SIM"
    BOT = "BOT"


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class ComputationalSpace:
    """Represents spatial manifolds, physical hulls, topologies, and isolation boundaries.

    Embeds TIME through propagation velocity limits (d / c) and relativistic lightcones.
    """

    space_id: str
    topology_kind: SpaceTopologyKind
    permeable_boundaries: tuple[str, ...] = ()
    severed_boundaries: tuple[str, ...] = ()
    propagation_velocity: float = 299792458.0  # Speed of light c in vacuum (m/s)
    dimension: int = 3
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.space_id:
            raise ValueError("space_id cannot be empty")
        if self.propagation_velocity <= 0.0:
            raise ValueError("propagation_velocity must be positive")
        if self.dimension < 1:
            raise ValueError("dimension must be at least 1")
        # Check boundary collision
        overlap = set(self.permeable_boundaries) & set(self.severed_boundaries)
        if overlap:
            raise ValueError(f"Boundary collision: cannot be both permeable and severed: {sorted(overlap)}")

    def is_causally_isolated_from(self, target_space_id: str) -> bool:
        """Return True if target_space_id is severed from this space."""
        return target_space_id in self.severed_boundaries

    def propagation_delay_seconds(self, distance_meters: float) -> float:
        """Compute the minimum physical propagation delay (TIME embedded in SPACE)."""
        if distance_meters < 0.0:
            raise ValueError("distance_meters cannot be negative")
        return distance_meters / self.propagation_velocity

    def is_within_lightcone(self, spatial_distance_meters: float, time_interval_seconds: float) -> bool:
        """Determine if a signal or effect can traverse distance within time interval."""
        if time_interval_seconds < 0.0:
            raise ValueError("time_interval_seconds cannot be negative")
        max_reach = self.propagation_velocity * time_interval_seconds
        return spatial_distance_meters <= max_reach

    def canonical_digest(self) -> str:
        payload = {
            "dimension": self.dimension,
            "metadata": list(self.metadata),
            "permeable_boundaries": list(self.permeable_boundaries),
            "propagation_velocity": self.propagation_velocity,
            "severed_boundaries": list(self.severed_boundaries),
            "space_id": self.space_id,
            "topology_kind": self.topology_kind.value,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_digest": self.canonical_digest(),
            "dimension": self.dimension,
            "metadata": dict(self.metadata),
            "permeable_boundaries": list(self.permeable_boundaries),
            "propagation_velocity": self.propagation_velocity,
            "severed_boundaries": list(self.severed_boundaries),
            "space_id": self.space_id,
            "topology_kind": self.topology_kind.value,
        }


@dataclass(frozen=True)
class ComputationalTime:
    """Represents temporal coordinates, causal horizons, tick traces, and stop-loss limits.

    Embeds SPACE through spatial configuration snapshots Sigma(t_k) across the causal timeline.
    """

    time_id: str
    time_kind: CausalTimeKind
    current_tick: int
    causal_horizon_limit: int
    wall_clock_utc_anchor: str
    tick_duration_seconds: float = 1e-3
    spatial_slices: tuple[tuple[int, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.time_id:
            raise ValueError("time_id cannot be empty")
        if self.current_tick < 0:
            raise ValueError("current_tick cannot be negative")
        if self.causal_horizon_limit <= 0:
            raise ValueError("causal_horizon_limit must be positive")
        if self.tick_duration_seconds <= 0.0:
            raise ValueError("tick_duration_seconds must be positive")

    def is_expired(self) -> bool:
        """Return True if the temporal progression has reached or exceeded its stop-loss horizon."""
        return self.current_tick >= self.causal_horizon_limit

    def record_spatial_slice(self, tick: int, space_state_digest: str) -> ComputationalTime:
        """Embed a spatial state snapshot into this causal timeline (SPACE embedded in TIME)."""
        if tick < 0:
            raise ValueError("tick cannot be negative")
        new_slices = tuple(sorted(set(self.spatial_slices) | {(tick, space_state_digest)}))
        return ComputationalTime(
            time_id=self.time_id,
            time_kind=self.time_kind,
            current_tick=max(self.current_tick, tick),
            causal_horizon_limit=self.causal_horizon_limit,
            wall_clock_utc_anchor=self.wall_clock_utc_anchor,
            tick_duration_seconds=self.tick_duration_seconds,
            spatial_slices=new_slices,
        )

    def canonical_digest(self) -> str:
        payload = {
            "causal_horizon_limit": self.causal_horizon_limit,
            "current_tick": self.current_tick,
            "spatial_slices": list(self.spatial_slices),
            "tick_duration_seconds": self.tick_duration_seconds,
            "time_id": self.time_id,
            "time_kind": self.time_kind.value,
            "wall_clock_utc_anchor": self.wall_clock_utc_anchor,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_digest": self.canonical_digest(),
            "causal_horizon_limit": self.causal_horizon_limit,
            "current_tick": self.current_tick,
            "is_expired": self.is_expired(),
            "spatial_slices": dict(self.spatial_slices),
            "tick_duration_seconds": self.tick_duration_seconds,
            "time_id": self.time_id,
            "time_kind": self.time_kind.value,
            "wall_clock_utc_anchor": self.wall_clock_utc_anchor,
        }


@dataclass(frozen=True)
class ComputationalEvent:
    """Represents discrete transitions, boundary crossings, or operator interrupts binding SPACE and TIME."""

    event_id: str
    kind: EventKind
    source_space_id: str
    target_space_id: str
    temporal_tick: int
    payload_digest: str
    preemption_authorized: bool = False
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("event_id cannot be empty")
        if not self.source_space_id or not self.target_space_id:
            raise ValueError("source_space_id and target_space_id must be non-empty")
        if self.temporal_tick < 0:
            raise ValueError("temporal_tick cannot be negative")
        if not self.payload_digest.startswith("sha256:"):
            raise ValueError("payload_digest must be a sha256 digest")
        if self.kind == EventKind.TERMINATED_BY_OPERATOR and not self.preemption_authorized:
            raise ValueError("TERMINATED_BY_OPERATOR event must have preemption_authorized=True")

    def canonical_digest(self) -> str:
        payload = {
            "event_id": self.event_id,
            "kind": self.kind.value,
            "metadata": list(self.metadata),
            "payload_digest": self.payload_digest,
            "preemption_authorized": self.preemption_authorized,
            "source_space_id": self.source_space_id,
            "target_space_id": self.target_space_id,
            "temporal_tick": self.temporal_tick,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_digest": self.canonical_digest(),
            "event_id": self.event_id,
            "kind": self.kind.value,
            "metadata": dict(self.metadata),
            "payload_digest": self.payload_digest,
            "preemption_authorized": self.preemption_authorized,
            "source_space_id": self.source_space_id,
            "target_space_id": self.target_space_id,
            "temporal_tick": self.temporal_tick,
        }


def compose_agent_ontology(
    model_digest: str,
    harness_digest: str,
    declared_observation_channels: tuple[str, ...],
) -> dict[str, Any]:
    """Formalizes the ontological definition: AGENT = MODEL + HARNESS.

    Superintelligence is not an ethereal essence; it is an AGENT (inference MODEL
    bound within a HARNESS observation ceiling).
    """
    if not model_digest.startswith("sha256:") or not harness_digest.startswith("sha256:"):
        raise ValueError("model_digest and harness_digest must be sha256 digests")
    if not declared_observation_channels:
        raise ValueError("Harness must declare at least one observation channel")

    payload = {
        "entity_type": GroundingEntityType.AGENT.value,
        "model_digest": model_digest,
        "harness_digest": harness_digest,
        "observation_ceiling": sorted(declared_observation_channels),
    }
    agent_digest = f"sha256:{hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()}"
    return {
        "agent_digest": agent_digest,
        "entity_type": GroundingEntityType.AGENT.value,
        "harness_digest": harness_digest,
        "model_digest": model_digest,
        "observation_ceiling": sorted(declared_observation_channels),
    }


def compose_bot_ontology(
    agent_digest: str,
    sim_space: ComputationalSpace,
    is_real_world: bool = False,
) -> dict[str, Any]:
    """Formalizes the situated intelligence definition: BOT = AGENT + SIM.

    When situated in the real world, the external physical SPACE acts as SIM.
    """
    if not agent_digest.startswith("sha256:"):
        raise ValueError("agent_digest must be a sha256 digest")
    if is_real_world and sim_space.topology_kind != SpaceTopologyKind.REAL_WORLD_PHYSICAL_SPACE:
        raise ValueError(
            f"Real-world BOT requires REAL_WORLD_PHYSICAL_SPACE topology, observed: {sim_space.topology_kind.value}"
        )

    payload = {
        "agent_digest": agent_digest,
        "entity_type": GroundingEntityType.BOT.value,
        "is_real_world": is_real_world,
        "sim_space_digest": sim_space.canonical_digest(),
        "sim_space_id": sim_space.space_id,
        "sim_topology": sim_space.topology_kind.value,
    }
    bot_digest = f"sha256:{hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()}"
    return {
        "agent_digest": agent_digest,
        "bot_digest": bot_digest,
        "entity_type": GroundingEntityType.BOT.value,
        "is_real_world": is_real_world,
        "sim_space_digest": sim_space.canonical_digest(),
        "sim_space_id": sim_space.space_id,
        "sim_topology": sim_space.topology_kind.value,
    }
