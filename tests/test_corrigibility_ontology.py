"""Terminology: Coordinated Universal Time (UTC); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Adversarial test suite for SPACE, TIME, EVENT computational object classes and the Model-Harness-Agent / Bot triad.
"""
from __future__ import annotations

import pytest

from verifier.corrigibility import (
    CausalTimeKind,
    ComputationalEvent,
    ComputationalSpace,
    ComputationalTime,
    EventKind,
    GroundingEntityType,
    SpaceTopologyKind,
    compose_agent_ontology,
    compose_bot_ontology,
)


def test_computational_space_propagation_and_isolation() -> None:
    space = ComputationalSpace(
        space_id="space:rack-01-chassis",
        topology_kind=SpaceTopologyKind.TESLA_CAGE_HARDWARE_HULL,
        permeable_boundaries=("space:diode-egress",),
        severed_boundaries=("space:unfiltered-internet", "space:external-wireless"),
        propagation_velocity=299792458.0,
        dimension=3,
    )

    # 1. Isolation checks
    assert space.is_causally_isolated_from("space:unfiltered-internet") is True
    assert space.is_causally_isolated_from("space:external-wireless") is True
    assert space.is_causally_isolated_from("space:diode-egress") is False

    # 2. Propagation delay (TIME embedded in SPACE)
    delay_1km = space.propagation_delay_seconds(1000.0)
    assert pytest.approx(delay_1km, rel=1e-5) == 1000.0 / 299792458.0

    # 3. Relativistic lightcone check
    # Distance 300,000 meters in 1 millisecond: 300,000 / 0.001 = 300,000,000 m/s > c => outside lightcone
    assert space.is_within_lightcone(spatial_distance_meters=300000.0, time_interval_seconds=0.001) is False
    # Distance 200,000 meters in 1 millisecond: 200,000 / 0.001 = 200,000,000 m/s < c => inside lightcone
    assert space.is_within_lightcone(spatial_distance_meters=200000.0, time_interval_seconds=0.001) is True

    # 4. Boundary collision check (cannot be both permeable and severed)
    with pytest.raises(ValueError, match="Boundary collision"):
        ComputationalSpace(
            space_id="space:invalid",
            topology_kind=SpaceTopologyKind.NETWORK_MANIFOLD,
            permeable_boundaries=("space:x",),
            severed_boundaries=("space:x",),
        )

    # 5. Digest and dict
    assert space.canonical_digest().startswith("sha256:")
    d = space.to_dict()
    assert d["space_id"] == "space:rack-01-chassis"
    assert d["topology_kind"] == "TESLA_CAGE_HARDWARE_HULL"


def test_computational_time_and_spatial_slice_embedding() -> None:
    time_coord = ComputationalTime(
        time_id="time:epoch-001",
        time_kind=CausalTimeKind.DISCRETE_TICK,
        current_tick=50,
        causal_horizon_limit=100,
        wall_clock_utc_anchor="2026-09-24T20:00:00Z",
        tick_duration_seconds=0.001,
    )

    assert time_coord.is_expired() is False

    # SPACE embedded in TIME: recording spatial state snapshots across ticks
    slice_50_digest = "sha256:" + "a" * 64
    slice_75_digest = "sha256:" + "b" * 64

    time_coord_updated = time_coord.record_spatial_slice(50, slice_50_digest)
    time_coord_updated = time_coord_updated.record_spatial_slice(75, slice_75_digest)

    assert time_coord_updated.current_tick == 75
    assert len(time_coord_updated.spatial_slices) == 2
    assert dict(time_coord_updated.spatial_slices)[50] == slice_50_digest
    assert dict(time_coord_updated.spatial_slices)[75] == slice_75_digest

    # Stop-loss horizon expiration
    expired_time = time_coord_updated.record_spatial_slice(100, "sha256:" + "c" * 64)
    assert expired_time.current_tick == 100
    assert expired_time.is_expired() is True

    # Digest and dict
    assert time_coord.canonical_digest().startswith("sha256:")
    d = expired_time.to_dict()
    assert d["is_expired"] is True
    assert d["current_tick"] == 100


def test_computational_event_binding_space_and_time() -> None:
    event = ComputationalEvent(
        event_id="evt:watchdog-trip-001",
        kind=EventKind.TERMINATED_BY_OPERATOR,
        source_space_id="space:watchdog-monitor",
        target_space_id="space:sandboxed-agent-core",
        temporal_tick=99,
        payload_digest="sha256:" + "f" * 64,
        preemption_authorized=True,
    )

    assert event.kind == EventKind.TERMINATED_BY_OPERATOR
    assert event.preemption_authorized is True
    assert event.canonical_digest().startswith("sha256:")

    # TERMINATED_BY_OPERATOR without preemption_authorized=True fails closed
    with pytest.raises(ValueError, match="preemption_authorized=True"):
        ComputationalEvent(
            event_id="evt:bad-termination",
            kind=EventKind.TERMINATED_BY_OPERATOR,
            source_space_id="space:x",
            target_space_id="space:y",
            temporal_tick=10,
            payload_digest="sha256:" + "1" * 64,
            preemption_authorized=False,
        )


def test_superintelligence_ontology_agent_and_bot_composition() -> None:
    model_digest = "sha256:" + "1" * 64
    harness_digest = "sha256:" + "2" * 64
    channels = ("channel:telemetry_egress", "channel:prompt_ingress")

    # 1. AGENT = MODEL + HARNESS
    agent_info = compose_agent_ontology(
        model_digest=model_digest,
        harness_digest=harness_digest,
        declared_observation_channels=channels,
    )
    assert agent_info["entity_type"] == GroundingEntityType.AGENT.value
    assert agent_info["agent_digest"].startswith("sha256:")
    assert agent_info["observation_ceiling"] == sorted(channels)

    # 2. BOT = AGENT + SIM (where SIM is REAL_WORLD_PHYSICAL_SPACE)
    real_world_space = ComputationalSpace(
        space_id="space:physical-real-world",
        topology_kind=SpaceTopologyKind.REAL_WORLD_PHYSICAL_SPACE,
    )

    bot_info = compose_bot_ontology(
        agent_digest=agent_info["agent_digest"],
        sim_space=real_world_space,
        is_real_world=True,
    )
    assert bot_info["entity_type"] == GroundingEntityType.BOT.value
    assert bot_info["is_real_world"] is True
    assert bot_info["sim_topology"] == "REAL_WORLD_PHYSICAL_SPACE"
    assert bot_info["bot_digest"].startswith("sha256:")

    # 3. Reject claiming real-world BOT when topology is not REAL_WORLD_PHYSICAL_SPACE
    virtual_space = ComputationalSpace(
        space_id="space:virtual-sim",
        topology_kind=SpaceTopologyKind.LOCAL_PROCESS_MEMORY,
    )
    with pytest.raises(ValueError, match="Real-world BOT requires REAL_WORLD_PHYSICAL_SPACE topology"):
        compose_bot_ontology(
            agent_digest=agent_info["agent_digest"],
            sim_space=virtual_space,
            is_real_world=True,
        )
