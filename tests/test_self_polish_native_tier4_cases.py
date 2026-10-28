"""Source-bound Tier-4 native specimen extension tests."""
from __future__ import annotations

import base64

import pytest

from verifier.domains.contracts import (
    actor_closure,
    agent_checks,
    arch_resolution,
    bench_checks,
    bot_checks,
    collective_closure,
    data_checks,
    env_pin_closure,
    event_closure,
    graph_closure,
    hardware_inventory_closure,
    harness_checks,
    human_population_declaration,
    hyper_closure,
    identity_presentation,
    model_checks,
    object_address_closure,
    owner_forks,
    receipt_prerequisite_closure,
    role_closure,
    sim_shard_coverage,
    sim_shard_relations,
    sim_shard_signatures,
    sim_surface_partition,
    space_closure,
    time_closure,
    token_checks,
    train_checks,
    verifier_coverage_closure,
)
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import self_polish_native_adapters as adapters
from verifier.runtime import self_polish_native_tier4_cases as tier4_cases


_CHECKING_MECHANISMS = {
    "verifier.domains.contracts.actor_closure.recheck_actor_closure_certificate": (
        actor_closure.build_actor_closure_certificate,
        actor_closure.recheck_actor_closure_certificate,
    ),
    "verifier.domains.contracts.agent_checks.recheck_agent_checks_certificate": (
        agent_checks.build_agent_checks_certificate,
        agent_checks.recheck_agent_checks_certificate,
    ),
    "verifier.domains.contracts.arch_resolution.recheck_arch_resolution_certificate": (
        arch_resolution.build_arch_resolution_certificate,
        arch_resolution.recheck_arch_resolution_certificate,
    ),
    "verifier.domains.contracts.bench_checks.recheck_bench_checks_certificate": (
        bench_checks.build_bench_checks_certificate,
        bench_checks.recheck_bench_checks_certificate,
    ),
    "verifier.domains.contracts.bot_checks.recheck_bot_checks_certificate": (
        bot_checks.build_bot_checks_certificate,
        bot_checks.recheck_bot_checks_certificate,
    ),
    "verifier.domains.contracts.collective_closure.recheck_collective_closure_certificate": (
        collective_closure.build_collective_closure_certificate,
        collective_closure.recheck_collective_closure_certificate,
    ),
    "verifier.domains.contracts.data_checks.recheck_data_checks_certificate": (
        data_checks.build_data_checks_certificate,
        data_checks.recheck_data_checks_certificate,
    ),
    "verifier.domains.contracts.env_pin_closure.recheck_env_pin_closure_certificate": (
        env_pin_closure.build_env_pin_closure_certificate,
        env_pin_closure.recheck_env_pin_closure_certificate,
    ),
    "verifier.domains.contracts.event_closure.recheck_event_closure_certificate": (
        event_closure.build_event_closure_certificate,
        event_closure.recheck_event_closure_certificate,
    ),
    "verifier.domains.contracts.graph_closure.recheck_graph_closure_certificate": (
        graph_closure.build_graph_closure_certificate,
        graph_closure.recheck_graph_closure_certificate,
    ),
    "verifier.domains.contracts.hardware_inventory_closure.recheck_hardware_inventory_closure_certificate": (
        hardware_inventory_closure.build_hardware_inventory_closure_certificate,
        hardware_inventory_closure.recheck_hardware_inventory_closure_certificate,
    ),
    "verifier.domains.contracts.harness_checks.recheck_harness_checks_certificate": (
        harness_checks.build_harness_checks_certificate,
        harness_checks.recheck_harness_checks_certificate,
    ),
    "verifier.domains.contracts.human_population_declaration.recheck_human_population_declaration_certificate": (
        human_population_declaration.build_human_population_declaration_certificate,
        human_population_declaration.recheck_human_population_declaration_certificate,
    ),
    "verifier.domains.contracts.hyper_closure.recheck_hyper_closure_certificate": (
        hyper_closure.build_hyper_closure_certificate,
        hyper_closure.recheck_hyper_closure_certificate,
    ),
    "verifier.domains.contracts.identity_presentation.recheck_identity_presentation_certificate": (
        identity_presentation.build_identity_presentation_certificate,
        identity_presentation.recheck_identity_presentation_certificate,
    ),
    "verifier.domains.contracts.model_checks.recheck_model_checks_certificate": (
        model_checks.build_model_checks_certificate,
        model_checks.recheck_model_checks_certificate,
    ),
    "verifier.domains.contracts.object_address_closure.recheck_object_address_closure_certificate": (
        object_address_closure.build_object_address_closure_certificate,
        object_address_closure.recheck_object_address_closure_certificate,
    ),
    "verifier.domains.contracts.owner_forks.recheck_owner_forks_certificate": (
        owner_forks.build_owner_forks_certificate,
        owner_forks.recheck_owner_forks_certificate,
    ),
    "verifier.domains.contracts.receipt_prerequisite_closure.recheck_receipt_prerequisite_closure_certificate": (
        receipt_prerequisite_closure.build_receipt_prerequisite_closure_certificate,
        receipt_prerequisite_closure.recheck_receipt_prerequisite_closure_certificate,
    ),
    "verifier.domains.contracts.role_closure.recheck_role_closure_certificate": (
        role_closure.build_role_closure_certificate,
        role_closure.recheck_role_closure_certificate,
    ),
    "verifier.domains.contracts.sim_shard_coverage.recheck_sim_shard_coverage_certificate": (
        sim_shard_coverage.build_sim_shard_coverage_certificate,
        sim_shard_coverage.recheck_sim_shard_coverage_certificate,
    ),
    "verifier.domains.contracts.sim_shard_relations.recheck_sim_shard_relations_certificate": (
        sim_shard_relations.build_sim_shard_relations_certificate,
        sim_shard_relations.recheck_sim_shard_relations_certificate,
    ),
    "verifier.domains.contracts.sim_shard_signatures.recheck_sim_shard_signatures_certificate": (
        sim_shard_signatures.build_sim_shard_signatures_certificate,
        sim_shard_signatures.recheck_sim_shard_signatures_certificate,
    ),
    "verifier.domains.contracts.sim_surface_partition.recheck_sim_surface_partition_certificate": (
        sim_surface_partition.build_sim_surface_partition_certificate,
        sim_surface_partition.recheck_sim_surface_partition_certificate,
    ),
    "verifier.domains.contracts.space_closure.recheck_space_closure_certificate": (
        space_closure.build_space_closure_certificate,
        space_closure.recheck_space_closure_certificate,
    ),
    "verifier.domains.contracts.time_closure.recheck_time_closure_certificate": (
        time_closure.build_time_closure_certificate,
        time_closure.recheck_time_closure_certificate,
    ),
    "verifier.domains.contracts.token_checks.recheck_token_checks_certificate": (
        token_checks.build_token_checks_certificate,
        token_checks.recheck_token_checks_certificate,
    ),
    "verifier.domains.contracts.train_checks.recheck_train_checks_certificate": (
        train_checks.build_train_checks_certificate,
        train_checks.recheck_train_checks_certificate,
    ),
    "verifier.domains.contracts.verifier_coverage_closure.recheck_verifier_coverage_closure_certificate": (
        verifier_coverage_closure.build_verifier_coverage_closure_certificate,
        verifier_coverage_closure.recheck_verifier_coverage_closure_certificate,
    ),
}


def _memberships() -> dict[str, dict]:
    inventory = core_tier_progression.installed_core_route_inventory()
    return {
        f"{cell['object_kind']}:{route['coordinate']}": {
            "object_kind": cell["object_kind"],
            **route,
        }
        for cell in inventory["family_cells"]
        if cell["tier"] == 4
        for route in cell["registered_route_memberships"]
    }


def test_tier4_extension_is_exact_source_bound_and_adapter_explicit() -> None:
    selected = tier4_cases.installed_case_inputs()
    memberships = _memberships()

    assert tier4_cases.CASE_REGISTRY_ENTRY_COUNT == 32
    assert set(selected) == set(memberships)
    assert set(_CHECKING_MECHANISMS) == {
        case["checking_mechanism"] for case in selected.values()
    }
    assert core_obligation_union.value_digest(selected) \
        == tier4_cases.CASE_REGISTRY_DIGEST
    for identifier, case in selected.items():
        route = memberships[identifier]
        request = case["request"]
        assert case["checking_mechanism"] == route["checking_mechanism"]
        assert request["coordinate"] == route["coordinate"]
        assert request["semantic_version"] == route["semantic_version"]
        assert request["proposition_digest"] == route["proposition_digest"]
        assert request["policy_digest"] \
            == core_obligation_union.value_digest(case["policy"])
        if identifier == "HYPER:HYPER-4.1":
            assert case["builder_adapter"] == "HYPER_OBJECT_COLLECTION"
            assert case["negative_adapter"] \
                == "HYPER_UNRELATED_OBJECT_COLLECTION"
            assert case["unknown_adapter"] \
                == "HYPER_CLOSURE_OPERATION_BUDGET"
        else:
            assert case["builder_adapter"] == "BOUNDED_EVIDENCE_BYTES"
            assert case["negative_adapter"] == "MALFORMED_EVIDENCE_REBIND"
            assert case["unknown_adapter"] == "ABSENT_EVIDENCE"


def test_tier4_extension_rejects_payload_drift(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tier4_cases, "_PAYLOAD_B85", b"not-the-payload")

    with pytest.raises(ValueError, match="NATIVE_CASE_REGISTRY_INVALID"):
        tier4_cases.installed_case_inputs()


def test_tier4_generator_reproduces_embedded_payload() -> None:
    from scripts import build_self_polish_native_tier4_cases as module

    raw, encoded = module.build_payload()
    second_raw, second_encoded = module.build_payload()

    assert (second_raw, second_encoded) == (raw, encoded)
    assert encoded == tier4_cases._PAYLOAD_B85
    assert core_obligation_union.bytes_digest(raw) \
        == tier4_cases.CASE_REGISTRY_DIGEST


def test_tier4_extension_reproduces_native_triads() -> None:
    selected = tier4_cases.installed_case_inputs()
    observed = {}
    for identifier, case in selected.items():
        builder, rechecker = _CHECKING_MECHANISMS[case["checking_mechanism"]]
        request = case["request"]
        policy = case["policy"]
        replay_input = base64.b64decode(
            case["evidence_base64"], validate=True
        )
        negative_request, negative_input = adapters.negative_case(
            case["negative_adapter"], request, replay_input, policy=policy
        )
        unknown_request, unknown_input = adapters.unknown_case(
            case["unknown_adapter"], request, replay_input, policy=policy
        )
        built = {
            "POSITIVE": (
                adapters.build_certificate(
                    case["builder_adapter"], "POSITIVE", builder,
                    request, replay_input, policy,
                ),
                request,
            ),
            "NEGATIVE": (
                adapters.build_certificate(
                    case["builder_adapter"], "NEGATIVE", builder,
                    negative_request, negative_input, policy,
                ),
                negative_request,
            ),
            "UNKNOWN": (
                adapters.build_certificate(
                    case["builder_adapter"], case["unknown_adapter"],
                    builder, unknown_request, unknown_input, policy,
                ),
                unknown_request,
            ),
        }
        observed[identifier] = {
            kind: rechecker(
                certificate,
                expected_request=expected_request,
                policy=policy,
            )["status"]
            for kind, (certificate, expected_request) in built.items()
        }

    assert len(observed) == 32
    assert set(tuple(statuses.values()) for statuses in observed.values()) \
        == {("PASS", "FAIL", "UNKNOWN")}
