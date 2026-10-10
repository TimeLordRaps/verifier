"""Explicit local replay selection for registered current-object objectives.

Verifier Standard (VSTD); Simulation (SIM); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256). Byte limits measure exact immutable input bytes or encoded selection
text; node and depth limits are dimensionless. Only listed objectives are registered.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import math
from typing import Any, Callable

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import ObjectKind
from verifier.domains.contracts import independence_checks, token_checks
from verifier.domains.contracts import role_constraints, collective_constraints
from verifier.domains.contracts import role_lifecycle, collective_lifecycle, arch_resolution
from verifier.domains.contracts import hyper_closure, object_facets, object_grounding, sim_checker, receipt_chain, typed_facets, identity_scope, data_checks, env_checks, bench_checks, train_checks, model_checks, harness_checks, agent_checks, bot_checks, privacy_checks, hardware_inventory, time_order, space_layout, space_closure, event_prerequisites
from verifier.domains.contracts import consent_checks, object_governance, hardware_capacity, hardware_topology, hardware_measurements, data_distribution, model_artifact_bytes, model_quantization
from verifier.domains.contracts import subject_security, receipt_authenticity, model_hardware_observation, model_data_citation, model_train_citation, train_data_bridge, model_data_lineage, graph_statics, graph_closure
from verifier.domains.contracts import env_executable, env_configuration_surface, arch_shapes, env_pin_closure, sim_dynamics, sim_resource, sim_response, sim_internal_state, sim_perspective, sim_external_law, sim_shard_coverage, sim_shard_relations, sim_shard_signatures, sim_surface_partition
from verifier.domains.contracts import event_closure
from verifier.domains.contracts import time_strict, time_closure
from verifier.domains.contracts import graph_order, graph_lineage
from verifier.domains.contracts import receipt_statics
from verifier.domains.contracts import receipt_validation_replay
from verifier.domains.contracts import receipt_prerequisite_closure
from verifier.domains.contracts import object_statics
from verifier.domains.contracts import object_address_closure
from verifier.domains.contracts import object_lineage
from verifier.domains.contracts import arch_schedule
from verifier.domains.contracts import train_accumulation
from verifier.domains.contracts import hyper_unknown_absorption, hyper_composed_ceiling
from verifier.domains.contracts import hardware_substrate_observations, hardware_inventory_closure
from verifier.domains.contracts import agent_ceiling_fixity
from verifier.domains.contracts import bot_inherited_ceiling
from verifier.domains.contracts import harness_gap_boundary
from verifier.domains.contracts import event_dispatch, space_migration, bench_attempts
from verifier.domains.contracts import actor_replay, actor_decision_record, actor_closure
from verifier.domains.contracts import human_template_irreversibility, human_no_composition, human_population_declaration
from verifier.domains.contracts import owner_replay, owner_forks, owner_eligibility
from verifier.domains.contracts import role_closure
from verifier.domains.contracts import collective_closure
from verifier.domains.contracts import identity_lifecycle, identity_presentation
from verifier.domains.contracts import verifier_run_constraints
from verifier.domains.contracts import verifier_coverage_closure


class CurrentObjectRouteRefusal(ValueError):
    """The external route or replay input is unsupported or inconsistent."""


class CurrentObjectRouteUnavailable(CurrentObjectRouteRefusal):
    """The selected native checker or its required input cannot be reached."""


_SEMANTIC_VERSION = "verifier-current-object-obligations-1"
MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
MAX_SELECTION_TEXT_BYTES = 1024 * 1024
_MAX_SELECTION_NODES = 10_000
_MAX_SELECTION_DEPTH = 64
_MAX_INTEGER_BITS = 4096
_MAX_CONTAINER_ITEMS = 10_000


@dataclass(frozen=True)
class _Route:
    module: Any
    replay: Callable[..., dict[str, Any]]
    fixed_kind: str | None
    scope: str


_ROUTES: dict[tuple[str, str], _Route] = {
    (object_facets.SEMANTIC_VERSION, object_facets.COORDINATE): _Route(
        object_facets, object_facets.recheck_object_facets_certificate, None,
        "generic_canonical_representation_and_address"),
    (object_grounding.SEMANTIC_VERSION, object_grounding.COORDINATE): _Route(
        object_grounding, object_grounding.recheck_current_object_certificate,
        "SIM", "finite_declared_capability_effect_confinement"),
    (hyper_closure.SEMANTIC_VERSION, hyper_closure.COORDINATE): _Route(
        hyper_closure, hyper_closure.recheck_hyper_closure_certificate,
        "HYPER", "finite_declared_hyper_operand_closure"),
    (sim_checker.SEMANTIC_VERSION, sim_checker.COORDINATE): _Route(
        sim_checker, sim_checker.recheck_sim_checker_certificate,
        "VERIFIER", "finite_native_sim_checker_outcome_correspondence"),
    (sim_dynamics.SEMANTIC_VERSION, sim_dynamics.COORDINATE): _Route(
        sim_dynamics.SimDynamicsDescriptor(), sim_dynamics.recheck_sim_dynamics_certificate,
        "SIM", sim_dynamics.SCOPE),
    (sim_resource.SEMANTIC_VERSION, sim_resource.COORDINATE): _Route(
        sim_resource.SimResourceDescriptor(), sim_resource.recheck_sim_resource_certificate,
        "SIM", sim_resource.SCOPE),
    (sim_response.SEMANTIC_VERSION, sim_response.COORDINATE): _Route(
        sim_response.SimResponseDescriptor(), sim_response.recheck_sim_response_certificate,
        "SIM", sim_response.SCOPE),
    (sim_internal_state.SEMANTIC_VERSION, sim_internal_state.COORDINATE): _Route(
        sim_internal_state.SimInternalStateDescriptor(),
        sim_internal_state.recheck_sim_internal_state_certificate,
        "SIM", sim_internal_state.SCOPE),
    (sim_perspective.SEMANTIC_VERSION, sim_perspective.COORDINATE): _Route(
        sim_perspective.SimPerspectiveDescriptor(),
        sim_perspective.recheck_sim_perspective_certificate,
        "SIM", sim_perspective.SCOPE),
    (sim_external_law.SEMANTIC_VERSION, sim_external_law.COORDINATE): _Route(
        sim_external_law.SimExternalLawDescriptor(),
        sim_external_law.recheck_sim_external_law_certificate,
        "SIM", sim_external_law.SCOPE),
    (sim_shard_coverage.SEMANTIC_VERSION, sim_shard_coverage.COORDINATE): _Route(
        sim_shard_coverage.SimShardCoverageDescriptor(),
        sim_shard_coverage.recheck_sim_shard_coverage_certificate,
        "SIM", sim_shard_coverage.SCOPE),
    (sim_shard_relations.SEMANTIC_VERSION, sim_shard_relations.COORDINATE): _Route(
        sim_shard_relations.SimShardRelationsDescriptor(),
        sim_shard_relations.recheck_sim_shard_relations_certificate,
        "SIM", sim_shard_relations.SCOPE),
    (sim_shard_signatures.SEMANTIC_VERSION, sim_shard_signatures.COORDINATE): _Route(
        sim_shard_signatures.SimShardSignaturesDescriptor(),
        sim_shard_signatures.recheck_sim_shard_signatures_certificate,
        "SIM", sim_shard_signatures.SCOPE),
    (sim_surface_partition.SEMANTIC_VERSION, sim_surface_partition.COORDINATE): _Route(
        sim_surface_partition.SimSurfacePartitionDescriptor(),
        sim_surface_partition.recheck_sim_surface_partition_certificate,
        "SIM", sim_surface_partition.SCOPE),
    (receipt_chain.SEMANTIC_VERSION, receipt_chain.COORDINATE): _Route(
        receipt_chain, receipt_chain.recheck_receipt_chain_certificate,
        "RECEIPT", "externally_selected_finite_receipt_hash_chain"),
    (receipt_authenticity.SEMANTIC_VERSION, receipt_authenticity.COORDINATE): _Route(
        receipt_authenticity.ReceiptAuthenticityDescriptor(), receipt_authenticity.recheck_receipt_authenticity_certificate,
        "RECEIPT", receipt_authenticity.SCOPE),
    (identity_scope.SEMANTIC_VERSION, identity_scope.COORDINATE): _Route(
        identity_scope, identity_scope.recheck_identity_scope_certificate,
        "IDENTITY", identity_scope.SCOPE),
    (hardware_inventory.SEMANTIC_VERSION, hardware_inventory.COORDINATE): _Route(
        hardware_inventory.HardwareInventoryDescriptor(),
        hardware_inventory.recheck_hardware_inventory_certificate,
        "HARDWARE", hardware_inventory.SCOPE),
    (hardware_topology.SEMANTIC_VERSION, hardware_topology.COORDINATE): _Route(
        hardware_topology.HardwareTopologyDescriptor(),
        hardware_topology.recheck_hardware_topology_certificate,
        "HARDWARE", hardware_topology.SCOPE),
    (graph_statics.SEMANTIC_VERSION, graph_statics.COORDINATE): _Route(
        graph_statics.GraphStaticsDescriptor(),
        graph_statics.recheck_graph_statics_certificate,
        "GRAPH", graph_statics.SCOPE),
    (graph_closure.SEMANTIC_VERSION, graph_closure.COORDINATE): _Route(
        graph_closure.GraphClosureDescriptor(),
        graph_closure.recheck_graph_closure_certificate,
        "GRAPH", graph_closure.SCOPE),
    (hardware_measurements.SEMANTIC_VERSION, hardware_measurements.COORDINATE): _Route(
        hardware_measurements.HardwareMeasurementsDescriptor(),
        hardware_measurements.recheck_hardware_measurements_certificate,
        "HARDWARE", hardware_measurements.SCOPE),
    (data_distribution.SEMANTIC_VERSION, data_distribution.COORDINATE): _Route(
        data_distribution.DataDistributionDescriptor(),
        data_distribution.recheck_data_distribution_certificate,
        "DATA", data_distribution.SCOPE),
    (time_order.SEMANTIC_VERSION, time_order.COORDINATE): _Route(
        time_order.TimeOrderDescriptor(), time_order.recheck_time_order_certificate,
        "TIME", time_order.SCOPE),
    (time_closure.SEMANTIC_VERSION, time_closure.COORDINATE): _Route(
        time_closure.TimeClosureDescriptor(), time_closure.recheck_time_closure_certificate,
        "TIME", time_closure.SCOPE),
    (arch_shapes.SEMANTIC_VERSION, arch_shapes.COORDINATE): _Route(
        arch_shapes.ArchShapesDescriptor(), arch_shapes.recheck_arch_shapes_certificate,
        "ARCH", arch_shapes.SCOPE),
    (space_layout.SEMANTIC_VERSION, space_layout.COORDINATE): _Route(
        space_layout.SpaceLayoutDescriptor(), space_layout.recheck_space_layout_certificate,
        "SPACE", space_layout.SCOPE),
    (space_closure.SEMANTIC_VERSION, space_closure.COORDINATE): _Route(
        space_closure.SpaceClosureDescriptor(),
        space_closure.recheck_space_closure_certificate,
        "SPACE", space_closure.SCOPE),
    (event_closure.SEMANTIC_VERSION, event_closure.COORDINATE): _Route(
        event_closure.EventClosureDescriptor(),
        event_closure.recheck_event_closure_certificate,
        "EVENT", event_closure.SCOPE),
    (time_strict.SEMANTIC_VERSION, time_strict.COORDINATE): _Route(
        time_strict.TimeStrictDescriptor(),
        time_strict.recheck_time_strict_certificate,
        "TIME", time_strict.SCOPE),
    (graph_lineage.SEMANTIC_VERSION, graph_lineage.COORDINATE): _Route(
        graph_lineage.GraphLineageDescriptor(),
        graph_lineage.recheck_graph_lineage_certificate,
        "GRAPH", graph_lineage.SCOPE),
    (graph_order.SEMANTIC_VERSION, graph_order.COORDINATE): _Route(
        graph_order.GraphOrderDescriptor(),
        graph_order.recheck_graph_order_certificate,
        "GRAPH", graph_order.SCOPE),
    (event_prerequisites.SEMANTIC_VERSION, event_prerequisites.COORDINATE): _Route(
        event_prerequisites.EventPrerequisitesDescriptor(),
        event_prerequisites.recheck_event_prerequisites_certificate,
        "EVENT", event_prerequisites.SCOPE),
    (object_governance.SEMANTIC_VERSION, object_governance.COORDINATE): _Route(
        object_governance.GovernanceDescriptor(), object_governance.recheck_governance_certificate,
        "OBJECT", object_governance.SCOPE),
    (hardware_capacity.SEMANTIC_VERSION, hardware_capacity.COORDINATE): _Route(
        hardware_capacity.HardwareCapacityDescriptor(), hardware_capacity.recheck_hardware_capacity_certificate,
        "HARDWARE", hardware_capacity.SCOPE),
    (model_artifact_bytes.SEMANTIC_VERSION, model_artifact_bytes.COORDINATE): _Route(
        model_artifact_bytes.ModelArtifactBytesDescriptor(),
        model_artifact_bytes.recheck_model_artifact_bytes_certificate,
        "MODEL", model_artifact_bytes.SCOPE),
    (model_hardware_observation.SEMANTIC_VERSION, model_hardware_observation.COORDINATE): _Route(
        model_hardware_observation.ModelHardwareDescriptor(),
        model_hardware_observation.recheck_model_hardware_certificate,
        "MODEL", model_hardware_observation.SCOPE),
    (model_data_citation.SEMANTIC_VERSION, model_data_citation.COORDINATE): _Route(
        model_data_citation.ModelDataDescriptor(),
        model_data_citation.recheck_model_data_certificate,
        "MODEL", model_data_citation.SCOPE),
    (model_train_citation.SEMANTIC_VERSION, model_train_citation.COORDINATE): _Route(
        model_train_citation.ModelTrainDescriptor(),
        model_train_citation.recheck_model_train_certificate,
        "MODEL", model_train_citation.SCOPE),
    (model_data_lineage.SEMANTIC_VERSION, model_data_lineage.COORDINATE): _Route(
        model_data_lineage.ModelDataLineageDescriptor(),
        model_data_lineage.recheck_model_data_lineage_certificate,
        "MODEL", model_data_lineage.SCOPE),
    (env_executable.SEMANTIC_VERSION, env_executable.COORDINATE): _Route(
        env_executable.EnvExecutableDescriptor(),
        env_executable.recheck_env_executable_certificate,
        "ENV", env_executable.SCOPE),
    (env_configuration_surface.SEMANTIC_VERSION, env_configuration_surface.COORDINATE): _Route(
        env_configuration_surface.EnvConfigurationSurfaceDescriptor(),
        env_configuration_surface.recheck_env_configuration_surface_certificate,
        "ENV", env_configuration_surface.SCOPE),
    (env_pin_closure.SEMANTIC_VERSION, env_pin_closure.COORDINATE): _Route(
        env_pin_closure.EnvPinClosureDescriptor(),
        env_pin_closure.recheck_env_pin_closure_certificate,
        "ENV", env_pin_closure.SCOPE),
    (train_data_bridge.SEMANTIC_VERSION, train_data_bridge.COORDINATE): _Route(
        train_data_bridge.TrainDataBridgeDescriptor(),
        train_data_bridge.recheck_train_data_bridge_certificate,
        "TRAIN", train_data_bridge.SCOPE),
    (model_quantization.SEMANTIC_VERSION, model_quantization.COORDINATE): _Route(
        model_quantization.ModelQuantizationDescriptor(),
        model_quantization.recheck_model_quantization_certificate,
        "MODEL", model_quantization.SCOPE),
    (arch_schedule.SEMANTIC_VERSION, arch_schedule.COORDINATE): _Route(
        arch_schedule.ArchScheduleDescriptor(),
        arch_schedule.recheck_arch_schedule_certificate,
        "ARCH", arch_schedule.SCOPE),
    (train_accumulation.SEMANTIC_VERSION, train_accumulation.COORDINATE): _Route(
        train_accumulation.TrainAccumulationDescriptor(),
        train_accumulation.recheck_train_accumulation_certificate,
        "TRAIN", train_accumulation.SCOPE),
    (hyper_unknown_absorption.SEMANTIC_VERSION, hyper_unknown_absorption.COORDINATE): _Route(
        hyper_unknown_absorption.HyperUnknownAbsorptionDescriptor(),
        hyper_unknown_absorption.recheck_hyper_unknown_absorption_certificate,
        "HYPER", hyper_unknown_absorption.SCOPE),
    (hyper_composed_ceiling.SEMANTIC_VERSION, hyper_composed_ceiling.COORDINATE): _Route(
        hyper_composed_ceiling.HyperComposedCeilingDescriptor(),
        hyper_composed_ceiling.recheck_hyper_composed_ceiling_certificate,
        "HYPER", hyper_composed_ceiling.SCOPE),
    (event_dispatch.SEMANTIC_VERSION, event_dispatch.COORDINATE): _Route(
        event_dispatch.EventDispatchDescriptor(),
        event_dispatch.recheck_event_dispatch_certificate,
        "EVENT", event_dispatch.SCOPE),
    (space_migration.SEMANTIC_VERSION, space_migration.COORDINATE): _Route(
        space_migration.SpaceMigrationDescriptor(),
        space_migration.recheck_space_migration_certificate,
        "SPACE", space_migration.SCOPE),
    (bench_attempts.SEMANTIC_VERSION, bench_attempts.COORDINATE): _Route(
        bench_attempts.BenchAttemptsDescriptor(),
        bench_attempts.recheck_bench_attempts_certificate,
        "BENCH", bench_attempts.SCOPE),
}

for _kind in ObjectKind:
    _ROUTES[(typed_facets.SEMANTIC_VERSION, typed_facets.coordinate(_kind.value))] = _Route(
        typed_facets.FacetDescriptor(_kind.value), typed_facets.recheck_typed_facets_certificate,
        _kind.value, typed_facets.SCOPE)

for _check, _coordinate in data_checks.CHECKS.items():
    _ROUTES[(data_checks.SEMANTIC_VERSION, _coordinate)] = _Route(
        data_checks.DataDescriptor(_check), data_checks.recheck_data_checks_certificate,
        "DATA", data_checks.scope(_check))


for _check, _coordinate in env_checks.CHECKS.items():
    _ROUTES[(env_checks.SEMANTIC_VERSION, _coordinate)] = _Route(
        env_checks.EnvDescriptor(_check), env_checks.recheck_env_checks_certificate,
        "ENV", env_checks.scope(_check))


for _check, _coordinate in bench_checks.CHECKS.items():
    _ROUTES[(bench_checks.SEMANTIC_VERSION, _coordinate)] = _Route(
        bench_checks.BenchDescriptor(_check), bench_checks.recheck_bench_checks_certificate,
        "BENCH", bench_checks.scope(_check))


for _check, _coordinate in train_checks.CHECKS.items():
    _ROUTES[(train_checks.SEMANTIC_VERSION, _coordinate)] = _Route(
        train_checks.TrainDescriptor(_check), train_checks.recheck_train_checks_certificate,
        "TRAIN", train_checks.scope(_check))


for _check, _coordinate in model_checks.CHECKS.items():
    _ROUTES[(model_checks.SEMANTIC_VERSION, _coordinate)] = _Route(
        model_checks.ModelDescriptor(_check), model_checks.recheck_model_checks_certificate,
        "MODEL", model_checks.scope(_check))


for _check, _coordinate in harness_checks.CHECKS.items():
    _ROUTES[(harness_checks.SEMANTIC_VERSION, _coordinate)] = _Route(
        harness_checks.HarnessDescriptor(_check), harness_checks.recheck_harness_checks_certificate,
        "HARNESS", harness_checks.scope(_check))


for _check, _coordinate in agent_checks.CHECKS.items():
    _ROUTES[(agent_checks.SEMANTIC_VERSION, _coordinate)] = _Route(
        agent_checks.AgentDescriptor(_check), agent_checks.recheck_agent_checks_certificate,
        "AGENT", agent_checks.scope(_check))

for _check, _coordinate in bot_checks.CHECKS.items():
    _ROUTES[(bot_checks.SEMANTIC_VERSION, _coordinate)] = _Route(
        bot_checks.BotDescriptor(_check), bot_checks.recheck_bot_checks_certificate,
        "BOT", bot_checks.scope(_check))


for _kind in ObjectKind:
    _ROUTES[(privacy_checks.SEMANTIC_VERSION, privacy_checks.coordinate(_kind.value))] = _Route(
        privacy_checks.PrivacyDescriptor(_kind.value), privacy_checks.recheck_privacy_checks_certificate,
        _kind.value, privacy_checks.SCOPE)


for _kind in ObjectKind:
    for _stage in range(1, 7):
        _ROUTES[(consent_checks.SEMANTIC_VERSION, consent_checks.coordinate(_kind.value, _stage))] = _Route(
            consent_checks.ConsentDescriptor(_kind.value, _stage), consent_checks.recheck_consent_checks_certificate,
            _kind.value, consent_checks.registration(_kind.value, _stage)["scope"])


for _kind in ObjectKind:
    if _kind is not ObjectKind.OBJECT:
        _ROUTES[(object_governance.SEMANTIC_VERSION, object_governance.coordinate(_kind.value))] = _Route(
            object_governance.KindGovernanceDescriptor(_kind.value),
            object_governance.recheck_governance_certificate, _kind.value, object_governance.SCOPE)
    _ROUTES[(subject_security.SEMANTIC_VERSION, subject_security.coordinate(_kind.value))] = _Route(
        subject_security.SubjectSecurityDescriptor(_kind.value),
        subject_security.recheck_subject_security_certificate, _kind.value, subject_security.SCOPE)


for _check, _coordinate in token_checks.CHECKS.items():
    _key = (token_checks.SEMANTIC_VERSION, _coordinate)
    if _key in _ROUTES:
        raise RuntimeError("duplicate current-object TOKEN route")
    _ROUTES[_key] = _Route(
        token_checks.TokenDescriptor(_check), token_checks.recheck_token_checks_certificate,
        "TOKEN", token_checks.scope(_check))

for _kind, _scope in independence_checks.KIND_SCOPES.items():
    _key = (independence_checks.SEMANTIC_VERSION, independence_checks.coordinate(_kind))
    if _key in _ROUTES:
        raise RuntimeError("duplicate current-object Independence route")
    _ROUTES[_key] = _Route(
        independence_checks.IndependenceChecksDescriptor(_kind),
        independence_checks.recheck_independence_checks_certificate, _kind, _scope)

if (receipt_statics.SEMANTIC_VERSION, receipt_statics.COORDINATE) in _ROUTES:
    raise RuntimeError("duplicate current-object RECEIPT-3.1 route")
_ROUTES[(receipt_statics.SEMANTIC_VERSION, receipt_statics.COORDINATE)] = _Route(
    receipt_statics.ReceiptStaticsDescriptor(),
    receipt_statics.recheck_receipt_statics_certificate,
    "RECEIPT", receipt_statics.SCOPE)

if (receipt_validation_replay.SEMANTIC_VERSION, receipt_validation_replay.COORDINATE) in _ROUTES:
    raise RuntimeError("duplicate current-object RECEIPT-2.1 route")
_ROUTES[(receipt_validation_replay.SEMANTIC_VERSION, receipt_validation_replay.COORDINATE)] = _Route(
    receipt_validation_replay.ReceiptValidationReplayDescriptor(),
    receipt_validation_replay.recheck_receipt_validation_replay_certificate,
    "RECEIPT", receipt_validation_replay.SCOPE)

if (receipt_prerequisite_closure.SEMANTIC_VERSION, receipt_prerequisite_closure.COORDINATE) in _ROUTES:
    raise RuntimeError("duplicate current-object RECEIPT-4.1 route")
_ROUTES[(receipt_prerequisite_closure.SEMANTIC_VERSION, receipt_prerequisite_closure.COORDINATE)] = _Route(
    receipt_prerequisite_closure.ReceiptPrerequisiteClosureDescriptor(),
    receipt_prerequisite_closure.recheck_receipt_prerequisite_closure_certificate,
    "RECEIPT", receipt_prerequisite_closure.SCOPE)

_ROUTES[(object_statics.SEMANTIC_VERSION, object_statics.COORDINATE)] = _Route(
    object_statics.ObjectStaticsDescriptor(),
    object_statics.recheck_object_statics_certificate,
    "OBJECT", object_statics.SCOPE)


_ROUTES[(object_address_closure.SEMANTIC_VERSION, object_address_closure.COORDINATE)] = _Route(
    object_address_closure.ObjectAddressClosureDescriptor(),
    object_address_closure.recheck_object_address_closure_certificate,
    None, object_address_closure.SCOPE)


# Objectives whose request selects the represented kind, as OBJECT-1.1 does.
_SELECTED_KIND_OBJECTIVES = frozenset(
    (object_lineage.COORDINATE, object_address_closure.COORDINATE))

_ROUTES[(object_lineage.SEMANTIC_VERSION, object_lineage.COORDINATE)] = _Route(
    object_lineage.ObjectLineageDescriptor(),
    object_lineage.recheck_object_lineage_certificate,
    None, object_lineage.SCOPE)

for _hardware_module, _hardware_descriptor, _hardware_recheck in (
    (hardware_substrate_observations, hardware_substrate_observations.HardwareSubstrateObservationsDescriptor,
     hardware_substrate_observations.recheck_hardware_substrate_observations_certificate),
    (hardware_inventory_closure, hardware_inventory_closure.HardwareInventoryClosureDescriptor,
     hardware_inventory_closure.recheck_hardware_inventory_closure_certificate),
):
    _key = (_hardware_module.SEMANTIC_VERSION, _hardware_module.COORDINATE)
    if _key in _ROUTES:
        raise RuntimeError("duplicate current-object HARDWARE route")
    _ROUTES[_key] = _Route(_hardware_descriptor(), _hardware_recheck, "HARDWARE", _hardware_module.SCOPE)

_ROUTES[(agent_ceiling_fixity.SEMANTIC_VERSION, agent_ceiling_fixity.COORDINATE)] = _Route(
    agent_ceiling_fixity.AgentCeilingFixityDescriptor(), agent_ceiling_fixity.recheck_agent_ceiling_fixity_certificate,
    "AGENT", agent_ceiling_fixity.SCOPE)
_ROUTES[(bot_inherited_ceiling.SEMANTIC_VERSION, bot_inherited_ceiling.COORDINATE)] = _Route(
    bot_inherited_ceiling.BotInheritedCeilingDescriptor(), bot_inherited_ceiling.recheck_bot_inherited_ceiling_certificate,
    "BOT", bot_inherited_ceiling.SCOPE)
_ROUTES[(harness_gap_boundary.SEMANTIC_VERSION, harness_gap_boundary.COORDINATE)] = _Route(
    harness_gap_boundary.HarnessGapBoundaryDescriptor(), harness_gap_boundary.recheck_harness_gap_boundary_certificate,
    "HARNESS", harness_gap_boundary.SCOPE)

_ROUTES[(actor_replay.SEMANTIC_VERSION, actor_replay.COORDINATE)] = _Route(
    actor_replay.ActorReplayDescriptor(),
    actor_replay.recheck_actor_replay_certificate,
    "ACTOR", actor_replay.SCOPE)
_ROUTES[(actor_decision_record.SEMANTIC_VERSION, actor_decision_record.COORDINATE)] = _Route(
    actor_decision_record.ActorDecisionRecordDescriptor(),
    actor_decision_record.recheck_actor_decision_record_certificate,
    "ACTOR", actor_decision_record.SCOPE)
_ROUTES[(actor_closure.SEMANTIC_VERSION, actor_closure.COORDINATE)] = _Route(
    actor_closure.ActorClosureDescriptor(),
    actor_closure.recheck_actor_closure_certificate,
    "ACTOR", actor_closure.SCOPE)

for _human_module, _human_descriptor, _human_recheck in (
    (human_template_irreversibility,
     human_template_irreversibility.HumanTemplateIrreversibilityDescriptor,
     human_template_irreversibility.recheck_human_template_irreversibility_certificate),
    (human_no_composition,
     human_no_composition.HumanNoCompositionDescriptor,
     human_no_composition.recheck_human_no_composition_certificate),
    (human_population_declaration,
     human_population_declaration.HumanPopulationDeclarationDescriptor,
     human_population_declaration.recheck_human_population_declaration_certificate),
):
    _key = (_human_module.SEMANTIC_VERSION, _human_module.COORDINATE)
    if _key in _ROUTES:
        raise RuntimeError("duplicate current-object HUMAN route")
    _ROUTES[_key] = _Route(_human_descriptor(), _human_recheck, "HUMAN", _human_module.SCOPE)

for _key, _owner_route in (
        ((owner_eligibility.SEMANTIC_VERSION, owner_eligibility.COORDINATE), _Route(
            owner_eligibility.OwnerEligibilityDescriptor(),
            owner_eligibility.recheck_owner_eligibility_certificate,
            "OWNER", owner_eligibility.SCOPE)),
        ((owner_replay.SEMANTIC_VERSION, owner_replay.COORDINATE), _Route(
            owner_replay.OwnerReplayDescriptor(),
            owner_replay.recheck_owner_replay_certificate,
            "OWNER", owner_replay.SCOPE)),
        ((owner_forks.SEMANTIC_VERSION, owner_forks.COORDINATE), _Route(
            owner_forks.OwnerForksDescriptor(),
            owner_forks.recheck_owner_forks_certificate,
            "OWNER", owner_forks.SCOPE))):
    if _key in _ROUTES:
        raise RuntimeError("duplicate current-object OWNER route")
    _ROUTES[_key] = _owner_route

if (verifier_run_constraints.SEMANTIC_VERSION, verifier_run_constraints.COORDINATE) in _ROUTES:
    raise RuntimeError("duplicate current-object VERIFIER-3.1 route")
_ROUTES[(verifier_run_constraints.SEMANTIC_VERSION, verifier_run_constraints.COORDINATE)] = _Route(
    verifier_run_constraints.VerifierRunConstraintsDescriptor(),
    verifier_run_constraints.recheck_verifier_run_constraints_certificate,
    "VERIFIER", verifier_run_constraints.SCOPE)

if (verifier_coverage_closure.SEMANTIC_VERSION, verifier_coverage_closure.COORDINATE) in _ROUTES:
    raise RuntimeError("duplicate current-object VERIFIER-4.1 route")
_ROUTES[(verifier_coverage_closure.SEMANTIC_VERSION, verifier_coverage_closure.COORDINATE)] = _Route(
    verifier_coverage_closure.VerifierCoverageClosureDescriptor(),
    verifier_coverage_closure.recheck_verifier_coverage_closure_certificate,
    "VERIFIER", verifier_coverage_closure.SCOPE)



_FINITE_CURRENT_BATCH_DESCRIPTORS = (role_constraints.RoleConstraintsDescriptor,
    collective_constraints.CollectiveConstraintsDescriptor)
for _module, _descriptor, _kind, _replay in (
    (role_constraints, role_constraints.RoleConstraintsDescriptor, 'ROLE', role_constraints.recheck_role_constraints_certificate),
    (collective_constraints, collective_constraints.CollectiveConstraintsDescriptor, 'COLLECTIVE', collective_constraints.recheck_collective_constraints_certificate),
):
    _key = (_module.SEMANTIC_VERSION, _module.COORDINATE)
    if _key in _ROUTES:
        raise ValueError("finite current objective route collision")
    _ROUTES[_key] = _Route(_descriptor(), _replay, _kind, _module.SCOPE)


_FINITE_CURRENT_BATCH_DESCRIPTORS += (role_lifecycle.RoleLifecycleDescriptor,
    collective_lifecycle.CollectiveLifecycleDescriptor, arch_resolution.ArchResolutionDescriptor)
for _module, _descriptor, _kind, _replay in (
    (role_lifecycle, role_lifecycle.RoleLifecycleDescriptor, 'ROLE', role_lifecycle.recheck_role_lifecycle_certificate),
    (collective_lifecycle, collective_lifecycle.CollectiveLifecycleDescriptor, 'COLLECTIVE', collective_lifecycle.recheck_collective_lifecycle_certificate),
    (arch_resolution, arch_resolution.ArchResolutionDescriptor, 'ARCH', arch_resolution.recheck_arch_resolution_certificate),
):
    _key = (_module.SEMANTIC_VERSION, _module.COORDINATE)
    if _key in _ROUTES:
        raise ValueError("second finite objective route collision")
    _ROUTES[_key] = _Route(_descriptor(), _replay, _kind, _module.SCOPE)

_ROUTES[(role_closure.SEMANTIC_VERSION, role_closure.COORDINATE)] = _Route(
    role_closure.RoleClosureDescriptor(), role_closure.recheck_role_closure_certificate,
    "ROLE", role_closure.SCOPE)
_FINITE_CURRENT_BATCH_DESCRIPTORS += (role_closure.RoleClosureDescriptor,)


_ROUTES[(collective_closure.SEMANTIC_VERSION, collective_closure.COORDINATE)] = _Route(
    collective_closure.CollectiveClosureDescriptor(), collective_closure.recheck_collective_closure_certificate,
    "COLLECTIVE", collective_closure.SCOPE)
_FINITE_CURRENT_BATCH_DESCRIPTORS += (collective_closure.CollectiveClosureDescriptor,)


_ROUTES[(identity_lifecycle.SEMANTIC_VERSION, identity_lifecycle.COORDINATE)] = _Route(
    identity_lifecycle, identity_lifecycle.recheck_identity_lifecycle_certificate,
    "IDENTITY", identity_lifecycle.SCOPE)


_ROUTES[(identity_presentation.SEMANTIC_VERSION, identity_presentation.COORDINATE)] = _Route(
    identity_presentation, identity_presentation.recheck_identity_presentation_certificate,
    "IDENTITY", identity_presentation.SCOPE)


def select_current_object_route(*, semantic_version: str, objective: str,
                                represented_kind: str) -> _Route:
    """Select installed native code from exact external coordinates only."""
    if (type(semantic_version) is not str or type(objective) is not str
            or type(represented_kind) is not str):
        raise CurrentObjectRouteRefusal("external route fields require plain text")
    if semantic_version == "verifier-current-ten-tier-object-obligations-1" and (
            objective not in ("VERIFIER-6.1", "VERIFIER-10.1") or represented_kind != "VERIFIER"):
        raise CurrentObjectRouteRefusal("exact native ten-tier objective/kind is unsupported")
    try:
        selected = (_ten_tier_routes().get((semantic_version, objective))
                    if semantic_version == "verifier-current-ten-tier-object-obligations-1"
                    else _ROUTES.get((semantic_version, objective)))
    except (ImportError, OSError, MemoryError) as exc:
        raise CurrentObjectRouteUnavailable("selected native family is unavailable") from exc
    if selected is None or semantic_version not in (
            _SEMANTIC_VERSION, "verifier-current-ten-tier-object-obligations-1"):
        raise CurrentObjectRouteRefusal("current semantic version or objective is unsupported")
    if represented_kind not in {kind.value for kind in ObjectKind}:
        raise CurrentObjectRouteRefusal("represented kind is not admitted")
    if selected.fixed_kind is not None and represented_kind != selected.fixed_kind:
        raise CurrentObjectRouteRefusal("represented kind differs from selected objective")
    return selected


def _ten_tier_routes() -> dict[tuple[str, str], _Route]:
    """Closed opt-in native family; no submitted module or fallback is admitted."""
    from verifier.domains.contracts import verifier_composed_security, verifier_replacement
    native, replacement = verifier_composed_security, verifier_replacement
    return {(native.SEMANTIC_VERSION, native.COORDINATE): _Route(
        native.VerifierComposedSecurityDescriptor(),
        native.recheck_verifier_composed_security_certificate, "VERIFIER", native.SCOPE),
        (replacement.SEMANTIC_VERSION, replacement.COORDINATE): _Route(
        replacement.VerifierReplacementDescriptor(),
        replacement.recheck_verifier_replacement_certificate, "VERIFIER", replacement.SCOPE)}


def current_ten_tier_route_catalog() -> list[dict[str, str]]:
    """List this distinct native family without extending historical catalogs."""
    return [{"semantic_version": semantic, "objective": objective,
             "certificate_schema_version": route.module.CERTIFICATE_VERSION,
             "proposition_digest": route.module.PROPOSITION_DIGEST,
             "represented_kind_rule": route.fixed_kind, "scope": route.scope,
             "object_profile_conformance": "NOT_ESTABLISHED"}
            for (semantic, objective), route in sorted(_ten_tier_routes().items())]


def current_object_route_catalog() -> list[dict[str, str]]:
    """List implemented objectives, not nominal profiles for all object kinds."""
    rows = []
    for (semantic_version, objective), route in sorted(_ROUTES.items()):
        rows.append({
            "semantic_version": semantic_version,
            "objective": objective,
            "certificate_schema_version": route.module.CERTIFICATE_VERSION,
            "proposition_digest": route.module.PROPOSITION_DIGEST,
            "represented_kind_rule": route.fixed_kind or "externally_selected_admitted_kind",
            "scope": route.scope,
            "object_profile_conformance": "NOT_ESTABLISHED",
        })
    return rows


def _capture_plain(value: Any) -> Any:
    """Bound exact built-in JSON-compatible selections before native callbacks."""
    nodes = text_bytes = 0
    active: set[int] = set()

    def copy(item: Any, depth: int) -> Any:
        nonlocal nodes, text_bytes
        nodes += 1
        if nodes > _MAX_SELECTION_NODES or depth > _MAX_SELECTION_DEPTH:
            raise CurrentObjectRouteRefusal("external selection structural bound exhausted")
        kind = type(item)
        if item is None or kind is bool:
            return item
        if kind is int:
            if item.bit_length() > _MAX_INTEGER_BITS:
                raise CurrentObjectRouteRefusal("external selection integer bound exhausted")
            return item
        if kind is float:
            if not math.isfinite(item):
                raise CurrentObjectRouteRefusal("external selection is nonfinite")
            return item
        if kind is str:
            if len(item) > MAX_SELECTION_TEXT_BYTES - text_bytes:
                raise CurrentObjectRouteRefusal("external selection text bound exhausted")
            text_bytes += len(item.encode("utf-8"))
            if text_bytes > MAX_SELECTION_TEXT_BYTES:
                raise CurrentObjectRouteRefusal("external selection text bound exhausted")
            return item
        if kind not in (dict, list):
            raise CurrentObjectRouteRefusal("external selection requires plain JSON values")
        identity = id(item)
        if identity in active:
            raise CurrentObjectRouteRefusal("external selection is cyclic")
        active.add(identity)
        try:
            if len(item) > _MAX_CONTAINER_ITEMS:
                raise CurrentObjectRouteRefusal("external selection collection bound exhausted")
            if kind is list:
                return [copy(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise CurrentObjectRouteRefusal("external selection keys require plain text")
                result[copy(key, depth + 1)] = copy(child, depth + 1)
            return result
        finally:
            active.remove(identity)

    try:
        return copy(value, 0)
    except (RecursionError, RuntimeError, UnicodeError) as exc:
        raise CurrentObjectRouteRefusal("external selection cannot be captured") from exc


def replay_current_object_certificate(
    certificate_bytes: bytes, *, semantic_version: str, objective: str,
    represented_kind: str, expected_request: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Reproduce one exact native certificate against independently selected intent."""
    route = select_current_object_route(
        semantic_version=semantic_version, objective=objective,
        represented_kind=represented_kind)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > MAX_CERTIFICATE_BYTES:
        raise CurrentObjectRouteRefusal("certificate is absent or exceeds transport bound")
    if type(expected_request) is not dict or type(policy) is not dict:
        raise CurrentObjectRouteRefusal("request and policy require external plain objects")
    request = _capture_plain(expected_request)
    admitted_policy = _capture_plain(policy)
    if (type(request.get("semantic_version")) is not str
            or request["semantic_version"] != semantic_version
            or type(request.get("coordinate")) is not str
            or request["coordinate"] != objective):
        raise CurrentObjectRouteRefusal("external request differs from selected objective")
    association = isinstance(route.module, subject_security.SubjectSecurityDescriptor)
    if association and request.get("object_kind") != represented_kind:
        raise CurrentObjectRouteRefusal("external request differs from selected security kind")
    if objective == "OBJECT-1.1" and (
            type(request.get("object_kind")) is not str
            or request["object_kind"] != represented_kind):
        raise CurrentObjectRouteRefusal("external request differs from represented kind")
    if objective in _SELECTED_KIND_OBJECTIVES and (
            type(request.get("object_kind")) is not str
            or request["object_kind"] != represented_kind):
        raise CurrentObjectRouteRefusal("external request differs from represented kind")
    try:
        native_result = route.replay(
            certificate_bytes, expected_request=request, policy=admitted_policy)
        if (type(native_result) is not dict
                or type(native_result.get("status")) is not str
                or native_result["status"] not in ("PASS", "FAIL", "UNKNOWN")
                or type(native_result.get("semantic_version")) is not str
                or native_result["semantic_version"] != semantic_version
                or type(native_result.get("coordinate")) is not str
                or native_result["coordinate"] != objective
                or native_result.get("object_profile_conformance") != "NOT_ESTABLISHED"
                or (objective == "OBJECT-1.1" and
                    (type(native_result.get("object_kind")) is not str or
                     native_result["object_kind"] != represented_kind))):
            raise CurrentObjectRouteRefusal("native replay returned unsupported result")
        if objective in _SELECTED_KIND_OBJECTIVES and (
                type(native_result.get("object_kind")) is not str
                or native_result["object_kind"] != represented_kind):
            raise CurrentObjectRouteRefusal("native replay returned unsupported result")
        if association and (type(native_result.get("object_kind")) is not str
                            or native_result["object_kind"] != represented_kind):
            raise CurrentObjectRouteRefusal("native security replay returned a different kind")
        finite_batch = isinstance(route.module, _FINITE_CURRENT_BATCH_DESCRIPTORS)
        if finite_batch and (native_result.get("object_kind") != represented_kind
                or native_result.get("scope") != route.scope
                or any(native_result.get(field) != "NOT_ESTABLISHED" for field in
                       ("object_profile_conformance", "whole_tier_conformance", "authority", "actual_execution"))):
            raise CurrentObjectRouteRefusal("native finite replay exceeds its selected boundary")
        resource = isinstance(route.module, sim_resource.SimResourceDescriptor)
        token = isinstance(route.module, token_checks.TokenDescriptor)
        independence = isinstance(route.module, independence_checks.IndependenceChecksDescriptor)
        consent = isinstance(route.module, consent_checks.ConsentDescriptor)
        governance = isinstance(route.module, object_governance.GovernanceDescriptor)
        authenticity = isinstance(route.module, receipt_authenticity.ReceiptAuthenticityDescriptor)
        ten_tier = semantic_version == "verifier-current-ten-tier-object-obligations-1"
        composed = ten_tier and objective == "VERIFIER-6.1"
        replacement = ten_tier and objective == "VERIFIER-10.1"
        replay_status = (native_result.get("certificate_replay_status") if consent
                         else native_result.get("replay_status") if ten_tier
                         else native_result.get("replay_status", "REPRODUCED") if governance or authenticity
                         else "REPRODUCED")
        if composed and (replay_status not in ("REPRODUCED", "UNAVAILABLE")
                or native_result.get("object_kind") != represented_kind
                or native_result.get("scope") != route.scope
                or native_result.get("composed_security_admission") != "UNKNOWN"
                or any(native_result.get(field) != "NOT_ESTABLISHED" for field in
                       ("whole_security_admission", "authority", "actual_execution",
                        "human_acceptance", "production_admission"))
                or replay_status == "UNAVAILABLE" and native_result["status"] != "UNKNOWN"):
            raise CurrentObjectRouteRefusal("native composed-security replay exceeds its boundary")
        if replacement and (replay_status not in ("REPRODUCED", "UNAVAILABLE")
                or native_result.get("object_kind") != represented_kind
                or native_result.get("scope") != route.scope
                or native_result.get("complete_corrigibility_admission") != "UNKNOWN"
                or native_result.get("finite_replacement") != ("PASS" if native_result["status"] == "PASS" else "NOT_ESTABLISHED")
                or any(native_result.get(field) != "NOT_ESTABLISHED" for field in
                       ("whole_corrigibility_conformance", "authority", "actual_execution",
                        "human_acceptance", "production_admission"))
                or replay_status == "UNAVAILABLE" and native_result["status"] != "UNKNOWN"):
            raise CurrentObjectRouteRefusal("native replacement replay exceeds its boundary")
        if governance and (replay_status not in ("REPRODUCED", "UNAVAILABLE")
                or native_result.get("object_kind") != represented_kind
                or replay_status == "UNAVAILABLE" and native_result["status"] != "UNKNOWN"):
            raise CurrentObjectRouteRefusal("native governance replay availability is inconsistent")
        if authenticity and (replay_status not in ("REPRODUCED", "UNAVAILABLE")
                or native_result.get("object_kind") != represented_kind
                or replay_status == "UNAVAILABLE" and native_result["status"] != "UNKNOWN"):
            raise CurrentObjectRouteRefusal("native receipt authenticity replay availability is inconsistent")
        signed_record_status = native_result.get("signed_record_status")
        if resource and (native_result.get("object_kind") != represented_kind
                or native_result.get("scope") != route.scope
                or type(signed_record_status) is not str
                or signed_record_status not in ("PASS", "FAIL", "UNKNOWN")
                or native_result["status"] != (
                    "FAIL" if signed_record_status == "FAIL" else "UNKNOWN")
                or any(native_result.get(field) != "NOT_ESTABLISHED" for field in
                       ("object_profile_conformance", "sim_tier_2_conformance",
                        "historical_device_use", "collector_honesty",
                        "actual_consumption_correspondence", "physical_resource_truth"))
                or native_result.get("authority") != "SELECTED_COLLECTOR_KEY_ONLY"):
            raise CurrentObjectRouteRefusal("native SIM resource replay exceeds its signed-record boundary")
        if consent and (replay_status not in ("REPRODUCED", "UNAVAILABLE")
                or native_result.get("object_kind") != represented_kind
                or replay_status == "UNAVAILABLE" and native_result["status"] != "UNKNOWN"):
            raise CurrentObjectRouteRefusal("native consent replay availability is inconsistent")
        if independence and (
                native_result.get("object_kind") != represented_kind
                or native_result.get("scope") != independence_checks.SCOPE
                or native_result.get("independence_tier_conformance") != "NOT_ESTABLISHED"
                or native_result.get("source_authenticity") != "UNKNOWN"
                or type(native_result.get("dimensions")) is not dict
                or set(native_result["dimensions"]) != set(independence_checks.DIMENSIONS)
                or native_result["dimensions"]["retained_provenance"] not in ("PASS", "FAIL", "UNKNOWN")
                or any(native_result["dimensions"][name] != "UNKNOWN"
                       for name in independence_checks.DIMENSIONS if name != "retained_provenance")):
            raise CurrentObjectRouteRefusal("native Independence replay exceeds its documentary boundary")
        if token and (native_result.get("object_kind") != represented_kind
                or native_result.get("scope") != route.scope
                or any(native_result.get(field) != "NOT_ESTABLISHED" for field in
                       ("authority", "signature_validity", "physical_clock",
                        "holding_completeness", "actual_execution"))):
            raise CurrentObjectRouteRefusal("native TOKEN replay exceeds its retained arithmetic boundary")
        return {
            "schema_version": "verifier-current-object-route-replay-2" if consent or governance or authenticity or ten_tier else "verifier-current-object-route-replay-1",
            "selection": {"semantic_version": semantic_version,
                          "objective": objective,
                          "represented_kind": represented_kind},
            "replay_status": replay_status,
            "computational_status": native_result["status"],
            "native_result": native_result,
            "certificate_sha256": "sha256:" + sha256(certificate_bytes).hexdigest(),
            "request_sha256": "sha256:" + sha256(canonical_bytes(request)).hexdigest(),
            "policy_sha256": "sha256:" + sha256(canonical_bytes(admitted_policy)).hexdigest(),
            "claim_boundary": (
                "one exact retained replacement lifecycle within an externally admitted registered callback boundary; "
                "complete application coverage, actual execution, production authority, whole corrigibility and acceptance remain unestablished"
                if replacement else
                "exact externally selected signed VERIFIER association only; complete security, "
                "authority, actual execution and production admission remain unestablished"
                if composed else
                "one selected finite declared constraint, state-transition or reference-closure replay over exact typed bytes only; "
                "no actual execution, real-world authority, enforcement, domain completeness, whole tier or object profile"
                if finite_batch else
                "selected retained capability-token lifecycle, declared-window or parent-grant arithmetic only; "
                "no signatures, issuer or genesis authenticity, physical clock, live status, consumed invocations, "
                "real-world authority, enforcement, complete holding or whole tier"
                if token else
                "finite selected documentary source-footprint separation over exact kind-specific namespace bytes only; "
                "source authenticity, real-world identity, authority, implementation/runtime separation, "
                "unrecorded common causes and causal/statistical independence remain UNKNOWN; "
                "no actual production/checking, independent witnesses or whole Independence tier"
                if independence else
                "one selected consent predicate over independently configured holders; "
                "reproduction is not admission; no real-world authority, voluntary consent, "
                "holder-set completeness, execution permission or computational verdict upgrade"
                if consent else
                "selected signed namespace governance under an externally chosen policy and clock only; "
                "no legal compliance, real-world authority, actual admission, enforcement, "
                "whole governance tier, object profile, privacy, consent or security conclusion"
                if governance else
                "selected issuer key and exact retained receipt-chain prerequisite under external policy, challenge and clock only; "
                "no real-world identity, governance authority, trusted time, live revocation, "
                "one-time challenge consumption, disclosure authority or whole security tier"
                if authenticity else
                "selected RECEIPT object and finite receipt chain under an externally trusted tip only; "
                "no issuer authenticity, signature validity, whole tier, object profile, "
                "privacy, consent, governance or other security conclusion"
                if objective == receipt_chain.COORDINATE else
                "exact retained typed-subject association to a selected finite chain entry only; "
                "no issuer authenticity, signature validity, payload truth, actual execution, "
                "enforcement, hardware authenticity, context consumption or complete security tier"
                if association else
                "one selected computational objective only; no whole tier, object profile, "
                "authority, privacy, consent, governance, security or physical-world conclusion"),
        }
    except (ImportError, OSError) as exc:
        raise CurrentObjectRouteUnavailable("selected native checker or input is unavailable") from exc
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError,
            RecursionError) as exc:
        if isinstance(exc, CurrentObjectRouteRefusal):
            raise
        raise CurrentObjectRouteRefusal("selected native certificate did not replay") from exc


__all__ = ["CurrentObjectRouteRefusal", "CurrentObjectRouteUnavailable", "MAX_CERTIFICATE_BYTES",
           "MAX_SELECTION_TEXT_BYTES", "select_current_object_route",
           "current_object_route_catalog", "current_ten_tier_route_catalog", "replay_current_object_certificate"]
