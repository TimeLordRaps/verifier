"""Exact semantic ownership for Verifier test and fixture sources.

Terminology: Supply Chain Integrity, Transparency, and Trust (SCITT).

The root package catchall admitted 566 retained ``tests/`` files. The current
source census keeps every later test explicit rather than allowing a new test
surface to fall back to a generic package object.
Executable groups accumulate only their test-harness software consequences;
testing a consequential subject never transfers that subject kind, authority,
evidence, or real-world effect to the test source itself.

The declarations are source ownership and Tier-0 semantic inputs only. They
do not assert fresh execution, passing tests, package conformance, release,
deployment, physical actuation, real-money effects, or confinement.
"""

from __future__ import annotations

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
)


# Every executable family is a bounded pytest controller: it selects
# mechanisms, causes isolated software effects, observes results, and applies
# assertions. The roles do not flow from the subjects named by individual
# tests; they follow from the test harness behavior itself.
TEST_FIXTURE_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-test-fixture-harness",
        "HARNESS",
        (
            "tests/conftest.py",
            "tests/current_token_dependency_fixture.py",
            "tests/finite_record_fixture.py",
            "tests/installed_composition_workflow.py",
        ),
        "Shared pytest lifecycle hooks and finite, token-dependency, and installed-composition fixture constructors.",
        (
            "The shared helpers control registry restoration, source loading, ephemeral keys, "
            "local SQLite state, and selected fixture assembly, so their software control, "
            "observation, protocol, policy, and transaction consequences require an exact owner."
        ),
        (
            "Fixture construction may change isolated test-local state and invoke selected "
            "mechanisms. It is not a production HARNESS, trusted authority, current receipt, "
            "durable LEDGER, financial transaction, physical controller, or evidence of "
            "confinement. A retained test definition or passing pytest execution is bounded "
            "regression evidence only. It does not establish whole-package conformance, "
            "production effects, physical actuation, real-money authority, a MARKET, or BOT, "
            "ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-formation-fixture-corpus",
        "DATA",
        (
            "tests/fixtures/formation-interoperability-corpus.json",
            "tests/fixtures/formation-receipt-corpus.json",
        ),
        "Retained cross-language formation and formation-receipt positive, negative, and recheck fixture records.",
        (
            "The corpora encode exact portable message shapes, expected outcomes, and adversarial "
            "mutations whose protocol and oracle policy would be hidden by a generic test-file "
            "owner."
        ),
        (
            "Checked-in fixture bytes are neither fresh executions nor independently "
            "authoritative RECEIPTs, and their synthetic identities, evidence, and outcomes are "
            "not production provenance or conformance. A retained test definition or passing "
            "pytest execution is bounded regression evidence only. It does not establish "
            "whole-package conformance, production effects, physical actuation, real-money "
            "authority, a MARKET, or BOT, ROBOT, or FINBOT status."
        ),
        "POLICY",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-test-spacetime-extension-schema",
        "PROTOCOL",
        (
            "tests/spacetime-context-extension-1.schema.json",
        ),
        "Retained test-only JavaScript Object Notation schema for the spacetime context extension.",
        (
            "The extension fixture defines exact field and validation rules consumed across a "
            "test protocol, so its schema policy needs a distinct owner from executable tests and "
            "retained result corpora."
        ),
        (
            "The schema declares a test wire shape only; it does not parse an instance, prove "
            "temporal or spatial truth, run an extension, or establish implementation "
            "compatibility. A retained test definition or passing pytest execution is bounded "
            "regression evidence only. It does not establish whole-package conformance, "
            "production effects, physical actuation, real-money authority, a MARKET, or BOT, "
            "ROBOT, or FINBOT status."
        ),
        "POLICY",
    ),
    ownership_spec(
        "vstd-test-namespace-admission-regressions",
        "VERIFIER",
        (
            "tests/test_admitted_root_binding.py",
            "tests/test_applicability_declaration_contract.py",
            "tests/test_exact_materialized_member.py",
            "tests/test_exact_materialized_member_parent_swap.py",
            "tests/test_exact_source_scope.py",
            "tests/test_manifest_gate.py",
            "tests/test_namespace_admission.py",
            "tests/test_namespace_agency_paths.py",
            "tests/test_namespace_closure.py",
            "tests/test_namespace_closure_current.py",
            "tests/test_namespace_consequence_graph.py",
            "tests/test_namespace_consequential_kinds.py",
            "tests/test_namespace_documents.py",
            "tests/test_namespace_dominance.py",
            "tests/test_namespace_dynamic.py",
            "tests/test_namespace_exports.py",
            "tests/test_namespace_html.py",
            "tests/test_namespace_javascript.py",
            "tests/test_namespace_manifest_compact.py",
            "tests/test_namespace_metadata_discovery.py",
            "tests/test_namespace_metadata_inventory.py",
            "tests/test_namespace_objects.py",
            "tests/test_namespace_reconciliation_capacity_v5.py",
            "tests/test_namespace_refutation.py",
            "tests/test_namespace_refutation_admission.py",
            "tests/test_namespace_source_imports.py",
            "tests/test_namespace_systems.py",
            "tests/test_object_context_closure.py",
            "tests/test_package_admission_semantic_review_replay.py",
            "tests/test_package_contract_coverage.py",
            "tests/test_package_contract_profiles.py",
            "tests/test_package_harness_applicability.py",
            "tests/test_package_instance_evidence.py",
            "tests/test_package_kind_requirements.py",
            "tests/test_package_manifest_execution.py",
            "tests/test_package_manifest_migration_added_execution.py",
            "tests/test_package_manifest_migration_harness_ownership.py",
            "tests/test_package_manifest_refresh.py",
            "tests/test_package_manifest_refresh_recovery.py",
            "tests/test_package_manifest_refresh_v6.py",
            "tests/test_package_namespace_migration.py",
            "tests/test_package_namespace_review.py",
            "tests/test_package_obligation_candidate.py",
            "tests/test_package_original_kind_catalog.py",
            "tests/test_package_original_kind_catalog_domains.py",
            "tests/test_package_original_kind_catalog_experiments_hardware.py",
            "tests/test_package_original_kind_catalog_python_apps_public_cli.py",
            "tests/test_package_original_kind_catalog_repository_assets.py",
            "tests/test_package_original_kind_catalog_retained.py",
            "tests/test_package_original_kind_catalog_runtime.py",
            "tests/test_package_original_kind_catalog_scripts_examples.py",
            "tests/test_package_original_kind_catalog_tests_normative.py",
            "tests/test_package_original_kind_review.py",
            "tests/test_package_original_review_computation.py",
            "tests/test_package_original_review_people.py",
            "tests/test_package_original_review_systems.py",
            "tests/test_package_owner_decision.py",
            "tests/test_package_report_capacity.py",
            "tests/test_package_representations.py",
            "tests/test_package_semantic_ownership.py",
            "tests/test_package_semantic_ownership_added_kind_behavioral.py",
            "tests/test_package_semantic_ownership_domains.py",
            "tests/test_package_semantic_ownership_experiments.py",
            "tests/test_package_semantic_ownership_hardware_interop.py",
            "tests/test_package_semantic_ownership_normative_assets.py",
            "tests/test_package_semantic_ownership_public_cli.py",
            "tests/test_package_semantic_ownership_python_apps.py",
            "tests/test_package_semantic_ownership_repository_assets.py",
            "tests/test_package_semantic_ownership_scripts_examples.py",
            "tests/test_package_semantic_ownership_tests_fixtures.py",
            "tests/test_package_semantic_review_admission.py",
            "tests/test_package_semantic_review_commands.py",
            "tests/test_package_semantic_review_core.py",
            "tests/test_package_semantic_review_hardware_cli.py",
            "tests/test_package_semantic_review_operations.py",
            "tests/test_package_semantic_review_package_object.py",
            "tests/test_package_semantic_review_partitions.py",
            "tests/test_package_semantic_review_records.py",
            "tests/test_package_semantic_review_scripts.py",
            "tests/test_package_semantic_review_subjects.py",
            "tests/test_package_semantic_review_verifier.py",
            "tests/test_package_source_contracts.py",
            "tests/test_polish0_interface_adversary.py",
            "tests/test_source_import_resolution.py",
            "tests/test_specification_digest_resolution.py",
            "tests/test_untraversable.py",
            "tests/test_untraversable_graph_binding.py",
            "tests/test_v6_package_admission_polish.py",
            "tests/test_v6_package_distribution_and_admission.py",
            "tests/test_windows_anchored_adapter_integration.py",
            "tests/test_windows_anchored_member.py",
        ),
        (
            "Repository admission, namespace, manifest, source-binding, and package semantic "
            "ownership regression mechanisms."
        ),
        (
            "These tests exercise parser exchanges, current-file censuses, manifest mutations, "
            "capacity precedence, and fail-closed applicability decisions; generic test ownership "
            "would hide their admission and mutation boundary."
        ),
        (
            "Tests may spawn isolated parsers and mutate temporary manifests, but do not admit "
            "the operator repository, validate an installed root, or prove every language and "
            "dynamic surface. A retained test definition or passing pytest execution is bounded "
            "regression evidence only. It does not establish whole-package conformance, "
            "production effects, physical actuation, real-money authority, a MARKET, or BOT, "
            "ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-polish-regressions",
        "VERIFIER",
        (
            "tests/test_build_self_polish_native_cases.py",
            "tests/test_build_self_polish_tier1_ledger.py",
            "tests/test_layer4.py",
            "tests/test_meta_tier_architecture.py",
            "tests/test_meta_tier_cardinality.py",
            "tests/test_meta_tier_notation.py",
            "tests/test_package_graph_fresh_adapter_adversarial.py",
            "tests/test_package_polish.py",
            "tests/test_package_polish_capacity_invariants.py",
            "tests/test_package_polish_coordinate_commitments.py",
            "tests/test_package_polish_cumulative_graph.py",
            "tests/test_package_polish_cumulative_schema.py",
            "tests/test_package_polish_human_output.py",
            "tests/test_package_polish_refresh_binding.py",
            "tests/test_package_self_polish.py",
            "tests/test_package_self_polish_recheck.py",
            "tests/test_package_semantic_review_polish.py",
            "tests/test_package_semantic_review_self_polish.py",
            "tests/test_polish.py",
            "tests/test_polish_authority_recheck_availability.py",
            "tests/test_polish_capacity.py",
            "tests/test_polish_digest_binds_executed_code.py",
            "tests/test_polish_findings.py",
            "tests/test_polish_inventory.py",
            "tests/test_polish_inventory_authority.py",
            "tests/test_polish_invocation_ledger.py",
            "tests/test_polish_preparation_cli.py",
            "tests/test_polish_prepare_input_reader.py",
            "tests/test_polish_public_authority.py",
            "tests/test_polish_public_authority_precrypto.py",
            "tests/test_polish_requirements.py",
            "tests/test_polish_requirements_admission_order.py",
            "tests/test_polish_requirements_capacity_precedence.py",
            "tests/test_polish_requirements_cli.py",
            "tests/test_polish_cli_extraction.py",
            "tests/test_polish_workflow.py",
            "tests/test_polish_workflow_replay.py",
            "tests/test_self_polish_application_authority.py",
            "tests/test_self_polish_cli_surface.py",
            "tests/test_self_polish_complete_denominator.py",
            "tests/test_self_polish_dynamics.py",
            "tests/test_self_polish_estate.py",
            "tests/test_self_polish_estate_authority.py",
            "tests/test_self_polish_estate_evidence.py",
            "tests/test_self_polish_estate_git_isolation.py",
            "tests/test_self_polish_evidence.py",
            "tests/test_self_polish_facet_reasons.py",
            "tests/test_self_polish_installed_binding.py",
            "tests/test_self_polish_native_extension_replay.py",
            "tests/test_self_polish_native_extensions.py",
            "tests/test_self_polish_native_full_candidate.py",
            "tests/test_self_polish_native_hyper_adapter.py",
            "tests/test_self_polish_native_replay.py",
            "tests/test_self_polish_native_tier3_cases.py",
            "tests/test_self_polish_native_tier4_cases.py",
            "tests/test_self_polish_native_tier5_cases.py",
            "tests/test_self_polish_native_tier6_cases.py",
            "tests/test_self_polish_native_tier7_cases.py",
            "tests/test_self_polish_native_tier8_cases.py",
            "tests/test_self_polish_native_tier9_cases.py",
            "tests/test_self_polish_statics.py",
            "tests/test_self_polish_tiers.py",
            "tests/test_ten_tier_native_selection.py",
            "tests/test_tier_progression.py",
            "tests/test_tier_zero.py",
            "tests/test_tier_zero_manifest.py",
            "tests/test_tier_zero_profile.py",
            "tests/test_tier_zero_reasons.py",
            "tests/test_vstd4_depth.py",
            "tests/test_vstd_gate.py",
        ),
        "Tier progression, package polish, self-polish, capacity, authority, and replay regression mechanisms.",
        (
            "These tests control bounded polish invocations and inspect exact gate outcomes, "
            "ledgers, retained cases, and failure precedence, so their orchestration and "
            "observation roles must remain explicit."
        ),
        (
            "A retained or passing polish test is not a package-wide polish receipt, independent "
            "application authority, release decision, or proof that the root graph currently "
            "passes tiers zero through three. A retained test definition or passing pytest "
            "execution is bounded regression evidence only. It does not establish whole-package "
            "conformance, production effects, physical actuation, real-money authority, a MARKET, "
            "or BOT, ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-current-object-regressions",
        "VERIFIER",
        (
            "tests/test_agency_surface.py",
            "tests/test_current_actor_closure.py",
            "tests/test_current_actor_decision_record.py",
            "tests/test_current_actor_replay.py",
            "tests/test_current_agent_ceiling_fixity.py",
            "tests/test_current_agent_checks.py",
            "tests/test_current_arch_resolution.py",
            "tests/test_current_arch_schedule.py",
            "tests/test_current_arch_shapes.py",
            "tests/test_current_bench_attempts.py",
            "tests/test_current_bench_checks.py",
            "tests/test_current_bot_checks.py",
            "tests/test_current_bot_inherited_ceiling.py",
            "tests/test_current_certificate_batch_2_integration.py",
            "tests/test_current_certificate_batch_integration.py",
            "tests/test_current_certificate_emission.py",
            "tests/test_current_collective_closure.py",
            "tests/test_current_collective_constraints.py",
            "tests/test_current_collective_lifecycle.py",
            "tests/test_current_consent_checks.py",
            "tests/test_current_data_checks.py",
            "tests/test_current_data_distribution.py",
            "tests/test_current_dependency_bindings.py",
            "tests/test_current_env_checks.py",
            "tests/test_current_env_configuration_surface.py",
            "tests/test_current_env_executable.py",
            "tests/test_current_env_pin_boundaries.py",
            "tests/test_current_env_pin_closure.py",
            "tests/test_current_env_pin_trace_oracles.py",
            "tests/test_current_event_closure.py",
            "tests/test_current_event_closure_oracle.py",
            "tests/test_current_event_closure_registration.py",
            "tests/test_current_event_dispatch.py",
            "tests/test_current_event_prerequisites.py",
            "tests/test_current_graph_closure.py",
            "tests/test_current_graph_lineage.py",
            "tests/test_current_graph_order.py",
            "tests/test_current_graph_order_addendum.py",
            "tests/test_current_graph_statics.py",
            "tests/test_current_hardware_capacity.py",
            "tests/test_current_hardware_inventory.py",
            "tests/test_current_hardware_inventory_closure.py",
            "tests/test_current_hardware_measurements.py",
            "tests/test_current_hardware_oracles.py",
            "tests/test_current_hardware_substrate_observations.py",
            "tests/test_current_hardware_topology.py",
            "tests/test_current_harness_checks.py",
            "tests/test_current_harness_gap_boundary.py",
            "tests/test_current_human_no_composition.py",
            "tests/test_current_human_population_declaration.py",
            "tests/test_current_human_template_irreversibility.py",
            "tests/test_current_hyper_closure.py",
            "tests/test_current_hyper_composed_ceiling.py",
            "tests/test_current_hyper_unknown_absorption.py",
            "tests/test_current_identity_lifecycle.py",
            "tests/test_current_identity_presentation.py",
            "tests/test_current_identity_scope.py",
            "tests/test_current_independence_checks.py",
            "tests/test_current_independence_route_integration.py",
            "tests/test_current_kind_governance.py",
            "tests/test_current_kind_governance_routes.py",
            "tests/test_current_model_artifact_bytes.py",
            "tests/test_current_model_checks.py",
            "tests/test_current_model_data_citation.py",
            "tests/test_current_model_data_lineage.py",
            "tests/test_current_model_hardware_observation.py",
            "tests/test_current_model_oracles.py",
            "tests/test_current_model_quantization.py",
            "tests/test_current_model_train_citation.py",
            "tests/test_current_object_address_closure.py",
            "tests/test_current_object_catalog_order.py",
            "tests/test_current_object_cli_memory.py",
            "tests/test_current_object_facets.py",
            "tests/test_current_object_governance.py",
            "tests/test_current_object_grounding.py",
            "tests/test_current_object_grounding_siblings.py",
            "tests/test_current_object_lineage.py",
            "tests/test_current_object_routes.py",
            "tests/test_current_object_statics.py",
            "tests/test_current_object_unavailability.py",
            "tests/test_current_owner_eligibility.py",
            "tests/test_current_owner_forks.py",
            "tests/test_current_owner_replay.py",
            "tests/test_current_privacy_checks.py",
            "tests/test_current_receipt_authenticity.py",
            "tests/test_current_receipt_chain.py",
            "tests/test_current_receipt_integration.py",
            "tests/test_current_receipt_prerequisite_closure.py",
            "tests/test_current_receipt_statics.py",
            "tests/test_current_receipt_validation_replay.py",
            "tests/test_current_role_closure.py",
            "tests/test_current_role_constraints.py",
            "tests/test_current_role_lifecycle.py",
            "tests/test_current_sim_checker.py",
            "tests/test_current_sim_cross_route_scope.py",
            "tests/test_current_sim_dynamics.py",
            "tests/test_current_sim_external_law.py",
            "tests/test_current_sim_internal_state.py",
            "tests/test_current_sim_perspective.py",
            "tests/test_current_sim_resource.py",
            "tests/test_current_sim_response.py",
            "tests/test_current_sim_shard_coverage.py",
            "tests/test_current_sim_shard_relations.py",
            "tests/test_current_sim_shard_signatures.py",
            "tests/test_current_sim_surface_partition.py",
            "tests/test_current_space_closure.py",
            "tests/test_current_space_layout.py",
            "tests/test_current_space_migration.py",
            "tests/test_current_subject_security.py",
            "tests/test_current_subject_security_routes.py",
            "tests/test_current_time_closure.py",
            "tests/test_current_time_order.py",
            "tests/test_current_time_strict.py",
            "tests/test_current_time_strict_oracle.py",
            "tests/test_current_time_strict_registration.py",
            "tests/test_current_token_checks.py",
            "tests/test_current_token_integration.py",
            "tests/test_current_train_accumulation.py",
            "tests/test_current_train_checks.py",
            "tests/test_current_train_data_bridge.py",
            "tests/test_current_typed_facets.py",
            "tests/test_current_verifier_composed_security.py",
            "tests/test_current_verifier_coverage_closure.py",
            "tests/test_current_verifier_run_constraints.py",
        ),
        (
            "Current-object routes, facets, closures, certificates, replay, ordering, governance, "
            "and consequence regression mechanisms."
        ),
        (
            "The suite invokes and observes the distinct current obligations of the original "
            "object kinds; one generic test object would erase per-route protocol, control, "
            "evidence, and failure boundaries."
        ),
        (
            "Testing a HUMAN, MODEL, SIM, BOT, HARDWARE, or another represented subject does not "
            "turn the test suite into that subject and does not transfer its evidence or "
            "consequences to the suite. A retained test definition or passing pytest execution is "
            "bounded regression evidence only. It does not establish whole-package conformance, "
            "production effects, physical actuation, real-money authority, a MARKET, or BOT, "
            "ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-simulation-model-regressions",
        "VERIFIER",
        (
            "tests/test_authenticated_corrigibility_stop.py",
            "tests/test_bot_check_selection.py",
            "tests/test_corrigibility_contracts.py",
            "tests/test_corrigibility_control_boundaries.py",
            "tests/test_corrigibility_ontology.py",
            "tests/test_corrigible_emission_session.py",
            "tests/test_fresh_sim_resource.py",
            "tests/test_logits_constraint_kernel.py",
            "tests/test_model_data_lineage_selection.py",
            "tests/test_sim_check_selection.py",
            "tests/test_sim_dynamics_boundaries.py",
            "tests/test_sim_dynamics_oracles.py",
            "tests/test_sim_internal_core_oracles.py",
            "tests/test_sim_internal_polynomial_oracles.py",
            "tests/test_sim_internal_selection_oracles.py",
            "tests/test_sim_isolation.py",
            "tests/test_sim_isolation_unknown_refutations.py",
            "tests/test_sim_response_boundaries.py",
            "tests/test_sim_response_oracles.py",
            "tests/test_simulation_constructor_guards.py",
            "tests/test_train_control.py",
            "tests/test_train_data_bridge_relations.py",
            "tests/test_vstd200_benchmark.py",
            "tests/test_vstd200_data.py",
            "tests/test_vstd200_environment.py",
            "tests/test_vstd200_graph.py",
            "tests/test_vstd200_hyperparameters.py",
            "tests/test_vstd200_model.py",
            "tests/test_vstd200_release_boundaries.py",
            "tests/test_vstd200_reward_lock.py",
            "tests/test_vstd200_simulation.py",
            "tests/test_vstd200_tesla_cage.py",
            "tests/test_vstd200_time_comb.py",
        ),
        "SIM, MODEL, AGENT, BOT, training, dynamics, response, isolation, and corrigibility regression mechanisms.",
        (
            "These tests drive simulated state and bounded model or agent control paths and "
            "observe their declared limits; those software effects and simulation boundaries need "
            "an exact verifier owner."
        ),
        (
            "A simulated or monkeypatched effect stays software-local unless external-world "
            "evidence proves otherwise. These test definitions are not SIMs, BOTs, ROBOTs, "
            "FINBOTs, trained MODEL artifacts, or evidence of isolation or corrigibility. A "
            "retained test definition or passing pytest execution is bounded regression evidence "
            "only. It does not establish whole-package conformance, production effects, physical "
            "actuation, real-money authority, a MARKET, or BOT, ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-hardware-environment-regressions",
        "VERIFIER",
        (
            "tests/test_diode_emulator.py",
            "tests/test_domain_hardware.py",
            "tests/test_env_checks_projection.py",
            "tests/test_env_resource_counts.py",
            "tests/test_env_selection_oracles.py",
            "tests/test_environment_completion.py",
            "tests/test_environment_contracts.py",
            "tests/test_environment_specimens.py",
            "tests/test_hardware_cli_extraction.py",
            "tests/test_language_runner_extension_outcomes.py",
            "tests/test_language_runners.py",
            "tests/test_native_language_extensions.py",
            "tests/test_native_language_extensions_batch_three.py",
            "tests/test_native_language_extensions_batch_two.py",
            "tests/test_native_language_package_dispatch_batch_three.py",
            "tests/test_native_language_package_dispatch_batch_two.py",
            "tests/test_native_language_top24_adapters.py",
            "tests/test_native_reader_resource_availability.py",
            "tests/test_openshell_extension.py",
            "tests/test_runner_adversarial.py",
            "tests/test_runner_extensions.py",
            "tests/test_scitt_native_runner.py",
            "tests/test_windows_job_termination.py",
        ),
        (
            "Hardware observation, execution environment, language runner, optional sandbox, "
            "emulator, and process termination regression mechanisms."
        ),
        (
            "The tests distinguish retained declarations, live observation adapters, emulation, "
            "optional dependencies, and child-process control, all of which have different "
            "failure and authority consequences from pure assertions."
        ),
        (
            "Emulators, mocks, discovery records, and optional sandbox tests command no physical "
            "device. They do not prove hardware identity, calibration, OpenShell confinement, "
            "ROBOT control, or production environment qualification. A retained test definition "
            "or passing pytest execution is bounded regression evidence only. It does not "
            "establish whole-package conformance, production effects, physical actuation, "
            "real-money authority, a MARKET, or BOT, ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-artifact-evidence-regressions",
        "VERIFIER",
        (
            "tests/test_artifact_control.py",
            "tests/test_artifact_network.py",
            "tests/test_artifact_network_wire_corpus.py",
            "tests/test_artifact_publish.py",
            "tests/test_assurance_compound_group_refusal.py",
            "tests/test_assurance_flow_invariants.py",
            "tests/test_assurance_graph_mutation_boundaries.py",
            "tests/test_certificate_dag_missing_support_precedence.py",
            "tests/test_certificate_dag_native_subjects.py",
            "tests/test_certifier_descriptor_contract.py",
            "tests/test_claim_garden_publish.py",
            "tests/test_claim_garden_publish_contract.py",
            "tests/test_component_index.py",
            "tests/test_component_index_build.py",
            "tests/test_component_index_r31_inventory.py",
            "tests/test_component_index_reviewed_increment.py",
            "tests/test_component_package_schema.py",
            "tests/test_component_package_storage.py",
            "tests/test_component_package_versions.py",
            "tests/test_core_receipt_integrity.py",
            "tests/test_domain_bound_certificate_guards.py",
            "tests/test_evidence_bound_assurance.py",
            "tests/test_finite_issuer_receipt_replay_binding.py",
            "tests/test_finite_issuer_retained_bindings.py",
            "tests/test_finite_record_issuance.py",
            "tests/test_flagship_demo.py",
            "tests/test_formation_catalog.py",
            "tests/test_formation_cross_language_corpus.py",
            "tests/test_formation_mechanism.py",
            "tests/test_formation_receipt.py",
            "tests/test_formation_receipt_resources.py",
            "tests/test_formation_resources.py",
            "tests/test_formation_storage.py",
            "tests/test_gdc_certificate.py",
            "tests/test_issuer_prerequisite_refutations.py",
            "tests/test_proposition_transfer.py",
            "tests/test_proposition_transfer_catalog.py",
            "tests/test_proposition_transfer_fixture.py",
            "tests/test_reference_component_catalog.py",
            "tests/test_reference_package_capacity.py",
            "tests/test_refutation_certificate.py",
            "tests/test_retained_selection.py",
            "tests/test_scitt_catalog_entry.py",
            "tests/test_scitt_crypto_example.py",
            "tests/test_scitt_derived_subjects.py",
            "tests/test_scitt_distribution.py",
            "tests/test_scitt_entry_planning.py",
            "tests/test_scitt_evidence_profiles.py",
            "tests/test_scitt_fetch.py",
            "tests/test_scitt_interop.py",
            "tests/test_scitt_package_comparison.py",
            "tests/test_scitt_python_requirements.py",
            "tests/test_scitt_reconstruction.py",
            "tests/test_scitt_statement_mechanism.py",
            "tests/test_session_binding_snapshots.py",
            "tests/test_silo_composition_fixture.py",
            "tests/test_silo_composition_receipt.py",
            "tests/test_stored_component_index_cli.py",
            "tests/test_stored_package_cli.py",
            "tests/test_stored_package_example.py",
            "tests/test_typed_formation.py",
            "tests/test_vstd3_artifact_tracers.py",
            "tests/test_vstd3_provenance.py",
            "tests/test_zizk_artifact_first.py",
            "tests/test_zizk_tokens.py",
        ),
        (
            "Artifact, certificate, receipt, provenance, formation, component, issuer, SCITT, and "
            "retained-evidence regression mechanisms."
        ),
        (
            "These tests create and mutate bounded records, signatures, stores, and replay inputs "
            "while checking binding and failure behavior, so observation, protocol, transaction, "
            "and control roles must be explicit."
        ),
        (
            "Synthetic keys, local stores, receipt corpora, claimed assets, ledger fixtures, and "
            "publication mocks establish no production identity, custody, backing, finality, "
            "financial value, or release authority. A retained test definition or passing pytest "
            "execution is bounded regression evidence only. It does not establish whole-package "
            "conformance, production effects, physical actuation, real-money authority, a MARKET, "
            "or BOT, ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-governance-authority-regressions",
        "VERIFIER",
        (
            "tests/test_accountability_adapter_integration.py",
            "tests/test_actor_adversarial_slippage.py",
            "tests/test_application_authority_binding.py",
            "tests/test_application_context_capacity.py",
            "tests/test_application_dependency_inventory.py",
            "tests/test_application_requirements.py",
            "tests/test_authority_binding_corrections.py",
            "tests/test_authority_binding_review_repaired.py",
            "tests/test_authority_composition.py",
            "tests/test_authority_composition_catalog.py",
            "tests/test_authority_pure_claim_preflight.py",
            "tests/test_consent_capabilities.py",
            "tests/test_consent_level7.py",
            "tests/test_consent_stages.py",
            "tests/test_controlled_current_emission.py",
            "tests/test_controlled_emission.py",
            "tests/test_core_application_scope_receipts.py",
            "tests/test_governance_integration_counterexamples.py",
            "tests/test_governance_level8.py",
            "tests/test_guilt_composition.py",
            "tests/test_human_identity_domains.py",
            "tests/test_identity_lifecycle_replay.py",
            "tests/test_identity_occupancy_contract.py",
            "tests/test_identity_scope_internal_capacity.py",
            "tests/test_independence_projection.py",
            "tests/test_issuer_authority_cancellation.py",
            "tests/test_package_policy_enforcement_execution.py",
            "tests/test_package_policy_enforcement_routes.py",
            "tests/test_package_policy_route_integration.py",
            "tests/test_permission_slot.py",
            "tests/test_policy_notification.py",
            "tests/test_policy_decision_evidence.py",
            "tests/test_privacy_admission.py",
            "tests/test_privacy_boundaries.py",
            "tests/test_privacy_engine.py",
            "tests/test_privacy_native_outcome_preservation.py",
            "tests/test_privacy_replay.py",
            "tests/test_provenance_privacy.py",
            "tests/test_role_collective_domains.py",
            "tests/test_runtime_authority_correspondence.py",
        ),
        (
            "Authority, consent, governance, identity, accountability, privacy, permission, and "
            "controlled-emission regression mechanisms."
        ),
        (
            "These tests select and exercise policy decisions, actor scopes, callbacks, "
            "disclosure paths, and refusal cases; their authority and effect boundaries would be "
            "lost under generic test ownership."
        ),
        (
            "Test actors, approvals, signatures, callbacks, and policies are synthetic or locally "
            "bounded and confer no human, legal, organizational, release, physical, or financial "
            "authority outside the tested proposition. A retained test definition or passing "
            "pytest execution is bounded regression evidence only. It does not establish "
            "whole-package conformance, production effects, physical actuation, real-money "
            "authority, a MARKET, or BOT, ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-release-publication-regressions",
        "VERIFIER",
        (
            "tests/test_agents_release_checks.py",
            "tests/test_application_release.py",
            "tests/test_checkout_cleanliness.py",
            "tests/test_ci_coordinate.py",
            "tests/test_collected_test_ids_public_safe.py",
            "tests/test_core_release_private.py",
            "tests/test_docs_portal.py",
            "tests/test_external_links.py",
            "tests/test_gate_public_paths_contract.py",
            "tests/test_gated_publish.py",
            "tests/test_merge_group_policy.py",
            "tests/test_pages_deployment.py",
            "tests/test_platform_comparison.py",
            "tests/test_platform_component_contracts.py",
            "tests/test_platform_release_evidence.py",
            "tests/test_pr_description_adversarial.py",
            "tests/test_pr_description_changed.py",
            "tests/test_pr_description_gate.py",
            "tests/test_pr_description_protected_head.py",
            "tests/test_pr_description_push_revision.py",
            "tests/test_pr_description_working_tree_gate.py",
            "tests/test_pr_lifecycle_workflows.py",
            "tests/test_pr_policy.py",
            "tests/test_presentation_surface.py",
            "tests/test_public_api.py",
            "tests/test_public_boundary_short_drive.py",
            "tests/test_public_checkability.py",
            "tests/test_public_cli.py",
            "tests/test_public_consent.py",
            "tests/test_public_data.py",
            "tests/test_public_estate_sync.py",
            "tests/test_public_scan_boundaries.py",
            "tests/test_public_test_evidence.py",
            "tests/test_release_artifacts.py",
            "tests/test_release_boundary_exception_contract.py",
            "tests/test_release_boundary_path_forms.py",
            "tests/test_release_selected_text_contract.py",
            "tests/test_release_source_binding.py",
        ),
        (
            "Release, pull-request, continuous-integration, documentation deployment, public "
            "boundary, and publication regression mechanisms."
        ),
        (
            "The suite invokes local builders and platform-shaped adapters and checks source, "
            "artifact, workflow, and disclosure gates, requiring explicit control and transaction "
            "boundaries."
        ),
        (
            "Local artifacts, mocked platform state, retained reports, and passing policy checks "
            "do not merge, publish, deploy, upload, tag, attest hosted state, or grant release "
            "authority. A retained test definition or passing pytest execution is bounded "
            "regression evidence only. It does not establish whole-package conformance, "
            "production effects, physical actuation, real-money authority, a MARKET, or BOT, "
            "ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-prdel-regressions",
        "VERIFIER",
        (
            "tests/test_prdel.py",
            "tests/test_prdel_changed_reachability.py",
            "tests/test_prdel_cli.py",
            "tests/test_prdel_coverage.py",
            "tests/test_prdel_frontier_redefinition.py",
            "tests/test_prdel_graph.py",
            "tests/test_prdel_graph_budget.py",
            "tests/test_prdel_graph_source_bound.py",
            "tests/test_prdel_graph_variadic_annotations.py",
            "tests/test_prdel_large_window.py",
            "tests/test_prdel_r2_sdist_contents.py",
            "tests/test_prdel_rules.py",
            "tests/test_prdel_shard_index.py",
            "tests/test_prdel_shards.py",
            "tests/test_prdel_v2_cli_overlay.py",
            "tests/test_prdel_v2_evidence_replay.py",
            "tests/test_prdel_v2_native.py",
            "tests/test_prdel_v2_selection.py",
            "tests/test_prdel_v2_selection_r2.py",
            "tests/test_prdel_v2_shards.py",
            "tests/test_private_prdel_schema_admission.py",
        ),
        (
            "Pull Request Domain Explanation Language graph, shard, coverage, source-selection, "
            "command, and replay regression mechanisms."
        ),
        (
            "PRDEL tests control bounded graph construction, source readers, shard protocols, and "
            "candidate selection and inspect their refusal and capacity behavior; these are "
            "consequential protocol operations."
        ),
        (
            "A test candidate or passing PRDEL check does not describe all current source, select "
            "a release description, establish platform provenance, approve a pull request, merge, "
            "or publish. A retained test definition or passing pytest execution is bounded "
            "regression evidence only. It does not establish whole-package conformance, "
            "production effects, physical actuation, real-money authority, a MARKET, or BOT, "
            "ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-security-privacy-regressions",
        "VERIFIER",
        (
            "tests/test_core_security9_accounting.py",
            "tests/test_dangerous_pathway_security.py",
            "tests/test_ed25519_admission.py",
            "tests/test_secret_gate.py",
            "tests/test_secret_gate_falsifiers.py",
            "tests/test_security_cli.py",
            "tests/test_subject_security_disclosure_guard.py",
            "tests/test_subject_security_native_kind_guard.py",
        ),
        (
            "Security route, secret-gate, signature admission, dangerous-pathway, "
            "disclosure-guard, and privacy regression mechanisms."
        ),
        (
            "These tests drive security-sensitive readers, gates, signatures, and refusal paths "
            "and observe bounded outcomes, so their control, protocol, and transaction "
            "consequences require a dedicated owner."
        ),
        (
            "Synthetic secrets, keys, attack cases, and passing guards do not prove system "
            "security, confidentiality, authorization, sandboxing, absence of vulnerabilities, or "
            "safe external operation. A retained test definition or passing pytest execution is "
            "bounded regression evidence only. It does not establish whole-package conformance, "
            "production effects, physical actuation, real-money authority, a MARKET, or BOT, "
            "ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-graph-composition-regressions",
        "VERIFIER",
        (
            "tests/test_arch_shape_oracles.py",
            "tests/test_bench_checks_projection.py",
            "tests/test_bounded_completeness.py",
            "tests/test_build_monograph.py",
            "tests/test_composition_qualification.py",
            "tests/test_composition_qualification_catalog.py",
            "tests/test_concepts_precedent_map.py",
            "tests/test_core_obligation_union.py",
            "tests/test_data_checks_projection.py",
            "tests/test_data_graph_facet_derivation.py",
            "tests/test_domain_actor.py",
            "tests/test_domain_grounding.py",
            "tests/test_domain_implementation_binding.py",
            "tests/test_domain_nested_recheck.py",
            "tests/test_domain_obligations.py",
            "tests/test_domain_owner.py",
            "tests/test_domain_statics_and_mainstays.py",
            "tests/test_explanation_projection.py",
            "tests/test_geometry_conflicts.py",
            "tests/test_geometry_constraints.py",
            "tests/test_geometry_constraints_example.py",
            "tests/test_geometry_io.py",
            "tests/test_global_cycle_assessment.py",
            "tests/test_graph_closure_oracles.py",
            "tests/test_graph_level.py",
            "tests/test_graph_lineage_relation_oracle.py",
            "tests/test_graph_obligations.py",
            "tests/test_graph_order_oracles.py",
            "tests/test_graph_statics_oracles.py",
            "tests/test_graph_topology.py",
            "tests/test_graph_topology_integration.py",
            "tests/test_grounded_certification.py",
            "tests/test_interoperability_catalog.py",
            "tests/test_interoperability_compositions.py",
            "tests/test_interoperability_planning_example.py",
            "tests/test_mainstay_carriers.py",
            "tests/test_mainstay_certification.py",
            "tests/test_mechanism_catalog.py",
            "tests/test_obligation_topological_order.py",
            "tests/test_package_protocol_dependency_relation.py",
            "tests/test_relation_boundary.py",
            "tests/test_reviewed_conflict_lane_refusals.py",
            "tests/test_reviewed_singleton_projections.py",
            "tests/test_reviewed_singleton_projections_batch04_06.py",
            "tests/test_spacetime_context_extension.py",
            "tests/test_token_checks_projection.py",
            "tests/test_token_statics.py",
            "tests/test_typed_facets_projection.py",
            "tests/test_union_composition_repair.py",
            "tests/test_verification_geometry.py",
            "tests/test_verifier_bootstrap.py",
            "tests/test_verifier_catalog_admission.py",
            "tests/test_verifier_domain.py",
            "tests/test_verifier_execution.py",
            "tests/test_verifier_grounding.py",
            "tests/test_verifier_replacement.py",
        ),
        (
            "Graph, geometry, relation, composition, architecture, domain, typed-formation, and "
            "verifier closure regression mechanisms."
        ),
        (
            "These tests construct and traverse bounded dependency structures, invoke checkers, "
            "and inspect order, completeness, and conflict outcomes; their topology and protocol "
            "boundaries are not generic test behavior."
        ),
        (
            "Finite graph and geometry cases are examples and regression oracles, not "
            "mathematical proofs of unrestricted completeness, global acyclicity, domain truth, "
            "or whole-system verification. A retained test definition or passing pytest execution "
            "is bounded regression evidence only. It does not establish whole-package "
            "conformance, production effects, physical actuation, real-money authority, a MARKET, "
            "or BOT, ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-runtime-execution-regressions",
        "VERIFIER",
        (
            "tests/test_accessibility_cli.py",
            "tests/test_added_kind_behavioral_mechanisms.py",
            "tests/test_added_kind_instance_evidence.py",
            "tests/test_added_kind_package_route_integration.py",
            "tests/test_certification_native_cli.py",
            "tests/test_cli_clearance_wiring.py",
            "tests/test_cli_clearance_workflow.py",
            "tests/test_control_surface.py",
            "tests/test_core_full_gate_replay.py",
            "tests/test_deriver_self_status.py",
            "tests/test_execution_readiness.py",
            "tests/test_experimental_workflow_cli.py",
            "tests/test_experimental_workflow_profile.py",
            "tests/test_gate_fail_closed.py",
            "tests/test_gate_memory_fail_closed.py",
            "tests/test_gate_paths_link_target.py",
            "tests/test_gate_pipeline.py",
            "tests/test_gate_selector_siblings.py",
            "tests/test_gate_text_coverage.py",
            "tests/test_gate_workflows.py",
            "tests/test_generic_run.py",
            "tests/test_harness_capture_integrity.py",
            "tests/test_independent_checker.py",
            "tests/test_inventory.py",
            "tests/test_local_ledger_contract_controls.py",
            "tests/test_native10_replacement_selection.py",
            "tests/test_native_child_capacity_fail_precedence.py",
            "tests/test_native_child_link_precedence.py",
            "tests/test_native_child_links.py",
            "tests/test_native_operation_cli.py",
            "tests/test_native_operation_contracts.py",
            "tests/test_package_asset_execution.py",
            "tests/test_package_asset_tier0_execution.py",
            "tests/test_package_checker_source_binding.py",
            "tests/test_package_emulator_control_execution.py",
            "tests/test_package_execution_observation.py",
            "tests/test_package_execution_owned_process_tree.py",
            "tests/test_package_execution_roles.py",
            "tests/test_package_ledger_execution.py",
            "tests/test_package_measurement_execution.py",
            "tests/test_package_policy_execution.py",
            "tests/test_package_protocol_execution.py",
            "tests/test_package_subject_binding.py",
            "tests/test_package_transaction_execution.py",
            "tests/test_preflight.py",
            "tests/test_preflight_fail_closed.py",
            "tests/test_preflight_outcomes.py",
            "tests/test_quality_checks.py",
            "tests/test_registration_bookkeeping_controls.py",
            "tests/test_run_process_observation.py",
            "tests/test_run_owned_process_tree.py",
            "tests/test_selected_execution.py",
            "tests/test_selected_native_contexts.py",
            "tests/test_selected_package_execution.py",
            "tests/test_selected_validation_example.py",
            "tests/test_test_observation.py",
            "tests/test_test_skip_summary.py",
            "tests/test_validation_loop.py",
            "tests/test_validation_loop_example.py",
            "tests/test_vstd3_cli.py",
        ),
        (
            "Runtime command, gate, selected execution, native operation, validation-loop, "
            "preflight, inventory, and command-line regression mechanisms."
        ),
        (
            "These tests submit bounded calls and subprocess commands, mutate temporary state, "
            "and observe channels, limits, and failures, so control and effect roles cannot be "
            "omitted."
        ),
        (
            "Test-local process and filesystem effects do not establish production execution, "
            "isolation, durability, deployment, live external state, or semantic correctness "
            "beyond each asserted proposition. A retained test definition or passing pytest "
            "execution is bounded regression evidence only. It does not establish whole-package "
            "conformance, production effects, physical actuation, real-money authority, a MARKET, "
            "or BOT, ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
    ownership_spec(
        "vstd-test-packaging-compatibility-regressions",
        "VERIFIER",
        (
            "tests/test_data_distribution_alias.py",
            "tests/test_distribution_declaration_required.py",
            "tests/test_distribution_source_spec_binding.py",
            "tests/test_distribution_spec_path_safety.py",
            "tests/test_mandatory_test_dependencies.py",
            "tests/test_optional_dependency_collection.py",
            "tests/test_package_planning_readiness_contract.py",
            "tests/test_packaged_schema_key_uniqueness.py",
            "tests/test_packaged_specifications.py",
            "tests/test_portable_assessment_binding.py",
            "tests/test_pr_source_grounding.py",
            "tests/test_python_floor_syntax.py",
            "tests/test_registry_census_characterization.py",
            "tests/test_registry_iteration_order.py",
            "tests/test_source_grounding.py",
            "tests/test_translation_boundary.py",
            "tests/test_vstd3_backward_compatibility.py",
            "tests/test_vstd3_capabilities.py",
            "tests/test_vstd3_emulator.py",
            "tests/test_vstd3_schema.py",
            "tests/test_vstd_schemas.py",
            "tests/test_v5_package_distribution_and_admission.py",
        ),
        (
            "Distribution, schema, version, registry, source-grounding, interoperability, Python "
            "floor, and packaging regression mechanisms."
        ),
        (
            "The suite builds or inspects bounded package representations and compatibility "
            "surfaces under exact source and dependency assumptions, requiring explicit "
            "observation, protocol, and transaction ownership."
        ),
        (
            "A local wheel, source distribution, schema, registry census, or compatibility "
            "specimen does not establish installation on every platform, dependency availability, "
            "publication, adoption, or release qualification. A retained test definition or "
            "passing pytest execution is bounded regression evidence only. It does not establish "
            "whole-package conformance, production effects, physical actuation, real-money "
            "authority, a MARKET, or BOT, ROBOT, or FINBOT status."
        ),
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    ),
)


__all__ = ["SemanticOwnershipSpec", "TEST_FIXTURE_OWNERSHIP_SPECS"]

