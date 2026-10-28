"""Verifier Standard (VSTD) 234-slot applicability and objective inventory.

Acronyms: application programming interface (API); artificial intelligence (AI);
central processing unit (CPU); command-line interface (CLI);
Edwards-curve digital signature algorithm with a 255-bit field (Ed25519);
Coordinated Universal Time (UTC); graphics processing unit (GPU);
identifier (ID); JavaScript Object Notation (JSON);
National Institute of Standards and Technology (NIST);
Secure Hash Algorithm 256-bit (SHA-256); Simulation (SIM);
Software Bill of Materials (SBOM);
Supply Chain Integrity, Transparency, and Trust (SCITT);
Supply-chain Levels for Software Artifacts (SLSA);
Unicode Transformation Format, 8-bit (UTF-8); Verifier Standard (VSTD).

This module defines the complete retained 26-``ObjectKind`` by nine-tier native
inventory (234 slots) governed by META_TIERS.md, DOMAIN_OBLIGATIONS.md, and
POLISHED_ARTIFACTS.md. The installed extensible namespace separately admits 12
accumulating consequential roles, for 38 kinds in total; this native inventory
does not discharge their obligations. Under the Verifier Standard, every
retained native object requires explicit assessment across all nine positive
meta-tiers. Security is tier 9; Governance is tier 8. No slot may be waived
without independent admissible evidence. Missing mechanisms and certificates
remain explicit UNKNOWN gaps.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from verifier.core.namespace import MetaTier, ObjectCoordinate, ObjectKind
from verifier.domains.contracts import independence_checks, token_checks
from verifier.domains.contracts import role_constraints, collective_constraints
from verifier.domains.contracts import role_lifecycle, collective_lifecycle, arch_resolution
from verifier.domains.contracts import typed_facets, identity_scope, data_checks, env_checks, bench_checks, train_checks, model_checks, harness_checks, agent_checks, bot_checks, privacy_checks, hardware_inventory, time_order, space_layout, event_prerequisites, space_closure
from verifier.domains.contracts import subject_security, consent_checks, object_governance, hardware_capacity, hardware_topology, hardware_measurements, data_distribution, model_artifact_bytes, model_quantization
from verifier.domains.contracts import receipt_authenticity, model_hardware_observation, model_data_citation, model_train_citation, train_data_bridge, model_data_lineage, graph_statics, graph_closure
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
from verifier.domains.contracts import human_template_irreversibility
from verifier.domains.contracts import human_no_composition
from verifier.domains.contracts import human_population_declaration
from verifier.domains.contracts import owner_replay, owner_forks, owner_eligibility
from verifier.domains.contracts import role_closure
from verifier.domains.contracts import collective_closure
from verifier.domains.contracts import identity_lifecycle, identity_presentation
from verifier.domains.contracts import verifier_run_constraints
from verifier.domains.contracts import verifier_coverage_closure

SCHEMA_VERSION = "verifier-current-object-inventory-1"

GOVERNING_QUESTIONS: dict[MetaTier, str] = {
    MetaTier.FACETS: (
        "Which fundamental structural facets constitute this object?"
    ),
    MetaTier.DYNAMICS: (
        "Which transitions and interactions can its facets undergo?"
    ),
    MetaTier.STATICS: (
        "Which external constraints and invariants must hold?"
    ),
    MetaTier.CLOSURE: (
        "What exact evidence closes a bounded claim about it?"
    ),
    MetaTier.INDEPENDENCE: (
        "Which facets and categories must remain separate, and where does "
        "the proposition require a non-self-witnessing or independent check?"
    ),
    MetaTier.PRIVACY: (
        "What information may be observed or emitted, by whom, and under which bound?"
    ),
    MetaTier.CONSENT: (
        "Whose consent is required, to what action, in what scope and interval, "
        "and how is revocation checked?"
    ),
    MetaTier.GOVERNANCE: (
        "Which applicable governance decisions, laws or rules, and ethical or moral "
        "boundaries constrain this object; who has authority to select them; "
        "and how are they enforced and contested?"
    ),
    MetaTier.SECURITY: (
        "Against which explicitly bounded adversarial or failure conditions must "
        "this object's execution, evidence, information, availability or enforcement "
        "remain protected, and which trusted mechanism detects or refuses a violation?"
    ),
}

OBJECT_DESCRIPTIONS: dict[ObjectKind, str] = {
    ObjectKind.HUMAN: "Living person and human accountability termination root.",
    ObjectKind.ACTOR: "Accountable decision maker (HUMAN, AGENT, BOT) rooted in a responsible HUMAN.",
    ObjectKind.COLLECTIVE: "Organized group, graph of roles and member relations.",
    ObjectKind.ROLE: "Authority-bearing role class and occupancy boundary.",
    ObjectKind.IDENTITY: "Binding of a bearer ACTOR into an admitted ROLE class.",
    ObjectKind.OWNER: "Ownership relation linking an ACTOR to held OBJECTs and rights.",
    ObjectKind.HARDWARE: "Execution substrate, platform architecture, and devices.",
    ObjectKind.RECEIPT: "Portable bounded refutable evidence record linking subject and execution.",
    ObjectKind.OBJECT: "Foundational generic admitted computational or relational entity.",
    ObjectKind.GRAPH: "Collection of artifacts, vertices, edges, and lineage relations.",
    ObjectKind.SPACE: "Spatial execution, network coordinate, or storage domain.",
    ObjectKind.TIME: "Temporal interval, sequence, clock source, or epoch coordinate.",
    ObjectKind.EVENT: "Spatiotemporal occurrence binding TIME, SPACE, action, and payload.",
    ObjectKind.ENV: "Verifiable execution environment, dependencies, toolchain, and variables.",
    ObjectKind.DATA: "Dataset integrity, content bytes, partition, schema, and immutability.",
    ObjectKind.VERIFIER: "Independent checking program, mechanism identity, and execution rules.",
    ObjectKind.BENCH: "Evaluation benchmark binding VERIFIER and DATA for scoring.",
    ObjectKind.ARCH: "Computational model architecture, layer graph, and tensor shapes.",
    ObjectKind.TRAIN: "Training run combining DATA, EVENT, BENCH, ARCH, and optimization.",
    ObjectKind.HYPER: "Composite entity with directed operand dependencies and cone closure.",
    ObjectKind.MODEL: "Trained parameter weights, forward execution, and evaluation probes.",
    ObjectKind.HARNESS: "Execution scaffold, test harness wrapper, and instrumentation.",
    ObjectKind.AGENT: "Autonomous software execution entity with goals, memory, and tools.",
    ObjectKind.SIM: "Generative simulation environment with state partitions and virtual hardware.",
    ObjectKind.BOT: "Automated task executor confined within isolated SIM or designated envelope.",
    ObjectKind.TOKEN: "Cryptographic or computational token representing access, unit, or marker.",
}

MECHANIZED_12_POINT_BINDINGS: dict[str, dict[str, Any]] = {
    "SIM-4.4": {
        "exact_claim": sim_surface_partition.registration()["proposition"],
        "artifact_coordinate": sim_surface_partition.COORDINATE,
        "facet_examined": "Exact passing SIM-4.3 child, external finite state-partition map, aligned root/shard values and replayed root transition expressions.",
        "translation": "Selected canonical declarations to bijective field accounting, exact retained value identity and expression-digest attribution.",
        "checking_mechanism": "verifier.domains.contracts.sim_surface_partition.recheck_sim_surface_partition_certificate",
        "resulting_evidence": sim_surface_partition.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Conditional on the external finite declaration and selected child signature policy; no hidden runtime state, projections, physical truth, unretained states, historical execution, full tier conformance or authority.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-4.4 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected SIM/collection, child selections, external map, transition expressions, rows, policy, backend availability/version, installed checker or specification.",
        "resource_limits": {"max_certificate_bytes": 16777216,
            "max_selection_text_bytes": 1048576, "max_evidence_bytes": 8388608,
            "max_operations": 1000000, "max_items": 4096},
        "public_route_and_tests": "tests/test_current_sim_surface_partition.py::test_exact_finite_surface_and_transitions_replay_without_scope_promotion",
    },
    "SIM-4.3": {
        "exact_claim": sim_shard_signatures.registration()["proposition"],
        "artifact_coordinate": sim_shard_signatures.COORDINATE,
        "facet_examined": "Exact passing SIM-4.2 child and signatures on every retained row of externally required shards under externally pinned admitted public keys.",
        "translation": "Exact child, policy, subject, shard, step, time and state bytes to domain-separated Ed25519 signature verification.",
        "checking_mechanism": "verifier.domains.contracts.sim_shard_signatures.recheck_sim_shard_signatures_certificate",
        "resulting_evidence": sim_shard_signatures.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Selected key/message validity only; optional cryptography 50.0.0 backend; no unrequired shards, origin, key custody, live revocation, historical execution, backend correctness, complete closure tier or authority.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-4.3 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected SIM or collection, SIM-4.2 child, required shards, public keys, signature bytes, policy, backend availability/version, installed checker or current specification.",
        "resource_limits": {"max_certificate_bytes": 16777216,
            "max_selection_text_bytes": 1048576,
            "max_evidence_bytes": 8388608, "max_operations": 100000,
            "max_items": 4096, "max_signatures": 4096},
        "public_route_and_tests": "tests/test_current_sim_shard_signatures.py::test_exact_selected_shard_signatures_replay_without_authority_promotion",
    },
    "SIM-4.2": {
        "exact_claim": sim_shard_relations.registration()["proposition"],
        "artifact_coordinate": sim_shard_relations.COORDINATE,
        "facet_examined": "Exact passing SIM-4.1 child and externally selected finite relations over aligned retained per-shard rows.",
        "translation": "Selected relation expression bytes and child shard rows to bounded per-time native Boolean evaluation.",
        "checking_mechanism": "verifier.domains.contracts.sim_shard_relations.recheck_sim_shard_relations_certificate",
        "resulting_evidence": sim_shard_relations.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Selected finite relation list only; no unselected relations, dimensional validity, physical truth, historical execution, signatures, whole surface, complete closure tier or authority.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-4.2 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected SIM or collection, SIM-4.1 child, relation list, retained rows, policy, installed checker or current specification.",
        "resource_limits": {"max_certificate_bytes": 16777216,
            "max_selection_text_bytes": 1048576,
            "max_evidence_bytes": 8388608, "max_operations": 100000,
            "max_items": 4096},
        "public_route_and_tests": "tests/test_current_sim_shard_relations.py::test_two_shard_relation_replays_at_every_selected_time",
    },
    "SIM-4.1": {
        "exact_claim": sim_shard_coverage.registration()["proposition"],
        "artifact_coordinate": sim_shard_coverage.COORDINATE,
        "facet_examined": "Exact passing SIM-2.1 child trajectory, declared shard identifiers and retained per-shard finite state/time rows.",
        "translation": "Externally selected child and shard bytes to complete finite shard inventory and per-state time alignment.",
        "checking_mechanism": "verifier.domains.contracts.sim_shard_coverage.recheck_sim_shard_coverage_certificate",
        "resulting_evidence": sim_shard_coverage.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Selected finite shard declaration only; no undeclared shards, physical execution, cross-shard relations, signatures, whole simulated surface, complete closure tier or authority.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-4.1 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected SIM or collection, SIM-2.1 child, declared shard identifiers, retained rows, policy, installed checker or current specification.",
        "resource_limits": {"max_certificate_bytes": 16777216,
            "max_selection_text_bytes": 1048576,
            "max_evidence_bytes": 8388608, "max_operations": 100000,
            "max_items": 4096},
        "public_route_and_tests": "tests/test_current_sim_shard_coverage.py::test_selected_shards_cover_every_trajectory_time_without_tier_promotion",
    },
    "SIM-3.4": {
        "exact_claim": sim_external_law.registration()["proposition"],
        "artifact_coordinate": sim_external_law.COORDINATE,
        "facet_examined": "Exact selected SIM and distinct external-law OBJECT in a finite typed collection, with retained statement, applicability and source reference.",
        "translation": "Canonical selected collection and text bytes to a bounded SIM-to-law operand and statement comparison.",
        "checking_mechanism": "verifier.domains.contracts.sim_external_law.recheck_sim_external_law_certificate",
        "resulting_evidence": sim_external_law.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Represented external statement only; no law truth, dimensional correctness, applicability, source independence or authority, simulation correspondence, whole statics tier or publication.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-3.4 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected SIM or law record, collection, retained statement, applicability, source reference, policy or installed checker.",
        "resource_limits": {"max_certificate_bytes": 2097152, "max_selection_text_bytes": 1048576,
            "max_objects": 64, "max_operations": 20000,
            "max_composition_operations": 20000, "max_items": 4096,
            "max_evidence_bytes": 1048576, "max_payload_bytes": 1048576,
            "max_reference_bytes": 1048576},
        "public_route_and_tests": "tests/test_current_sim_external_law.py::test_public_route_rechecks_exact_external_law_statement",
    },
    "SIM-2.5": {
        "exact_claim": sim_perspective.registration()["proposition"],
        "artifact_coordinate": sim_perspective.COORDINATE,
        "facet_examined": "Exact passing SIM-2.3 child and its embedded SIM-2.1 micro trajectory, selected projection and aligned macro states.",
        "translation": "Child-bound finite projection expressions and macro values to bounded native per-state refinement comparison.",
        "checking_mechanism": "verifier.domains.contracts.sim_perspective.recheck_sim_perspective_certificate",
        "resulting_evidence": sim_perspective.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Selected homogeneous macro unit and absolute tolerance are external declarations; no independent macro source, dimensional proof, physical truth, historical execution, whole dynamics tier or publication authority.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-2.5 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed SIM-2.3/SIM-2.1 child, micro trajectory, projection, macro values, unit, tolerance, selected policy or installed interpreter.",
        "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
            "max_evidence_bytes": 8388608, "max_operations": 100000, "max_items": 4096},
        "public_route_and_tests": "tests/test_current_sim_perspective.py::test_public_route_rechecks_selected_bytes_and_retains_unknown_tier",
    },
    "SIM-2.3": {
        "exact_claim": sim_internal_state.registration()["proposition"],
        "artifact_coordinate": sim_internal_state.COORDINATE,
        "facet_examined": "Exact passing SIM-2.1 child, selected finite state trajectory, externally selected complete-channel declaration and hidden-change enumeration.",
        "translation": "Canonical selected channel expressions and trajectory bytes to exhaustive finite endpoint-hybrid sensitivity checks.",
        "checking_mechanism": "verifier.domains.contracts.sim_internal_state.recheck_sim_internal_state_certificate",
        "resulting_evidence": sim_internal_state.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Complete inventory is a selected model declaration, not physical omniscience; no undeclared channels, unselected states, privacy, whole dynamics tier or authority.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-2.3 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected SIM-2.1 child, observation program, channel-inventory declaration, expected hidden list, policy or installed checker.",
        "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
            "max_evidence_bytes": 8388608, "max_operations": 100000, "max_items": 4096,
            "max_endpoint_dimensions": 12},
        "public_route_and_tests": "tests/test_current_sim_internal_state.py::test_public_route_replays_selected_internal_state_without_tier_promotion",
    },
    "SIM-2.2": {
        "exact_claim": sim_response.registration()["proposition"],
        "artifact_coordinate": sim_response.COORDINATE,
        "facet_examined": "Exact passing SIM-2.1 child, selected action-aware model, retained actions, next states and model times.",
        "translation": "Canonical selected action and trajectory bytes to bounded actual-versus-baseline next-state replay.",
        "checking_mechanism": "verifier.domains.contracts.sim_response.recheck_sim_response_certificate",
        "resulting_evidence": sim_response.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Selected model counterfactual only; no historical causality, unselected intervention, physical time, hidden state, whole dynamics tier or authority.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-2.2 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected SIM-2.1 child, action program, actions, baseline, bounds, model time unit, delay, policy or installed checker.",
        "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
            "max_evidence_bytes": 8388608, "max_operations": 100000, "max_items": 4096},
        "public_route_and_tests": "tests/test_current_sim_response.py::test_current_public_route_rechecks_selected_response",
    },
    "SIM-2.1": {
        "exact_claim": sim_dynamics.registration()["proposition"],
        "artifact_coordinate": sim_dynamics.COORDINATE,
        "facet_examined": "Exact SIM record, finite typed collection, native transition program and retained state, entropy and time arrays.",
        "translation": "Canonical selected program and trajectory bytes to bounded native transition-expression replay.",
        "checking_mechanism": "verifier.domains.contracts.sim_dynamics.recheck_sim_dynamics_certificate",
        "resulting_evidence": sim_dynamics.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Trusted installed interpreter and externally selected finite trace; no historical execution, action/observation response, hidden state, resource usage, perspective, whole dynamics tier or authority.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-2.1 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected SIM, collection, artifact, inputs, expected counts, policy, native interpreter or current SIM specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_evidence_bytes": 4194304, "max_operations": 100000, "max_items": 4096},
        "public_route_and_tests": "tests/test_current_sim_dynamics.py::test_selected_trajectory_reexecutes_without_tier_promotion",
    },
    "ARCH-3.1": {
        "exact_claim": arch_shapes.registration()["proposition"],
        "artifact_coordinate": arch_shapes.COORDINATE,
        "facet_examined": "Exact ARCH record, finite typed collection and retained ordered tensor graph.",
        "translation": "Retained canonical graph bytes to bounded operator arity, ancestry and shape equations.",
        "checking_mechanism": "verifier.domains.contracts.arch_shapes.recheck_arch_shapes_certificate",
        "resulting_evidence": arch_shapes.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Four static operators only; no values, execution equivalence, source authenticity, whole ARCH statics tier or backend portability.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective ARCH-3.1 --represented-kind ARCH --request <req> --policy <pol>",
        "invalidating_dependencies": "Selected ARCH record, collection, retained graph, policy, native source or current ARCH specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_objects": 256, "max_operations": 100000, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_arch_shapes.py::test_public_route_and_polish_preserve_unknown_aggregate",
    },
    "EVENT-3.1": {
        "exact_claim": event_prerequisites.registration()["proposition"],
        "artifact_coordinate": "EVENT-3.1",
        "facet_examined": "Selected EVENT namespace record and finite reachable prerequisite cone with retained payload commitments.",
        "translation": "Externally selected finite typed collection and retained payload bytes to bounded declared-parent and digest checks.",
        "checking_mechanism": "verifier.domains.contracts.event_prerequisites.recheck_event_prerequisites_certificate",
        "resulting_evidence": event_prerequisites.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Declared sequence and payload only; no occurrence authenticity, physical causality, operand truth or whole EVENT statics tier.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective EVENT-3.1 --represented-kind EVENT --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected EVENT, collection, reachable payloads, policy, source or current EVENT specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_objects": 256, "max_operations": 100000, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_event_prerequisites.py::test_public_command_and_polish_keep_boundary",
    },
    "SPACE-3.1": {
        "exact_claim": space_layout.registration()["proposition"],
        "artifact_coordinate": "SPACE-3.1",
        "facet_examined": "Exact SPACE namespace record, logical byte extent and retained aligned half-open partitions.",
        "translation": "Externally selected finite collection and retained bytes to bounded native interval and alignment checks.",
        "checking_mechanism": "verifier.domains.contracts.space_layout.recheck_space_layout_certificate",
        "resulting_evidence": space_layout.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Logical byte addresses only; no host allocation, physical containment, isolation or whole SPACE statics tier.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SPACE-3.1 --represented-kind SPACE --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected SPACE record, collection, retained partitions, policy, source or current SPACE specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_objects": 256, "max_operations": 100000, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_space_layout.py::test_public_command_and_polish_keep_boundary",
    },
    "SPACE-4.1": {
        "exact_claim": space_closure.registration()["proposition"],
        "artifact_coordinate": space_closure.COORDINATE,
        "facet_examined": "Selected SPACE-3.1 child and complete finite logical byte extent.",
        "translation": "Replayed exact child certificate and retained partitions to gapless half-open byte coverage.",
        "checking_mechanism": "verifier.domains.contracts.space_closure.recheck_space_closure_certificate",
        "resulting_evidence": space_closure.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Logical byte extent only; no real allocation, physical non-leakage, isolation or whole SPACE closure tier.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SPACE-4.1 --represented-kind SPACE --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected child request, policy, certificate, retained partitions, source or current SPACE specifications.",
        "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
            "max_evidence_bytes": 8388608, "max_operations": 100000, "max_items": 4096},
        "public_route_and_tests": "tests/test_current_space_closure.py::test_public_route_and_inventory_select_only_this_closure_objective",
    },
    "EVENT-4.1": {
        "exact_claim": event_closure.registration()["proposition"],
        "artifact_coordinate": event_closure.COORDINATE,
        "facet_examined": "Selected EVENT-3.1 child, its retained finite collection and the selected first sequence and log commitment.",
        "translation": "Replayed exact child certificate and retained EVENT records to no-orphan, gapless-sequence and recomputed log-commitment checks.",
        "checking_mechanism": "verifier.domains.contracts.event_closure.recheck_event_closure_certificate",
        "resulting_evidence": event_closure.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Declared single-head log only; no occurrence authenticity, physical causality, completeness outside the collection, append-only behaviour, operand truth or whole EVENT closure tier.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective EVENT-4.1 --represented-kind EVENT --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected child request, policy, certificate, first sequence, log digest, retained records, source or current EVENT specifications.",
        "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
            "max_evidence_bytes": 8388608, "max_operations": 100000, "max_items": 4096},
        "public_route_and_tests": "tests/test_current_event_closure.py::test_public_route_and_inventory_select_only_this_closure_objective",
    },
    "DATA-3.4": {
        "exact_claim": data_distribution.registration()["proposition"],
        "artifact_coordinate": "DATA-3.4",
        "facet_examined": "Exact DATA record, complete retained shards and selected distribution fields.",
        "translation": "Exact retained canonical values to class counts, rational balances and bounded entropy comparison.",
        "checking_mechanism": "verifier.domains.contracts.data_distribution.recheck_data_distribution_certificate",
        "resulting_evidence": data_distribution.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "No population representativeness, external origin, rights, authenticated authority or whole DATA statics tier.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective DATA-3.4 --represented-kind DATA --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed DATA record, collection, retained shards, entropy policy, native source or selected specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_objects": 256, "max_operations": 100000, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_data_distribution.py::test_public_command_and_polish_keep_boundary",
    },
    "TIME-2.1": {
        "exact_claim": time_order.registration()["proposition"],
        "artifact_coordinate": "TIME-2.1",
        "facet_examined": "Exact TIME namespace record, declared clock label, half-open microsecond span and retained sample sequence.",
        "translation": "Externally selected finite collection and retained bytes to bounded native sequence and span checks.",
        "checking_mechanism": "verifier.domains.contracts.time_order.recheck_time_order_certificate",
        "resulting_evidence": time_order.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "One declared clock only; no physical clock truth, cross-clock synchronization, actual causality or whole TIME dynamics tier.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective TIME-2.1 --represented-kind TIME --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected TIME record, collection, retained samples, policy, source or current TIME specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_objects": 256, "max_operations": 100000, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_time_order.py::test_public_command_and_polish_keep_boundary",
    },
    "TIME-3.1": {
        "exact_claim": time_strict.registration()["proposition"],
        "artifact_coordinate": time_strict.COORDINATE,
        "facet_examined": "Selected TIME-2.1 child and its retained sample instants on one declared clock.",
        "translation": "Replayed exact child certificate and retained samples to strictly increasing consecutive instants.",
        "checking_mechanism": "verifier.domains.contracts.time_strict.recheck_time_strict_certificate",
        "resulting_evidence": time_strict.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "One declared clock only; no causal arrow, clock skew, clock identity, calibration, wall-clock truth, cross-clock relation, minimum spacing or whole TIME statics tier.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective TIME-3.1 --represented-kind TIME --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected child request, policy, certificate, retained samples, source or current TIME specifications.",
        "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
            "max_evidence_bytes": 8388608, "max_operations": 100000, "max_items": 4096},
        "public_route_and_tests": "tests/test_current_time_strict.py::test_public_command_route_inventory_and_polish_keep_tier_boundary",
    },
    "IDENTITY-3.1": {
        "exact_claim": identity_scope.PROPOSITION["proposition"],
        "artifact_coordinate": "IDENTITY-3.1",
        "facet_examined": "Exact IDENTITY, ACTOR, represented kind, responsible HUMAN, ROLE, COLLECTIVE and declared scope.",
        "translation": "Exact canonical namespace records and identity declaration to typed composition and native role/scope admission.",
        "checking_mechanism": "verifier.domains.contracts.identity_scope.recheck_identity_scope_certificate",
        "resulting_evidence": identity_scope.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Declared relation only; no human authenticity, live occupancy, role authority, locator resolution or complete statics tier.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective IDENTITY-3.1 --represented-kind IDENTITY --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collective, declaration, collection, evidence, selected policy, implementation or identity specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_objects": 256, "max_operations": 100000, "max_relation_steps": 100000, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_identity_scope.py::test_identity_public_command_replays_exact_selection",
    },
    "OBJECT-1.1": {
        "exact_claim": "Generic canonical representation and address binding for admitted namespace object.",
        "artifact_coordinate": "OBJECT-1.1",
        "facet_examined": "ObjectKind, object_id, payload, operands, canonical bytes.",
        "translation": "NamespaceObject to canonical JSON bytes and SHA-256 digest.",
        "checking_mechanism": "verifier.domains.contracts.object_facets.recheck_object_facets_certificate",
        "resulting_evidence": "verifier-current-object-facets-certificate-1",
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Finite typed composition; does not authenticate human identity or physical existence.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective OBJECT-1.1 --represented-kind <kind> --request <req> --policy <pol>",
        "invalidating_dependencies": "Changes to object payload, kind, operands, or policy trust roots.",
        "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576},
        "public_route_and_tests": "tests/test_current_object_routes.py::test_public_cli_reads_local_files_and_leaves_them_unchanged",
    },
    "SIM-5.1": {
        "exact_claim": "Finite declared capability effect confinement and isolation of simulation states.",
        "artifact_coordinate": "SIM-5.1",
        "facet_examined": "SIM object, virtual hardware, state partitions, transitions, effects.",
        "translation": "State transition model and isolation evidence bytes.",
        "checking_mechanism": "verifier.domains.contracts.object_grounding.recheck_current_object_certificate",
        "resulting_evidence": "verifier-current-object-certificate-1",
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Declared state model and partition tags; does not prove kernel/OS-level process containment.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SIM-5.1 --represented-kind SIM --request <req> --policy <pol>",
        "invalidating_dependencies": "State partition violation, illegal capability access, missing transition.",
        "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576},
        "public_route_and_tests": "tests/test_current_object_routes.py::test_public_cli_main_check_fail_sim_escape",
    },
    "HYPER-4.1": {
        "exact_claim": "Finite declared HYPER operand cone closure and acyclic composition.",
        "artifact_coordinate": "HYPER-4.1",
        "facet_examined": "HYPER composite object and reachable operand dependency tree.",
        "translation": "Namespace operand map and collection-wide references.",
        "checking_mechanism": "verifier.domains.contracts.hyper_closure.recheck_hyper_closure_certificate",
        "resulting_evidence": "verifier-current-hyper-closure-certificate-1",
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Declared collection records; does not prove semantic correctness of composite operands.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective HYPER-4.1 --represented-kind HYPER --request <req> --policy <pol>",
        "invalidating_dependencies": "Missing operand in collection, cyclic reference, dangling ID.",
        "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576},
        "public_route_and_tests": "tests/test_current_object_routes.py::test_public_cli_main_check_pass",
    },
    "VERIFIER-2.1": {
        "exact_claim": "Installed native simulation checker reproduces every independently selected finite expected outcome.",
        "artifact_coordinate": "VERIFIER-2.1",
        "facet_examined": "Exact checker, ordered case/check invocations, input digests, expected native results and refutations.",
        "translation": "Canonical finite input cases and external acceptance conditions to bounded native checker calls.",
        "checking_mechanism": "verifier.domains.contracts.sim_checker.recheck_sim_checker_certificate",
        "resulting_evidence": "verifier-current-sim-checker-certificate-1",
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Trusted installed checker and interpreter; no class-wide soundness, historical execution, public checkability, authority or effect-confinement claim.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective VERIFIER-2.1 --represented-kind VERIFIER --request <req> --policy <pol>",
        "invalidating_dependencies": "Changes to case inputs, expectations, selected bounds, policy, native checker, specification or interpreter version.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_evidence_bytes": 4194304, "max_total_operations": 1000000},
        "public_route_and_tests": "tests/test_current_sim_checker.py::test_public_command_executes_new_native_route",
    },
    "RECEIPT-9.1": {
        "exact_claim": "Selected RECEIPT namespace record and finite retained receipt byte sequence reach the selected hash-chain tip.",
        "artifact_coordinate": "RECEIPT-9.1",
        "facet_examined": "Exact RECEIPT object record, opaque receipt bytes, selected domain, genesis, sequence and tip.",
        "translation": "Canonical RECEIPT record and finite chain evidence to domain-separated SHA-256 links.",
        "checking_mechanism": "verifier.domains.contracts.receipt_chain.recheck_receipt_chain_certificate",
        "resulting_evidence": "verifier-current-receipt-chain-certificate-1",
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Externally trusted tip and SHA-256 collision resistance; no issuer or signature proof.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective RECEIPT-9.1 --represented-kind RECEIPT --request <req> --policy <pol>",
        "invalidating_dependencies": "Substituted tip, omitted or reordered receipt, changed checker or policy.",
        "resource_limits": {"max_certificate_bytes": 2097152, "max_selection_text_bytes": 1048576},
        "public_route_and_tests": "tests/test_current_receipt_chain.py::test_registered_public_route_and_inventory_bind_exact_receipt_security_slice",
    },
}

for _check, _coordinate in data_checks.CHECKS.items():
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": data_checks.registration(_check)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Selected DATA payload, retained records and exact native " + _check + " predicate.",
        "translation": "Exact retained canonical dataset records to the selected native computational check.",
        "checking_mechanism": "verifier.domains.contracts.data_checks.recheck_data_checks_certificate",
        "resulting_evidence": data_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Retained records only; no external origin, rights, population representativeness, semantic contamination or complete tier.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {data_checks.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind DATA --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collection, retained bytes, native check, selected policy, implementation or dataset specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                            "max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
                            "max_items": 4096, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_data_checks.py::test_public_data_command_executes_native_replay",
    }

for _check, _coordinate in env_checks.CHECKS.items():
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": env_checks.registration(_check)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Selected ENV payload, retained records and exact native " + _check + " predicate.",
        "translation": "Exact retained canonical environment records to the selected native computational check.",
        "checking_mechanism": "verifier.domains.contracts.env_checks.recheck_env_checks_certificate",
        "resulting_evidence": env_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Retained observations only; no live collection, actual rerun, physical enforcement, independent observer or complete tier.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {env_checks.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind ENV --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collection, retained bytes, native check, selected policy, implementation or environment specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                            "max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
                            "max_items": 4096, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_env_checks.py::test_public_env_command_executes_native_replay",
    }

MECHANIZED_12_POINT_BINDINGS[env_executable.COORDINATE] = {
    "exact_claim": env_executable.registration()["proposition"],
    "artifact_coordinate": env_executable.COORDINATE,
    "facet_examined": "Exact ENV entrypoint and interpreter logical paths, selected version labels, byte commitments and retained ENV-1.2 inventory.",
    "translation": "Recheck the externally selected ENV-1.2 child, then compare exact runtime coordinates and labels with its retained subject and rehashed inventory.",
    "checking_mechanism": "verifier.domains.contracts.env_executable.recheck_env_executable_certificate",
    "resulting_evidence": env_executable.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Selected labels bind retained bytes; no observed program version, actual execution, interpreter compatibility, complete toolchain, host isolation, authority or whole tier.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective ENV-1.3 --represented-kind ENV --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected ENV runtime, inventory files, child certificate/request/policy, retained bytes, installed checkers or current specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        "max_objects": 256, "max_operations": 100000,
                        "max_evidence_bytes": 6291456,
                        "max_child_certificate_bytes": 4194304},
    "public_route_and_tests": "tests/test_current_env_executable.py::test_public_route_replays_selected_executable",
}

MECHANIZED_12_POINT_BINDINGS[env_configuration_surface.COORDINATE] = {
    "exact_claim": env_configuration_surface.registration()["proposition"],
    "artifact_coordinate": env_configuration_surface.COORDINATE,
    "facet_examined": "Exact selected required ENV configuration names and finite value domains in one retained ENV record, with ENV-1.1 structural replay.",
    "translation": "Recheck the selected ENV-1.1 child, then compare its ENV declaration with the external surface and evaluate each retained value in its selected domain.",
    "checking_mechanism": "verifier.domains.contracts.env_configuration_surface.recheck_env_configuration_surface_certificate",
    "resulting_evidence": env_configuration_surface.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Completeness is relative to externally selected names; no exhaustive live host discovery, authentic observation, secret disclosure authority, physical isolation or whole tier.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective ENV-1.4 --represented-kind ENV --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected surface, ENV record or collection, child certificate/request/policy, installed domain checker or current specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        "max_surface_bytes": 65536, "max_schema_nodes": 512,
                        "max_schema_depth": 16, "max_operations": 100000,
                        "max_items": 4096, "max_evidence_bytes": 6291456,
                        "max_child_certificate_bytes": 4194304},
    "public_route_and_tests": "tests/test_current_env_configuration_surface.py::test_public_route_replays_selected_configuration_surface",
}

MECHANIZED_12_POINT_BINDINGS[env_pin_closure.COORDINATE] = {
    "exact_claim": env_pin_closure.registration()["proposition"],
    "artifact_coordinate": env_pin_closure.COORDINATE,
    "facet_examined": "Selected finite ENV resolver trace, retained target/digest observations and rehashed pinned ENV-1.2 inventory.",
    "translation": "Check each available selected resolution for contradictions, replay the selected ENV-1.2 child, then compare the externally pinned inventory; absence remains UNKNOWN only without a contradiction.",
    "checking_mechanism": "verifier.domains.contracts.env_pin_closure.recheck_env_pin_closure_certificate",
    "resulting_evidence": env_pin_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Closure is relative to externally selected trace; no complete real-host resolver capture, collector authenticity, host or network closure, isolation, authority or whole tier.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective ENV-4.1 --represented-kind ENV --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected pins or trace, ENV record or collection, child certificate/request/policy, retained observations, installed checkers or current specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        "max_pins": 256, "max_resolutions": 256,
                        "max_selection_bytes": 131072, "max_operations": 200000,
                        "max_items": 4096, "max_evidence_bytes": 6291456,
                        "max_child_certificate_bytes": 4194304},
    "public_route_and_tests": "tests/test_current_env_pin_closure.py::test_public_route_replays_pin_closure",
}

for _check, _coordinate in bench_checks.CHECKS.items():
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": bench_checks.registration(_check)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Selected BENCH payload, retained records and exact native " + _check + " predicate.",
        "translation": "Exact retained canonical benchmark records to the selected native computational check.",
        "checking_mechanism": "verifier.domains.contracts.bench_checks.recheck_bench_checks_certificate",
        "resulting_evidence": bench_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Selected built-in predicates and retained observations only; no general oracle correctness, live execution, sampling validity, measurement authenticity or complete tier.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {bench_checks.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind BENCH --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collection, retained bytes, native check, selected policy, implementation or benchmark specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                            "max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
                            "max_items": 4096, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_bench_checks.py::test_public_bench_command_executes_native_replay",
    }

for _check, _coordinate in train_checks.CHECKS.items():
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": train_checks.registration(_check)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Selected TRAIN payload, retained records and exact native " + _check + " predicate.",
        "translation": "Exact retained canonical training records to the selected native computational check.",
        "checking_mechanism": "verifier.domains.contracts.train_checks.recheck_train_checks_certificate",
        "resulting_evidence": train_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Retained dense numerical trace only; no live training, physical event observation, accelerator arithmetic, discarded history, empirical utility or complete tier.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {train_checks.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind TRAIN --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collection, retained bytes, native check, selected policy, implementation or training specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                            "max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
                            "max_items": 4096, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_train_checks.py::test_public_train_command_executes_native_replay",
    }

MECHANIZED_12_POINT_BINDINGS[train_data_bridge.COORDINATE] = {
    "exact_claim": train_data_bridge.registration()["proposition"],
    "artifact_coordinate": train_data_bridge.COORDINATE,
    "facet_examined": "Externally selected TRAIN-4.1 and DATA-1.2 certificates, exact TRAIN batch-view DATA record and selected retained DATA shards.",
    "translation": "Each retained TRAIN batch digest maps to one canonical selected DATA shard record; no selected batch or TRAIN view entry remains unmatched.",
    "checking_mechanism": "verifier.domains.contracts.train_data_bridge.recheck_train_data_bridge_certificate",
    "resulting_evidence": train_data_bridge.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Selected retained record views only; no actual historical consumption, execution, origin, rights, consent, MODEL derivation, whole TRAIN tier or polished issuance.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective TRAIN-1.5 --represented-kind TRAIN --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected TRAIN or DATA child certificate/request/policy, selected batch view or shards, retained bytes, installed child checkers or current bridge specification change.",
    "resource_limits": {"max_certificate_bytes": 10485760, "max_selection_text_bytes": 1048576,
                        "max_operations": 100000, "max_items": 4096,
                        "max_evidence_bytes": 8388608,
                        "max_train_certificate_bytes": 2097152,
                        "max_data_certificate_bytes": 2097152},
    "public_route_and_tests": "tests/test_current_train_data_bridge.py::test_current_public_route_replays_selected_bridge",
}

for _check, _coordinate in model_checks.CHECKS.items():
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": model_checks.registration(_check)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Selected MODEL payload, retained records and exact native " + _check + " predicate.",
        "translation": "Exact retained canonical model records to the selected native computational check.",
        "checking_mechanism": "verifier.domains.contracts.model_checks.recheck_model_checks_certificate",
        "resulting_evidence": model_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Retained dense model checks only; no training-gradient correctness, observed execution, hardware authenticity, empirical generalization or complete tier.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {model_checks.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind MODEL --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collection, retained bytes, native check, selected policy, implementation or model specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                            "max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
                            "max_items": 4096, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_model_checks.py::test_public_model_command_executes_native_replay",
    }

for _check, _coordinate in harness_checks.CHECKS.items():
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": harness_checks.registration(_check)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Selected HARNESS payload, retained records and exact native " + _check + " predicate.",
        "translation": "Exact retained canonical harness records to the selected native computational check.",
        "checking_mechanism": "verifier.domains.contracts.harness_checks.recheck_harness_checks_certificate",
        "resulting_evidence": harness_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Retained observation records only; no authentic instrument placement, actual execution, tool functionality, real-world history completeness or complete tier.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {harness_checks.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind HARNESS --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collection, retained bytes, native check, selected policy, implementation or harness specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                            "max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
                            "max_items": 4096, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_harness_checks.py::test_public_harness_command_executes_native_replay",
    }

for _check, _coordinate in agent_checks.CHECKS.items():
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": agent_checks.registration(_check)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Selected AGENT payload, retained records and exact native " + _check + " predicate.",
        "translation": "Exact retained canonical agent records to the selected native computational check.",
        "checking_mechanism": "verifier.domains.contracts.agent_checks.recheck_agent_checks_certificate",
        "resulting_evidence": agent_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Retained declared decisions and exact context only; no actual execution, authentic observation, internal deliberation, semantic entailment, historical child-policy reproduction or complete tier.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {agent_checks.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind AGENT --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collection, retained bytes, native check, selected policy, implementation or agent specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                            "max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
                            "max_items": 4096, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_agent_checks.py::test_public_agent_command_executes_native_replay",
    }

for _check, _coordinate in bot_checks.CHECKS.items():
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": bot_checks.registration(_check)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Selected BOT payload, retained records and exact native " + _check + " predicate.",
        "translation": "Exact retained canonical bot records to the selected native computational check.",
        "checking_mechanism": "verifier.domains.contracts.bot_checks.recheck_bot_checks_certificate",
        "resulting_evidence": bot_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Retained child and coupling correspondence only; no actual invocation, physical containment, simulation effect confinement, historical child-policy reproduction or complete tier.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {bot_checks.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind BOT --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collection, retained bytes, native check, selected policy, implementation or bot specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                            "max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
                            "max_items": 4096, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_bot_checks.py::test_public_bot_command_executes_native_replay",
    }

for _kind in ObjectKind:
    _coordinate = typed_facets.coordinate(_kind.value)
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": typed_facets.registration(_kind.value)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Exact subject record, kind-specific named operands and selected finite typed collection.",
        "translation": "Canonical namespace records and complete collection commitment; native typed-composition replay.",
        "checking_mechanism": "verifier.domains.contracts.typed_facets.recheck_typed_facets_certificate",
        "resulting_evidence": typed_facets.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Declared structure only; no payload truth, actual personhood, execution, title, authority or whole-tier conformance.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {typed_facets.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind {_kind.value} --request <req> --policy <pol>",
        "invalidating_dependencies": "Subject, collection, evidence, selected policy, native composition checker, direct dependencies or bound specifications change.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_objects": 256, "max_operations": 100000, "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_typed_facets.py::test_public_native_facets_command_replays_selected_certificate",
    }

MECHANIZED_12_POINT_BINDINGS[receipt_authenticity.COORDINATE] = {
    "exact_claim": receipt_authenticity.registration()["proposition"],
    "artifact_coordinate": receipt_authenticity.COORDINATE,
    "facet_examined": "Exact RECEIPT subject, native chain prerequisite, externally selected issuer key, challenge and finite interval.",
    "translation": "Canonical retained chain certificate plus domain-separated signed intent under independently selected request and policy.",
    "checking_mechanism": "verifier.domains.contracts.receipt_authenticity.recheck_receipt_authenticity_certificate",
    "resulting_evidence": receipt_authenticity.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Externally admitted key, chain anchor and clock; no real-world identity, key custody, governance authority, live revocation, challenge consumption, disclosure authority or complete security tier.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective RECEIPT-9.2 --represented-kind RECEIPT --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed subject, chain, signed intent, key, policy, signature implementation or transitive checker source; unavailable signature implementation preserves UNKNOWN.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_evidence_bytes": 4194304, "max_signed_payload_bytes": 8192},
    "public_route_and_tests": "tests/test_current_receipt_authenticity.py::test_integration_public_route_preserves_native_result",
}

MECHANIZED_12_POINT_BINDINGS[object_governance.COORDINATE] = {
    "exact_claim": object_governance.registration()["proposition"],
    "artifact_coordinate": object_governance.COORDINATE,
    "facet_examined": "Selected exact OBJECT record, namespace admission action, revisioned policy, distinct signed decisions and fresh signed revocation view.",
    "translation": "Retained canonical record and Ed25519 decision/status envelopes to an externally selected public-key quorum rule.",
    "checking_mechanism": "verifier.domains.contracts.object_governance.recheck_governance_certificate",
    "resulting_evidence": object_governance.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Selected public policy and clock only; no policy issuer authenticity, legal compliance, actual namespace admission, enforcement or whole governance tier.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective OBJECT-8.1 --represented-kind OBJECT --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected record, namespace, policy, clock, signatures, revocation view, installed code or current OBJECT governance specification changes.",
    "resource_limits": {"max_certificate_bytes": 4194304, "max_selection_text_bytes": 1048576, "max_evidence_bytes": 1048576, "max_decisions": 16},
    "public_route_and_tests": "tests/test_current_object_governance.py::test_exact_configured_quorum_and_fresh_status_replay_under_selected_policy",
}

MECHANIZED_12_POINT_BINDINGS[hardware_capacity.COORDINATE] = {
    "exact_claim": hardware_capacity.registration()["proposition"],
    "artifact_coordinate": hardware_capacity.COORDINATE,
    "facet_examined": "Exact HARDWARE subject, retained per-device capacities and half-open reservation occupancy by unit.",
    "translation": "Canonical namespace record and selected retained leases to bounded native capacity sweep.",
    "checking_mechanism": "verifier.domains.contracts.hardware_capacity.recheck_hardware_capacity_certificate",
    "resulting_evidence": hardware_capacity.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Declared devices, leases and one clock only; no physical availability, enforcement, delivery, credit authority or whole tier.",
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + hardware_capacity.SEMANTIC_VERSION + " --objective "
        + hardware_capacity.COORDINATE
        + " --represented-kind HARDWARE --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Subject, collection, retained devices and leases, policy, native sweep or bound specifications change.",
    "resource_limits": {
        "max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
        "max_objects": 256, "max_operations": 100000,
        "max_composition_operations": 100000, "max_items": 4096,
        "max_evidence_bytes": 4194304,
    },
    "public_route_and_tests": "tests/test_current_hardware_capacity.py::test_half_open_capacity_boundary_replays_without_physical_promotion",
}

MECHANIZED_12_POINT_BINDINGS[hardware_measurements.COORDINATE] = {
    "exact_claim": hardware_measurements.registration()["proposition"],
    "artifact_coordinate": hardware_measurements.COORDINATE,
    "facet_examined": "Exact HARDWARE subject, retained integer observations and declared per-device/unit capacity envelope.",
    "translation": "Canonical namespace record and selected retained samples to bounded native measurement-envelope replay.",
    "checking_mechanism": "verifier.domains.contracts.hardware_measurements.recheck_hardware_measurements_certificate",
    "resulting_evidence": hardware_measurements.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Declared devices, observations and one clock only; no sensor authenticity, calibration, live availability, credit authority or whole tier.",
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + hardware_measurements.SEMANTIC_VERSION + " --objective "
        + hardware_measurements.COORDINATE
        + " --represented-kind HARDWARE --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Subject, collection, retained devices and samples, policy, native envelope or bound specifications change.",
    "resource_limits": {
        "max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
        "max_objects": 256, "max_operations": 100000,
        "max_composition_operations": 100000, "max_items": 4096,
        "max_evidence_bytes": 4194304,
    },
    "public_route_and_tests": "tests/test_current_hardware_measurements.py::test_exact_retained_measurement_envelope_replays_without_sensor_promotion",
}


MECHANIZED_12_POINT_BINDINGS[hardware_inventory.COORDINATE] = {
    "exact_claim": hardware_inventory.registration()["proposition"],
    "artifact_coordinate": hardware_inventory.COORDINATE,
    "facet_examined": "Exact HARDWARE subject, finite typed collection, retained device kinds and per-device integer capacities.",
    "translation": "Canonical namespace record and device inventory to bounded native retained-record checking.",
    "checking_mechanism": "verifier.domains.contracts.hardware_inventory.recheck_hardware_inventory_certificate",
    "resulting_evidence": hardware_inventory.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Retained declarations only; no physical authenticity, live availability, workload delivery, credit authority or whole tier.",
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + hardware_inventory.SEMANTIC_VERSION + " --objective "
        + hardware_inventory.COORDINATE
        + " --represented-kind HARDWARE --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Selected subject, collection, retained inventory, policy, checker implementation or hardware specification changes.",
    "resource_limits": {
        "max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
        "max_objects": 256, "max_operations": 100000,
        "max_composition_operations": 100000, "max_items": 4096,
        "max_evidence_bytes": 4194304,
    },
    "public_route_and_tests": "tests/test_current_hardware_inventory.py::test_retained_inventory_replays_at_distinct_coordinate_without_physical_promotion",
}

MECHANIZED_12_POINT_BINDINGS[hardware_topology.COORDINATE] = {
    "exact_claim": hardware_topology.registration()["proposition"],
    "artifact_coordinate": hardware_topology.COORDINATE,
    "facet_examined": "Exact HARDWARE subject, retained named devices and finite declared containment edges.",
    "translation": "Canonical namespace record, device inventory and edge list to bounded native acyclicity replay.",
    "checking_mechanism": "verifier.domains.contracts.hardware_topology.recheck_hardware_topology_certificate",
    "resulting_evidence": hardware_topology.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Declared containment only; no physical wiring, live availability, network acyclicity, credit authority or whole tier.",
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + hardware_topology.SEMANTIC_VERSION + " --objective "
        + hardware_topology.COORDINATE
        + " --represented-kind HARDWARE --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Selected subject, collection, retained devices and edges, policy, native checker or bound specification changes.",
    "resource_limits": {
        "max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
        "max_objects": 256, "max_operations": 100000,
        "max_composition_operations": 100000, "max_items": 4096,
        "max_evidence_bytes": 4194304,
    },
    "public_route_and_tests": "tests/test_current_hardware_topology.py::test_exact_retained_containment_replays_without_physical_promotion",
}

MECHANIZED_12_POINT_BINDINGS[graph_statics.COORDINATE] = {
    "exact_claim": graph_statics.registration()["proposition"],
    "artifact_coordinate": graph_statics.COORDINATE,
    "facet_examined": "Exact GRAPH subject, selected direct members, retained nodes and directed edges.",
    "translation": "Canonical member identifiers and edge bytes to bounded endpoint and cycle replay.",
    "checking_mechanism": "verifier.domains.contracts.graph_statics.recheck_graph_statics_certificate",
    "resulting_evidence": graph_statics.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Declared finite directed edges only; no undeclared relationships, graph meaning, connectedness, lineage truth or whole tier.",
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + graph_statics.SEMANTIC_VERSION + " --objective "
        + graph_statics.COORDINATE
        + " --represented-kind GRAPH --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Selected GRAPH record, collection, retained nodes and edges, policy, native checker or current GRAPH statics specification changes.",
    "resource_limits": {
        "max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
        "max_objects": 256, "max_operations": 100000,
        "max_composition_operations": 100000, "max_items": 4096,
        "max_evidence_bytes": 4194304,
    },
    "public_route_and_tests": "tests/test_current_graph_statics.py::test_selected_acyclic_edges_pass_with_bounded_meaning",
}


MECHANIZED_12_POINT_BINDINGS[graph_closure.COORDINATE] = {
    "exact_claim": graph_closure.registration()["proposition"],
    "artifact_coordinate": graph_closure.COORDINATE,
    "facet_examined": "Selected GRAPH-3.1 child, retained nodes and directed edges, and the declared per-node reachability closure.",
    "translation": "Replayed exact child certificate and retained edges to bounded per-node traversal compared with the selected closure rows.",
    "checking_mechanism": "verifier.domains.contracts.graph_closure.recheck_graph_closure_certificate",
    "resulting_evidence": graph_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Declared finite directed edges only; no undeclared edges, lineage truth, submitted path witnesses, legacy GRAPH-4 profile or whole tier.",
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + graph_closure.SEMANTIC_VERSION + " --objective "
        + graph_closure.COORDINATE
        + " --represented-kind GRAPH --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Changed selected child request, policy, certificate, retained edges, declared closure, policy, native checkers or current GRAPH specifications.",
    "resource_limits": {
        "max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
        "max_operations": 2000000, "max_items": 4096, "max_nodes": 256,
        "max_edges": 4096, "max_closure_pairs": 32640,
        "max_evidence_bytes": 8388608,
    },
    "public_route_and_tests": "tests/test_current_graph_closure.py::test_public_route_and_inventory_select_only_this_closure_objective",
}


MECHANIZED_12_POINT_BINDINGS[graph_lineage.COORDINATE] = {
    "exact_claim": graph_lineage.registration()["proposition"],
    "artifact_coordinate": graph_lineage.COORDINATE,
    "facet_examined": "Exact GRAPH direct members, complete canonical collection, retained directed edges, endpoint-content commitments and separately selected GRAPH-3.1 child.",
    "translation": "Named operand roles project to a deduplicated direct relation among selected members; compare its exact edge set and full-record endpoint digests, then independently replay the selected native child.",
    "checking_mechanism": "verifier.domains.contracts.graph_lineage.recheck_graph_lineage_certificate",
    "resulting_evidence": graph_lineage.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Finite selected direct relation only; no real-world or historical lineage, record-maker authenticity, transitive closure, recursive member expansion, generic GRAPH-9.1 receipt inclusion, authority or whole tier.",
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + graph_lineage.SEMANTIC_VERSION + " --objective "
        + graph_lineage.COORDINATE
        + " --represented-kind GRAPH --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Selected graph/collection/nodes/edges/content manifest/evidence, child request/policy/raw certificate, parent policy/limits, native checkers, executed helpers and current GRAPH or namespace specifications.",
    "resource_limits": {
        "max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
        "max_operations": 2000000, "max_items": 4096, "max_objects": 256,
        "max_composition_operations": 100000, "max_nodes": 256,
        "max_edges": 4096, "max_evidence_bytes": 8388608,
        "max_payload_bytes": 4194304, "max_reference_bytes": 4194304,
        "max_child_certificate_bytes": 8388608,
    },
    "public_route_and_tests": "tests/test_current_graph_lineage.py::test_public_route_inventory_and_dependency_selection",
}

MECHANIZED_12_POINT_BINDINGS[graph_order.COORDINATE] = {
    "exact_claim": graph_order.registration()["proposition"],
    "artifact_coordinate": graph_order.COORDINATE,
    "facet_examined": "Selected GRAPH-3.1 child, retained nodes and directed edges, and the declared node order.",
    "translation": "Replayed exact child certificate and retained edges to a bounded least-first topological order compared position by position with the selected order.",
    "checking_mechanism": "verifier.domains.contracts.graph_order.recheck_graph_order_certificate",
    "resulting_evidence": graph_order.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Declared finite directed edges only; no undeclared edges, temporal or lineage truth, execution of the order, other topological orders, legacy GRAPH-2 member rating, legacy profile or whole tier.",
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + graph_order.SEMANTIC_VERSION + " --objective "
        + graph_order.COORDINATE
        + " --represented-kind GRAPH --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Changed selected child request, policy, certificate, retained edges, declared order, policy, native checkers or current GRAPH specifications.",
    "resource_limits": {
        "max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
        "max_operations": 2000000, "max_items": 4096, "max_nodes": 256,
        "max_edges": 4096, "max_evidence_bytes": 8388608,
    },
    "public_route_and_tests": "tests/test_current_graph_order.py::test_public_route_and_inventory_select_only_this_order_objective",
}


MECHANIZED_12_POINT_BINDINGS[model_artifact_bytes.COORDINATE] = {
    "exact_claim": model_artifact_bytes.registration()["proposition"],
    "artifact_coordinate": model_artifact_bytes.COORDINATE,
    "facet_examined": "Exact MODEL subject, typed collection, one ARCH operand and raw retained architecture and weight artifact bytes.",
    "translation": "Selected raw byte lengths and SHA-256 commitments to finite canonical retained-byte replay.",
    "checking_mechanism": "verifier.domains.contracts.model_artifact_bytes.recheck_model_artifact_bytes_certificate",
    "resulting_evidence": model_artifact_bytes.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Openly disclosable retained bytes and selected hash algorithm only; no format, training, execution, provenance, confidentiality or whole tier.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective MODEL-3.1 --represented-kind MODEL --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected MODEL and ARCH records, collection, raw artifact bytes, policy, installed checker source or current MODEL-3.1 specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        "max_objects": 256, "max_operations": 100000,
                        "max_evidence_bytes": 4194304, "max_artifact_bytes": 2097152},
    "public_route_and_tests": "tests/test_current_model_artifact_bytes.py::test_public_command_replays_exact_bytes",
}

MECHANIZED_12_POINT_BINDINGS[model_hardware_observation.COORDINATE] = {
    "exact_claim": model_hardware_observation.registration()["proposition"],
    "artifact_coordinate": model_hardware_observation.COORDINATE,
    "facet_examined": "Exact MODEL, one typed HARDWARE operand, selected open raw model bytes, input/output and two enforced committed-memory caps.",
    "translation": "Replayed MODEL-3.1 raw bytes to fixed installed Windows CPU execution under queried Job Object limits and observed finite trial bracket.",
    "checking_mechanism": "verifier.domains.contracts.model_hardware_observation.recheck_model_hardware_certificate",
    "resulting_evidence": model_hardware_observation.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Openly disclosable bytes and trusted local Windows CPython/operating system (OS); no intrinsic minimum, authenticated physical device, other runtime, GPU, storage or whole tier.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective MODEL-3.2 --represented-kind MODEL --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected MODEL/HARDWARE, raw bytes, workload, caps, source, runtime, OS enforcement or current MODEL-3.2 specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        "max_objects": 256, "max_operations": 100000,
                        "max_evidence_bytes": 4194304, "max_job_memory_bytes": 67108864,
                        "max_wall_seconds": 5, "max_trials": 3},
    "public_route_and_tests": "tests/test_current_model_hardware_observation.py::test_integrated_public_route_and_command",
}


MECHANIZED_12_POINT_BINDINGS[model_data_citation.COORDINATE] = {
    "exact_claim": model_data_citation.registration()["proposition"],
    "artifact_coordinate": model_data_citation.COORDINATE,
    "facet_examined": "Exact MODEL and one typed DATA operand, retained DATA-1.2 inventory certificate and externally selected child request and policy.",
    "translation": "The MODEL data operand's exact DATA record is matched to a separately selected retained-inventory certificate and that certificate is natively replayed.",
    "checking_mechanism": "verifier.domains.contracts.model_data_citation.recheck_model_data_certificate",
    "resulting_evidence": model_data_citation.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Retained and disclosable DATA records only; no actual training use, origin rights, complete corpus, authority, MODEL provenance or whole tier.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective MODEL-3.4 --represented-kind MODEL --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected MODEL/DATA, child certificate/request/policy, retained bytes, installed DATA checker, current MODEL-3.4 source or specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        "max_objects": 256, "max_operations": 100000,
                        "max_evidence_bytes": 4194304,
                        "max_child_certificate_bytes": 2097152},
    "public_route_and_tests": "tests/test_current_model_data_citation.py::test_public_route_and_command_replay_exact_selected_citation",
}

MECHANIZED_12_POINT_BINDINGS[model_train_citation.COORDINATE] = {
    "exact_claim": model_train_citation.registration()["proposition"],
    "artifact_coordinate": model_train_citation.COORDINATE,
    "facet_examined": "Exact MODEL, TRAIN and DATA operands in one composition, retained MODEL-3.4 certificate and externally selected child request and policy.",
    "translation": "The MODEL train operand's exact TRAIN record cites the same DATA as MODEL; the separately selected MODEL-3.4 certificate is natively replayed.",
    "checking_mechanism": "verifier.domains.contracts.model_train_citation.recheck_model_train_certificate",
    "resulting_evidence": model_train_citation.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Retained and disclosable exact records only; no actual training execution, checkpoint validity, DATA use, MODEL weight derivation, authority or whole tier.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective MODEL-3.5 --represented-kind MODEL --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected MODEL/TRAIN/DATA or collection, child MODEL-3.4 certificate/request/policy, retained bytes, installed checkers or current specifications change.",
    "resource_limits": {"max_certificate_bytes": 10485760, "max_selection_text_bytes": 1048576,
                        "max_objects": 256, "max_operations": 100000,
                        "max_evidence_bytes": 8388608,
                        "max_child_certificate_bytes": 4194304},
    "public_route_and_tests": "tests/test_current_model_train_citation.py::test_public_route_replays_exact_model_train_citation",
}

MECHANIZED_12_POINT_BINDINGS[model_data_lineage.COORDINATE] = {
    "exact_claim": model_data_lineage.registration()["proposition"],
    "artifact_coordinate": model_data_lineage.COORDINATE,
    "facet_examined": "Exact MODEL, TRAIN, distinct DATA inventory and batch-view operands, retained MODEL-3.4 and TRAIN-1.5 children.",
    "translation": "Recheck both externally selected children, their identical DATA-1.2 child and retained collection bytes; assess finite composition and selected operands.",
    "checking_mechanism": "verifier.domains.contracts.model_data_lineage.recheck_model_data_lineage_certificate",
    "resulting_evidence": model_data_lineage.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "Retained and disclosable exact records only; no historical execution, actual DATA consumption, weight derivation, rights, authority, whole tier or polished issuance.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective MODEL-3.7 --represented-kind MODEL --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected MODEL, TRAIN, DATA views, child certificates, requests and policies, collection bytes, installed checkers or current specifications change.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
                        "max_objects": 256, "max_operations": 100000,
                        "max_evidence_bytes": 12582912,
                        "max_model_data_certificate_bytes": 3145728,
                        "max_bridge_certificate_bytes": 5242880},
    "public_route_and_tests": "tests/test_current_model_data_lineage.py::test_public_route_replays_selected_lineage",
}

MECHANIZED_12_POINT_BINDINGS[model_quantization.COORDINATE] = {
    "exact_claim": model_quantization.registration()["proposition"],
    "artifact_coordinate": model_quantization.COORDINATE,
    "facet_examined": "Exact MODEL record, selected weight commitment, retained quantization specification and supported affine configuration.",
    "translation": "Selected canonical JSON byte digest and length to finite native scheme/configuration validation.",
    "checking_mechanism": "verifier.domains.contracts.model_quantization.recheck_model_quantization_certificate",
    "resulting_evidence": model_quantization.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "One supported affine-per-tensor scheme only; MODEL-3.1 prerequisite, actual weight encoding and execution, origin, disclosure authority and whole tier are not established.",
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective MODEL-3.3 --represented-kind MODEL --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected MODEL, weight commitment, collection, retained specification, policy, installed checker or current MODEL-3.3 specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        "max_objects": 256, "max_operations": 100000,
                        "max_evidence_bytes": 4194304, "max_spec_bytes": 1048576},
    "public_route_and_tests": "tests/test_current_model_quantization.py::test_integrated_public_route_and_command",
}

for _kind in ObjectKind:
    _coordinate = privacy_checks.coordinate(_kind.value)
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        "exact_claim": privacy_checks.registration(_kind.value)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": "Complete selected namespace record, external field bounds and declared observer context.",
        "translation": "Exact namespace subject and typed co-disclosures to native whole-field disclosure admission.",
        "checking_mechanism": "verifier.domains.contracts.privacy_checks.recheck_privacy_checks_certificate",
        "resulting_evidence": privacy_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Declared observer and exact record only; no authentication, general composition privacy, payload truth, actual transmission, authority or whole-tier conformance.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {privacy_checks.SEMANTIC_VERSION} --objective {_coordinate} --represented-kind {_kind.value} --request <req> --policy <pol>",
        "invalidating_dependencies": "Selected subject, collection, evidence, disclosure policy, context label, native checker or bound specification changes.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                            "max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
                            "max_evidence_bytes": 4194304},
        "public_route_and_tests": "tests/test_current_privacy_checks.py::test_public_privacy_command_does_not_echo_retained_payload",
    }


_SLOT_RATIONALES: dict[tuple[ObjectKind, MetaTier], str] = {
    # HUMAN (1..9)
    (ObjectKind.HUMAN, MetaTier.FACETS): "Structural attributes, biological identifiers, and legal personality attributes constituting a living human.",
    (ObjectKind.HUMAN, MetaTier.DYNAMICS): "Cognitive agency transitions, delegation grants, and authorization state changes performed by a human.",
    (ObjectKind.HUMAN, MetaTier.STATICS): "Non-delegable living personhood, biological mortality, and physical accountability grounding invariants.",
    (ObjectKind.HUMAN, MetaTier.CLOSURE): "Verification of authentic human attribution, non-repudiation evidence, and identity termination closure.",
    (ObjectKind.HUMAN, MetaTier.INDEPENDENCE): "Separation of human principal from automated decision systems and non-self-witnessing verification.",
    (ObjectKind.HUMAN, MetaTier.PRIVACY): "Protection of personal data, biometric identifiers, and private behavioral boundaries against disclosure.",
    (ObjectKind.HUMAN, MetaTier.CONSENT): "Explicit, informed, uncoerced human consent, scope definition, interval validity, and revocation checking.",
    (ObjectKind.HUMAN, MetaTier.GOVERNANCE): "Applicable jurisdictional laws, human rights frameworks, fiduciary duties, and ethical governance constraints.",
    (ObjectKind.HUMAN, MetaTier.SECURITY): "Mitigations against physical coercion, credential theft, biometric spoofing, and social engineering attacks.",

    # ACTOR (1..9)
    (ObjectKind.ACTOR, MetaTier.FACETS): "Decision-maker classification (HUMAN, AGENT, BOT) and human-rooted responsibility attribution structures.",
    (ObjectKind.ACTOR, MetaTier.DYNAMICS): "Decision dispatch, action execution, delegation chains, and accountability flow across systems.",
    (ObjectKind.ACTOR, MetaTier.STATICS): "Strict non-circularity of delegation chains and mandatory responsible human root invariants.",
    (ObjectKind.ACTOR, MetaTier.CLOSURE): "Complete attribution closure, verifiable decision trace, and human responsibility lineage evidence.",
    (ObjectKind.ACTOR, MetaTier.INDEPENDENCE): "Separation of decision execution from auditing and logging witnesses to prevent self-witnessing.",
    (ObjectKind.ACTOR, MetaTier.PRIVACY): "Zero-knowledge presentation of actor qualifications and masking of actor metadata where authorized.",
    (ObjectKind.ACTOR, MetaTier.CONSENT): "Consent scopes for delegated actor decision-making, duration bounds, and revocability enforcement.",
    (ObjectKind.ACTOR, MetaTier.GOVERNANCE): "Organizational policies, corporate governance bylaws, and legal responsibility attribution rules.",
    (ObjectKind.ACTOR, MetaTier.SECURITY): "Protection against unauthorized delegation, session hijacking, compromised keys, and rogue decision loops.",

    # COLLECTIVE (1..9)
    (ObjectKind.COLLECTIVE, MetaTier.FACETS): "Organized group composition, role membership graph, governance charter, and quorum rules.",
    (ObjectKind.COLLECTIVE, MetaTier.DYNAMICS): "Member admission, departure, voting rounds, consensus formation, and charter amendments.",
    (ObjectKind.COLLECTIVE, MetaTier.STATICS): "Quorum thresholds, non-empty charter invariants, and member non-duplication invariants.",
    (ObjectKind.COLLECTIVE, MetaTier.CLOSURE): "Ratified consensus closure, complete voting receipts, and recorded minute proofs.",
    (ObjectKind.COLLECTIVE, MetaTier.INDEPENDENCE): "Independence of voting members, Sybil resistance, and absence of single-point coercion.",
    (ObjectKind.COLLECTIVE, MetaTier.PRIVACY): "Secret ballot protections, blinded membership rosters, and confidential deliberation bounds.",
    (ObjectKind.COLLECTIVE, MetaTier.CONSENT): "Collective consent ratification, supermajority approval rules, and member opt-in/opt-out terms.",
    (ObjectKind.COLLECTIVE, MetaTier.GOVERNANCE): "Distributed Aggregated Governance, bylaws, legal entity governance, and dispute resolution rules.",
    (ObjectKind.COLLECTIVE, MetaTier.SECURITY): "Protection against 51% attacks, bribery, collusion, censorship, and voter impersonation.",

    # ROLE (1..9)
    (ObjectKind.ROLE, MetaTier.FACETS): "Authority class specification, permissible action sets, privilege bounds, and occupancy requirements.",
    (ObjectKind.ROLE, MetaTier.DYNAMICS): "Role activation, suspension, privilege delegation, scope expansion, and de-provisioning.",
    (ObjectKind.ROLE, MetaTier.STATICS): "Separation-of-duties invariants, mutually exclusive role constraints, and least-privilege bounds.",
    (ObjectKind.ROLE, MetaTier.CLOSURE): "Complete authorization matrix closure and non-vacant operational occupancy proof.",
    (ObjectKind.ROLE, MetaTier.INDEPENDENCE): "Separation of conflicting authority classes and independent role-granting authorization.",
    (ObjectKind.ROLE, MetaTier.PRIVACY): "Concealment of internal authority mappings and selective disclosure of role privileges.",
    (ObjectKind.ROLE, MetaTier.CONSENT): "Role assumption consent, duty acceptance agreement, and voluntary resignation rights.",
    (ObjectKind.ROLE, MetaTier.GOVERNANCE): "Institutional policies governing role assignment, authority hierarchy, and statutory requirements.",
    (ObjectKind.ROLE, MetaTier.SECURITY): "Mitigations against privilege escalation, unauthorized role assumption, and credential forging.",

    # IDENTITY (1..9)
    (ObjectKind.IDENTITY, MetaTier.FACETS): "Association binding between a bearer ACTOR, an admitted ROLE, and cryptographic credentials.",
    (ObjectKind.IDENTITY, MetaTier.DYNAMICS): "Identity issuance, credential rotation, renewal, suspension, and identity revocation.",
    (ObjectKind.IDENTITY, MetaTier.STATICS): "Cryptographic binding invariants, credential format validity, and single-active-binding rules.",
    (ObjectKind.IDENTITY, MetaTier.CLOSURE): "Closed credential chain verification, non-revocation proofs, and root trust validation.",
    (ObjectKind.IDENTITY, MetaTier.INDEPENDENCE): "Separation of identity issuer, credential bearer, and relying party verifier.",
    (ObjectKind.IDENTITY, MetaTier.PRIVACY): "Pseudonymous identifiers, unlinkable credentials, and zero-knowledge attribute presentation.",
    (ObjectKind.IDENTITY, MetaTier.CONSENT): "Subject consent for identity verification, claims presentation, and attribute sharing.",
    (ObjectKind.IDENTITY, MetaTier.GOVERNANCE): "Trust framework compliance, identity assurance standards, and public-key infrastructure policies.",
    (ObjectKind.IDENTITY, MetaTier.SECURITY): "Resistance against identity impersonation, credential theft, replay attacks, and key compromise.",

    # OWNER (1..9)
    (ObjectKind.OWNER, MetaTier.FACETS): "Property relation linking an ACTOR to held OBJECTs, rights bundles, and legal instruments.",
    (ObjectKind.OWNER, MetaTier.DYNAMICS): "Transfer of ownership, rights licensing, encumbrance assignment, and abandonment.",
    (ObjectKind.OWNER, MetaTier.STATICS): "Conservation of ownership title, no double-ownership without joint tenure, and eligibility invariants.",
    (ObjectKind.OWNER, MetaTier.CLOSURE): "Clear title chain closure, transfer receipt verification, and absence of outstanding liens.",
    (ObjectKind.OWNER, MetaTier.INDEPENDENCE): "Independence of ownership registrar and transfer witness from owner and transferee.",
    (ObjectKind.OWNER, MetaTier.PRIVACY): "Confidential ownership registries, blinded holdings balances, and private title transfers.",
    (ObjectKind.OWNER, MetaTier.CONSENT): "Explicit owner transfer consent, asset usage permission grant, and revocable license terms.",
    (ObjectKind.OWNER, MetaTier.GOVERNANCE): "Property law compliance, statutory forfeiture rules, and legal dispute adjudication protocols.",
    (ObjectKind.OWNER, MetaTier.SECURITY): "Mitigations against asset theft, double-transfer fraud, unauthorized encumbrance, and signature forgery.",

    # HARDWARE (1..9)
    (ObjectKind.HARDWARE, MetaTier.FACETS): "Substrate architecture, CPU/GPU compute units, volatile/persistent memory, and peripheral buses.",
    (ObjectKind.HARDWARE, MetaTier.DYNAMICS): "Execution cycles, power state transitions, clock frequency adjustments, and thermal state changes.",
    (ObjectKind.HARDWARE, MetaTier.STATICS): "Physical silicon bounds, measured boot constants, fuse configurations, and hardware serial numbers.",
    (ObjectKind.HARDWARE, MetaTier.CLOSURE): "Complete measured boot attestation closure and hardware security module verification.",
    (ObjectKind.HARDWARE, MetaTier.INDEPENDENCE): "Hardware root of trust independence from executed software and out-of-band verifier channels.",
    (ObjectKind.HARDWARE, MetaTier.PRIVACY): "Side-channel emissions limits, memory bus encryption, and secure enclave isolation boundaries.",
    (ObjectKind.HARDWARE, MetaTier.CONSENT): "Operator consent for remote hardware lease, execution provisioning, and diagnostic telemetry.",
    (ObjectKind.HARDWARE, MetaTier.GOVERNANCE): "Hardware export regulations, regulatory emission certifications, and environmental compliance.",
    (ObjectKind.HARDWARE, MetaTier.SECURITY): "Protection against physical tampering, fault injection, Spectre/Meltdown side channels, and supply chain interdiction.",

    # RECEIPT (1..9)
    (ObjectKind.RECEIPT, MetaTier.FACETS): "Evidence record structure, subject reference, hardware execution linkage, and claim coordinates.",
    (ObjectKind.RECEIPT, MetaTier.DYNAMICS): "Receipt generation, validation replay, revocation event logging, and ledger registration.",
    (ObjectKind.RECEIPT, MetaTier.STATICS): "Canonical serialization byte invariants, immutable SHA-256 digest bindings, and schema validity.",
    (ObjectKind.RECEIPT, MetaTier.CLOSURE): "Refutable transformation closure, prerequisite receipt chain validation, and complete proof bounds.",
    (ObjectKind.RECEIPT, MetaTier.INDEPENDENCE): "Independent notary corroboration, transparency log inclusion, and SCITT witness checks.",
    (ObjectKind.RECEIPT, MetaTier.PRIVACY): "Selective redaction of confidential evidence fields while preserving cryptographic verification.",
    (ObjectKind.RECEIPT, MetaTier.CONSENT): "Declarant consent to evidence publication and consumer acceptance of receipt boundaries.",
    (ObjectKind.RECEIPT, MetaTier.GOVERNANCE): "Audit standard compliance, evidence retention mandates, and regulatory evidence admissibility.",
    (ObjectKind.RECEIPT, MetaTier.SECURITY): "Tamper-evident hash chaining, digital signature non-repudiation, and digest collision resistance.",

    # OBJECT (1..9)
    (ObjectKind.OBJECT, MetaTier.FACETS): "Canonical JSON representation, object_id, ObjectKind, payload dictionary, and operand references.",
    (ObjectKind.OBJECT, MetaTier.DYNAMICS): "Representation serialization, versioned lineage progression, and referenced operand binding.",
    (ObjectKind.OBJECT, MetaTier.STATICS): "Canonical UTF-8 byte serialization, SHA-256 digest uniqueness, and finite structural invariants.",
    (ObjectKind.OBJECT, MetaTier.CLOSURE): "Canonical representation and address closure under admitted VSTD-NAMESPACE.",
    (ObjectKind.OBJECT, MetaTier.INDEPENDENCE): "Separation of object identity from reference pointers and independent address reproduction.",
    (ObjectKind.OBJECT, MetaTier.PRIVACY): "Minimal disclosure of payload attributes and confidential property masking.",
    (ObjectKind.OBJECT, MetaTier.CONSENT): "Data subject consent for object inclusion, transformation, and distribution.",
    (ObjectKind.OBJECT, MetaTier.GOVERNANCE): "Namespace admission governance, schema authority rules, and taxonomy maintenance.",
    (ObjectKind.OBJECT, MetaTier.SECURITY): "Prevention of canonical byte tampering, injection vulnerabilities, and payload forgery.",

    # GRAPH (1..9)
    (ObjectKind.GRAPH, MetaTier.FACETS): "Node inventories, directed edge sets, edge relation typings, and collection boundaries.",
    (ObjectKind.GRAPH, MetaTier.DYNAMICS): "Node addition, edge insertion, subgraph extraction, topological traversal, and mutation logging.",
    (ObjectKind.GRAPH, MetaTier.STATICS): "Directed acyclic graph invariants, connectivity constraints, and unique node identifier rules.",
    (ObjectKind.GRAPH, MetaTier.CLOSURE): "Complete reachability closure, transitive edge traversal proofs, and boundary integrity.",
    (ObjectKind.GRAPH, MetaTier.INDEPENDENCE): "Independent graph notary validation and cross-repository edge corroboration.",
    (ObjectKind.GRAPH, MetaTier.PRIVACY): "Graph topology anonymization, edge sanitization, and k-anonymity over relationship graphs.",
    (ObjectKind.GRAPH, MetaTier.CONSENT): "Participant consent for relationship linking, graph publishing, and node inclusion.",
    (ObjectKind.GRAPH, MetaTier.GOVERNANCE): "Graph schema standards, federation policies, and cross-organization lineage governance.",
    (ObjectKind.GRAPH, MetaTier.SECURITY): "Mitigations against edge injection attacks, graph poisoning, cyclic denial-of-service, and false lineage claims.",

    # SPACE (1..9)
    (ObjectKind.SPACE, MetaTier.FACETS): "Spatial coordinate systems, network namespaces, memory address ranges, and storage partitions.",
    (ObjectKind.SPACE, MetaTier.DYNAMICS): "Coordinate remapping, routing table updates, memory allocation/deallocation, and spatial migration.",
    (ObjectKind.SPACE, MetaTier.STATICS): "Spatial coordinate non-overlap invariants, memory alignment bounds, and partition isolation bounds.",
    (ObjectKind.SPACE, MetaTier.CLOSURE): "Spatial boundary containment closure and complete non-leakage verification.",
    (ObjectKind.SPACE, MetaTier.INDEPENDENCE): "Spatial isolation verification and physical/virtual channel non-interference proofs.",
    (ObjectKind.SPACE, MetaTier.PRIVACY): "Network address obfuscation, geolocation privacy, and physical address protection.",
    (ObjectKind.SPACE, MetaTier.CONSENT): "Consent for spatial tracking, geolocation monitoring, and memory space inspection.",
    (ObjectKind.SPACE, MetaTier.GOVERNANCE): "Jurisdictional territorial governance, frequency band regulations, and storage sovereignty rules.",
    (ObjectKind.SPACE, MetaTier.SECURITY): "Memory safety mitigations (ASLR, DEP), network intrusion defense, and spatial breakout prevention.",

    # TIME (1..9)
    (ObjectKind.TIME, MetaTier.FACETS): "Time coordinates, timestamp formats, interval specifications, and clock reference metadata.",
    (ObjectKind.TIME, MetaTier.DYNAMICS): "Clock ticks, temporal progression, interval expiration, timeout triggering, and epoch transitions.",
    (ObjectKind.TIME, MetaTier.STATICS): "Strict temporal monotonicity, causal arrow preservation, and physical clock skew bounds.",
    (ObjectKind.TIME, MetaTier.CLOSURE): "Closed interval bounds, synchronized timestamp proofs, and causal sequence verification.",
    (ObjectKind.TIME, MetaTier.INDEPENDENCE): "Multi-source clock corroboration and independent time server consensus.",
    (ObjectKind.TIME, MetaTier.PRIVACY): "Timestamp coarsening and differential privacy noise applied to temporal logs.",
    (ObjectKind.TIME, MetaTier.CONSENT): "Consent duration validity windows, temporal authorization limits, and expiration enforcement.",
    (ObjectKind.TIME, MetaTier.GOVERNANCE): "UTC standardization compliance, statutory timestamping standards, and leap second handling.",
    (ObjectKind.TIME, MetaTier.SECURITY): "Protection against clock skew attacks, time replay attacks, timestamp manipulation, and NTP poisoning.",

    # EVENT (1..9)
    (ObjectKind.EVENT, MetaTier.FACETS): "Spatiotemporal occurrence binding TIME, SPACE, acting entities, and action payload.",
    (ObjectKind.EVENT, MetaTier.DYNAMICS): "Event emission, bus routing, handler dispatch, state mutation, and acknowledgment.",
    (ObjectKind.EVENT, MetaTier.STATICS): "Immutable historical occurrence invariant, causal prerequisite satisfaction, and payload integrity.",
    (ObjectKind.EVENT, MetaTier.CLOSURE): "Complete event log closure, sequence gap absence, and verified causality chains.",
    (ObjectKind.EVENT, MetaTier.INDEPENDENCE): "Independent event witnessing and third-party append-only audit trail logging.",
    (ObjectKind.EVENT, MetaTier.PRIVACY): "Payload attribute redaction, confidential event logging, and encrypted transit bounds.",
    (ObjectKind.EVENT, MetaTier.CONSENT): "Subject consent for event capture, activity monitoring, and event log distribution.",
    (ObjectKind.EVENT, MetaTier.GOVERNANCE): "Audit trail compliance mandates, legal event retention schedules, and evidence admissibility.",
    (ObjectKind.EVENT, MetaTier.SECURITY): "Mitigations against event spoofing, event replay, log truncation, and unauthorized message injection.",

    # ENV (1..9)
    (ObjectKind.ENV, MetaTier.FACETS): "Environment variable definitions, toolchain versions, operating system configuration, and library dependencies.",
    (ObjectKind.ENV, MetaTier.DYNAMICS): "Container provisioning, environment variable setting, process initialization, and teardown.",
    (ObjectKind.ENV, MetaTier.STATICS): "Pinned dependency digests, deterministic toolchain hashes, and immutable container image layers.",
    (ObjectKind.ENV, MetaTier.CLOSURE): "Hermetic environment closure, complete software bill of materials (SBOM), and dependency resolution proofs.",
    (ObjectKind.ENV, MetaTier.INDEPENDENCE): "Clean-room execution isolation and decoupling from host environment state.",
    (ObjectKind.ENV, MetaTier.PRIVACY): "Environment secret scrubbing, credential exclusion, and sanitized environment exports.",
    (ObjectKind.ENV, MetaTier.CONSENT): "Administrator consent for environment instrumentation, inspection, and software installation.",
    (ObjectKind.ENV, MetaTier.GOVERNANCE): "Software supply chain security standards (SLSA, NIST), and organizational configuration baselines.",
    (ObjectKind.ENV, MetaTier.SECURITY): "Protection against malicious dependency injection, container breakout, and environment tampering.",

    # DATA (1..9)
    (ObjectKind.DATA, MetaTier.FACETS): "Raw payload bytes, schema specifications, row/column layouts, partition bounds, and metadata.",
    (ObjectKind.DATA, MetaTier.DYNAMICS): "Data ingestion, append operations, schema transformations, and pipeline processing.",
    (ObjectKind.DATA, MetaTier.STATICS): "Content hash integrity, schema validity invariants, and snapshot immutability.",
    (ObjectKind.DATA, MetaTier.CLOSURE): "Lineage graph closure, provenance trace verification, and complete origin-to-current proof.",
    (ObjectKind.DATA, MetaTier.INDEPENDENCE): "Independent data validation and segregation of training, validation, and test datasets.",
    (ObjectKind.DATA, MetaTier.PRIVACY): "Differential privacy bounds, anonymization, pseudonymization, and sensitive field masking.",
    (ObjectKind.DATA, MetaTier.CONSENT): "Data subject consent, purpose limitation compliance, and right-to-be-forgotten deletion workflows.",
    (ObjectKind.DATA, MetaTier.GOVERNANCE): "Data protection regulations (GDPR, CCPA, HIPAA), and data stewardship policies.",
    (ObjectKind.DATA, MetaTier.SECURITY): "Mitigations against data poisoning, tampering, unauthorized exfiltration, and bitrot corruption.",

    # VERIFIER (1..9)
    (ObjectKind.VERIFIER, MetaTier.FACETS): "Verification rule definitions, checking algorithm code, trusted computing base, and execution contract.",
    (ObjectKind.VERIFIER, MetaTier.DYNAMICS): "Proof verification execution, constraint satisfaction cycles, and verdict emission.",
    (ObjectKind.VERIFIER, MetaTier.STATICS): "Verifier determinism, termination guarantees, and algorithmic soundness invariants.",
    (ObjectKind.VERIFIER, MetaTier.CLOSURE): "Formal proof closure, exhaustive rule evaluation, and zero unresolved proof obligations.",
    (ObjectKind.VERIFIER, MetaTier.INDEPENDENCE): "Independence of verifier implementation from proof producer to avoid shared bugs.",
    (ObjectKind.VERIFIER, MetaTier.PRIVACY): "Zero-knowledge claim verification without leaking confidential witness or proof inputs.",
    (ObjectKind.VERIFIER, MetaTier.CONSENT): "Mutual consent on verification protocols, proof standards, and inspection permissions.",
    (ObjectKind.VERIFIER, MetaTier.GOVERNANCE): "Verifier accreditation standards, peer review, and formal specification governance.",
    (ObjectKind.VERIFIER, MetaTier.SECURITY): "Protection against verifier exploit payloads, memory corruption, soundness attacks, and resource exhaustion.",

    # BENCH (1..9)
    (ObjectKind.BENCH, MetaTier.FACETS): "Problem set specifications, evaluation tasks, scoring functions, and reference oracle bindings.",
    (ObjectKind.BENCH, MetaTier.DYNAMICS): "Candidate attempt execution, score computation, adaptive query sequencing, and metric aggregation.",
    (ObjectKind.BENCH, MetaTier.STATICS): "Fixed test problem splits, invariant oracle answers, and deterministic scoring metrics.",
    (ObjectKind.BENCH, MetaTier.CLOSURE): "Evaluation closure across the complete problem set with no missing or substituted runs.",
    (ObjectKind.BENCH, MetaTier.INDEPENDENCE): "Separation of benchmark evaluation set from model training data to detect contamination.",
    (ObjectKind.BENCH, MetaTier.PRIVACY): "Confidential benchmark test questions and blinded evaluation queries to prevent overfitting.",
    (ObjectKind.BENCH, MetaTier.CONSENT): "Model owner consent for benchmark evaluation, leaderboard listing, and score publication.",
    (ObjectKind.BENCH, MetaTier.GOVERNANCE): "Standardized benchmark committee rules, transparent metric definitions, and dispute protocols.",
    (ObjectKind.BENCH, MetaTier.SECURITY): "Mitigations against benchmark gaming, prompt injection attacks, test set exfiltration, and answer leakages.",

    # ARCH (1..9)
    (ObjectKind.ARCH, MetaTier.FACETS): "Layer graph topology, operator specifications, tensor shapes, and activation definitions.",
    (ObjectKind.ARCH, MetaTier.DYNAMICS): "Forward graph compilation, layer fusion, dynamic routing, and execution scheduling.",
    (ObjectKind.ARCH, MetaTier.STATICS): "Tensor dimension compatibility, acyclic computation flow, and invariant layer dimensions.",
    (ObjectKind.ARCH, MetaTier.CLOSURE): "Complete architecture definition closure with all submodules and operators resolved.",
    (ObjectKind.ARCH, MetaTier.INDEPENDENCE): "Framework-independent architecture representation decoupled from proprietary runtimes.",
    (ObjectKind.ARCH, MetaTier.PRIVACY): "Architecture IP protection, confidential layer topology, and obfuscated operator graph.",
    (ObjectKind.ARCH, MetaTier.CONSENT): "Architecture licensing terms, open-source patent covenants, and derivative work consent.",
    (ObjectKind.ARCH, MetaTier.GOVERNANCE): "Open neural network exchange standards, model architecture registries, and safety guidelines.",
    (ObjectKind.ARCH, MetaTier.SECURITY): "Detection of architectural backdoors, Trojan trigger circuits, and malformed operator exploits.",

    # TRAIN (1..9)
    (ObjectKind.TRAIN, MetaTier.FACETS): "Training recipe, hyperparameter configuration, optimizer specifications, loss functions, and dataset bindings.",
    (ObjectKind.TRAIN, MetaTier.DYNAMICS): "Gradient computation, weight update steps, learning rate schedules, and checkpoint saves.",
    (ObjectKind.TRAIN, MetaTier.STATICS): "Deterministic seed initialization, reproducible batching, and invariant loss definitions.",
    (ObjectKind.TRAIN, MetaTier.CLOSURE): "Complete training run closure, verified step count, and rehashed checkpoint inventories.",
    (ObjectKind.TRAIN, MetaTier.INDEPENDENCE): "Independent training run reproduction and non-colluding compute provider audits.",
    (ObjectKind.TRAIN, MetaTier.PRIVACY): "Differential privacy in training (DP-SGD), secure aggregation, and training data privacy.",
    (ObjectKind.TRAIN, MetaTier.CONSENT): "Data copyright owner consent for training ingestion and intellectual property licensing.",
    (ObjectKind.TRAIN, MetaTier.GOVERNANCE): "AI training transparency regulations, environmental compute reporting, and safety mandates.",
    (ObjectKind.TRAIN, MetaTier.SECURITY): "Mitigations against training data poisoning, Byzantine worker nodes, and gradient leakage.",

    # HYPER (1..9)
    (ObjectKind.HYPER, MetaTier.FACETS): "Composite structure, constituent operand roles, sub-object pointers, and assembly configuration.",
    (ObjectKind.HYPER, MetaTier.DYNAMICS): "Operand resolution, sub-object dynamic binding, composition evaluation, and lifecycle cascade.",
    (ObjectKind.HYPER, MetaTier.STATICS): "Operand cone acyclicity, well-founded dependency hierarchy, and sub-object type compatibility.",
    (ObjectKind.HYPER, MetaTier.CLOSURE): "Finite declared HYPER operand cone closure and complete dependency tree admission.",
    (ObjectKind.HYPER, MetaTier.INDEPENDENCE): "Decoupling of composite hyper-structure from operand implementation details.",
    (ObjectKind.HYPER, MetaTier.PRIVACY): "Confidential sub-component masking and selective disclosure of composite operands.",
    (ObjectKind.HYPER, MetaTier.CONSENT): "Composite author and constituent sub-object owners' mutual integration consent.",
    (ObjectKind.HYPER, MetaTier.GOVERNANCE): "Package composition policies, upstream dependency licensing, and component governance.",
    (ObjectKind.HYPER, MetaTier.SECURITY): "Mitigations against cyclic dependency denial-of-service, operand confusion, and dependency hijacking.",

    # MODEL (1..9)
    (ObjectKind.MODEL, MetaTier.FACETS): "Model weights tensors, quantization format, inference entry points, and tokenizer metadata.",
    (ObjectKind.MODEL, MetaTier.DYNAMICS): "Forward inference passes, attention computation, token generation, and output sampling.",
    (ObjectKind.MODEL, MetaTier.STATICS): "Parameter tensor SHA-256 digests, numerical precision constraints, and immutable weight bytes.",
    (ObjectKind.MODEL, MetaTier.CLOSURE): "Inference metric recomputation closure and evaluation probe inventory verification.",
    (ObjectKind.MODEL, MetaTier.INDEPENDENCE): "Third-party model evaluation on independent test sets without developer intervention.",
    (ObjectKind.MODEL, MetaTier.PRIVACY): "Mitigations against weight inversion, training data extraction, and membership inference.",
    (ObjectKind.MODEL, MetaTier.CONSENT): "Model deployment terms of service, end-user license agreements, and output usage consent.",
    (ObjectKind.MODEL, MetaTier.GOVERNANCE): "Responsible AI release governance, safety evaluations, and regulatory risk categorizations.",
    (ObjectKind.MODEL, MetaTier.SECURITY): "Hardening against adversarial perturbation, jailbreaking, prompt injection, and weight tampering.",

    # HARNESS (1..9)
    (ObjectKind.HARNESS, MetaTier.FACETS): "Execution scaffold, test fixture setup, interception hooks, and measurement assertions.",
    (ObjectKind.HARNESS, MetaTier.DYNAMICS): "Test case execution, observation capture, exception handling, and teardown execution.",
    (ObjectKind.HARNESS, MetaTier.STATICS): "Harness isolation invariants, deterministic interceptor behavior, and immutable test logic.",
    (ObjectKind.HARNESS, MetaTier.CLOSURE): "Exhaustive test suite execution closure with all assertions evaluated and recorded.",
    (ObjectKind.HARNESS, MetaTier.INDEPENDENCE): "Separation of test harness logic from the target artifact under evaluation.",
    (ObjectKind.HARNESS, MetaTier.PRIVACY): "Sanitization of sensitive test inputs and masking of proprietary traces in test reports.",
    (ObjectKind.HARNESS, MetaTier.CONSENT): "Authorized testing agreement and scope consent for testing against target systems.",
    (ObjectKind.HARNESS, MetaTier.GOVERNANCE): "Quality assurance testing standards, safety verification policies, and compliance testing rules.",
    (ObjectKind.HARNESS, MetaTier.SECURITY): "Protection against harness escape, assertion mocking attacks, and test bypass exploits.",

    # AGENT (1..9)
    (ObjectKind.AGENT, MetaTier.FACETS): "Agent goal representation, tool inventory, memory buffers, and action planning structures.",
    (ObjectKind.AGENT, MetaTier.DYNAMICS): "Perception-planning-action loops, tool invocation, memory updates, and goal completion.",
    (ObjectKind.AGENT, MetaTier.STATICS): "Bounded memory consumption, immutable safety guardrails, and non-escalation invariants.",
    (ObjectKind.AGENT, MetaTier.CLOSURE): "Closed execution trajectory log, complete tool call verification, and goal termination proof.",
    (ObjectKind.AGENT, MetaTier.INDEPENDENCE): "Multi-agent check-and-balance, independent supervisor monitoring, and external verification.",
    (ObjectKind.AGENT, MetaTier.PRIVACY): "Private deliberation traces, confidential user interactions, and masked internal memory.",
    (ObjectKind.AGENT, MetaTier.CONSENT): "User authorization for autonomous agent actions and human-in-the-loop confirmation gates.",
    (ObjectKind.AGENT, MetaTier.GOVERNANCE): "Autonomous systems safety governance, ethical alignment policies, and agent accountability standards.",
    (ObjectKind.AGENT, MetaTier.SECURITY): "Mitigations against prompt injection, unauthorized tool execution, memory corruption, and goal hijacking.",

    # SIM (1..9)
    (ObjectKind.SIM, MetaTier.FACETS): "Simulation state spaces, state partition tags, virtual hardware devices, and transition tables.",
    (ObjectKind.SIM, MetaTier.DYNAMICS): "Simulation ticks, state transitions, action effects on virtual hardware, and observation output.",
    (ObjectKind.SIM, MetaTier.STATICS): "Total state partition conservation and strict virtual hardware boundary invariants.",
    (ObjectKind.SIM, MetaTier.CLOSURE): "Complete simulation trace verification with every transition validated against declared rules.",
    (ObjectKind.SIM, MetaTier.INDEPENDENCE): "Finite declared capability effect confinement and isolation of simulation states.",
    (ObjectKind.SIM, MetaTier.PRIVACY): "Simulation state privacy, player data confidentiality, and hidden-information game boundaries.",
    (ObjectKind.SIM, MetaTier.CONSENT): "Participant consent for virtual world simulation, avatar interaction, and data logging.",
    (ObjectKind.SIM, MetaTier.GOVERNANCE): "Virtual environment rules, content standards, and simulation platform policies.",
    (ObjectKind.SIM, MetaTier.SECURITY): "Hypervisor and state escape prevention, resource starvation mitigation, and deterministic sandbox confinement.",

    # BOT (1..9)
    (ObjectKind.BOT, MetaTier.FACETS): "Automated task script, execution profile, virtual hardware confinement, and trigger schedule.",
    (ObjectKind.BOT, MetaTier.DYNAMICS): "Task execution, API polling, scheduled command dispatch, and error handling loops.",
    (ObjectKind.BOT, MetaTier.STATICS): "Execution quota limits, strict capability whitelists, and bounded operation budgets.",
    (ObjectKind.BOT, MetaTier.CLOSURE): "Verified task completion receipt, execution log closure, and resource accounting proof.",
    (ObjectKind.BOT, MetaTier.INDEPENDENCE): "Bot execution sandboxing and complete isolation from host operating system processes.",
    (ObjectKind.BOT, MetaTier.PRIVACY): "Task parameter encryption, output masking, and confidential credential storage.",
    (ObjectKind.BOT, MetaTier.CONSENT): "Explicit operator consent for bot automation tasks and rate-limited delegation permissions.",
    (ObjectKind.BOT, MetaTier.GOVERNANCE): "Automated bot identification disclosure regulations and API terms of service compliance.",
    (ObjectKind.BOT, MetaTier.SECURITY): "Botnet compromise defense, credential theft prevention, and unauthorized API invocation blocking.",

    # TOKEN (1..9)
    (ObjectKind.TOKEN, MetaTier.FACETS): "Token identifier, token type, denomination, issuance record, and owner attribution.",
    (ObjectKind.TOKEN, MetaTier.DYNAMICS): "Token transfer, balance deduction/credit, minting, burning, and allowance approval.",
    (ObjectKind.TOKEN, MetaTier.STATICS): "Conservation of total supply, non-counterfeiting invariants, and balance non-negativity.",
    (ObjectKind.TOKEN, MetaTier.CLOSURE): "Complete transaction history closure and verifiable double-spending exclusion.",
    (ObjectKind.TOKEN, MetaTier.INDEPENDENCE): "Independent settlement verifier consensus and non-custodial cryptographic verification.",
    (ObjectKind.TOKEN, MetaTier.PRIVACY): "Zero-knowledge transaction amounts, stealth destination addresses, and transaction unlinkability.",
    (ObjectKind.TOKEN, MetaTier.CONSENT): "Owner cryptographic signature authorization for transfer and allowance approval consent.",
    (ObjectKind.TOKEN, MetaTier.GOVERNANCE): "Monetary/economic policies, smart contract rule enforcement, and regulatory compliance.",
    (ObjectKind.TOKEN, MetaTier.SECURITY): "Reentrancy attack defenses, arithmetic overflow protections, and front-running mitigations.",
}


@dataclass(frozen=True)
class SlotRequirement:
    """An exact applicability and objective requirement slot for one object-tier intersection."""

    object_kind: ObjectKind
    tier: MetaTier
    governing_question: str
    applicability: str
    rationale: str
    mechanized: bool
    status: str
    coordinate: str
    mechanized_route: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "coordinate": self.coordinate,
            "object_kind": self.object_kind.value,
            "tier": self.tier.value,
            "tier_name": self.tier.name,
            "governing_question": self.governing_question,
            "applicability": self.applicability,
            "rationale": self.rationale,
            "mechanized": self.mechanized,
            "status": self.status,
        }
        if self.mechanized_route is not None:
            data["mechanized_route"] = self.mechanized_route
        data["registered_objectives"] = [
            {"coordinate": coordinate, "semantic_version": typed_facets.SEMANTIC_VERSION,
             "binding": binding}
            for coordinate, binding in sorted(MECHANIZED_12_POINT_BINDINGS.items())
            if coordinate.startswith(f"{self.object_kind.value}-{self.tier.value}.")]
        data["objective_inventory_closure"] = "NOT_ESTABLISHED"
        data["coordinate_role"] = "PRIMARY_REGISTERED_OBJECTIVE" if self.mechanized else "UNREGISTERED_SLOT_PLACEHOLDER"
        data["rationale_status"] = "PLANNING_CONTEXT_NOT_NUMBERED_REQUIREMENTS"
        return data


for _consent_kind in ObjectKind:
    for _consent_stage in range(1, 7):
        _consent_coordinate = consent_checks.coordinate(_consent_kind.value, _consent_stage)
        MECHANIZED_12_POINT_BINDINGS[_consent_coordinate] = {
            "exact_claim": consent_checks.registration(_consent_kind.value, _consent_stage)["proposition"],
            "artifact_coordinate": _consent_coordinate,
            "facet_examined": "Full selected namespace record, collection, action and every independently selected holder.",
            "translation": "Retained signed grants and status to distinct native consent predicates or exact historical reproduction.",
            "checking_mechanism": "verifier.domains.contracts.consent_checks.recheck_consent_checks_certificate",
            "resulting_evidence": consent_checks.CERTIFICATE_VERSION,
            "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
            "assumptions_and_exclusions": "Configured holder policies only; no holder-set completeness, real-world authority, voluntary consent, clock authenticity, enforcement or whole-tier conformance. Reproduction is not admission.",
            "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {consent_checks.SEMANTIC_VERSION} --objective {_consent_coordinate} --represented-kind {_consent_kind.value} --request <req> --policy <pol>",
            "invalidating_dependencies": "Changed selected subject, collection, holders, policies, time, evidence, native source or specification.",
            "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                "max_objects": 256, "max_holder_evaluations": 16, "max_operations": 100000, "max_evidence_bytes": 4194304},
            "public_route_and_tests": "tests/test_current_consent_checks.py::test_each_kind_and_stage_replays_two_independently_selected_holders",
        }


for _kind in ObjectKind:
    if _kind is ObjectKind.OBJECT:
        continue
    _coordinate = object_governance.coordinate(_kind.value)
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = {
        **MECHANIZED_12_POINT_BINDINGS[object_governance.COORDINATE],
        "exact_claim": object_governance.registration(_kind.value)["proposition"],
        "artifact_coordinate": _coordinate,
        "facet_examined": (
            "Selected exact " + _kind.value + " namespace record and signed admission action; "
            "revisioned policy, distinct signed decisions and fresh signed revocation view."),
        "reproduction_instructions": (
            "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 "
            "--objective " + _coordinate + " --represented-kind " + _kind.value +
            " --request <req> --policy <pol>"),
        "invalidating_dependencies": (
            "Selected kind, record, namespace, policy, clock, signatures, revocation view, "
            "installed code or current governance specification changes."),
        "public_route_and_tests": (
            "tests/test_current_kind_governance_routes.py::"
            "test_each_kind_public_route_binds_selected_governance"),
    }

for _security_kind in ObjectKind:
    _security_coordinate = subject_security.coordinate(_security_kind.value)
    MECHANIZED_12_POINT_BINDINGS[_security_coordinate] = {
        "exact_claim": subject_security.registration(_security_kind.value)["proposition"],
        "artifact_coordinate": _security_coordinate,
        "facet_examined": "Exact selected typed namespace record, direct RECEIPT subject operand, selected native chain and exact selected sequence entry.",
        "translation": "Canonical retained record and entry bytes to exact typed association under independently selected anchors, context and policy.",
        "checking_mechanism": "verifier.domains.contracts.subject_security.recheck_subject_security_certificate",
        "resulting_evidence": subject_security.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN"],
        "assumptions_and_exclusions": "External anchors and context; no issuer authenticity, signature validity, actual execution, enforcement, hardware authenticity, one-time context consumption, disclosure authority or complete security tier.",
        "reproduction_instructions": f"vstd current-object check <cert> --semantic-version {subject_security.SEMANTIC_VERSION} --objective {_security_coordinate} --represented-kind {_security_kind.value} --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed selected kind, subject record, RECEIPT record, domain, genesis, interval, tip, selected position, context, child certificate, policy, installed checker or specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, "max_evidence_bytes": 4194304,
                            "child_max_entries": 64, "child_max_certificate_bytes": 2097152},
        "public_route_and_tests": "tests/test_current_subject_security.py::test_every_exact_kind_replays_selected_entry_with_bounded_claim",
    }

for _independence_kind in independence_checks.KIND_SCOPES:
    _independence_coordinate = independence_checks.coordinate(_independence_kind)
    if _independence_coordinate in MECHANIZED_12_POINT_BINDINGS:
        raise RuntimeError("duplicate current-object Independence binding")
    MECHANIZED_12_POINT_BINDINGS[_independence_coordinate] = {
        "exact_claim": independence_checks.registration(_independence_kind)["proposition"],
        "artifact_coordinate": _independence_coordinate,
        "facet_examined": "Exact " + _independence_kind + " record, kind-specific typed composition, payload, every named direct operand and transitive operand; selected producer/checker traces and retained source byte/dependency footprints.",
        "translation": "Canonical selected bytes to typed namespace replay, nested exact facet inventory, retained artifact rehashing and finite source-graph traversal/intersection.",
        "checking_mechanism": "verifier.domains.contracts.independence_checks.recheck_independence_checks_certificate",
        "resulting_evidence": independence_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "Externally selected documentary provenance graph and roles only. Source authenticity, real-world identity, authority, implementation/runtime separation, common causes, causal/statistical independence remain UNKNOWN. No actual production/checking, non-self-witnessing, out-of-model provenance completeness, payload truth, complete tier or profile conclusion.",
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective " + _independence_coordinate + " --represented-kind " + _independence_kind + " --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed exact kind/subject/collection, role roots, graph commitment or dimensions, retained trace/source bytes/dependencies, limits, selected policy, installed checker/namespace/facet specifications.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
            **independence_checks._CEILINGS, "max_selection_nodes": 10000, "max_selection_depth": 64,
            "max_roots_or_parents_per_array": 64},
        "public_route_and_tests": "tests/test_current_independence_route_integration.py::test_each_independence_route_preserves_documentary_verdicts",
    }

MECHANIZED_12_POINT_BINDINGS[sim_resource.COORDINATE] = {
    "exact_claim": sim_resource.registration()["proposition"],
    "artifact_coordinate": sim_resource.COORDINATE,
    "facet_examined": (
        "Exact passing selected SIM-2.1 child, installed fixed meter source, one retained "
        "per-transition state-bound resource record and its externally admitted collector signature."),
    "translation": (
        "Canonical retained child and signed capture bytes to native trajectory replay, exact "
        "step/state coverage, installed meter-source binding and Ed25519 signature verification."),
    "checking_mechanism": "verifier.domains.contracts.sim_resource.recheck_sim_resource_certificate",
    "resulting_evidence": sim_resource.CERTIFICATE_VERSION,
    "admitted_verdicts": ["FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": (
        "Valid signed records remain overall UNKNOWN: the collector can sign fabricated numbers. "
        "No collector honesty, host attestation, historical execution or actual-consumption "
        "correspondence; no whole-device CPU, resident memory, GPU, energy, billing, whole dynamics "
        "tier, privacy, consent, governance, security, publication or object-profile conformance."),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version " + sim_resource.SEMANTIC_VERSION
        + " --objective " + sim_resource.COORDINATE
        + " --represented-kind SIM --request <req> --policy <pol>"),
    "invalidating_dependencies": (
        "Changed selected SIM or collection, SIM-2.1 child, trajectory request/policy, capture, "
        "state commitment, collector key/signature, installed meter/checker source, limits or specification."),
    "resource_limits": {"max_certificate_bytes": 16777216,
        "max_selection_text_bytes": 1048576, **sim_resource._CEILINGS},
    "public_route_and_tests": (
        "tests/test_current_sim_resource.py::"
        "test_signed_record_is_registered_but_cannot_close_sim_resource"),
}


for _token_check, _token_coordinate in token_checks.CHECKS.items():
    _token_registration = token_checks.registration(_token_check)
    MECHANIZED_12_POINT_BINDINGS[_token_coordinate] = {
        "exact_claim": _token_registration["proposition"],
        "artifact_coordinate": _token_coordinate,
        "facet_examined": {
            "tenure": "Selected birth seed, ordered epoch-status recurrence, aging interval/head and active-epoch counts.",
            "windows": "Selected lifetime windows and declared clock/skew in integer microseconds.",
            "delegation": "Retained parent-grant relations and scope/window/quota/caveat/soulbound attenuation.",
        }[_token_check],
        "translation": "Exact externally selected TOKEN record/collection and committed retained arrays to native bounded arithmetic; composition and inventory replay inline.",
        "checking_mechanism": "verifier.domains.contracts.token_checks.recheck_token_checks_certificate",
        "resulting_evidence": token_checks.CERTIFICATE_VERSION,
        "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
        "assumptions_and_exclusions": "; ".join(_token_registration["exclusions"]),
        "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective " + _token_coordinate + " --represented-kind TOKEN --request <req> --policy <pol>",
        "invalidating_dependencies": "Changed subject, collection, retained arrays, declared clock/unit, check, selected policy/limits, native source or scoped specification.",
        "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **token_checks._CEILINGS},
        "public_route_and_tests": "tests/test_current_token_integration.py::test_central_token_routes_preserve_native_outcomes",
    }


MECHANIZED_12_POINT_BINDINGS["RECEIPT-3.1"] = {
    "exact_claim": receipt_statics.registration()["proposition"],
    "artifact_coordinate": receipt_statics.COORDINATE,
    "facet_examined": "Exact selected RECEIPT namespace record, its receipt commitment and declared prerequisite list, and the exact retained VSTD-1 claim-receipt bytes.",
    "translation": "Retained bytes to commitment rehash, strict canonical JSON re-serialization, installed VSTD-1 model decode with exact field sets and types, model re-serialization and stable-payload digest recomputation.",
    "checking_mechanism": "verifier.domains.contracts.receipt_statics.recheck_receipt_statics_certificate",
    "resulting_evidence": receipt_statics.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(receipt_statics.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective RECEIPT-3.1 --represented-kind RECEIPT --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed selected RECEIPT record, retained receipt bytes, limits, selected policy, installed receipt/checker/provenance/namespace model, VSTD-1 or current RECEIPT statics specification.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **receipt_statics._CEILINGS},
    "public_route_and_tests": "tests/test_current_receipt_statics.py::test_public_route_reaches_pass",
}


MECHANIZED_12_POINT_BINDINGS["RECEIPT-2.1"] = {
    "exact_claim": receipt_validation_replay.registration()["proposition"],
    "artifact_coordinate": receipt_validation_replay.COORDINATE,
    "facet_examined": "Exact selected RECEIPT record and retained VSTD-1 receipt bytes: claim identifier, Boolean satisfiability problem (SAT) formula, atomic reasons, assumptions and the retained independent audit report.",
    "translation": "RECEIPT-3.1 statics re-run, a priori Davis-Putnam-Logemann-Loveland (DPLL) work bound, rerun of the installed IndependentAuditor with the selected expectation, then field-ordered canonical comparison with the retained report.",
    "checking_mechanism": "verifier.domains.contracts.receipt_validation_replay.recheck_receipt_validation_replay_certificate",
    "resulting_evidence": receipt_validation_replay.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(receipt_validation_replay.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective RECEIPT-2.1 --represented-kind RECEIPT --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed selected RECEIPT record, retained receipt bytes, selected expected satisfiability, limits, policy, installed checker/receipt/provenance/namespace model, RECEIPT-3.1 mechanism, VSTD-1 or current RECEIPT replay specification.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **receipt_validation_replay._CEILINGS},
    "public_route_and_tests": "tests/test_current_receipt_validation_replay.py::test_public_route_reaches_pass",
}


MECHANIZED_12_POINT_BINDINGS["RECEIPT-4.1"] = {
    "exact_claim": receipt_prerequisite_closure.registration()["proposition"],
    "artifact_coordinate": receipt_prerequisite_closure.COORDINATE,
    "facet_examined": "Selected root RECEIPT record and one separately selected RECEIPT-3.1 child per cone member, with each retained record's declared prerequisite identifiers.",
    "translation": "Replayed exact RECEIPT-3.1 child certificates, then closed reachability from the root over declared prerequisites and Kahn topological ordering.",
    "checking_mechanism": "verifier.domains.contracts.receipt_prerequisite_closure.recheck_receipt_prerequisite_closure_certificate",
    "resulting_evidence": receipt_prerequisite_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(receipt_prerequisite_closure.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective RECEIPT-4.1 --represented-kind RECEIPT --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed root selection, any child request, policy or certificate, retained records, limits, selected policy, RECEIPT-3.1 mechanism, namespace model or current RECEIPT specifications.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576, **receipt_prerequisite_closure._CEILINGS},
    "public_route_and_tests": "tests/test_current_receipt_prerequisite_closure.py::test_public_route_reaches_pass",
}


MECHANIZED_12_POINT_BINDINGS[object_statics.COORDINATE] = {
    "exact_claim": object_statics.registration()["proposition"],
    "artifact_coordinate": object_statics.COORDINATE,
    "facet_examined": "Selected OBJECT subject and every retained record byte, address, identifier and declared structural bound of one finite collection.",
    "translation": "Exact retained record bytes to SHA-256 address, strict canonical JSON, namespace reconstruction, uniqueness and inclusive bound checks.",
    "checking_mechanism": "verifier.domains.contracts.object_statics.recheck_object_statics_certificate",
    "resulting_evidence": object_statics.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(object_statics.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective OBJECT-3.1 --represented-kind OBJECT --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed subject, collection, declared bounds, retained record bytes, policy, namespace or mechanism source, or current OBJECT statics specification.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
        "max_evidence_bytes": 8388608, "max_operations": 100000, "max_items": 4096},
    "public_route_and_tests": "tests/test_current_object_statics.py::test_public_route_inventory_and_kind_selection",
}


MECHANIZED_12_POINT_BINDINGS[object_address_closure.COORDINATE] = {
    "exact_claim": object_address_closure.registration()["proposition"],
    "artifact_coordinate": object_address_closure.COORDINATE,
    "facet_examined": "Selected root record of the selected admitted kind and every operand reference reachable from it in one finite retained collection.",
    "translation": "Exact retained canonical namespace records to a bounded acyclic reachability walk and a canonical closure manifest digest.",
    "checking_mechanism": "verifier.domains.contracts.object_address_closure.recheck_object_address_closure_certificate",
    "resulting_evidence": object_address_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(object_address_closure.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective OBJECT-4.2 --represented-kind <kind> --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed root or its selected kind, collection, closure commitment, retained records, policy, namespace or mechanism source, or current OBJECT address closure specification.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
        "max_evidence_bytes": 8388608, "max_operations": 100000, "max_items": 4096},
    "public_route_and_tests": "tests/test_current_object_address_closure.py::test_public_route_inventory_and_kind_selection",
}


MECHANIZED_12_POINT_BINDINGS[object_lineage.COORDINATE] = {
    "exact_claim": object_lineage.registration()["proposition"],
    "artifact_coordinate": object_lineage.COORDINATE,
    "facet_examined": "Selected head record of the selected admitted kind, its declared lineage identifier, predecessor digests and pinned operand digests in one finite retained collection.",
    "translation": "Exact retained canonical namespace records to a bounded predecessor walk, consecutive-version, pin and completeness checks.",
    "checking_mechanism": "verifier.domains.contracts.object_lineage.recheck_object_lineage_certificate",
    "resulting_evidence": object_lineage.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(object_lineage.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective OBJECT-2.1 --represented-kind <kind> --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed head or its selected kind, lineage identifier, collection, retained records, policy, namespace or mechanism source, or current OBJECT lineage specification.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
        "max_evidence_bytes": 8388608, "max_operations": 100000, "max_items": 4096},
    "public_route_and_tests": "tests/test_current_object_lineage.py::test_public_route_inventory_and_kind_selection",
}


MECHANIZED_12_POINT_BINDINGS["ARCH-2.1"] = {
    "exact_claim": arch_schedule.registration()["proposition"],
    "artifact_coordinate": arch_schedule.COORDINATE,
    "facet_examined": "Replayed ARCH-3.1 child graph and the retained execution schedule committed by the parent request.",
    "translation": "Retained child certificate and canonical schedule bytes to node coverage, uniqueness and producer-before-consumer positions.",
    "checking_mechanism": "verifier.domains.contracts.arch_schedule.recheck_arch_schedule_certificate",
    "resulting_evidence": arch_schedule.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(arch_schedule.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective ARCH-2.1 --represented-kind ARCH --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected ARCH record, collection, child request, policy and certificate, retained schedule, parent policy, native parent or child source, or either ARCH specification.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576, **arch_schedule._CEILINGS},
    "public_route_and_tests": "tests/test_current_arch_schedule.py::test_public_route_replays_selected_schedule",
}


MECHANIZED_12_POINT_BINDINGS["TRAIN-3.2"] = {
    "exact_claim": train_accumulation.registration()["proposition"],
    "artifact_coordinate": train_accumulation.COORDINATE,
    "facet_examined": "Exact TRAIN record, finite typed collection and the retained reduction record its payload commits to.",
    "translation": "Retained canonical binary64 text and two addition-step orders to exact recomputation, tree distinctness up to commutativity and an exact rational order-effect bound.",
    "checking_mechanism": "verifier.domains.contracts.train_accumulation.recheck_train_accumulation_certificate",
    "resulting_evidence": train_accumulation.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(train_accumulation.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective TRAIN-3.2 --represented-kind TRAIN --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected TRAIN record, collection, retained reduction record, policy, native source, DOMAIN_OBLIGATIONS.md or the current TRAIN-3.2 specification.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **train_accumulation._CEILINGS},
    "public_route_and_tests": "tests/test_current_train_accumulation.py::test_public_route_replays_selected_reduction",
}


MECHANIZED_12_POINT_BINDINGS[hyper_unknown_absorption.COORDINATE] = {
    "exact_claim": hyper_unknown_absorption.registration()["proposition"],
    "artifact_coordinate": hyper_unknown_absorption.COORDINATE,
    "facet_examined": "Exact HYPER record, its direct operand records and one selected child request, policy and certificate per direct operand.",
    "translation": "Canonical collection and child selection bytes to typed namespace replay, digest binding to each exact operand record and public-route child replay.",
    "checking_mechanism": "verifier.domains.contracts.hyper_unknown_absorption.recheck_hyper_unknown_absorption_certificate",
    "resulting_evidence": hyper_unknown_absorption.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(hyper_unknown_absorption.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + hyper_unknown_absorption.SEMANTIC_VERSION + " --objective "
        + hyper_unknown_absorption.COORDINATE
        + " --represented-kind HYPER --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Changed HYPER record, collection, child selections or retained child bytes, policy, limits, native checker, public route table or HYPER-2.3 specification.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
                        **hyper_unknown_absorption._CEILINGS},
    "public_route_and_tests": "tests/test_current_hyper_unknown_absorption.py::test_public_route_dispatch_reaches_pass",
}


MECHANIZED_12_POINT_BINDINGS[hyper_composed_ceiling.COORDINATE] = {
    "exact_claim": hyper_composed_ceiling.registration()["proposition"],
    "artifact_coordinate": hyper_composed_ceiling.COORDINATE,
    "facet_examined": "Exact HYPER record and declared_depth, its direct operand records and selected per-tier child certificates of each operand.",
    "translation": "Canonical collection and child selection bytes to public-route child replay, uninterrupted tier prefixes per operand and an independent minimum.",
    "checking_mechanism": "verifier.domains.contracts.hyper_composed_ceiling.recheck_hyper_composed_ceiling_certificate",
    "resulting_evidence": hyper_composed_ceiling.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(hyper_composed_ceiling.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + hyper_composed_ceiling.SEMANTIC_VERSION + " --objective "
        + hyper_composed_ceiling.COORDINATE
        + " --represented-kind HYPER --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Changed HYPER record or declaration, collection, child selections or retained child bytes, policy, limits, native checker, HYPER-2.3 helper, public route table, LADDER, META_TIERS or HYPER-3.1 specification.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576,
                        **hyper_composed_ceiling._CEILINGS},
    "public_route_and_tests": "tests/test_current_hyper_composed_ceiling.py::test_public_route_dispatch_reaches_pass",
}


MECHANIZED_12_POINT_BINDINGS[hardware_substrate_observations.COORDINATE] = {
    "exact_claim": hardware_substrate_observations.registration()["proposition"],
    "artifact_coordinate": hardware_substrate_observations.COORDINATE,
    "facet_examined": "Exact HARDWARE subject, retained substrate claims in the five row categories, and observation records' clock, closed freshness interval, trust-root label, value and measured-boot event log.",
    "translation": "Canonical namespace record and committed claim/observation arrays to bounded qualification at the selected clock and instant, exact canonical value comparison and SHA-256 extend replay to the quoted register values.",
    "checking_mechanism": "verifier.domains.contracts.hardware_substrate_observations.recheck_hardware_substrate_observations_certificate",
    "resulting_evidence": hardware_substrate_observations.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(hardware_substrate_observations.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + hardware_substrate_observations.SEMANTIC_VERSION + " --objective "
        + hardware_substrate_observations.COORDINATE
        + " --represented-kind HARDWARE --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Subject, collection, selected clock, instant or admitted trust-root set, retained claims and observation records, limits, native checker or bound specifications change.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **hardware_substrate_observations._CEILINGS},
    "public_route_and_tests": "tests/test_current_hardware_substrate_observations.py::test_every_claim_qualified_and_replayed_passes_and_rechecks_from_bytes",
}


MECHANIZED_12_POINT_BINDINGS[hardware_inventory_closure.COORDINATE] = {
    "exact_claim": hardware_inventory_closure.registration()["proposition"],
    "artifact_coordinate": hardware_inventory_closure.COORDINATE,
    "facet_examined": "Exact HARDWARE subject, externally selected scope members, retained inventory author, entries' identity keys and coverage, and evidence records' producer, identity key and coverage.",
    "translation": "Canonical namespace record, committed member list and inventory to bounded identity-key aliasing, scope coverage, evidence consistency and producer-label independence checks.",
    "checking_mechanism": "verifier.domains.contracts.hardware_inventory_closure.recheck_hardware_inventory_closure_certificate",
    "resulting_evidence": hardware_inventory_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(hardware_inventory_closure.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + hardware_inventory_closure.SEMANTIC_VERSION + " --objective "
        + hardware_inventory_closure.COORDINATE
        + " --represented-kind HARDWARE --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Subject, collection, selected member list, retained inventory and evidence records, limits, native checker or bound specifications change.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **hardware_inventory_closure._CEILINGS},
    "public_route_and_tests": "tests/test_current_hardware_inventory_closure.py::test_nonaliasing_covered_independent_inventory_passes_and_rechecks",
}


MECHANIZED_12_POINT_BINDINGS[agent_ceiling_fixity.COORDINATE] = {
    "exact_claim": agent_ceiling_fixity.registration()["proposition"],
    "artifact_coordinate": agent_ceiling_fixity.COORDINATE,
    "facet_examined": "Exact AGENT subject, its single bound HARNESS operand record and that record's retained observation ceiling against the agent's declared ceiling.",
    "translation": "Canonical namespace records and typed composition to the native statics:ceiling equality between the bound harness ceiling and the agent declaration.",
    "checking_mechanism": "verifier.domains.contracts.agent_ceiling_fixity.recheck_agent_ceiling_fixity_certificate",
    "resulting_evidence": agent_ceiling_fixity.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(agent_ceiling_fixity.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + agent_ceiling_fixity.SEMANTIC_VERSION + " --objective " + agent_ceiling_fixity.COORDINATE
        + " --represented-kind AGENT --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Changed AGENT or bound HARNESS record, collection, evidence bytes, limits, policy, statics.py, this mechanism or CURRENT_AGENT_CEILING_FIXITY.md.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        **agent_ceiling_fixity._CEILINGS},
    "public_route_and_tests": "tests/test_current_agent_ceiling_fixity.py::test_public_route_and_command_replay_the_selected_objective",
}


MECHANIZED_12_POINT_BINDINGS[bot_inherited_ceiling.COORDINATE] = {
    "exact_claim": bot_inherited_ceiling.registration()["proposition"],
    "artifact_coordinate": bot_inherited_ceiling.COORDINATE,
    "facet_examined": "Exact BOT subject, its single bound AGENT record, that agent's single bound HARNESS record and its retained observation ceiling against every present claim.",
    "translation": "Canonical namespace records and typed composition to the native statics:inherited comparison through two exact operand bindings.",
    "checking_mechanism": "verifier.domains.contracts.bot_inherited_ceiling.recheck_bot_inherited_ceiling_certificate",
    "resulting_evidence": bot_inherited_ceiling.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(bot_inherited_ceiling.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + bot_inherited_ceiling.SEMANTIC_VERSION + " --objective " + bot_inherited_ceiling.COORDINATE
        + " --represented-kind BOT --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Changed BOT, bound AGENT or bound HARNESS record, collection, evidence bytes, limits, policy, statics.py, this mechanism or CURRENT_BOT_INHERITED_CEILING.md.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        **bot_inherited_ceiling._CEILINGS},
    "public_route_and_tests": "tests/test_current_bot_inherited_ceiling.py::test_public_route_and_command_replay_the_selected_objective",
}


MECHANIZED_12_POINT_BINDINGS[harness_gap_boundary.COORDINATE] = {
    "exact_claim": harness_gap_boundary.registration()["proposition"],
    "artifact_coordinate": harness_gap_boundary.COORDINATE,
    "facet_examined": "Exact HARNESS subject, its declared session window and named gaps, and the retained named instrument placements its commitment selects.",
    "translation": "Canonical namespace record and committed retained placements to the native statics:gap complement over the window, with named placement anchors per gap.",
    "checking_mechanism": "verifier.domains.contracts.harness_gap_boundary.recheck_harness_gap_boundary_certificate",
    "resulting_evidence": harness_gap_boundary.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(harness_gap_boundary.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + harness_gap_boundary.SEMANTIC_VERSION + " --objective " + harness_gap_boundary.COORDINATE
        + " --represented-kind HARNESS --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Changed HARNESS record, collection, retained placements, evidence bytes, limits, policy, statics.py, this mechanism or CURRENT_HARNESS_GAP_BOUNDARY.md.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        **harness_gap_boundary._CEILINGS},
    "public_route_and_tests": "tests/test_current_harness_gap_boundary.py::test_public_route_and_command_replay_the_selected_objective",
}


MECHANIZED_12_POINT_BINDINGS[event_dispatch.COORDINATE] = {
    "exact_claim": event_dispatch.registration()["proposition"],
    "artifact_coordinate": event_dispatch.COORDINATE,
    "facet_examined": "Selected EVENT record, retained handler declaration, ordered emit/dispatch/ack log and initial/final state.",
    "translation": "Externally selected finite typed collection and committed retained log bytes to a bounded single-pass dispatch, acknowledgment and declared-write fold replay.",
    "checking_mechanism": "verifier.domains.contracts.event_dispatch.recheck_event_dispatch_certificate",
    "resulting_evidence": event_dispatch.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(event_dispatch.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective EVENT-2.1 --represented-kind EVENT --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed selected EVENT record, collection, retained handlers, log or states, limits, selected policy, native source or current EVENT dispatch specification.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **event_dispatch._CEILINGS},
    "public_route_and_tests": "tests/test_current_event_dispatch.py::test_public_route_command_and_polish_keep_dynamics_boundary",
}
MECHANIZED_12_POINT_BINDINGS[space_migration.COORDINATE] = {
    "exact_claim": space_migration.registration()["proposition"],
    "artifact_coordinate": space_migration.COORDINATE,
    "facet_examined": "Selected before and after SPACE-3.1 children for one SPACE subject and the retained partition migration map.",
    "translation": "Replayed exact child certificates and their retained partitions to bounded bijection, declared-offset and byte-length checks.",
    "checking_mechanism": "verifier.domains.contracts.space_migration.recheck_space_migration_certificate",
    "resulting_evidence": space_migration.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(space_migration.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective SPACE-2.1 --represented-kind SPACE --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed selected child requests, policies or certificates, retained partitions or map, limits, selected policy, native source or current SPACE specifications.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576, **space_migration._CEILINGS},
    "public_route_and_tests": "tests/test_current_space_migration.py::test_public_route_command_and_polish_keep_dynamics_boundary",
}
MECHANIZED_12_POINT_BINDINGS[bench_attempts.COORDINATE] = {
    "exact_claim": bench_attempts.registration()["proposition"],
    "artifact_coordinate": bench_attempts.COORDINATE,
    "facet_examined": "Selected BENCH record, retained per-problem attempt bounds, retained attempts and best-of-N selections.",
    "translation": "Externally selected finite typed collection and committed problem declaration to bounded attempt counting and exact best-of-N score recomputation.",
    "checking_mechanism": "verifier.domains.contracts.bench_attempts.recheck_bench_attempts_certificate",
    "resulting_evidence": bench_attempts.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(bench_attempts.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective BENCH-2.1 --represented-kind BENCH --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed selected BENCH record, collection, retained problems, attempts or selections, limits, selected policy, native source, DOMAIN_OBLIGATIONS row or current BENCH attempt specification.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **bench_attempts._CEILINGS},
    "public_route_and_tests": "tests/test_current_bench_attempts.py::test_public_route_command_and_polish_keep_dynamics_boundary",
}


MECHANIZED_12_POINT_BINDINGS[actor_replay.COORDINATE] = {
    "exact_claim": actor_replay.registration()["proposition"],
    "artifact_coordinate": actor_replay.COORDINATE,
    "facet_examined": "Exact ACTOR subject, retained base keys and decision classes, declared delegation, revocation, rotation, membership, dissolution and succession events, and retained current state.",
    "translation": "Canonical retained base, event and state bytes to a bounded replay from the first event compared byte for byte with the retained state.",
    "checking_mechanism": "verifier.domains.contracts.actor_replay.recheck_actor_replay_certificate",
    "resulting_evidence": actor_replay.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(actor_replay.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + actor_replay.SEMANTIC_VERSION + " --objective "
        + actor_replay.COORDINATE
        + " --represented-kind ACTOR --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Selected ACTOR record, collection, retained base, declared events or current state, policy, native checker or current ACTOR replay specification changes.",
    "resource_limits": {
        "max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
        **actor_replay._CEILINGS,
    },
    "public_route_and_tests": "tests/test_current_actor_replay.py::test_declared_events_replay_to_the_retained_current_state",
}

MECHANIZED_12_POINT_BINDINGS[actor_decision_record.COORDINATE] = {
    "exact_claim": actor_decision_record.registration()["proposition"],
    "artifact_coordinate": actor_decision_record.COORDINATE,
    "facet_examined": "Exact ACTOR subject, retained earlier and later decision records, and the declared revocation, rotation, dissolution and delegation window between them.",
    "translation": "Canonical retained record and window bytes to bounded per-decision identifier, position, actor and content comparison.",
    "checking_mechanism": "verifier.domains.contracts.actor_decision_record.recheck_actor_decision_record_certificate",
    "resulting_evidence": actor_decision_record.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(actor_decision_record.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + actor_decision_record.SEMANTIC_VERSION + " --objective "
        + actor_decision_record.COORDINATE
        + " --represented-kind ACTOR --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Selected ACTOR record, collection, retained earlier or later record, declared window, policy, native checker or current ACTOR decision-record specification changes.",
    "resource_limits": {
        "max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
        **actor_decision_record._CEILINGS,
    },
    "public_route_and_tests": "tests/test_current_actor_decision_record.py::test_past_decisions_remain_their_actors_own_after_ending_events",
}

MECHANIZED_12_POINT_BINDINGS[actor_closure.COORDINATE] = {
    "exact_claim": actor_closure.registration()["proposition"],
    "artifact_coordinate": actor_closure.COORDINATE,
    "facet_examined": "Exact ACTOR subject, retained decision inventory, attributions and independence records, each reported as a component.",
    "translation": "Canonical retained component bytes to bounded contiguity, typed attribution, coverage, duplicate and sole-control checks reported together.",
    "checking_mechanism": "verifier.domains.contracts.actor_closure.recheck_actor_closure_certificate",
    "resulting_evidence": actor_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(actor_closure.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + actor_closure.SEMANTIC_VERSION + " --objective "
        + actor_closure.COORDINATE
        + " --represented-kind ACTOR --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Selected ACTOR record, collection, any retained closure component, policy, native checker or current ACTOR closure specification changes.",
    "resource_limits": {
        "max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
        **actor_closure._CEILINGS,
    },
    "public_route_and_tests": "tests/test_current_actor_closure.py::test_inventory_attributions_and_independence_pass_reported_together",
}


MECHANIZED_12_POINT_BINDINGS[human_template_irreversibility.COORDINATE] = {
    "exact_claim": human_template_irreversibility.registration()["proposition"],
    "artifact_coordinate": human_template_irreversibility.COORDINATE,
    "facet_examined": "Exact typed HUMAN record, finite typed collection and one retained declared biometric template event log.",
    "translation": "Externally selected subject, collection and event-log digests to native composition replay and a sequential declared-template state check.",
    "checking_mechanism": "verifier.domains.contracts.human_template_irreversibility.recheck_human_template_irreversibility_certificate",
    "resulting_evidence": human_template_irreversibility.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(human_template_irreversibility.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective HUMAN-2.5 --represented-kind HUMAN --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected HUMAN record, collection, retained event log, policy or limits, installed checker, NAMESPACE_OBJECTS.md or the current HUMAN-2.5 specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        **human_template_irreversibility._CEILINGS},
    "public_route_and_tests": "tests/test_current_human_template_irreversibility.py::test_public_route_and_command_replay_template_irreversibility",
}

MECHANIZED_12_POINT_BINDINGS[human_no_composition.COORDINATE] = {
    "exact_claim": human_no_composition.registration()["proposition"],
    "artifact_coordinate": human_no_composition.COORDINATE,
    "facet_examined": "Exact typed HUMAN record, finite typed collection and retained declared arrangement records.",
    "translation": "Externally selected subject, collection and arrangement digests to native composition replay and least route depth from typed MODEL, AGENT, BOT, SIM and COLLECTIVE records.",
    "checking_mechanism": "verifier.domains.contracts.human_no_composition.recheck_human_no_composition_certificate",
    "resulting_evidence": human_no_composition.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(human_no_composition.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective HUMAN-3.6 --represented-kind HUMAN --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected HUMAN record, collection, retained arrangements, policy or limits, installed checker, NAMESPACE_OBJECTS.md or the current HUMAN-3.6 specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        **human_no_composition._CEILINGS},
    "public_route_and_tests": "tests/test_current_human_no_composition.py::test_public_route_and_command_replay_no_composition",
}

MECHANIZED_12_POINT_BINDINGS[human_population_declaration.COORDINATE] = {
    "exact_claim": human_population_declaration.registration()["proposition"],
    "artifact_coordinate": human_population_declaration.COORDINATE,
    "facet_examined": "Exact typed HUMAN record and the declared evidence class, operating point, error rates and enrollment population of every typed HUMAN assertion in a finite collection; a declared deduplication mechanism and both rates zero are observed, never decided.",
    "translation": "Externally selected subject and collection digests to native composition replay and exact-rational declaration checks under the policy's admitted evidence classes.",
    "checking_mechanism": "verifier.domains.contracts.human_population_declaration.recheck_human_population_declaration_certificate",
    "resulting_evidence": human_population_declaration.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(human_population_declaration.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective HUMAN-4.3 --represented-kind HUMAN --request <req> --policy <pol>",
    "invalidating_dependencies": "Selected HUMAN record, collection, policy or admitted evidence classes, limits, installed checker, NAMESPACE_OBJECTS.md or the current HUMAN-4.3 specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576,
                        **human_population_declaration._CEILINGS},
    "public_route_and_tests": "tests/test_current_human_population_declaration.py::test_public_route_and_command_replay_population_declaration",
}


MECHANIZED_12_POINT_BINDINGS[owner_eligibility.COORDINATE] = {
    "exact_claim": owner_eligibility.registration()["proposition"],
    "artifact_coordinate": owner_eligibility.COORDINATE,
    "facet_examined": "Exact OWNER, expanded typed ACTOR representation and HARDWARE operands, full collection, retained SIM isolation evidence and external binding.",
    "translation": "Reconstruct exact typed namespace bytes, then freshly replay the existing declared hardware-ownership eligibility assessor and any selected finite SIM isolation.",
    "checking_mechanism": "verifier.domains.contracts.owner_eligibility.recheck_owner_eligibility_certificate",
    "resulting_evidence": owner_eligibility.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(owner_eligibility.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version " + owner_eligibility.SEMANTIC_VERSION + " --objective OWNER-3.1 --represented-kind OWNER --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed OWNER/collection, evidence-byte reference, exact external isolation binding, policy, installed native/shared source or namespace/SIM/OWNER eligibility specifications.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **owner_eligibility._CEILINGS},
    "public_route_and_tests": "tests/test_current_owner_eligibility.py::test_versioned_registration_is_current_and_legacy_meaning_is_not_transferred",
}


MECHANIZED_12_POINT_BINDINGS[owner_replay.COORDINATE] = {
    "exact_claim": owner_replay.registration()["proposition"],
    "artifact_coordinate": owner_replay.COORDINATE,
    "facet_examined": "Exact OWNER subject, typed ACTOR holders and held objects, retained instrument bytes, origin grants, ordered declared events and retained current holding.",
    "translation": "Committed retained replay inputs to bounded ordered transfer, delegation, revocation and term-lapse replay compared row for row with the retained holding.",
    "checking_mechanism": "verifier.domains.contracts.owner_replay.recheck_owner_replay_certificate",
    "resulting_evidence": owner_replay.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(owner_replay.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + owner_replay.SEMANTIC_VERSION + " --objective "
        + owner_replay.COORDINATE
        + " --represented-kind OWNER --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Selected OWNER record, collection, retained replay inputs or instrument bytes, policy, native checker, shared selection helper or current OWNER replay specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **owner_replay._CEILINGS},
    "public_route_and_tests": "tests/test_current_owner_replay.py::test_public_route_and_inventory_select_ordered_replay",
}


MECHANIZED_12_POINT_BINDINGS[owner_forks.COORDINATE] = {
    "exact_claim": owner_forks.registration()["proposition"],
    "artifact_coordinate": owner_forks.COORDINATE,
    "facet_examined": "Exact OWNER subject, typed ACTOR holders and held objects, retained instrument bytes, retained holdings and one declared chain per held object.",
    "translation": "Committed retained holdings and chains to bounded per-limb interval sweeps reporting every same-limb pair and every chain origin or coverage finding.",
    "checking_mechanism": "verifier.domains.contracts.owner_forks.recheck_owner_forks_certificate",
    "resulting_evidence": owner_forks.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(owner_forks.registration()["exclusions"]),
    "reproduction_instructions": (
        "vstd current-object check <cert> --semantic-version "
        + owner_forks.SEMANTIC_VERSION + " --objective "
        + owner_forks.COORDINATE
        + " --represented-kind OWNER --request <req> --policy <pol>"
    ),
    "invalidating_dependencies": "Selected OWNER record, collection, retained holdings, chains or instrument bytes, policy, native checker, shared selection helper or current OWNER fork specification changes.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 1048576, **owner_forks._CEILINGS},
    "public_route_and_tests": "tests/test_current_owner_forks.py::test_public_route_and_inventory_select_fork_detection",
}


MECHANIZED_12_POINT_BINDINGS["VERIFIER-3.1"] = {
    "exact_claim": verifier_run_constraints.registration()["proposition"],
    "artifact_coordinate": "VERIFIER-3.1",
    "facet_examined": "Exact VERIFIER record naming one registered child route, exact child request/policy/certificate, declared constraint maxima and the checker's own trace-event and report-byte observations of two replays.",
    "translation": "Declared constraints to checker-produced observations bound to one run digest; caller declarations are retained and counted but never admitted.",
    "checking_mechanism": "verifier.domains.contracts.verifier_run_constraints.recheck_verifier_run_constraints_certificate",
    "resulting_evidence": verifier_run_constraints.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(verifier_run_constraints.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective VERIFIER-3.1 --represented-kind VERIFIER --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed VERIFIER record, child selection or bytes, constraints, limits, policy, route dispatcher, native source or scoped specification; a replay relation that changes between build and recheck.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576, **verifier_run_constraints._CEILINGS},
    "public_route_and_tests": "tests/test_current_verifier_run_constraints.py::test_public_route_dispatch_reaches_pass",
}

MECHANIZED_12_POINT_BINDINGS["VERIFIER-4.1"] = {
    "exact_claim": verifier_coverage_closure.registration()["proposition"],
    "artifact_coordinate": "VERIFIER-4.1",
    "facet_examined": "Exact VERIFIER record naming the class objectives, declared finite claim class, retained directed acyclic graph (DAG) bundle/policy/artifact files, member node replays and declared counterexample-boundary certificates.",
    "translation": "Declared class to the class enumerated from approved retained profiles; member coverage recomputed from certificate DAG node replays; boundary cases replayed through registered routes.",
    "checking_mechanism": "verifier.domains.contracts.verifier_coverage_closure.recheck_verifier_coverage_closure_certificate",
    "resulting_evidence": verifier_coverage_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(verifier_coverage_closure.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective VERIFIER-4.1 --represented-kind VERIFIER --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed VERIFIER record, declared class, boundary cases or bytes, DAG bundle/policy/files, limits, policy, certificate DAG, route dispatcher, native source or scoped specification.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576, **verifier_coverage_closure._CEILINGS},
    "public_route_and_tests": "tests/test_current_verifier_coverage_closure.py::test_public_route_dispatch_reaches_pass",
}



_FINITE_CURRENT_BATCH_BINDINGS = {'COLLECTIVE-3.1': {'admitted_verdicts': ['PASS', 'FAIL', 'UNKNOWN', 'REJECTED'],
                    'artifact_coordinate': 'COLLECTIVE-3.1',
                    'assumptions_and_exclusions': 'Relative to the externally selected finite ROLE '
                                                  'list and retained charter digest. Complete '
                                                  'declared roles operand equality is checked; '
                                                  'complete real membership, exhaustive charter '
                                                  'requirements, ROLE occupancy, natural-person '
                                                  'separation, legal validity, charter authority, '
                                                  'real votes, signature validity, enforcement, '
                                                  'actual execution and whole object/tier '
                                                  'conformance remain NOT_ESTABLISHED. This static '
                                                  'predicate does not discharge selected '
                                                  'governance admission.',
                    'checking_mechanism': 'verifier.domains.contracts.collective_constraints.recheck_collective_constraints_certificate',
                    'exact_claim': 'The externally selected exact COLLECTIVE occurs in the '
                                   'selected finite typed collection; its complete declared roles '
                                   'operand equals the externally selected sorted distinct ROLE '
                                   'records; the retained membership and nonblank UTF-8 charter '
                                   'rehash to the selected commitments; and its selected integer '
                                   'quorum lies between one and that declared role count, '
                                   'inclusive.',
                    'facet_examined': 'Exact selected COLLECTIVE static_constraints payload, full '
                                      'roles operand, externally selected ROLE record digests, '
                                      'retained charter bytes and declared integer quorum.',
                    'invalidating_dependencies': 'Changed external '
                                                 'subject/collection/member/charter/quorum '
                                                 'selection, retained namespace records or charter '
                                                 'bytes, evidence commitment, selected '
                                                 'policy/limits, '
                                                 'canonicalization/evidence/namespace/JSON '
                                                 'reader/domain primitives, native module or '
                                                 'current specifications.',
                    'public_route_and_tests': 'tests/test_current_certificate_batch_integration.py::test_real_native_certificate_replays_through_selected_public_route',
                    'reproduction_instructions': 'Native: '
                                                 'build_collective_constraints_certificate(request, '
                                                 'evidence_bytes, policy=policy), then '
                                                 'recheck_collective_constraints_certificate(certificate_bytes, '
                                                 'expected_request=request, policy=policy). '
                                                 'Proposed central route after owner integration: '
                                                 'vstd current-object check <certificate> '
                                                 '--semantic-version '
                                                 'verifier-current-object-obligations-1 '
                                                 '--objective COLLECTIVE-3.1 --represented-kind '
                                                 'COLLECTIVE --request <request> --policy '
                                                 '<policy>.',
                    'resource_limits': {'max_certificate_bytes': 8388608,
                                        'max_charter_bytes': 65536,
                                        'max_composition_operations': 100000,
                                        'max_depth': 64,
                                        'max_evidence_bytes': 4194304,
                                        'max_identifier_characters': 256,
                                        'max_items': 4096,
                                        'max_objects': 256,
                                        'max_operations': 100000,
                                        'max_payload_bytes': 4194304,
                                        'max_reference_bytes': 4194304,
                                        'max_selected_members': 4096,
                                        'max_selection_text_bytes': 1048576,
                                        'max_trust_root_labels': 16},
                    'resulting_evidence': 'verifier-current-collective-constraints-certificate-1',
                    'translation': 'Reconstruct exact namespace records and full finite typed '
                                   'composition; require complete declared role operand equality '
                                   'to the external sorted distinct membership; rehash the '
                                   'retained membership and nonblank UTF-8 charter; compute the '
                                   'inclusive integer bound 1 <= quorum <= selected ROLE count.'},
 'ROLE-3.1': {'admitted_verdicts': ['PASS', 'FAIL', 'UNKNOWN', 'REJECTED'],
              'artifact_coordinate': 'ROLE-3.1',
              'assumptions_and_exclusions': 'real-world authority, permission issuance or actual '
                                            'enforcement; human authenticity, actor independence, '
                                            'actual occupancy or liveness; out-of-collection role, '
                                            'actor, identity or permission completeness; '
                                            'unselected constraints, permission meaning, law or '
                                            'ethical adequacy; complete ROLE statics tier or '
                                            'object-profile conformance; privacy, consent, '
                                            'governance and security admission',
              'checking_mechanism': 'verifier.domains.contracts.role_constraints.recheck_role_constraints_certificate',
              'exact_claim': 'The exact externally selected ROLE record and complete finite typed '
                             'collection agree with an externally committed matrix covering every '
                             'retained ROLE, ACTOR and IDENTITY. The selected COLLECTIVE contains '
                             'exactly those roles; declared permissions and scopes satisfy '
                             'selected bounds; every identity equals one selected actor-role-scope '
                             'cell; distinct declared occupancy counts satisfy each selected '
                             'interval; and selected mutually exclusive roles have neither a '
                             'shared ACTOR nor a shared declared responsible HUMAN.',
              'facet_examined': 'Exact ROLE subject, complete finite typed collection, every '
                                'retained ROLE/ACTOR/IDENTITY, selected COLLECTIVE role graph, '
                                'retained externally committed matrix, permission/scope and '
                                'occupancy constraints, mutually exclusive ACTOR/responsible-HUMAN '
                                'identifiers.',
              'invalidating_dependencies': 'Changed exact ROLE subject or full collection, '
                                           'selected matrix/collective and any role/actor/identity '
                                           'declaration, evidence bytes, trust-root labels or '
                                           'limits, installed native/shared source, '
                                           'namespace/identity/new ROLE specification bytes.',
              'public_route_and_tests': 'tests/test_current_certificate_batch_integration.py::test_real_native_certificate_replays_through_selected_public_route',
              'reproduction_instructions': 'After central allocation: vstd current-object check '
                                           '<cert> --semantic-version '
                                           'verifier-current-object-obligations-1 --objective '
                                           'ROLE-3.1 --represented-kind ROLE --request <req> '
                                           '--policy <pol>. Direct native replay uses the '
                                           'externally selected expected_request and policy.',
              'resource_limits': {'max_certificate_bytes': 8388608,
                                  'max_composition_operations': 100000,
                                  'max_evidence_bytes': 4194304,
                                  'max_items': 4096,
                                  'max_json_nesting': 64,
                                  'max_objects': 256,
                                  'max_operations': 100000,
                                  'max_payload_bytes': 4194304,
                                  'max_reference_bytes': 4194304,
                                  'max_relation_steps': 100000,
                                  'max_selection_text_bytes': 1048576},
              'resulting_evidence': 'verifier-current-role-constraints-certificate-1',
              'translation': 'Canonical retained records to typed namespace replay, shared bounded '
                             'graph expansion, exact inventory/cell comparison, finite '
                             'permission/scope subset and count/declared-root disjointness '
                             'predicates.'}}
for _coordinate, _binding in _FINITE_CURRENT_BATCH_BINDINGS.items():
    if _coordinate in MECHANIZED_12_POINT_BINDINGS:
        raise ValueError("finite current objective registration collision")
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = _binding


_FINITE_CURRENT_BATCH_2_BINDINGS = {'ARCH-4.1': {'admitted_verdicts': ['PASS', 'FAIL', 'UNKNOWN', 'REJECTED'],
              'artifact_coordinate': 'ARCH-4.1',
              'assumptions_and_exclusions': 'Externally selected finite library/definition '
                                            'representations only; no execution, shape or '
                                            'numerical validity, operator truth/safety, hidden '
                                            'references in opaque bodies, authenticity, authority '
                                            'or whole tier/profile. Primitive ARCH has no '
                                            'supported namespace submodules; broader required '
                                            'submodule closure remains UNKNOWN.',
              'checking_mechanism': 'verifier.domains.contracts.arch_resolution.recheck_arch_resolution_certificate',
              'exact_claim': 'For the exact externally selected primitive ARCH, complete typed '
                             'namespace collection and retained tensor graph, the selected '
                             'operator-tag table binds each used tag once to an exact retained '
                             'canonical operator definition; all declared definition dependencies '
                             'resolve under externally selected complete library-byte commitments; '
                             'the finite reachable definition relation is acyclic and equals the '
                             'selected closure manifest with no missing or extra entries; and '
                             "every tensor-node input count equals its selected definition's "
                             'declared arity.',
              'facet_examined': 'Exact selected primitive ARCH graph, externally selected '
                                'operator-tag table and dependency-definition closure manifest, '
                                'complete retained canonical library bytes and declared operator '
                                'dependencies.',
              'invalidating_dependencies': 'Changed selected ARCH/collection/graph, tag bindings, '
                                           'library inventory/bytes, definition rows or declared '
                                           'dependencies, closure manifest, external policy, '
                                           'evidence, finite limits, installed '
                                           'canonicalization/namespace/evidence/selection/budget '
                                           'code or bound specifications.',
              'public_route_and_tests': 'tests/test_current_certificate_batch_2_integration.py::test_real_next_native_certificate_replays_through_selected_public_route',
              'reproduction_instructions': 'Replay with independently selected request/policy through '
                                           'the installed public route: vstd current-object check '
                                           '<cert> --semantic-version '
                                           'verifier-current-object-obligations-1 --objective '
                                           'ARCH-4.1 --represented-kind ARCH --request <req> '
                                           '--policy <pol>.',
              'resource_limits': {'max_certificate_bytes': 16777216,
                                  'max_composition_operations': 100000,
                                  'max_definitions': 512,
                                  'max_depth': 64,
                                  'max_evidence_bytes': 8388608,
                                  'max_items': 4096,
                                  'max_libraries': 32,
                                  'max_library_bytes': 1048576,
                                  'max_nodes': 512,
                                  'max_objects': 256,
                                  'max_operations': 300000,
                                  'max_payload_bytes': 2097152,
                                  'max_reference_bytes': 2097152,
                                  'max_references': 4096,
                                  'max_selection_text_bytes': 1048576,
                                  'max_total_library_bytes': 4194304},
              'resulting_evidence': 'verifier-current-arch-resolution-certificate-1',
              'translation': 'Canonical namespace/graph/library/definition commitments to exact '
                             'name resolution, arity agreement, acyclic reachable dependency '
                             'traversal and equality with the complete selected finite closure '
                             'manifest.'},
 'COLLECTIVE-2.1': {'admitted_verdicts': ['PASS', 'FAIL', 'UNKNOWN', 'REJECTED'],
                    'artifact_coordinate': 'COLLECTIVE-2.1',
                    'assumptions_and_exclusions': 'Conditional on the selected finite declarations '
                                                  'and exact independently admitted static child '
                                                  'selections. Actual event occurrence/capture '
                                                  'completeness, physical timing, complete real '
                                                  'membership, independent occupants, actual '
                                                  'votes, human/actor authority, signatures, '
                                                  'enforcement, arbitrary ROLE changes, '
                                                  'charter/quorum updates and whole object/tier '
                                                  'conformance remain NOT_ESTABLISHED. Required '
                                                  'applicable .m inventory closure remains '
                                                  'UNKNOWN.',
                    'checking_mechanism': 'verifier.domains.contracts.collective_lifecycle.recheck_collective_lifecycle_certificate',
                    'exact_claim': 'The exact externally selected chronological finite ROLE '
                                   'ADMIT/DEPART inventory on one declared clock reproduces the '
                                   'selected COLLECTIVE membership and exact typed collection at '
                                   'every independently selected, rechecked COLLECTIVE-3.1 '
                                   'endpoint. Each step adds or removes exactly the selected ROLE '
                                   'record; persistent records, charter, quorum and other subject '
                                   "fields remain byte-identical, and every endpoint's quorum is "
                                   'feasible.',
                    'facet_examined': 'Exact externally selected event inventory and declared '
                                      'clock, independent COLLECTIVE-3.1 endpoint '
                                      'selections/certificate commitments, full retained typed '
                                      'collections, ROLE membership, frozen charter/quorum and '
                                      'persistent record bytes.',
                    'invalidating_dependencies': 'Changed external '
                                                 'event/clock/time/endpoint/subject/collection '
                                                 'selection, child certificate bytes or '
                                                 'requests/policies, ROLE records or retained '
                                                 'charter, limits, shared installed '
                                                 'readers/namespace/specification, frozen static '
                                                 'mechanism/specification, native lifecycle module '
                                                 'or lifecycle specification.',
                    'public_route_and_tests': 'tests/test_current_certificate_batch_2_integration.py::test_real_next_native_certificate_replays_through_selected_public_route',
                    'reproduction_instructions': 'Native: '
                                                 'build_collective_lifecycle_certificate(request, '
                                                 'evidence_bytes, policy=policy), then '
                                                 'recheck_collective_lifecycle_certificate(certificate_bytes, '
                                                 'expected_request=request, policy=policy). After '
                                                 'owner integration: vstd current-object check '
                                                 '<certificate> --semantic-version '
                                                 'verifier-current-object-obligations-1 '
                                                 '--objective COLLECTIVE-2.1 --represented-kind '
                                                 'COLLECTIVE --request <request> --policy '
                                                 '<policy>. Each endpoint independently supplies '
                                                 'time_us, certificate_ref, static_request and '
                                                 'static_policy.',
                    'resource_limits': {'max_certificate_bytes': 33554432,
                                        'max_child_certificate_bytes': 8388608,
                                        'max_child_composition_operations': 1000000,
                                        'max_child_operations': 1000000,
                                        'max_depth': 64,
                                        'max_endpoints': 65,
                                        'max_events': 64,
                                        'max_evidence_bytes': 16777216,
                                        'max_identifier_characters': 256,
                                        'max_items': 4096,
                                        'max_operations': 1000000,
                                        'max_selection_text_bytes': 1048576,
                                        'max_trust_root_labels': 16,
                                        'maximum_time_us': 9007199254740991},
                    'resulting_evidence': 'verifier-current-collective-lifecycle-certificate-1',
                    'translation': 'Replay each externally selected static endpoint using its real '
                                   'native rechecker; require unique contiguous event positions '
                                   'and strict endpoint-aligned integer chronology; compute one '
                                   'exact ROLE ADMIT/DEPART collection mutation at each step, '
                                   'recompute selected membership commitments and quorum '
                                   'feasibility, and compare every persistent or unrelated record '
                                   'by canonical bytes.'},
 'ROLE-2.1': {'admitted_verdicts': ['PASS', 'FAIL', 'UNKNOWN', 'REJECTED'],
              'artifact_coordinate': 'ROLE-2.1',
              'assumptions_and_exclusions': 'actual occurrence, complete historical event '
                                            'inventory, physical time or execution; real-world '
                                            'authority, lifecycle-state meaning, permission '
                                            'issuance or enforcement; human authenticity, actual '
                                            'occupancy, actor independence or decision '
                                            'attribution; delegation, in-flight decisions, acting '
                                            'personally versus in role or complete hand-over '
                                            'semantics; out-of-collection completeness, all '
                                            'required current .m obligations or whole ROLE '
                                            'dynamics tier; object-profile conformance, privacy, '
                                            'consent, governance or security admission',
              'checking_mechanism': 'verifier.domains.contracts.role_lifecycle.recheck_role_lifecycle_certificate',
              'exact_claim': 'Every externally selected exact ROLE endpoint and complete typed '
                             'collection passes its independently selected, freshly rechecked '
                             "ROLE-3.1 prerequisite. The same ROLE class's remaining payload "
                             'facets are preserved; ordered lifecycle-state pairs obey the '
                             'externally selected finite protocol; every permission/scope addition '
                             'and removal is permitted by that pair; and ordered declared '
                             "taking/leaving events exactly reproduce each endpoint's selected "
                             'finite ACTOR occupancy set.',
              'facet_examined': 'Exact selected ROLE endpoints/full typed collections, externally '
                                'selected ROLE-3.1 requests/policies/certificates, selected '
                                'state-transition protocol, permission/scope changes and ordered '
                                'finite occupancy taking/leaving declarations.',
              'invalidating_dependencies': 'Changed endpoint subject/record/full collection or '
                                           'child request/policy/certificate bytes, finite '
                                           'protocol, retained '
                                           'event/state/permission/scope/occupancy declarations, '
                                           'limits or trust labels, installed source or '
                                           'parent/child/shared normative bytes.',
              'public_route_and_tests': 'tests/test_current_certificate_batch_2_integration.py::test_real_next_native_certificate_replays_through_selected_public_route',
              'reproduction_instructions': 'After verified central allocation: vstd current-object '
                                           'check <cert> --semantic-version '
                                           'verifier-current-object-obligations-1 --objective '
                                           'ROLE-2.1 --represented-kind ROLE --request <req> '
                                           '--policy <pol>. Direct replay uses the independently '
                                           'selected parent expected_request and policy; each '
                                           'child selection is externally committed in the ordered '
                                           'parent endpoint selections.',
              'resource_limits': {'max_certificate_bytes': 16777216,
                                  'max_child_certificate_bytes': 2097152,
                                  'max_child_operations': 4800000,
                                  'max_endpoints': 16,
                                  'max_evidence_bytes': 8388608,
                                  'max_items': 4096,
                                  'max_json_nesting': 64,
                                  'max_operations': 100000,
                                  'max_selection_text_bytes': 1048576},
              'resulting_evidence': 'verifier-current-role-lifecycle-certificate-1',
              'translation': 'Fresh child native replay; canonical fixed-facet comparison; '
                             'selected legal state-pair lookup; exact permission/scope '
                             'addition/removal predicates; ACTOR occupancy differences and ordered '
                             'removal/addition replay.'}}
for _coordinate, _binding in _FINITE_CURRENT_BATCH_2_BINDINGS.items():
    if _coordinate in MECHANIZED_12_POINT_BINDINGS:
        raise ValueError("second finite objective registration collision")
    MECHANIZED_12_POINT_BINDINGS[_coordinate] = _binding

MECHANIZED_12_POINT_BINDINGS[time_closure.COORDINATE] = {
    "exact_claim": time_closure.registration()["proposition"],
    "artifact_coordinate": time_closure.COORDINATE,
    "facet_examined": "Exact declared TIME clock/span, selected ordered sample inventory and TIME-2.1 native tuple.",
    "translation": "Independently selected finite inventory and exact native child to ordered sample equality, root/terminal/count and half-open cutoff checks.",
    "checking_mechanism": "verifier.domains.contracts.time_closure.recheck_time_closure_certificate",
    "resulting_evidence": time_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(time_closure.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective TIME-4.1 --represented-kind TIME --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed inventory, exact native TIME-2.1 request/policy/certificate, source/specification, external selections or retained evidence.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576, **time_closure._CEILINGS},
    "public_route_and_tests": "tests/test_current_time_closure.py::test_public_route_inventory_and_polish_preserve_exact_boundary",
}


MECHANIZED_12_POINT_BINDINGS[role_closure.COORDINATE] = {
    "exact_claim": role_closure.registration()["proposition"],
    "artifact_coordinate": role_closure.COORDINATE,
    "facet_examined": "Exact selected ROLE occupancy sets, timed events, point-decision inventory and native ROLE-2.1/inline ROLE-3.1 revision contexts.",
    "translation": "Fresh exact native lifecycle/static witnesses and independent complete inventories to half-open occupancy cells and exact literal decision attribution.",
    "checking_mechanism": "verifier.domains.contracts.role_closure.recheck_role_closure_certificate",
    "resulting_evidence": role_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(role_closure.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective ROLE-4.1 --represented-kind ROLE --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed exact ROLE/collection, endpoint times, events, decisions, child request/policy/certificate or executed native source/spec/schema.",
    "resource_limits": {"max_certificate_bytes": 16777216, "max_selection_text_bytes": 1048576, **role_closure._CEILINGS},
    "public_route_and_tests": "tests/test_current_role_closure.py::test_public_route_and_inventory_preserve_finite_scope",
}


MECHANIZED_12_POINT_BINDINGS[collective_closure.COORDINATE] = {
    "exact_claim": collective_closure.registration()["proposition"],
    "artifact_coordinate": collective_closure.COORDINATE,
    "facet_examined": "Exact selected current COLLECTIVE charter/quorum/typed ROLE membership, class protocol and complete point-decision/component inventories.",
    "translation": "Fresh exact COLLECTIVE-3.1 and member ROLE-4.1 native tuples in their selected contexts to nonreused same-instant/content/class collective assemblies.",
    "checking_mechanism": "verifier.domains.contracts.collective_closure.recheck_collective_closure_certificate",
    "resulting_evidence": collective_closure.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(collective_closure.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective COLLECTIVE-4.1 --represented-kind COLLECTIVE --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed exact COLLECTIVE/collection/ROLE revisions, clock/period, protocol/inventories, any native child request/policy/byte certificate, source/spec/schema.",
    "resource_limits": {"max_certificate_bytes":16777216, "max_selection_text_bytes":1048576, **collective_closure._CEILINGS},
    "public_route_and_tests": "tests/test_current_collective_closure.py::test_public_route_and_inventory_preserve_finite_scope",
}


MECHANIZED_12_POINT_BINDINGS[identity_lifecycle.COORDINATE] = {
    "exact_claim": identity_lifecycle.registration()["proposition"],
    "artifact_coordinate": identity_lifecycle.COORDINATE,
    "facet_examined": "Exact selected IDENTITY relation, immutable lifecycle binding, complete retained event and presentation inventory.",
    "translation": "Fresh exact IDENTITY-3.1 tuple to declared single-binding half-open validity, renewal, prospective terminals and presentation ties.",
    "checking_mechanism": "verifier.domains.contracts.identity_lifecycle.recheck_identity_lifecycle_certificate",
    "resulting_evidence": identity_lifecycle.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(identity_lifecycle.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective IDENTITY-2.1 --represented-kind IDENTITY --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed exact IDENTITY/collection/child tuple, binding/history/presentation/anchor/head/count/clock, protocol, policies, source/spec/schema.",
    "resource_limits": {"max_certificate_bytes":8388608, "max_selection_text_bytes":1048576, **identity_lifecycle._CEILINGS},
    "public_route_and_tests": "tests/test_current_identity_lifecycle.py::test_public_route_cli_and_inventory_preserve_declared_lifecycle_boundary",
}



MECHANIZED_12_POINT_BINDINGS[identity_presentation.COORDINATE] = {
    "exact_claim": identity_presentation.registration()["proposition"],
    "artifact_coordinate": identity_presentation.COORDINATE,
    "facet_examined": "Exact native identity relation/lifecycle, complete selected presentation inventory, configured purpose-specific public witnesses and holder-signed terminal probe.",
    "translation": "Fresh exact selected IDENTITY-2.1/3.1 tuples plus actual configured source/holder signature and finite terminal-interpreter replay to bounded presentation prerequisites.",
    "checking_mechanism": "verifier.domains.contracts.identity_presentation.recheck_identity_presentation_certificate",
    "resulting_evidence": identity_presentation.CERTIFICATE_VERSION,
    "admitted_verdicts": ["PASS", "FAIL", "UNKNOWN", "REJECTED"],
    "assumptions_and_exclusions": "; ".join(identity_presentation.registration()["exclusions"]),
    "reproduction_instructions": "vstd current-object check <cert> --semantic-version verifier-current-object-obligations-1 --objective IDENTITY-4.1 --represented-kind IDENTITY --request <req> --policy <pol>",
    "invalidating_dependencies": "Changed exact identity/collection/children/binding/presentation inventory, configured purposes/source/holder keys, witness/probe bytes, selected clock/time/limits, source/spec/schema.",
    "resource_limits": {"max_certificate_bytes": 8388608, "max_selection_text_bytes": 8388608, **identity_presentation._CEILINGS},
    "public_route_and_tests": "tests/test_current_identity_presentation.py::test_public_route_cli_and_inventory_preserve_configured_scope",
}


def build_234_inventory() -> list[SlotRequirement]:
    """Construct the complete 234-slot applicability and objective inventory."""
    slots: list[SlotRequirement] = []
    for kind in ObjectKind:
        for tier in MetaTier:
            coordinate_base = f"{kind.value}-{tier.value}"
            question = GOVERNING_QUESTIONS[tier]
            rationale = _SLOT_RATIONALES.get(
                (kind, tier),
                f"Applicable {tier.name} requirement for {kind.value}.",
            )
            # A registered objective occupies a slot without closing its whole tier.
            mechanized_coord = None
            if kind == ObjectKind.OBJECT and tier == MetaTier.FACETS:
                mechanized_coord = "OBJECT-1.1"
            elif tier == MetaTier.FACETS:
                mechanized_coord = typed_facets.coordinate(kind.value)
            elif tier == MetaTier.PRIVACY:
                mechanized_coord = privacy_checks.coordinate(kind.value)
            elif tier == MetaTier.CONSENT:
                mechanized_coord = consent_checks.coordinate(kind.value, 1)
            elif kind == ObjectKind.SIM and tier == MetaTier.INDEPENDENCE:
                mechanized_coord = "SIM-5.1"
            elif tier == MetaTier.INDEPENDENCE:
                mechanized_coord = independence_checks.coordinate(kind.value)
            elif kind == ObjectKind.ROLE and tier == MetaTier.DYNAMICS:
                mechanized_coord = role_lifecycle.COORDINATE
            elif kind == ObjectKind.COLLECTIVE and tier == MetaTier.DYNAMICS:
                mechanized_coord = collective_lifecycle.COORDINATE
            elif kind == ObjectKind.ARCH and tier == MetaTier.CLOSURE:
                mechanized_coord = arch_resolution.COORDINATE
            elif kind == ObjectKind.ROLE and tier == MetaTier.STATICS:
                mechanized_coord = role_constraints.COORDINATE
            elif kind == ObjectKind.ROLE and tier == MetaTier.CLOSURE:
                mechanized_coord = role_closure.COORDINATE
            elif kind == ObjectKind.COLLECTIVE and tier == MetaTier.STATICS:
                mechanized_coord = collective_constraints.COORDINATE
            elif kind == ObjectKind.COLLECTIVE and tier == MetaTier.CLOSURE:
                mechanized_coord = collective_closure.COORDINATE
            elif kind == ObjectKind.OBJECT and tier == MetaTier.DYNAMICS:
                mechanized_coord = object_lineage.COORDINATE
            elif kind == ObjectKind.TOKEN and tier in (MetaTier.DYNAMICS, MetaTier.STATICS, MetaTier.CLOSURE):
                mechanized_coord = {MetaTier.DYNAMICS: "TOKEN-2.1", MetaTier.STATICS: "TOKEN-3.1", MetaTier.CLOSURE: "TOKEN-4.1"}[tier]
            elif kind == ObjectKind.SIM and tier == MetaTier.DYNAMICS:
                mechanized_coord = sim_dynamics.COORDINATE
            elif kind == ObjectKind.SIM and tier == MetaTier.STATICS:
                mechanized_coord = sim_external_law.COORDINATE
            elif kind == ObjectKind.SIM and tier == MetaTier.CLOSURE:
                mechanized_coord = sim_shard_coverage.COORDINATE
            elif kind == ObjectKind.HYPER and tier == MetaTier.CLOSURE:
                mechanized_coord = "HYPER-4.1"
            elif kind == ObjectKind.VERIFIER and tier == MetaTier.DYNAMICS:
                mechanized_coord = "VERIFIER-2.1"
            elif kind == ObjectKind.RECEIPT and tier == MetaTier.SECURITY:
                mechanized_coord = "RECEIPT-9.1"
            elif tier == MetaTier.SECURITY:
                mechanized_coord = subject_security.coordinate(kind.value)
            elif kind == ObjectKind.IDENTITY and tier == MetaTier.DYNAMICS:
                mechanized_coord = identity_lifecycle.COORDINATE
            elif kind == ObjectKind.IDENTITY and tier == MetaTier.CLOSURE:
                mechanized_coord = identity_presentation.COORDINATE
            elif kind == ObjectKind.IDENTITY and tier == MetaTier.STATICS:
                mechanized_coord = "IDENTITY-3.1"
            elif tier == MetaTier.GOVERNANCE:
                mechanized_coord = object_governance.coordinate(kind.value)
            elif kind == ObjectKind.HARDWARE and tier == MetaTier.DYNAMICS:
                mechanized_coord = hardware_capacity.COORDINATE
            elif kind == ObjectKind.TIME and tier == MetaTier.DYNAMICS:
                mechanized_coord = "TIME-2.1"
            elif kind == ObjectKind.TIME and tier == MetaTier.STATICS:
                mechanized_coord = time_strict.COORDINATE
            elif kind == ObjectKind.TIME and tier == MetaTier.CLOSURE:
                mechanized_coord = time_closure.COORDINATE
            elif kind == ObjectKind.SPACE and tier == MetaTier.STATICS:
                mechanized_coord = "SPACE-3.1"
            elif kind == ObjectKind.SPACE and tier == MetaTier.CLOSURE:
                mechanized_coord = space_closure.COORDINATE
            elif kind == ObjectKind.ARCH and tier == MetaTier.STATICS:
                mechanized_coord = arch_shapes.COORDINATE
            elif kind == ObjectKind.GRAPH and tier == MetaTier.STATICS:
                mechanized_coord = graph_statics.COORDINATE
            elif kind == ObjectKind.GRAPH and tier == MetaTier.CLOSURE:
                mechanized_coord = graph_closure.COORDINATE
            elif kind == ObjectKind.GRAPH and tier == MetaTier.DYNAMICS:
                mechanized_coord = graph_order.COORDINATE
            elif kind == ObjectKind.EVENT and tier == MetaTier.CLOSURE:
                mechanized_coord = event_closure.COORDINATE
            elif kind == ObjectKind.EVENT and tier == MetaTier.STATICS:
                mechanized_coord = "EVENT-3.1"
            elif kind == ObjectKind.BOT and tier == MetaTier.DYNAMICS:
                mechanized_coord = "BOT-2.1"
            elif kind == ObjectKind.BOT and tier == MetaTier.CLOSURE:
                mechanized_coord = "BOT-4.1"
            elif kind == ObjectKind.AGENT and tier == MetaTier.DYNAMICS:
                mechanized_coord = "AGENT-2.1"
            elif kind == ObjectKind.AGENT and tier == MetaTier.CLOSURE:
                mechanized_coord = "AGENT-4.1"
            elif kind == ObjectKind.HARNESS and tier == MetaTier.DYNAMICS:
                mechanized_coord = "HARNESS-2.1"
            elif kind == ObjectKind.HARNESS and tier == MetaTier.CLOSURE:
                mechanized_coord = "HARNESS-4.1"
            elif kind == ObjectKind.MODEL and tier == MetaTier.DYNAMICS:
                mechanized_coord = "MODEL-2.1"
            elif kind == ObjectKind.MODEL and tier == MetaTier.STATICS:
                mechanized_coord = "MODEL-3.1"
            elif kind == ObjectKind.MODEL and tier == MetaTier.CLOSURE:
                mechanized_coord = "MODEL-4.2"
            elif kind == ObjectKind.TRAIN and tier == MetaTier.DYNAMICS:
                mechanized_coord = "TRAIN-2.1"
            elif kind == ObjectKind.TRAIN and tier == MetaTier.CLOSURE:
                mechanized_coord = "TRAIN-4.1"
            elif kind == ObjectKind.BENCH and tier == MetaTier.STATICS:
                mechanized_coord = "BENCH-3.6"
            elif kind == ObjectKind.BENCH and tier == MetaTier.CLOSURE:
                mechanized_coord = "BENCH-4.4"
            elif kind == ObjectKind.ENV and tier == MetaTier.DYNAMICS:
                mechanized_coord = "ENV-2.3"
            elif kind == ObjectKind.ENV and tier == MetaTier.STATICS:
                mechanized_coord = "ENV-3.3"
            elif kind == ObjectKind.ENV and tier == MetaTier.CLOSURE:
                mechanized_coord = env_pin_closure.COORDINATE
            elif kind == ObjectKind.DATA and tier == MetaTier.STATICS:
                mechanized_coord = "DATA-3.4"
            elif kind == ObjectKind.DATA and tier == MetaTier.DYNAMICS:
                mechanized_coord = "DATA-2.1"
            elif kind == ObjectKind.DATA and tier == MetaTier.CLOSURE:
                mechanized_coord = "DATA-4.1"
            elif kind == ObjectKind.RECEIPT and tier == MetaTier.STATICS:
                mechanized_coord = receipt_statics.COORDINATE
            elif kind == ObjectKind.RECEIPT and tier == MetaTier.DYNAMICS:
                mechanized_coord = receipt_validation_replay.COORDINATE
            elif kind == ObjectKind.RECEIPT and tier == MetaTier.CLOSURE:
                mechanized_coord = receipt_prerequisite_closure.COORDINATE
            elif kind == ObjectKind.OBJECT and tier == MetaTier.STATICS:
                mechanized_coord = object_statics.COORDINATE
            elif kind == ObjectKind.OBJECT and tier == MetaTier.CLOSURE:
                mechanized_coord = object_address_closure.COORDINATE
            elif kind == ObjectKind.ARCH and tier == MetaTier.DYNAMICS:
                mechanized_coord = arch_schedule.COORDINATE
            elif kind == ObjectKind.TRAIN and tier == MetaTier.STATICS:
                mechanized_coord = train_accumulation.COORDINATE
            elif kind == ObjectKind.HYPER and tier == MetaTier.DYNAMICS:
                mechanized_coord = hyper_unknown_absorption.COORDINATE
            elif kind == ObjectKind.HYPER and tier == MetaTier.STATICS:
                mechanized_coord = hyper_composed_ceiling.COORDINATE
            elif kind == ObjectKind.HARDWARE and tier == MetaTier.STATICS:
                mechanized_coord = hardware_substrate_observations.COORDINATE
            elif kind == ObjectKind.HARDWARE and tier == MetaTier.CLOSURE:
                mechanized_coord = hardware_inventory_closure.COORDINATE
            elif kind == ObjectKind.AGENT and tier == MetaTier.STATICS:
                mechanized_coord = agent_ceiling_fixity.COORDINATE
            elif kind == ObjectKind.BOT and tier == MetaTier.STATICS:
                mechanized_coord = bot_inherited_ceiling.COORDINATE
            elif kind == ObjectKind.HARNESS and tier == MetaTier.STATICS:
                mechanized_coord = harness_gap_boundary.COORDINATE
            elif kind == ObjectKind.EVENT and tier == MetaTier.DYNAMICS:
                mechanized_coord = event_dispatch.COORDINATE
            elif kind == ObjectKind.SPACE and tier == MetaTier.DYNAMICS:
                mechanized_coord = space_migration.COORDINATE
            elif kind == ObjectKind.BENCH and tier == MetaTier.DYNAMICS:
                mechanized_coord = bench_attempts.COORDINATE
            elif kind == ObjectKind.ACTOR and tier == MetaTier.DYNAMICS:
                mechanized_coord = actor_replay.COORDINATE
            elif kind == ObjectKind.ACTOR and tier == MetaTier.STATICS:
                mechanized_coord = actor_decision_record.COORDINATE
            elif kind == ObjectKind.ACTOR and tier == MetaTier.CLOSURE:
                mechanized_coord = actor_closure.COORDINATE
            elif kind == ObjectKind.HUMAN and tier == MetaTier.DYNAMICS:
                mechanized_coord = human_template_irreversibility.COORDINATE
            elif kind == ObjectKind.HUMAN and tier == MetaTier.STATICS:
                mechanized_coord = human_no_composition.COORDINATE
            elif kind == ObjectKind.HUMAN and tier == MetaTier.CLOSURE:
                mechanized_coord = human_population_declaration.COORDINATE
            elif kind == ObjectKind.OWNER and tier == MetaTier.DYNAMICS:
                mechanized_coord = owner_replay.COORDINATE
            elif kind == ObjectKind.OWNER and tier == MetaTier.STATICS:
                mechanized_coord = owner_eligibility.COORDINATE
            elif kind == ObjectKind.OWNER and tier == MetaTier.CLOSURE:
                mechanized_coord = owner_forks.COORDINATE
            elif kind == ObjectKind.VERIFIER and tier == MetaTier.STATICS:
                mechanized_coord = verifier_run_constraints.COORDINATE
            elif kind == ObjectKind.VERIFIER and tier == MetaTier.CLOSURE:
                mechanized_coord = verifier_coverage_closure.COORDINATE

            if mechanized_coord is not None and mechanized_coord in MECHANIZED_12_POINT_BINDINGS:
                binding = MECHANIZED_12_POINT_BINDINGS[mechanized_coord]
                slots.append(
                    SlotRequirement(
                        object_kind=kind,
                        tier=tier,
                        governing_question=question,
                        applicability="REQUIRED",
                        rationale=rationale,
                        mechanized=True,
                        status="REPLAYABLE",
                        coordinate=mechanized_coord,
                        mechanized_route=binding,
                    )
                )
            else:
                slots.append(
                    SlotRequirement(
                        object_kind=kind,
                        tier=tier,
                        governing_question=question,
                        applicability="REQUIRED",
                        rationale=rationale,
                        mechanized=False,
                        status="UNKNOWN",
                        coordinate=f"{coordinate_base}.1",
                        mechanized_route=None,
                    )
                )
    return slots


def slot_inventory() -> list[dict[str, Any]]:
    """Return the serialized 234-slot inventory records."""
    return [slot.to_dict() for slot in build_234_inventory()]


def get_slot(object_kind: str | ObjectKind, tier: int | MetaTier) -> SlotRequirement:
    """Look up a single slot by object kind and meta-tier."""
    target_kind = ObjectKind(object_kind) if isinstance(object_kind, str) else object_kind
    target_tier = MetaTier(tier) if isinstance(tier, int) else tier
    for slot in build_234_inventory():
        if slot.object_kind == target_kind and slot.tier == target_tier:
            return slot
    raise KeyError(f"No slot found for {target_kind.value}-{target_tier.value}")


__all__ = [
    "GOVERNING_QUESTIONS",
    "MECHANIZED_12_POINT_BINDINGS",
    "OBJECT_DESCRIPTIONS",
    "SCHEMA_VERSION",
    "SlotRequirement",
    "build_234_inventory",
    "get_slot",
    "slot_inventory",
]
