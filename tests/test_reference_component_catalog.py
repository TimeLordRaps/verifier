"""Terminology: application programming interface (API);
Supply Chain Integrity, Transparency, and Trust (SCITT); Verifier Standard (VSTD).

Characterization tests for the shipped first-party planning catalog.
"""

from __future__ import annotations

import hashlib
import json
from importlib import import_module
from inspect import signature
from pathlib import Path
from typing import get_origin, get_type_hints

import pytest

from verifier.artifact_control import ArtifactVerification
from verifier.core.geometry import VerificationGeometry
from verifier.core.geometry_io import GeometryLoadError
from verifier.core.kernel import KernelOutcome, KernelResult
from verifier.core.witness import WitnessCorroborationResult, WitnessResultStatus
from verifier.data.assurance import AssuranceFlowError, AssuranceLedger
from verifier.data.models import ProvenanceHypergraph
from verifier.interoperability import ComponentKind, ComponentLifecycle, InteractionMode
from verifier.interoperability.network import (
    SiloComposition,
    SiloCompositionAssessmentReceipt,
)
from verifier.interoperability.reference_catalog import (
    REFERENCE_CATALOG_VERSION,
    reference_component_registry,
)


def _resolve(reference: str) -> object:
    module_name, separator, attribute_path = reference.partition(":")
    assert separator and module_name and attribute_path
    value: object = import_module(module_name)
    for attribute in attribute_path.split("."):
        value = getattr(value, attribute)
    return value


def test_reference_catalog_has_nineteen_explicit_families_and_real_entry_points() -> None:
    registry = reference_component_registry()
    families = {
        family
        for component in registry.components
        for family in component.verifier_family_ids
    }

    assert registry.registry_version == REFERENCE_CATALOG_VERSION
    assert len(registry.components) == 43
    assert len(families) == 19
    assert families == {
        "artifact-control",
        "artifact-network",
        "vstd-bounded-completeness",
        "vstd-deriver-self-status",
        "vstd-global-cycle",
        "vstd-relation-boundary",
        "vstd-runtime-authority",
        "vstd-source-grounding",
        "generic-run",
        "platform-comparison",
        "provenance-policy",
        "vstd-1-sat-grounding",
        "vstd-2-geometry",
        "vstd-3-hardware",
        "vstd-4-evidence-bound",
        "vstd-5-witness",
        "vstd-graph",
        "vstd-graph-assurance",
        "vstd-scitt-composition",
    }
    assert all(_resolve(component.implementation_ref) is not None for component in registry.components)


@pytest.mark.parametrize(
    ("component_id", "implementation_ref", "family_id", "kind", "mode", "relation_id", "mechanism_id"),
    (
        (
            "component:artifact-network-source-grounding-assessor",
            "verifier.interoperability.source_grounding:qualify_source_grounding",
            "vstd-source-grounding",
            ComponentKind.CHECKER,
            InteractionMode.OFFLINE_REPLAY,
            "relation:assesses-source-grounding",
            "mechanism:source-grounding-assessment",
        ),
        (
            "component:artifact-network-source-grounding-receipt-rechecker",
            "verifier.interoperability.source_grounding:recheck_source_grounding_receipt",
            "vstd-source-grounding",
            ComponentKind.CHECKER,
            InteractionMode.OFFLINE_REPLAY,
            "relation:rechecks-source-grounding-receipt",
            "mechanism:source-grounding-receipt-recheck",
        ),
        (
            "component:artifact-network-relation-boundary-assessor",
            "verifier.interoperability.relation_boundary:qualify_relation_boundary",
            "vstd-relation-boundary",
            ComponentKind.CHECKER,
            InteractionMode.OFFLINE_REPLAY,
            "relation:assesses-relation-boundary",
            "mechanism:relation-boundary-assessment",
        ),
        (
            "component:artifact-network-relation-boundary-receipt-rechecker",
            "verifier.interoperability.relation_boundary:recheck_relation_boundary_receipt",
            "vstd-relation-boundary",
            ComponentKind.CHECKER,
            InteractionMode.OFFLINE_REPLAY,
            "relation:rechecks-relation-boundary-receipt",
            "mechanism:relation-boundary-receipt-recheck",
        ),
        (
            "component:artifact-network-deriver-session-recorder",
            "verifier.interoperability.deriver_self_status:record_deriver_session",
            "vstd-deriver-self-status",
            ComponentKind.COLLECTOR,
            InteractionMode.LIVE_MUTATING,
            "relation:records-deriver-session",
            "mechanism:bounded-deriver-session-recording",
        ),
        (
            "component:artifact-network-deriver-self-status-rechecker",
            "verifier.interoperability.deriver_self_status:recheck_deriver_self_status",
            "vstd-deriver-self-status",
            ComponentKind.CHECKER,
            InteractionMode.LIVE_MUTATING,
            "relation:rechecks-deriver-session-receipt",
            "mechanism:deriver-self-status-recheck",
        ),
        (
            "component:artifact-network-global-cycle-assessor",
            "verifier.interoperability.global_cycle_assessment:assess_global_cycles",
            "vstd-global-cycle",
            ComponentKind.CHECKER,
            InteractionMode.OFFLINE_REPLAY,
            "relation:assesses-global-cycles",
            "mechanism:grounded-global-cycle-assessment",
        ),
        (
            "component:artifact-network-global-cycle-receipt-rechecker",
            "verifier.interoperability.global_cycle_assessment:recheck_global_cycle_receipt",
            "vstd-global-cycle",
            ComponentKind.CHECKER,
            InteractionMode.OFFLINE_REPLAY,
            "relation:rechecks-global-cycle-receipt",
            "mechanism:global-cycle-receipt-recheck",
        ),
        (
            "component:artifact-network-bounded-completeness-assessor",
            "verifier.interoperability.bounded_completeness:assess_bounded_completeness",
            "vstd-bounded-completeness",
            ComponentKind.CHECKER,
            InteractionMode.OFFLINE_REPLAY,
            "relation:assesses-bounded-completeness",
            "mechanism:bounded-completeness-assessment",
        ),
        (
            "component:artifact-network-bounded-completeness-receipt-rechecker",
            "verifier.interoperability.bounded_completeness:recheck_bounded_completeness_receipt",
            "vstd-bounded-completeness",
            ComponentKind.CHECKER,
            InteractionMode.OFFLINE_REPLAY,
            "relation:rechecks-bounded-completeness-receipt",
            "mechanism:bounded-completeness-receipt-recheck",
        ),
        (
            "component:artifact-network-runtime-authority-correspondence-assessor",
            "verifier.interoperability.runtime_authority_correspondence:build_runtime_authority_correspondence_receipt",
            "vstd-runtime-authority",
            ComponentKind.CHECKER,
            InteractionMode.LIVE_MUTATING,
            "relation:assesses-runtime-authority-correspondence",
            "mechanism:runtime-authority-correspondence-assessment",
        ),
        (
            "component:artifact-network-runtime-authority-correspondence-receipt-rechecker",
            "verifier.interoperability.runtime_authority_correspondence:recheck_runtime_authority_correspondence_receipt",
            "vstd-runtime-authority",
            ComponentKind.CHECKER,
            InteractionMode.LIVE_MUTATING,
            "relation:rechecks-runtime-authority-correspondence-receipt",
            "mechanism:runtime-authority-correspondence-receipt-recheck",
        ),
    ),
)
def test_mechanism_obligation_descriptors_are_role_accurate_and_exactly_matchable(
    component_id: str,
    implementation_ref: str,
    family_id: str,
    kind: ComponentKind,
    mode: InteractionMode,
    relation_id: str,
    mechanism_id: str,
) -> None:
    registry = reference_component_registry()
    component = registry.get(component_id)

    assert component.implementation_ref == implementation_ref
    assert component.verifier_family_ids == (family_id,)
    assert component.kind is kind
    assert component.lifecycle is ComponentLifecycle.EXPERIMENTAL
    assert component.interaction_modes == (mode,)
    assert component.supported_relations == (relation_id,)
    assert component.mechanism_ids == (mechanism_id,)
    assert registry.match_exact(
        schema_id="VSTD-2",
        interaction_mode=mode,
        relation_id=relation_id,
        mechanism_id=mechanism_id,
    ) == (component,)


def test_mechanism_obligation_profile_digests_match_current_native_profiles() -> None:
    source = import_module("verifier.interoperability.source_grounding")
    relation = import_module("verifier.interoperability.relation_boundary")
    deriver = import_module("verifier.interoperability.deriver_self_status")
    completeness = import_module("verifier.interoperability.bounded_completeness")
    runtime = import_module("verifier.interoperability.runtime_authority_correspondence")
    registry = reference_component_registry()
    expected = {
        "vstd-source-grounding": source.source_grounding_mechanism_profile_digest(),
        "vstd-relation-boundary": relation.relation_boundary_mechanism_profile_digest(),
        "vstd-deriver-self-status": "sha256:"
        + hashlib.sha256(deriver.checker_profile_bytes()).hexdigest(),
        "vstd-bounded-completeness": completeness.mechanism_profile_digest(),
        "vstd-runtime-authority": runtime.runtime_authority_profile_digest(),
    }

    for component in registry.components:
        family_id = component.verifier_family_ids[0]
        if family_id in expected:
            assert expected[family_id] in component.native_versions


def test_planning_surfaces_are_separate_from_native_input_schemas() -> None:
    registry = reference_component_registry()

    assert all(
        component.planning_surface_schema_ids == ("VSTD-2",)
        for component in registry.components
    )
    assert all(component.native_inputs for component in registry.components)
    typed_or_unversioned = {
        component.component_id
        for component in registry.components
        if not component.accepted_schema_ids
    }
    assert "component:vstd1-independent-auditor" in typed_or_unversioned
    assert "component:vstd3-receipt-validator" in typed_or_unversioned
    assert any(
        "unversioned" in native_input
        for component in registry.components
        for native_input in component.native_inputs
    )
    assert registry.get("component:vstd2-geometry-loader").accepted_schema_ids == (
        "VSTD-2",
    )


def test_only_native_parsers_declare_serialized_schema_acceptance() -> None:
    registry = reference_component_registry()
    declared = {
        component.component_id: component.accepted_schema_ids
        for component in registry.components
        if component.accepted_schema_ids
    }

    assert declared == {
        "component:artifact-bundle-verifier": (
            "verifier-artifact-freeze-1",
            "verifier-artifact-seal-1",
        ),
        "component:artifact-network-transfer-materializer": (
            "verifier-silo-transfer-1",
        ),
        "component:artifact-network-authority-composition-assessor": (
            "verifier-finite-authority-composition-1",
        ),
        "component:artifact-network-bounded-completeness-assessor": (
            "verifier-bounded-completeness-1",
            "verifier-bounded-completeness-denominator-1",
            "verifier-bounded-completeness-observations-1",
            "verifier-source-grounding-1",
            "verifier-source-grounding-receipt-1",
        ),
        "component:artifact-network-bounded-completeness-receipt-rechecker": (
            "verifier-bounded-completeness-1",
            "verifier-bounded-completeness-denominator-1",
            "verifier-bounded-completeness-observations-1",
            "verifier-bounded-completeness-receipt-1",
            "verifier-source-grounding-1",
            "verifier-source-grounding-receipt-1",
        ),
        "component:artifact-network-finite-composition-qualifier": (
            "verifier-finite-authority-composition-1",
            "verifier-silo-commit-1",
        ),
        "component:artifact-network-composition-declaration-decoder": (
            "verifier-silo-composition-1",
        ),
        "component:artifact-network-composition-receipt-rechecker": (
            "verifier-silo-composition-assessment-receipt-1",
        ),
        "component:artifact-network-deriver-self-status-rechecker": (
            "verifier-deriver-self-status-1",
            "verifier-deriver-self-status-receipt-1",
        ),
        "component:artifact-network-deriver-session-recorder": (
            "verifier-deriver-self-status-1",
        ),
        "component:artifact-network-proposition-transfer-assessor": (
            "verifier-proposition-transfer-1",
        ),
        "component:artifact-network-proposition-transfer-rechecker": (
            "verifier-proposition-transfer-1",
            "verifier-proposition-transfer-receipt-1",
        ),
        "component:artifact-network-global-cycle-assessor": (
            "verifier-cycle-relation-semantics-1",
            "verifier-global-cycle-assessment-1",
            "verifier-relation-boundary-receipt-1",
            "verifier-source-grounding-1",
            "verifier-source-grounding-receipt-1",
        ),
        "component:artifact-network-global-cycle-receipt-rechecker": (
            "verifier-cycle-relation-semantics-1",
            "verifier-global-cycle-assessment-1",
            "verifier-global-cycle-assessment-receipt-1",
            "verifier-relation-boundary-receipt-1",
            "verifier-source-grounding-1",
            "verifier-source-grounding-receipt-1",
        ),
        "component:artifact-network-relation-boundary-assessor": (
            "verifier-relation-boundary-1",
            "verifier-relation-boundary-evidence-1",
        ),
        "component:artifact-network-relation-boundary-receipt-rechecker": (
            "verifier-relation-boundary-1",
            "verifier-relation-boundary-evidence-1",
            "verifier-relation-boundary-receipt-1",
        ),
        "component:artifact-network-runtime-authority-correspondence-assessor": (
            "verifier-authority-model-1",
            "verifier-deriver-self-status-1",
            "verifier-deriver-self-status-receipt-1",
            "verifier-runtime-authority-correspondence-1",
            "verifier-runtime-authority-trace-1",
        ),
        "component:artifact-network-runtime-authority-correspondence-receipt-rechecker": (
            "verifier-runtime-authority-correspondence-receipt-1",
        ),
        "component:artifact-network-source-grounding-assessor": (
            "verifier-source-grounding-1",
            "verifier-source-grounding-certificate-1",
        ),
        "component:artifact-network-source-grounding-receipt-rechecker": (
            "verifier-source-grounding-1",
            "verifier-source-grounding-certificate-1",
            "verifier-source-grounding-receipt-1",
        ),
        "component:artifact-network-typed-formation-checker": (
            "verifier-typed-formation-1",
            "verifier-typed-formation-certificate-1",
        ),
        "component:artifact-network-typed-formation-producer": (
            "verifier-typed-formation-1",
        ),
        "component:artifact-network-typed-formation-receipt-rechecker": (
            "verifier-silo-commit-1",
            "verifier-silo-formation-receipt-1",
            "verifier-silo-formation-selection-1",
        ),
        "component:generic-run-validator": ("VSTD-1",),
        "component:platform-run-comparator": ("VSTD-1",),
        "component:vstd-graph-assurance-rechecker": (
            "verifier-graph-assurance-1",
        ),
        "component:vstd-graph-receipt-validator": ("verifier-data-1",),
        "component:vstd2-geometry-loader": ("VSTD-2",),
        "component:vstd4-evidence-rechecker": ("VSTD-4",),
        "component:vstd5-witness-rechecker": ("VSTD-5",),
    }


def test_reference_result_metadata_matches_native_return_contracts() -> None:
    registry = reference_component_registry()

    declaration_decoder = registry.get(
        "component:artifact-network-composition-declaration-decoder"
    )
    assert get_type_hints(_resolve(declaration_decoder.implementation_ref))["return"] is SiloComposition
    receipt_builder = registry.get(
        "component:artifact-network-composition-receipt-builder"
    )
    assert get_type_hints(_resolve(receipt_builder.implementation_ref))["return"] is SiloCompositionAssessmentReceipt
    receipt_rechecker = registry.get(
        "component:artifact-network-composition-receipt-rechecker"
    )
    assert get_type_hints(_resolve(receipt_rechecker.implementation_ref))["return"] is type(None)

    kernel = registry.get("component:vstd4-grounded-certificate-kernel")
    kernel_callable = _resolve(kernel.implementation_ref)
    assert get_type_hints(kernel_callable)["return"] is KernelResult
    assert kernel.native_outputs == (KernelResult.__name__,)
    assert kernel.native_result_vocabulary == tuple(
        sorted(outcome.value for outcome in KernelOutcome)
    )

    witness = registry.get("component:vstd5-witness-rechecker")
    witness_callable = _resolve(witness.implementation_ref)
    assert get_type_hints(witness_callable)["return"] is WitnessCorroborationResult
    assert witness.native_outputs == (WitnessCorroborationResult.__name__,)
    assert witness.native_result_vocabulary == tuple(
        sorted(status.value for status in WitnessResultStatus)
    )

    assurance = registry.get("component:vstd-graph-assurance-rechecker")
    assurance_callable = _resolve(assurance.implementation_ref)
    assert get_type_hints(assurance_callable)["return"] is AssuranceLedger
    assert assurance.native_outputs == (AssuranceLedger.__name__,)
    assert assurance.native_result_vocabulary == ()
    assert "raises AssuranceFlowError" in assurance.failure_behavior

    artifact = registry.get("component:artifact-bundle-verifier")
    assert artifact.native_result_vocabulary == (
        "CONFLICTED",
        "FAIL",
        "FROZEN_UNSEALED",
        "NOT_ESTABLISHED",
        "SEALED",
    )
    assert "INVALID" not in artifact.native_result_vocabulary

    geometry = registry.get("component:vstd2-geometry-loader")
    geometry_callable = _resolve(geometry.implementation_ref)
    assert get_type_hints(geometry_callable)["return"] is VerificationGeometry
    assert geometry.native_result_vocabulary == ()
    assert geometry.emitted_schema_ids == ()

    scitt_consumer = registry.get("component:scitt-evidence-consumer")
    scitt_consumer_callable = _resolve(scitt_consumer.implementation_ref)
    assert get_origin(get_type_hints(scitt_consumer_callable)["return"]) is dict
    assert scitt_consumer.native_outputs == (
        "bounded SCITT transparency evidence mapping",
    )


def test_refutation_relation_is_an_exact_catalog_capability() -> None:
    registry = reference_component_registry()
    relation = "PRODUCES_CHECKABLE_REFUTATION"

    producer = registry.match_exact(
        schema_id="VSTD-2",
        interaction_mode=InteractionMode.STATIC,
        relation_id=relation,
        mechanism_id="mechanism:vstd4-refutation-proof-production",
    )
    checker = registry.match_exact(
        schema_id="VSTD-2",
        interaction_mode=InteractionMode.STATIC,
        relation_id=relation,
        mechanism_id="mechanism:vstd4-refutation-proof-check",
    )

    assert [item.component_id for item in producer] == [
        "component:vstd4-refutation-producer"
    ]
    assert [item.component_id for item in checker] == [
        "component:vstd4-refutation-checker"
    ]


def test_graph_topology_metadata_declares_typed_experimental_bounded_analysis() -> None:
    component = reference_component_registry().get("component:graph-topology-analyzer")

    assert component.kind is ComponentKind.CONSTRAINT
    assert component.lifecycle is ComponentLifecycle.EXPERIMENTAL
    assert component.verifier_family_ids == ("vstd-graph",)
    assert component.implementation_ref == (
        "verifier.interoperability.graph_topology:analyze_graph_topology"
    )
    assert component.accepted_schema_ids == ()
    assert component.planning_surface_schema_ids == ("VSTD-2",)
    assert component.emitted_schema_ids == (
        "verifier-graph-topology-report-experimental-1",
    )
    assert component.native_versions == ("verifier-graph-topology-experimental-1",)
    assert component.native_inputs == (
        "max_assignments bound",
        "typed GraphTopologyContract",
        "typed ProvenanceHypergraph",
    )
    assert component.native_outputs == ("GraphTopologyReport",)
    assert component.native_result_vocabulary == (
        "CONFLICTED", "CONSISTENT", "INVALID", "NOT_ESTABLISHED"
    )
    assert component.supported_relations == ("relation:graph-topology",)
    assert component.mechanism_ids == ("mechanism:graph-topology-analysis",)
    assert component.interaction_modes == (InteractionMode.STATIC,)
    assert "separate facets" in component.failure_behavior
    assert "no aggregate verdict" in component.failure_behavior
    assert "12 variables" in component.failure_behavior
    assert "128 equations" in component.failure_behavior
    assert "4096 assignments" in component.failure_behavior
    assert "loaded separately" in component.transformation_loss
    assert "physical causality" in component.claim_boundary


def test_graph_topology_metadata_matches_the_native_callable_contract() -> None:
    topology = import_module("verifier.interoperability.graph_topology")
    component = reference_component_registry().get("component:graph-topology-analyzer")
    analyzer = _resolve(component.implementation_ref)

    assert get_type_hints(analyzer) == {
        "graph": ProvenanceHypergraph,
        "contract": topology.GraphTopologyContract,
        "max_assignments": int,
        "return": topology.GraphTopologyReport,
    }
    assert signature(analyzer).parameters["max_assignments"].default == 4096
    assert component.native_outputs == (topology.GraphTopologyReport.__name__,)
    assert component.native_versions == (topology.GRAPH_TOPOLOGY_SCHEMA_VERSION,)
    assert component.emitted_schema_ids == (
        topology.GRAPH_TOPOLOGY_REPORT_SCHEMA_VERSION,
    )
    assert component.native_result_vocabulary == tuple(
        sorted(status.value for status in topology.GraphTopologyStatus)
    )
    assert topology.SUPPORTED_CONSTRAINT_LOGIC == "classical-boolean-equations-v1"


def test_untraversability_metadata_matches_the_native_callable_contract() -> None:
    evidence = import_module("verifier.core.evidence")
    untraversable = import_module("verifier.interoperability.untraversable")
    component = reference_component_registry().get(
        "component:composed-untraversability-analyzer"
    )
    analyzer = _resolve(component.implementation_ref)

    assert component.kind is ComponentKind.CONSTRAINT
    assert component.lifecycle is ComponentLifecycle.EXPERIMENTAL
    assert component.verifier_family_ids == ("vstd-graph",)
    assert component.accepted_schema_ids == ()
    assert component.planning_surface_schema_ids == ("VSTD-2",)
    assert component.native_inputs == (
        "VerificationSession",
        "typed ProvenanceHypergraph",
        "typed UntraversableContract",
    )
    assert get_type_hints(analyzer) == {
        "graph": ProvenanceHypergraph,
        "contract": untraversable.UntraversableContract,
        "session": evidence.VerificationSession,
        "return": untraversable.UntraversabilityReport,
    }
    assert component.native_versions == (
        untraversable.UNTRAVERSABLE_SCHEMA_VERSION,
    )
    assert component.emitted_schema_ids == (
        untraversable.UNTRAVERSABLE_REPORT_SCHEMA_VERSION,
    )
    assert component.native_result_vocabulary == tuple(
        sorted(status.value for status in untraversable.UntraversabilityStatus)
    )
    assert component.supported_relations == (
        "relation:composed-untraversability",
    )
    assert component.mechanism_ids == (
        "mechanism:composed-untraversability-analysis",
    )
    assert component.interaction_modes == (
        InteractionMode.OFFLINE_REPLAY,
        InteractionMode.STATIC,
    )
    assert "universal confidentiality" in component.claim_boundary
    assert "exhausted bounds remain UNKNOWN" in component.failure_behavior


@pytest.mark.parametrize(
    ("override", "expected_ids"),
    (
        ({}, ("component:composed-untraversability-analyzer",)),
        ({"relation_id": "relation:composed-Untraversability"}, ()),
        ({"mechanism_id": "mechanism:composed-untraversability"}, ()),
        ({"schema_id": "verifier-untraversable-experimental-1"}, ()),
        ({"interaction_mode": InteractionMode.SIMULATION}, ()),
    ),
    ids=("exact", "relation-case", "mechanism-near-miss", "native-schema", "mode"),
)
def test_untraversability_catalog_matching_is_exact(
    override: dict[str, object], expected_ids: tuple[str, ...]
) -> None:
    query = {
        "schema_id": "VSTD-2",
        "interaction_mode": InteractionMode.STATIC,
        "relation_id": "relation:composed-untraversability",
        "mechanism_id": "mechanism:composed-untraversability-analysis",
    }
    query.update(override)

    matches = reference_component_registry().match_exact(**query)

    assert tuple(component.component_id for component in matches) == expected_ids


@pytest.mark.parametrize(
    ("relation_id", "mechanism_id", "expected_id"),
    (
        (
            "relation:decodes-silo-composition-declaration",
            "mechanism:artifact-network-composition-declaration-decode",
            "component:artifact-network-composition-declaration-decoder",
        ),
        (
            "relation:constructs-silo-composition-assessment-receipt",
            "mechanism:artifact-network-composition-receipt-construction",
            "component:artifact-network-composition-receipt-builder",
        ),
        (
            "relation:rechecks-silo-composition-assessment-receipt",
            "mechanism:artifact-network-composition-receipt-independent-recheck",
            "component:artifact-network-composition-receipt-rechecker",
        ),
    ),
)
def test_artifact_network_composition_planning_matches_only_exact_capabilities(
    relation_id: str, mechanism_id: str, expected_id: str
) -> None:
    registry = reference_component_registry()
    matches = registry.match_exact(
        schema_id="VSTD-2",
        interaction_mode=(
            InteractionMode.STATIC
            if expected_id.endswith("declaration-decoder")
            else InteractionMode.OFFLINE_REPLAY
        ),
        relation_id=relation_id,
        mechanism_id=mechanism_id,
    )

    assert tuple(component.component_id for component in matches) == (expected_id,)
    assert registry.match_exact(
        schema_id="VSTD-2",
        interaction_mode=InteractionMode.OFFLINE_REPLAY,
        relation_id=relation_id,
        mechanism_id=mechanism_id + "-typescript",
    ) == ()


@pytest.mark.parametrize(
    ("override", "expected_ids"),
    (
        ({}, ("component:graph-topology-analyzer",)),
        ({"relation_id": "relation:Graph-topology"}, ()),
        ({"mechanism_id": "mechanism:graph-topology"}, ()),
        ({"mechanism_id": "mechanism:vstd4-grounded-certificate-check"}, ()),
        ({"interaction_mode": InteractionMode.OFFLINE_REPLAY}, ()),
        ({"schema_id": "verifier-graph-topology-experimental-1"}, ()),
        ({"schema_id": "verifier-data-1"}, ()),
    ),
    ids=("exact", "relation-case", "mechanism-near-miss", "other-constraint",
         "mode", "stored-contract-not-planning-schema", "graph-not-planning-schema"),
)
def test_graph_topology_catalog_matching_is_exact(
    override: dict[str, object], expected_ids: tuple[str, ...]
) -> None:
    query = {
        "schema_id": "VSTD-2",
        "interaction_mode": InteractionMode.STATIC,
        "relation_id": "relation:graph-topology",
        "mechanism_id": "mechanism:graph-topology-analysis",
    }
    query.update(override)

    matches = reference_component_registry().match_exact(**query)

    assert tuple(component.component_id for component in matches) == expected_ids


def test_graph_topology_platform_manifest_records_only_configured_intent() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (root / "docs" / "platform-component-contracts.json").read_text(encoding="utf-8")
    )
    records = {
        component["component_id"]: component for component in manifest["components"]
    }
    record = records["component:graph-topology-analyzer"]
    component = reference_component_registry().get(record["component_id"])

    assert len(records) == 43
    assert record["label"] == component.label
    assert record["coverage_kind"] == "BEHAVIOR"
    assert record["dependency_profiles"] == ["test"]
    assert record["catalog_optional_dependencies"] == list(component.optional_dependencies) == []
    assert record["test_modules"] == [
        "tests/test_graph_topology.py", "tests/test_graph_topology_integration.py"
    ]
    assert record["coordinate_intent"] == {
        "linux-x64": "CONFIGURED_UNRUN",
        "windows-x64": "CONFIGURED_UNRUN",
        "macos-x64": "CONFIGURED_UNRUN",
        "macos-arm64": "CONFIGURED_UNRUN",
    }
    assert "physical causality" in record["test_scope"]
    assert "external verifier qualification" in record["test_scope"]


def test_schema_parsers_and_artifact_verifier_fail_closed_on_representative_inputs(
    tmp_path: Path,
) -> None:
    registry = reference_component_registry()

    geometry_callable = _resolve(
        registry.get("component:vstd2-geometry-loader").implementation_ref
    )
    geometry_path = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "verification_geometry_residual"
        / "geometry.json"
    )
    geometry_payload = json.loads(geometry_path.read_text(encoding="utf-8"))
    geometry_payload["schema_version"] = "NOT-VSTD-2"
    with pytest.raises(GeometryLoadError, match="schema_version"):
        geometry_callable(geometry_payload)

    assurance_callable = _resolve(
        registry.get("component:vstd-graph-assurance-rechecker").implementation_ref
    )
    with pytest.raises(AssuranceFlowError, match="not a VSTD-GRAPH assurance log"):
        assurance_callable({"schema_version": "NOT-ASSURANCE"}, mechanisms=())

    artifact_callable = _resolve(
        registry.get("component:artifact-bundle-verifier").implementation_ref
    )
    assert get_type_hints(artifact_callable)["return"] is ArtifactVerification
    artifact_result = artifact_callable(tmp_path / "missing-bundle")
    assert isinstance(artifact_result, ArtifactVerification)
    assert artifact_result.state == "FAIL"


def test_reference_catalog_is_deterministic_and_claim_bounded() -> None:
    first = reference_component_registry()
    second = reference_component_registry()

    assert first.canonical_json_bytes() == second.canonical_json_bytes()
    assert first.canonical_digest() == second.canonical_digest()
    assert all(component.claim_boundary for component in first.components)
    assert all("does not" in component.claim_boundary.lower() for component in first.components)


def test_exact_mechanism_match_does_not_substitute_family_or_case() -> None:
    registry = reference_component_registry()
    matches = registry.match_exact(
        schema_id="VSTD-2",
        interaction_mode=InteractionMode.OFFLINE_REPLAY,
        mechanism_id="mechanism:vstd5-witness-recheck",
    )

    assert [component.component_id for component in matches] == [
        "component:vstd5-witness-rechecker"
    ]
    assert (
        registry.match_exact(
            schema_id="VSTD-2",
            interaction_mode=InteractionMode.OFFLINE_REPLAY,
            mechanism_id="mechanism:VSTD5-witness-recheck",
        )
        == ()
    )


def test_catalog_construction_is_description_only() -> None:
    registry = reference_component_registry()

    assert all(component.execution_prerequisites for component in registry.components)
    assert all(
        "execution" in component.claim_boundary.lower()
        or "run" in component.claim_boundary.lower()
        for component in registry.components
    )
