"""Terminology: application programming interface (API);
Supply Chain Integrity, Transparency, and Trust (SCITT); Verifier Standard (VSTD).

Characterization tests for the shipped first-party planning catalog.
"""

from __future__ import annotations

import json
from importlib import import_module
from pathlib import Path
from typing import get_origin, get_type_hints

import pytest

from verifier.artifact_control import ArtifactVerification
from verifier.core.geometry import VerificationGeometry
from verifier.core.geometry_io import GeometryLoadError
from verifier.core.kernel import KernelOutcome, KernelResult
from verifier.core.witness import WitnessCorroborationResult, WitnessResultStatus
from verifier.data.assurance import AssuranceFlowError, AssuranceLedger
from verifier.interoperability import InteractionMode
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


def test_reference_catalog_has_twelve_explicit_families_and_real_entry_points() -> None:
    registry = reference_component_registry()
    families = {
        family
        for component in registry.components
        for family in component.verifier_family_ids
    }

    assert registry.registry_version == REFERENCE_CATALOG_VERSION
    assert len(registry.components) == 17
    assert len(families) == 12
    assert families == {
        "artifact-control",
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
            "VSTD-ARTIFACT-FREEZE-1",
            "VSTD-ARTIFACT-SEAL-1",
        ),
        "component:generic-run-validator": ("VSTD-1",),
        "component:platform-run-comparator": ("VSTD-1",),
        "component:vstd-graph-assurance-rechecker": (
            "VSTD-GRAPH-ASSURANCE-1",
        ),
        "component:vstd-graph-receipt-validator": ("VSTD-DATA-0.1",),
        "component:vstd2-geometry-loader": ("VSTD-2",),
        "component:vstd4-evidence-rechecker": ("VSTD-4",),
        "component:vstd5-witness-rechecker": ("VSTD-5",),
    }


def test_reference_result_metadata_matches_native_return_contracts() -> None:
    registry = reference_component_registry()

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
    with pytest.raises(AssuranceFlowError, match="not a VSTD-Graph assurance log"):
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
