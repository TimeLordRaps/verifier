"""Verifier Standard (VSTD) certifier declarations, not native issuance evidence.

JavaScript Object Notation (JSON) round trips retain certificate-issuance capability
without adding a component kind or authenticating authority. Fixtures never issue
certificates or execute the retained implementation bytes.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

import pytest

from verifier.interoperability.catalog import (
    CATALOG_SCHEMA_VERSION, CatalogError, ComponentAvailability, ComponentKind,
    ComponentLifecycle, InteractionMode, InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from verifier.interoperability.control_surface import (
    CandidateStatus, ControlSurfaceContext, SurfaceAnalysis, SurfaceHole,
    SurfaceHoleKind, plan_validation,
)
from verifier.interoperability.storage import (
    COMPONENT_PACKAGE_SCHEMA_VERSION, ComponentPackageError, ImplementationBinding,
    PackageArtifact, StoredComponentPackage, load_component_package, save_component_package,
)

ISSUANCE = "relation:certificate-issuance"
MECHANISM = "mechanism:test-certificate-issuer"


def _descriptor(kind: ComponentKind = ComponentKind.WORKFLOW) -> InteroperabilityComponentDescriptor:
    return InteroperabilityComponentDescriptor(
        component_id="component:test-certifier", label="Declared test certifier",
        kind=kind, lifecycle=ComponentLifecycle.EXPERIMENTAL,
        implementation_ref="uninstalled_test_certifier:issue",
        accepted_schema_ids=("TEST-CERTIFICATE-REQUEST-1",),
        planning_surface_schema_ids=("VSTD-2",),
        native_objects=("certifier", "test certificate artifact"),
        native_inputs=("exact subject digest, assertion, and declared certification basis",),
        native_outputs=("test certificate artifact",),
        emitted_schema_ids=("TEST-CERTIFICATE-1",),
        native_result_vocabulary=("ISSUED", "REFUSED", "UNKNOWN"),
        supported_relations=(ISSUANCE,), mechanism_ids=(MECHANISM,),
        interaction_modes=(InteractionMode.STATIC,), domain_tags=("certifier",),
        execution_prerequisites=("AUTHORIZED_CERTIFICATE_ISSUANCE",),
        availability=ComponentAvailability.NOT_CHECKED,
        claim_boundary="Test declaration only; issuance is not proof or issuer authority.",
    )


def _analysis() -> SurfaceAnalysis:
    """Isolate exact planner matching over one declared, unevidenced surface hole."""
    return SurfaceAnalysis(
        geometry_id="geometry:test-certificate-issuance",
        geometry_digest=hashlib.sha256(b"declared certifier planning fixture").hexdigest(),
        context=ControlSurfaceContext(authority_requirements=("ISSUER_AUTHORIZATION",)),
        validity_errors=(), ordinary_closed=False, self_closed=False,
        ordinary_blockers=("certificate not issued",), self_closure_blockers=(),
        holes=(SurfaceHole(
            hole_id="hole:test-certificate-issuance", kind=SurfaceHoleKind.MISSING_JUDGMENT,
            source_kind="COORDINATE", source_id="coordinate:test-issuance",
            native_status="UNKNOWN", description="No certificate issuance evidence supplied.",
            blocks_ordinary_closure=True, blocks_self_closure=True,
            schema_id="VSTD-2", interaction_mode=InteractionMode.STATIC,
            required_relations=(ISSUANCE,), mechanism_ids=(MECHANISM,),
        ),),
    )


def _package(descriptor: InteroperabilityComponentDescriptor) -> StoredComponentPackage:
    return StoredComponentPackage(
        package_id="package:test-certifier", package_version="test-1",
        publisher="unsigned test declaration", license="test declaration only",
        description="Serialization fixture, not an implemented or qualified certifier.",
        registry=InteroperabilityComponentRegistry("test-1", (descriptor,)),
        artifacts=(PackageArtifact(
            "src/certifier.py", "text/x-python", b"raise AssertionError('must not execute')\n",
        ),),
        implementations=(ImplementationBinding(
            descriptor.component_id, descriptor.implementation_ref, ("src/certifier.py",),
        ),),
    )


@pytest.mark.parametrize("kind", [ComponentKind.WORKFLOW, ComponentKind.PROVER])
def test_certifier_capability_survives_strict_catalog_and_package_roundtrip(
    kind: ComponentKind, tmp_path: Path,
) -> None:
    descriptor = _descriptor(kind)
    package = _package(descriptor)
    registry = InteroperabilityComponentRegistry.from_dict(
        json.loads(package.registry.canonical_json_bytes())
    )
    assert registry == package.registry
    assert registry.get(descriptor.component_id).to_dict() == descriptor.to_dict()
    assert registry.schema_version == CATALOG_SCHEMA_VERSION == "VSTD-INTEROPERABILITY-CATALOG-1.1"
    assert package.schema_version == COMPONENT_PACKAGE_SCHEMA_VERSION == "VSTD-COMPONENT-PACKAGE-1"
    path = tmp_path / "certifier.json"
    save_component_package(package, path)
    loaded = load_component_package(path, expected_digest=package.canonical_digest())
    assert loaded == package
    assert loaded.artifacts[0].content == package.artifacts[0].content
    plan = plan_validation(_analysis(), loaded.registry, package=loaded)
    assert plan.binding_scope == "STORED_PACKAGE"
    assert plan.package_digest == loaded.canonical_digest()
    candidate, = plan.candidates
    assert candidate.component_id == descriptor.component_id
    assert candidate.relation_id == ISSUANCE and candidate.mechanism_id == MECHANISM
    assert candidate.status is CandidateStatus.BLOCKED
    assert "component availability is NOT_CHECKED" in candidate.blockers
    assert not (tmp_path / "src").exists()
    assert "uninstalled_test_certifier" not in sys.modules


@pytest.mark.parametrize("changes", [
    {"supported_relations": ()},
    {"supported_relations": ("relation:proof-search",)},
    {"mechanism_ids": ("mechanism:test-proof-search",)},
    {"planning_surface_schema_ids": ("TEST-OTHER-SURFACE-1",)},
    {"interaction_modes": (InteractionMode.OFFLINE_REPLAY,)},
], ids=["missing-issuance", "wrong-relation", "wrong-mechanism", "wrong-planning-schema", "wrong-mode"])
def test_prover_kind_and_certifier_metadata_cannot_replace_exact_capability(changes: dict) -> None:
    descriptor = replace(_descriptor(ComponentKind.PROVER), **changes)
    assert "certifier" in descriptor.native_objects
    assert descriptor.emitted_schema_ids == ("TEST-CERTIFICATE-1",)
    registry = InteroperabilityComponentRegistry("test-1", (descriptor,))
    assert not registry.match_exact(
        schema_id="VSTD-2", interaction_mode=InteractionMode.STATIC,
        relation_id=ISSUANCE, mechanism_id=MECHANISM,
    )
    candidate, = plan_validation(_analysis(), registry).candidates
    assert candidate.status is CandidateStatus.UNMATCHED
    assert candidate.component_id is None


def test_declared_availability_and_certificate_metadata_do_not_grant_authority() -> None:
    descriptor = replace(_descriptor(), availability=ComponentAvailability.AVAILABLE)
    package = _package(descriptor)
    plan = plan_validation(_analysis(), package.registry, package=package)
    candidate, = plan.candidates
    assert candidate.status is CandidateStatus.CANDIDATE
    assert "AUTHORITY:ISSUER_AUTHORIZATION" in candidate.execution_prerequisites
    assert "AUTHORIZED_CERTIFICATE_ISSUANCE" in candidate.execution_prerequisites
    assert plan.plan_only and not plan.execution_performed
    assert candidate.plan_only and not candidate.execution_performed
    inspection = package.inspect()
    assert inspection["integrity_result"] == "PASS"
    assert inspection["native_qualification"] == "NOT_ESTABLISHED"
    assert "unsigned declarations" in inspection["claim_boundary"]
    assert "authority" in plan.claim_boundary
    assert "uninstalled_test_certifier" not in sys.modules


def test_certifier_does_not_silently_extend_closed_kind_vocabulary() -> None:
    descriptor = _descriptor().to_dict()
    descriptor["kind"] = "CERTIFIER"
    with pytest.raises(CatalogError):
        InteroperabilityComponentDescriptor.from_dict(descriptor)
    payload = _package(_descriptor()).to_dict()
    payload["registry"]["components"][0]["kind"] = "CERTIFIER"
    with pytest.raises(ComponentPackageError, match="invalid stored component registry"):
        StoredComponentPackage.from_dict(payload)
