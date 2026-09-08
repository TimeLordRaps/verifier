"""Verifier Standard (VSTD) stored-package-to-readiness integration contract.

Secure Hash Algorithm 256-bit (SHA-256) digests bind declarations, not execution.
The geometry specimen carries declared judgments; no native result is inferred.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from test_control_surface import self_closed_geometry
from verifier.core.geometry import CoordinateStatus
from verifier.core.geometry_io import load_verification_geometry
from verifier.interoperability.catalog import (
    ComponentAvailability, ComponentKind, ComponentLifecycle, InteractionMode,
    InteroperabilityComponentDescriptor, InteroperabilityComponentRegistry,
)
from verifier.interoperability.control_surface import (
    CandidateStatus, ControlSurfaceContext, SurfaceAnalysis, ValidationPlan, _declared_plan_id,
    analyze_verification_surface, plan_validation,
)
from verifier.interoperability.execution_readiness import (
    AuthorizationDecision, CandidateExecutionDeclaration, ExecutionReadinessReport,
    ExecutionReadinessStatus, NativeInputBinding, PlannedEvidenceMapping,
    PostExecutionReassessmentContract, PrerequisiteResolution,
    RUNTIME_AVAILABILITY_PREREQUISITE, SuppliedAuthorizationDecision,
    assess_execution_readiness,
)
from verifier.interoperability.storage import (
    ComponentPackageError, ImplementationBinding, PackageArtifact, PackageDependency, StoredComponentPackage,
    load_component_package, save_component_package,
)


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _transported_case(tmp_path: Path) -> tuple[StoredComponentPackage, SurfaceAnalysis]:
    component = InteroperabilityComponentDescriptor(
        component_id="component:result", label="Declared ordering checker",
        kind=ComponentKind.CHECKER, lifecycle=ComponentLifecycle.EXPERIMENTAL,
        implementation_ref="uninstalled_contract_checker:check",
        accepted_schema_ids=("ORDERING-1",), planning_surface_schema_ids=("VSTD-2",),
        mechanism_ids=("mechanism:result",), interaction_modes=(InteractionMode.STATIC,),
        native_inputs=("ordering-input",), native_outputs=("ordering-result",),
        optional_dependencies=("runtime:ordering",),
        availability=ComponentAvailability.AVAILABLE,
        claim_boundary="Availability is a declaration; this specimen must never execute.",
    )
    package = StoredComponentPackage(
        package_id="package:ordering", package_version="1", publisher="specimen",
        license="Apache-2.0", description="Transported declaration-only preflight.",
        registry=InteroperabilityComponentRegistry("registry:ordering:1", (component, replace(
            component, component_id="component:unselected", mechanism_ids=("mechanism:other",),
        ))),
        artifacts=(PackageArtifact(
            "checker.py", "text/x-python", b"raise AssertionError('must never execute')\n",
        ), PackageArtifact("runtime.txt", "text/plain", b"retained, not installed\n")),
        implementations=(ImplementationBinding(
            component.component_id, component.implementation_ref, ("checker.py",),
            ("runtime:ordering",),
        ), ImplementationBinding(
            "component:unselected", component.implementation_ref, ("checker.py",),
            ("unselected:tool",),
        )),
        dependencies=(
            PackageDependency("runtime:ordering", "Ordering runtime ==1", ("runtime.txt",)),
            PackageDependency("unselected:tool", "Attached only to the unselected implementation"),
        ),
    )
    path = tmp_path / "component.json"
    save_component_package(package, path)
    transported = load_component_package(path, expected_digest=package.canonical_digest())
    assert transported is not package and transported.registry is not package.registry

    geometry = self_closed_geometry()
    geometry.judgments[0] = replace(
        geometry.judgments[0], status=CoordinateStatus.INDETERMINATE,
    )
    geometry_path = tmp_path / "geometry.json"
    geometry_path.write_text(json.dumps(geometry.to_dict()), encoding="utf-8")
    loaded_geometry = load_verification_geometry(geometry_path)
    analysis = analyze_verification_surface(
        loaded_geometry, ControlSurfaceContext(authority_requirements=("LOCAL_REVIEW",)),
    )
    assert analysis.geometry_digest == geometry.canonical_digest()
    assert len(analysis.holes) == 1
    assert analysis.holes[0].native_status == "INDETERMINATE"
    return transported, analysis


def _declarations(
    analysis: SurfaceAnalysis, plan: ValidationPlan,
) -> tuple[CandidateExecutionDeclaration, SuppliedAuthorizationDecision, PostExecutionReassessmentContract]:
    candidate, = plan.candidates
    hole, = analysis.holes
    assert candidate.component_id is not None
    declaration = CandidateExecutionDeclaration(
        candidate.candidate_id, hole.hole_id, candidate.component_id,
        native_inputs=(NativeInputBinding(
            "input:ordering", candidate.candidate_id, hole.hole_id,
            candidate.component_id, "ordering-input", _digest(b"declared input"),
            "ORDERING-1", "application/json",
        ),),
        evidence_mappings=(PlannedEvidenceMapping(
            "mapping:ordering", candidate.candidate_id, hole.hole_id,
            candidate.component_id, "ordering-result", "evidence:ordering-result:1",
            hole.source_kind, hole.source_id,
        ),),
        prerequisite_resolutions=tuple(
            PrerequisiteResolution(candidate.candidate_id, name, True, _digest(name.encode()))
            for name in sorted({
                name for name in candidate.execution_prerequisites
                if not name.startswith("AUTHORITY:")
            } | {RUNTIME_AVAILABILITY_PREREQUISITE})
        ),
    )
    authorization = SuppliedAuthorizationDecision(
        AuthorizationDecision.AUTHORIZED, ("LOCAL_REVIEW",), _digest(b"caller declaration"),
        plan_digest=_digest(plan.canonical_json_bytes()),
    )
    reassessment = PostExecutionReassessmentContract(
        analysis.geometry_id, analysis.geometry_digest, ("mapping:ordering",),
    )
    return declaration, authorization, reassessment


def _assess(
    package: StoredComponentPackage | None, analysis: SurfaceAnalysis, plan: ValidationPlan,
    registry: InteroperabilityComponentRegistry,
    declaration: CandidateExecutionDeclaration, authorization: SuppliedAuthorizationDecision,
    reassessment: PostExecutionReassessmentContract,
) -> ExecutionReadinessReport:
    return assess_execution_readiness(
        analysis, plan, registry, (declaration,), authorization, reassessment, package=package,
    )


def test_transported_implementation_dependency_cannot_disappear_at_readiness(tmp_path: Path) -> None:
    package, analysis = _transported_case(tmp_path)
    registry_plan = plan_validation(analysis, package.registry)
    plan = plan_validation(analysis, package.registry, package=package)
    declaration, authorization, reassessment = _declarations(analysis, plan)
    required = f"PACKAGE_DEPENDENCY:{package.canonical_digest()}:runtime:ordering"
    missing = replace(declaration, prerequisite_resolutions=tuple(
        item for item in declaration.prerequisite_resolutions if item.prerequisite != required
    ))
    report = _assess(package, analysis, plan, package.registry, missing, authorization, reassessment)
    assert report.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert any(required in finding for finding in report.findings)
    assert required in plan.candidates[0].execution_prerequisites
    assert plan.candidates[0].status is CandidateStatus.CANDIDATE
    assert registry_plan.candidates[0].status is CandidateStatus.CANDIDATE
    assert "DEPENDENCY:runtime:ordering" in plan.candidates[0].execution_prerequisites
    assert not any("unselected:tool" in item for item in plan.candidates[0].execution_prerequisites)
    assert not any(item.startswith("PACKAGE_DEPENDENCY:") for item in registry_plan.candidates[0].execution_prerequisites)

    ready = _assess(package, analysis, plan, package.registry, declaration, authorization, reassessment)
    assert ready.status is ExecutionReadinessStatus.READY
    assert ready.execution_performed is False
    assert ready.authorization_granted_by_module is False
    assert analysis.ordinary_closed is False and analysis.self_closed is False
    assert plan_validation(analysis, package.registry).canonical_json_bytes() == registry_plan.canonical_json_bytes()
    assert {path.name for path in tmp_path.iterdir()} == {"component.json", "geometry.json"}


def test_missing_package_stays_unknown_but_unrecomputed_plan_mutation_is_invalid(tmp_path: Path) -> None:
    package, analysis = _transported_case(tmp_path)
    plan = plan_validation(analysis, package.registry, package=package)
    declaration, authorization, reassessment = _declarations(analysis, plan)
    missing = _assess(None, analysis, plan, package.registry, declaration, authorization, reassessment)
    assert missing.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert any("exact stored package" in item for item in missing.findings)
    candidate, = plan.candidates
    for added in (
        "INVENTED_RUNTIME_PERMISSION",
        f"PACKAGE_DEPENDENCY:{'0' * 64}:runtime:ordering",
        f"PACKAGE_DEPENDENCY:{package.canonical_digest()}:invented",
    ):
        forged = replace(plan, candidates=(replace(
            candidate, execution_prerequisites=(*candidate.execution_prerequisites, added),
        ),))
        invalid = _assess(None, analysis, forged, package.registry, declaration, authorization, reassessment)
        assert invalid.status is ExecutionReadinessStatus.INVALID
        assert any("inconsistent with exact replanning" in item for item in invalid.findings)


@pytest.mark.parametrize("change", ["package-add", "package-drop", "registry-drop"])
def test_recomputed_plan_and_authority_cannot_authenticate_package_obligations(
    change: str, tmp_path: Path,
) -> None:
    package, analysis = _transported_case(tmp_path)
    plan = plan_validation(analysis, package.registry, package=package)
    candidate, = plan.candidates
    prerequisites = candidate.execution_prerequisites
    if change == "package-add":
        prerequisites = (*prerequisites, f"PACKAGE_DEPENDENCY:{plan.package_digest}:invented")
    else:
        removed = (
            f"PACKAGE_DEPENDENCY:{plan.package_digest}:runtime:ordering"
            if change == "package-drop" else "RESOURCE_BOUNDS"
        )
        prerequisites = tuple(item for item in prerequisites if item != removed)
    forged_candidates = (replace(candidate, execution_prerequisites=prerequisites),)
    forged = replace(plan, candidates=forged_candidates, plan_id=_declared_plan_id(
        analysis, package.registry, forged_candidates, package.canonical_digest(),
    ))
    declaration, authorization, reassessment = _declarations(analysis, forged)
    assert authorization.plan_digest == _digest(forged.canonical_json_bytes())
    present = _assess(package, analysis, forged, package.registry, declaration, authorization, reassessment)
    assert present.status is ExecutionReadinessStatus.INVALID
    assert any("inconsistent with exact replanning" in item for item in present.findings)
    absent = _assess(None, analysis, forged, package.registry, declaration, authorization, reassessment)
    assert absent.status is (
        ExecutionReadinessStatus.INVALID if change == "registry-drop"
        else ExecutionReadinessStatus.NOT_ESTABLISHED
    )
    assert absent.execution_performed is False and absent.authorization_granted_by_module is False


def test_duplicate_package_dependency_references_are_rejected_before_planning(tmp_path: Path) -> None:
    package, _ = _transported_case(tmp_path)
    binding = next(item for item in package.implementations if item.component_id == "component:result")
    with pytest.raises(ComponentPackageError, match="duplicate references"):
        replace(binding, dependency_ids=("runtime:ordering", "runtime:ordering"))


@pytest.mark.parametrize("changed", ["implementation", "dependency", "registry", "geometry"])
def test_changed_transported_coordinate_invalidates_old_plan(
    changed: str, tmp_path: Path,
) -> None:
    package, analysis = _transported_case(tmp_path)
    plan = plan_validation(analysis, package.registry, package=package)
    declaration, authorization, reassessment = _declarations(analysis, plan)
    if changed == "implementation":
        package = replace(package, artifacts=tuple(
            replace(item, content=b"different retained implementation") if item.path == "checker.py" else item
            for item in package.artifacts
        ))
    elif changed == "dependency":
        package = replace(package, dependencies=tuple(
            replace(item, requirement="Ordering runtime ==2") if item.dependency_id == "runtime:ordering" else item
            for item in package.dependencies
        ))
    elif changed == "registry":
        package = replace(package, registry=replace(package.registry, registry_version="registry:ordering:2"))
    else:
        geometry = load_verification_geometry(tmp_path / "geometry.json")
        geometry.judgments[0] = replace(geometry.judgments[0], status=CoordinateStatus.STALE)
        analysis = analyze_verification_surface(geometry, analysis.context)
    new_plan = plan_validation(analysis, package.registry, package=package)
    assert new_plan.canonical_json_bytes() != plan.canonical_json_bytes()
    assert _assess(package, analysis, plan, package.registry, declaration, authorization, reassessment).status is ExecutionReadinessStatus.INVALID
    fresh_declaration, _, fresh_reassessment = _declarations(analysis, new_plan)
    stale_authority = _assess(
        package, analysis, new_plan, package.registry,
        fresh_declaration, authorization, fresh_reassessment,
    )
    assert stale_authority.status is ExecutionReadinessStatus.INVALID
    assert any("authorization plan binding" in item for item in stale_authority.findings)


def test_transported_package_never_supplies_missing_permission(tmp_path: Path) -> None:
    package, analysis = _transported_case(tmp_path)
    plan = plan_validation(analysis, package.registry, package=package)
    declaration, authorization, reassessment = _declarations(analysis, plan)
    report = _assess(package, analysis, plan, package.registry, declaration, replace(
        authorization, decision=AuthorizationDecision.UNKNOWN, decision_evidence_sha256=None,
    ), reassessment)
    assert report.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert report.execution_performed is False and report.authorization_granted_by_module is False
