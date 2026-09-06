"""Terminology: Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Adversarial tests for experimental, nonexecuting execution-readiness preflight.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from verifier.interoperability.catalog import (
    ComponentAvailability,
    ComponentKind,
    ComponentLifecycle,
    InteractionMode,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from verifier.interoperability.control_surface import (
    CandidateStatus,
    ControlSurfaceContext,
    SurfaceAnalysis,
    SurfaceAnalysisError,
    SurfaceHole,
    SurfaceHoleKind,
    ValidationPlan,
    plan_validation,
)
from verifier.interoperability.execution_readiness import (
    AuthorizationDecision,
    CandidateExecutionDeclaration,
    ExecutionReadinessError,
    ExecutionReadinessReport,
    ExecutionReadinessStatus,
    NativeInputBinding,
    PlannedEvidenceMapping,
    PostExecutionReassessmentContract,
    PrerequisiteResolution,
    RUNTIME_AVAILABILITY_PREREQUISITE,
    SuppliedAuthorizationDecision,
    assess_execution_readiness,
)
from verifier.interoperability.storage import (
    ImplementationBinding,
    PackageArtifact,
    StoredComponentPackage,
)


SENTINEL_CALLS = 0
GEOMETRY_DIGEST = hashlib.sha256(b"geometry").hexdigest()
EVIDENCE_DIGEST = hashlib.sha256(b"evidence").hexdigest()
INPUT_DIGEST = hashlib.sha256(b"native input").hexdigest()


def sentinel_component(_: object) -> str:
    """Fail the test contract if readiness preflight ever invokes this callable."""

    global SENTINEL_CALLS
    SENTINEL_CALLS += 1
    raise AssertionError("execution-readiness preflight invoked component code")


def _component(
    *,
    component_id: str = "component:sentinel",
    accepted_schema_ids: tuple[str, ...] = ("NATIVE-SENTINEL-1",),
    availability: ComponentAvailability = ComponentAvailability.AVAILABLE,
) -> InteroperabilityComponentDescriptor:
    return InteroperabilityComponentDescriptor(
        component_id=component_id,
        label="Sentinel verifier",
        kind=ComponentKind.VERIFIER,
        lifecycle=ComponentLifecycle.EXPERIMENTAL,
        implementation_ref="tests.test_execution_readiness:sentinel_component",
        accepted_schema_ids=accepted_schema_ids,
        planning_surface_schema_ids=("VSTD-2",),
        native_system="sentinel",
        native_objects=("sentinel-native-object",),
        native_versions=("sentinel-1",),
        native_inputs=("sentinel-native-input",),
        native_outputs=("sentinel-native-result",),
        native_result_vocabulary=("ACCEPTED", "REJECTED"),
        mechanism_ids=("mechanism:sentinel",),
        interaction_modes=(InteractionMode.STATIC,),
        execution_prerequisites=("EXACT_NATIVE_INPUT", "RESOURCE_BOUNDS"),
        freshness_behavior="Caller supplies a current input digest.",
        transformation_loss="No input bytes are read during preflight.",
        failure_behavior="The native verifier may reject after execution.",
        availability=availability,
        claim_boundary="Catalog membership does not execute or validate the sentinel.",
    )


def _analysis() -> SurfaceAnalysis:
    context = ControlSurfaceContext(
        schema_id="VSTD-2",
        interaction_mode=InteractionMode.STATIC,
        authority_requirements=("LOCAL_REVIEW",),
    )
    hole = SurfaceHole(
        hole_id="hole:sentinel",
        kind=SurfaceHoleKind.MECHANISM,
        source_kind="COORDINATE",
        source_id="coordinate:sentinel",
        native_status="UNVERIFIED",
        description="The sentinel mechanism has not run.",
        blocks_ordinary_closure=True,
        blocks_self_closure=True,
        schema_id="VSTD-2",
        interaction_mode=InteractionMode.STATIC,
        mechanism_ids=("mechanism:sentinel",),
    )
    return SurfaceAnalysis(
        geometry_id="geometry:sentinel",
        geometry_digest=GEOMETRY_DIGEST,
        context=context,
        validity_errors=(),
        ordinary_closed=False,
        self_closed=False,
        ordinary_blockers=("sentinel not checked",),
        self_closure_blockers=("sentinel not checked",),
        holes=(hole,),
    )


def _case(
    *,
    component: InteroperabilityComponentDescriptor | None = None,
) -> tuple[
    SurfaceAnalysis,
    InteroperabilityComponentRegistry,
    object,
    CandidateExecutionDeclaration,
    SuppliedAuthorizationDecision,
    PostExecutionReassessmentContract,
]:
    analysis = _analysis()
    registry = InteroperabilityComponentRegistry(
        "registry:sentinel:1", (component or _component(),)
    )
    plan = plan_validation(analysis, registry)
    candidate = next(
        item for item in plan.candidates if item.status is CandidateStatus.CANDIDATE
    )
    native_input = NativeInputBinding(
        binding_id="input:sentinel",
        candidate_id=candidate.candidate_id,
        hole_id=candidate.hole_id,
        component_id=candidate.component_id or "",
        native_input_contract="sentinel-native-input",
        input_sha256=INPUT_DIGEST,
        schema_id="NATIVE-SENTINEL-1",
        media_type="application/json",
    )
    mapping = PlannedEvidenceMapping(
        mapping_id="mapping:sentinel",
        candidate_id=candidate.candidate_id,
        hole_id=candidate.hole_id,
        component_id=candidate.component_id or "",
        native_output_contract="sentinel-native-result",
        evidence_contract="evidence:sentinel-result:1",
        target_source_kind="COORDINATE",
        target_source_id="coordinate:sentinel",
    )
    prerequisites = tuple(
        PrerequisiteResolution(
            candidate_id=candidate.candidate_id,
            prerequisite=prerequisite,
            resolved=True,
            evidence_sha256=EVIDENCE_DIGEST,
        )
        for prerequisite in sorted(
            {
                item
                for item in candidate.execution_prerequisites
                if not item.startswith("AUTHORITY:")
            }
            | {RUNTIME_AVAILABILITY_PREREQUISITE}
        )
    )
    declaration = CandidateExecutionDeclaration(
        candidate_id=candidate.candidate_id,
        hole_id=candidate.hole_id,
        component_id=candidate.component_id or "",
        native_inputs=(native_input,),
        evidence_mappings=(mapping,),
        prerequisite_resolutions=prerequisites,
    )
    authorization = SuppliedAuthorizationDecision(
        decision=AuthorizationDecision.AUTHORIZED,
        authority_requirements=("LOCAL_REVIEW",),
        decision_evidence_sha256=EVIDENCE_DIGEST,
        reason="The caller supplied a bounded local authorization decision.",
    )
    reassessment = PostExecutionReassessmentContract(
        geometry_id=analysis.geometry_id,
        prior_geometry_digest=analysis.geometry_digest,
        evidence_mapping_ids=(mapping.mapping_id,),
    )
    return analysis, registry, plan, declaration, authorization, reassessment


def _assess(case):
    analysis, registry, plan, declaration, authorization, reassessment = case
    return assess_execution_readiness(
        analysis,
        plan,
        registry,
        (declaration,),
        authorization,
        reassessment,
    )


def test_ready_is_deterministic_digest_bound_and_executes_nothing() -> None:
    global SENTINEL_CALLS
    SENTINEL_CALLS = 0
    case = _case()

    first = _assess(case)
    second = _assess(case)

    assert first.status is ExecutionReadinessStatus.READY
    assert first.findings == ()
    assert first.canonical_json_bytes() == second.canonical_json_bytes()
    assert first.canonical_digest() == second.canonical_digest()
    assert first.geometry_digest == case[0].geometry_digest
    assert first.registry_digest == case[1].canonical_digest()
    assert first.execution_performed is False
    assert first.authorization_granted_by_module is False
    assert first.authorization.to_dict()["decision_source"] == "CALLER_SUPPLIED"
    assert SENTINEL_CALLS == 0
    payload = json.loads(first.canonical_json_bytes())
    assert payload["status"] == "READY"
    assert "does not execute" in payload["claim_boundary"]


def _package(registry: InteroperabilityComponentRegistry, content: bytes) -> StoredComponentPackage:
    component = registry.components[0]
    return StoredComponentPackage(
        package_id="package:sentinel", package_version="1", publisher="specimen",
        license="Apache-2.0", description="Nonexecuting package-binding specimen.",
        registry=registry,
        artifacts=(PackageArtifact("sentinel.py", "text/x-python", content),),
        implementations=(ImplementationBinding(
            component.component_id, component.implementation_ref, ("sentinel.py",),
        ),),
    )


def test_equal_registries_with_different_package_bytes_have_different_plans() -> None:
    analysis, registry, registry_plan, *_ = _case()
    first = _package(registry, b"raise RuntimeError('first; must not execute')")
    second = _package(registry, b"raise RuntimeError('second; must not execute')")

    first_plan = plan_validation(analysis, registry, package=first)
    second_plan = plan_validation(analysis, registry, package=second)

    assert first.registry == second.registry
    assert first_plan.candidates == second_plan.candidates == registry_plan.candidates
    assert first_plan.package_digest == first.canonical_digest()
    assert second_plan.package_digest == second.canonical_digest()
    assert len({first_plan.plan_id, second_plan.plan_id, registry_plan.plan_id}) == 3
    assert first_plan.canonical_json_bytes() != second_plan.canonical_json_bytes()
    assert first_plan.to_dict()["binding_scope"] == "STORED_PACKAGE"
    assert registry_plan.to_dict()["binding_scope"] == "REGISTRY_ONLY"
    assert registry_plan.to_dict()["package_digest"] is None
    assert first_plan.execution_performed is False


def test_package_readiness_rejects_payload_substitution_and_authorization_reuse() -> None:
    analysis, registry, _, declaration, authorization, reassessment = _case()
    first = _package(registry, b"first bytes")
    second = _package(registry, b"second bytes")
    first_plan = plan_validation(analysis, registry, package=first)
    second_plan = plan_validation(analysis, registry, package=second)
    authorized_first = replace(
        authorization, plan_digest=hashlib.sha256(first_plan.canonical_json_bytes()).hexdigest(),
    )

    def assess(
        plan: ValidationPlan,
        package: StoredComponentPackage | None,
        decision: SuppliedAuthorizationDecision = authorized_first,
    ) -> ExecutionReadinessReport:
        return assess_execution_readiness(
            analysis, plan, registry, (declaration,), decision, reassessment,
            package=package,
        )

    ready = assess(first_plan, first)
    assert ready.status is ExecutionReadinessStatus.READY
    assert ready.package_digest == first.canonical_digest()
    assert ready.to_dict()["binding_scope"] == "STORED_PACKAGE"
    assert ready.execution_performed is False
    assert ready.authorization_granted_by_module is False
    assert ready.authorization.to_dict()["decision_source"] == "CALLER_SUPPLIED"
    assert ready.canonical_json_bytes() == assess(first_plan, first).canonical_json_bytes()

    substituted = assess(first_plan, second)
    assert substituted.status is ExecutionReadinessStatus.INVALID
    assert any("package binding" in item for item in substituted.findings)
    reused = assess(second_plan, second)
    assert reused.status is ExecutionReadinessStatus.INVALID
    assert any("authorization plan binding" in item for item in reused.findings)
    unbound = assess(first_plan, first, authorization)
    assert unbound.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert any("authorization lacks" in item and "plan" in item for item in unbound.findings)
    missing = assess(first_plan, None)
    assert missing.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert any("exact stored package" in item for item in missing.findings)


def test_package_cannot_upgrade_registry_only_plan_or_accept_a_digest_string() -> None:
    analysis, registry, plan, declaration, authorization, reassessment = _case()
    package = _package(registry, b"never execute")
    report = assess_execution_readiness(
        analysis, plan, registry, (declaration,), authorization, reassessment,
        package=package,
    )
    assert report.status is ExecutionReadinessStatus.INVALID
    assert any("package binding" in item for item in report.findings)
    with pytest.raises(SurfaceAnalysisError, match="StoredComponentPackage"):
        plan_validation(analysis, registry, package=package.canonical_digest())


def test_planning_revalidates_package_and_exact_registry() -> None:
    analysis, registry, _, declaration, authorization, reassessment = _case()
    package = _package(registry, b"never execute")
    plan = plan_validation(analysis, registry, package=package)
    other_registry = replace(registry, registry_version="different-registry")
    with pytest.raises(SurfaceAnalysisError, match="registry"):
        plan_validation(analysis, other_registry, package=package)
    # A Python caller can bypass frozen guards; package context must be checked
    # again rather than trusting that construction once validated this object.
    object.__setattr__(package.artifacts[0], "path", "../outside")
    with pytest.raises(SurfaceAnalysisError, match="package"):
        plan_validation(analysis, registry, package=package)
    report = assess_execution_readiness(
        analysis, plan, registry, (declaration,), authorization, reassessment,
        package=package,
    )
    assert report.status is ExecutionReadinessStatus.INVALID
    assert any("package binding cannot be recomposed" in item for item in report.findings)


def test_package_plan_transport_and_empty_authority_remain_nonexecuting() -> None:
    analysis, registry, _, declaration, _, reassessment = _case()
    analysis = replace(analysis, context=replace(analysis.context, authority_requirements=()))
    package = _package(registry, b"never execute")
    transported = StoredComponentPackage.from_dict(json.loads(package.canonical_json_bytes()))
    plan = plan_validation(analysis, registry, package=package)
    assert plan.canonical_json_bytes() == plan_validation(
        analysis, registry, package=transported,
    ).canonical_json_bytes()
    authorization = SuppliedAuthorizationDecision(AuthorizationDecision.NOT_REQUIRED, ())
    report = assess_execution_readiness(
        analysis, plan, registry, (declaration,), authorization, reassessment,
        package=transported,
    )
    assert report.status is ExecutionReadinessStatus.READY
    assert report.authorization_granted_by_module is False
    assert report.execution_performed is False


def test_missing_package_does_not_hide_substituted_plan_content() -> None:
    analysis, registry, _, declaration, authorization, reassessment = _case()
    plan = plan_validation(analysis, registry, package=_package(registry, b"never execute"))
    plan = replace(plan, candidates=(replace(plan.candidates[0], mechanism_id="substituted"),))
    report = assess_execution_readiness(
        analysis, plan, registry, (declaration,), authorization, reassessment,
    )
    assert report.status is ExecutionReadinessStatus.INVALID
    assert any("exact replanning" in item for item in report.findings)


def test_missing_package_still_rejects_forged_plan_identity() -> None:
    analysis, registry, _, declaration, authorization, reassessment = _case()
    plan = plan_validation(analysis, registry, package=_package(registry, b"never execute"))
    plan = replace(plan, plan_id="validation-plan:" + "0" * 64)
    authorization = replace(
        authorization, plan_digest=hashlib.sha256(plan.canonical_json_bytes()).hexdigest(),
    )
    report = assess_execution_readiness(
        analysis, plan, registry, (declaration,), authorization, reassessment,
    )
    assert report.status is ExecutionReadinessStatus.INVALID
    assert any("exact stored package" in item for item in report.findings)
    assert any("exact replanning" in item for item in report.findings)


@pytest.mark.parametrize("digest", ("+" + "1" * 63, "1_" + "1" * 62, "１" * 64),
                         ids=("signed", "underscores", "non-ascii-digits"))
@pytest.mark.parametrize("field", (
    "native-input", "prerequisite", "authorization-evidence", "authorization-plan",
    "report-package", "report-plan",
))
def test_readiness_digest_fields_require_ascii_lowercase_hex(field: str, digest: str) -> None:
    case = _case()
    with pytest.raises(ExecutionReadinessError, match="SHA-256"):
        if field == "native-input":
            replace(case[3].native_inputs[0], input_sha256=digest)
        elif field == "prerequisite":
            replace(case[3].prerequisite_resolutions[0], evidence_sha256=digest)
        elif field == "authorization-evidence":
            replace(case[4], decision_evidence_sha256=digest)
        elif field == "authorization-plan":
            replace(case[4], plan_digest=digest)
        elif field == "report-package":
            replace(_assess(case), package_digest=digest)
        else:
            replace(_assess(case), plan_digest=digest)


def test_missing_native_input_or_evidence_mapping_is_not_established() -> None:
    analysis, registry, plan, declaration, authorization, reassessment = _case()

    missing_input = _assess(
        (
            analysis,
            registry,
            plan,
            replace(declaration, native_inputs=()),
            authorization,
            reassessment,
        )
    )
    missing_mapping_declaration = replace(declaration, evidence_mappings=())
    missing_mapping = assess_execution_readiness(
        analysis,
        plan,
        registry,
        (missing_mapping_declaration,),
        authorization,
        replace(reassessment, evidence_mapping_ids=()),
    )

    assert missing_input.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert any("missing native input bindings" in item for item in missing_input.findings)
    assert missing_mapping.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert any("no planned output/evidence mapping" in item for item in missing_mapping.findings)


def test_wrong_native_schema_output_or_geometry_mapping_is_invalid() -> None:
    analysis, registry, plan, declaration, authorization, reassessment = _case()
    binding = replace(
        declaration.native_inputs[0],
        schema_id="NATIVE-SUBSTITUTED-1",
    )
    mapping = replace(
        declaration.evidence_mappings[0],
        native_output_contract="forged-output",
        target_source_id="coordinate:other",
    )
    report = _assess(
        (
            analysis,
            registry,
            plan,
            replace(
                declaration,
                native_inputs=(binding,),
                evidence_mappings=(mapping,),
            ),
            authorization,
            reassessment,
        )
    )

    assert report.status is ExecutionReadinessStatus.INVALID
    assert any("not accepted" in item for item in report.findings)
    assert any("unknown native output" in item for item in report.findings)
    assert any("exact geometry hole" in item for item in report.findings)


def test_unversioned_component_requires_and_accepts_exact_named_contract() -> None:
    component = _component(accepted_schema_ids=())
    analysis, registry, plan, declaration, authorization, reassessment = _case(
        component=component
    )
    named_binding = replace(
        declaration.native_inputs[0], schema_id=None, media_type=None
    )

    ready = _assess(
        (
            analysis,
            registry,
            plan,
            replace(declaration, native_inputs=(named_binding,)),
            authorization,
            reassessment,
        )
    )
    false_schema = _assess(
        (analysis, registry, plan, declaration, authorization, reassessment)
    )

    assert ready.status is ExecutionReadinessStatus.READY
    assert false_schema.status is ExecutionReadinessStatus.INVALID
    assert any("no versioned native input schema" in item for item in false_schema.findings)


@pytest.mark.parametrize(
    ("decision", "evidence", "expected"),
    (
        (AuthorizationDecision.DENIED, EVIDENCE_DIGEST, ExecutionReadinessStatus.BLOCKED),
        (AuthorizationDecision.UNKNOWN, None, ExecutionReadinessStatus.NOT_ESTABLISHED),
        (AuthorizationDecision.AUTHORIZED, None, ExecutionReadinessStatus.NOT_ESTABLISHED),
    ),
)
def test_denied_unknown_or_unsubstantiated_authority_never_becomes_ready(
    decision: AuthorizationDecision,
    evidence: str | None,
    expected: ExecutionReadinessStatus,
) -> None:
    analysis, registry, plan, declaration, authorization, reassessment = _case()
    report = _assess(
        (
            analysis,
            registry,
            plan,
            declaration,
            replace(
                authorization,
                decision=decision,
                decision_evidence_sha256=evidence,
            ),
            reassessment,
        )
    )

    assert report.status is expected
    assert report.authorization_granted_by_module is False


def test_unresolved_or_unevidenced_prerequisite_is_not_ready() -> None:
    analysis, registry, plan, declaration, authorization, reassessment = _case()
    first, *rest = declaration.prerequisite_resolutions
    unresolved = replace(first, resolved=False, evidence_sha256=None, reason="not installed")
    blocked = _assess(
        (
            analysis,
            registry,
            plan,
            replace(
                declaration,
                prerequisite_resolutions=(unresolved, *rest),
            ),
            authorization,
            reassessment,
        )
    )
    unevidenced = replace(first, evidence_sha256=None)
    not_established = _assess(
        (
            analysis,
            registry,
            plan,
            replace(
                declaration,
                prerequisite_resolutions=(unevidenced, *rest),
            ),
            authorization,
            reassessment,
        )
    )

    assert blocked.status is ExecutionReadinessStatus.BLOCKED
    assert not_established.status is ExecutionReadinessStatus.NOT_ESTABLISHED


def test_plan_candidate_component_and_registry_substitution_are_invalid() -> None:
    analysis, registry, plan, declaration, authorization, reassessment = _case()

    changed_plan = replace(plan, plan_id="validation-plan:substituted")
    plan_result = _assess(
        (
            analysis,
            registry,
            changed_plan,
            declaration,
            authorization,
            reassessment,
        )
    )
    candidate_result = _assess(
        (
            analysis,
            registry,
            plan,
            replace(declaration, component_id="component:other"),
            authorization,
            reassessment,
        )
    )
    changed_registry = InteroperabilityComponentRegistry(
        registry.registry_version, (_component(component_id="component:replacement"),)
    )
    registry_result = assess_execution_readiness(
        analysis,
        plan,
        changed_registry,
        (declaration,),
        authorization,
        reassessment,
    )

    assert plan_result.status is ExecutionReadinessStatus.INVALID
    assert any("exact replanning" in item for item in plan_result.findings)
    assert candidate_result.status is ExecutionReadinessStatus.INVALID
    assert any("declaration component_id" in item for item in candidate_result.findings)
    assert registry_result.status is ExecutionReadinessStatus.INVALID
    assert any("registry binding" in item for item in registry_result.findings)


def test_unavailable_component_is_blocked_even_with_runtime_evidence() -> None:
    unavailable = _component(availability=ComponentAvailability.UNAVAILABLE)
    analysis = _analysis()
    registry = InteroperabilityComponentRegistry("registry:sentinel:1", (unavailable,))
    plan = plan_validation(analysis, registry)
    blocked_candidate = next(iter(plan.candidates))
    assert blocked_candidate.status is CandidateStatus.BLOCKED

    # Build from the valid declarations and rebind only the exact blocked candidate.
    _, _, _, declaration, authorization, reassessment = _case()
    rebound_inputs = tuple(
        replace(
            item,
            candidate_id=blocked_candidate.candidate_id,
            hole_id=blocked_candidate.hole_id,
            component_id=blocked_candidate.component_id or "",
        )
        for item in declaration.native_inputs
    )
    rebound_mappings = tuple(
        replace(
            item,
            candidate_id=blocked_candidate.candidate_id,
            hole_id=blocked_candidate.hole_id,
            component_id=blocked_candidate.component_id or "",
        )
        for item in declaration.evidence_mappings
    )
    required = {
        item
        for item in blocked_candidate.execution_prerequisites
        if not item.startswith("AUTHORITY:")
    } | {RUNTIME_AVAILABILITY_PREREQUISITE}
    rebound_prerequisites = tuple(
        PrerequisiteResolution(
            candidate_id=blocked_candidate.candidate_id,
            prerequisite=item,
            resolved=True,
            evidence_sha256=EVIDENCE_DIGEST,
        )
        for item in sorted(required)
    )
    rebound = CandidateExecutionDeclaration(
        candidate_id=blocked_candidate.candidate_id,
        hole_id=blocked_candidate.hole_id,
        component_id=blocked_candidate.component_id or "",
        native_inputs=rebound_inputs,
        evidence_mappings=rebound_mappings,
        prerequisite_resolutions=rebound_prerequisites,
    )

    report = assess_execution_readiness(
        analysis,
        plan,
        registry,
        (rebound,),
        authorization,
        reassessment,
    )
    assert report.status is ExecutionReadinessStatus.BLOCKED
    assert any("availability is UNAVAILABLE" in item for item in report.findings)


def test_missing_selection_and_reassessment_substitution_are_preserved() -> None:
    analysis, registry, plan, declaration, authorization, reassessment = _case()
    no_selection = assess_execution_readiness(
        analysis,
        plan,
        registry,
        (),
        authorization,
        replace(reassessment, evidence_mapping_ids=()),
    )
    changed_reassessment = _assess(
        (
            analysis,
            registry,
            plan,
            declaration,
            authorization,
            replace(reassessment, prior_geometry_digest="substituted"),
        )
    )

    assert no_selection.status is ExecutionReadinessStatus.NOT_ESTABLISHED
    assert any("no selected candidate" in item for item in no_selection.findings)
    assert changed_reassessment.status is ExecutionReadinessStatus.INVALID
    assert any("reassessment geometry binding" in item for item in changed_reassessment.findings)


def test_duplicate_mapping_identity_across_two_holes_is_invalid() -> None:
    first_hole = _analysis().holes[0]
    second_hole = replace(
        first_hole,
        hole_id="hole:second",
        source_id="coordinate:second",
        description="A second sentinel mechanism has not run.",
    )
    analysis = replace(_analysis(), holes=(first_hole, second_hole))
    registry = InteroperabilityComponentRegistry(
        "registry:sentinel:1", (_component(),)
    )
    plan = plan_validation(analysis, registry)
    candidates = tuple(
        candidate
        for candidate in plan.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )
    assert len(candidates) == 2

    declarations = []
    for index, candidate in enumerate(candidates):
        native_input = NativeInputBinding(
            binding_id=f"input:{index}",
            candidate_id=candidate.candidate_id,
            hole_id=candidate.hole_id,
            component_id=candidate.component_id or "",
            native_input_contract="sentinel-native-input",
            input_sha256=INPUT_DIGEST,
            schema_id="NATIVE-SENTINEL-1",
            media_type="application/json",
        )
        mapping = PlannedEvidenceMapping(
            mapping_id="mapping:duplicated",
            candidate_id=candidate.candidate_id,
            hole_id=candidate.hole_id,
            component_id=candidate.component_id or "",
            native_output_contract="sentinel-native-result",
            evidence_contract="evidence:sentinel-result:1",
            target_source_kind="COORDINATE",
            target_source_id=(
                first_hole.source_id
                if candidate.hole_id == first_hole.hole_id
                else second_hole.source_id
            ),
        )
        prerequisite_resolutions = tuple(
            PrerequisiteResolution(
                candidate_id=candidate.candidate_id,
                prerequisite=prerequisite,
                resolved=True,
                evidence_sha256=EVIDENCE_DIGEST,
            )
            for prerequisite in sorted(
                {
                    item
                    for item in candidate.execution_prerequisites
                    if not item.startswith("AUTHORITY:")
                }
                | {RUNTIME_AVAILABILITY_PREREQUISITE}
            )
        )
        declarations.append(
            CandidateExecutionDeclaration(
                candidate_id=candidate.candidate_id,
                hole_id=candidate.hole_id,
                component_id=candidate.component_id or "",
                native_inputs=(native_input,),
                evidence_mappings=(mapping,),
                prerequisite_resolutions=prerequisite_resolutions,
            )
        )

    authorization = SuppliedAuthorizationDecision(
        decision=AuthorizationDecision.AUTHORIZED,
        authority_requirements=("LOCAL_REVIEW",),
        decision_evidence_sha256=EVIDENCE_DIGEST,
        reason="The caller supplied a bounded local authorization decision.",
    )
    reassessment = PostExecutionReassessmentContract(
        geometry_id=analysis.geometry_id,
        prior_geometry_digest=analysis.geometry_digest,
        evidence_mapping_ids=("mapping:duplicated",),
    )

    report = assess_execution_readiness(
        analysis,
        plan,
        registry,
        tuple(declarations),
        authorization,
        reassessment,
    )

    assert report.status is ExecutionReadinessStatus.INVALID
    assert any("globally unique" in item for item in report.findings)


def test_digest_and_record_shapes_fail_closed() -> None:
    with pytest.raises(ExecutionReadinessError, match="SHA-256"):
        NativeInputBinding(
            binding_id="input:bad",
            candidate_id="candidate:bad",
            hole_id="hole:bad",
            component_id="component:bad",
            native_input_contract="native-input",
            input_sha256="not-a-digest",
        )
    with pytest.raises(ExecutionReadinessError, match="both be supplied"):
        replace(
            _case()[3].native_inputs[0],
            schema_id="NATIVE-SENTINEL-1",
            media_type=None,
        )
    with pytest.raises(ExecutionReadinessError, match="geometry_digest.*SHA-256"):
        replace(_assess(_case()), geometry_digest="not-a-digest")
