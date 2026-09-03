"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Adversarial tests for modeled-only surface analysis and nonexecuting plans.
"""

import json
from dataclasses import replace

import pytest

from verifier.core.geometry import (
    Coordinate,
    CoordinateJudgment,
    CoordinateStatus,
    Facet,
    Grain,
    Horizon,
    HorizonKind,
    Locus,
    LocusKind,
    Residual,
    ResidualDisposition,
    ResidualType,
    Stratum,
    Subject,
    ValenceStatus,
    VerificationGeometry,
    VerificationLayer,
    VerificationMechanism,
    VerificationSurface,
    VerificationValence,
)
from verifier.interoperability.catalog import (
    ComponentAvailability,
    ComponentKind,
    ComponentLifecycle,
    InteractionMode,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from verifier.interoperability.control_surface import (
    ANALYSIS_CLAIM_BOUNDARY,
    ANALYSIS_INPUT_MODE,
    MODELED_SURFACE_SCOPE,
    PLAN_CLAIM_BOUNDARY,
    STRICT_WIRE_LOADING_STATUS,
    CandidateStatus,
    ControlSurfaceContext,
    SurfaceAnalysis,
    SurfaceAnalysisError,
    SurfaceHoleKind,
    ValidationCandidate,
    ValidationPlan,
    analyze_verification_surface,
    plan_validation,
)


def horizon_geometry(
    coordinate_status: CoordinateStatus = CoordinateStatus.VERIFIED,
) -> VerificationGeometry:
    return VerificationGeometry(
        geometry_id="geometry:example",
        primary_subject_id="subject:primary",
        secondary_subject_id="subject:geometry",
        subjects=[
            Subject("subject:primary", "Example process", "1"),
            Subject(
                "subject:geometry",
                "Example verification geometry",
                "1",
                parent_subject_id="subject:primary",
            ),
        ],
        loci=[
            Locus(
                "locus:primary",
                "subject:primary",
                "example",
                LocusKind.PROCESS,
                Grain.SUBJECT,
                Stratum.EXECUTION,
                "example",
            ),
            Locus(
                "locus:geometry",
                "subject:geometry",
                "geometry",
                LocusKind.VERIFICATION_GEOMETRY,
                Grain.SUBJECT,
                Stratum.VERIFICATION,
                "geometry:example",
            ),
        ],
        facets=[
            Facet("facet:result", "result", "The bounded result."),
            Facet("facet:sufficiency", "sufficiency", "The bounded geometry."),
        ],
        coordinates=[
            Coordinate("coordinate:result", "locus:primary", "facet:result"),
            Coordinate(
                "coordinate:sufficiency", "locus:geometry", "facet:sufficiency"
            ),
        ],
        surface=VerificationSurface(
            "surface:example",
            "subject:primary",
            ("coordinate:result",),
            scope_statement="Only the declared example result.",
        ),
        mechanisms=[
            VerificationMechanism(
                "mechanism:result",
                "result verifier",
                "1",
                boundary_horizon_id="horizon:evidence",
            ),
            VerificationMechanism(
                "mechanism:geometry",
                "geometry verifier",
                "1",
                boundary_horizon_id="horizon:evidence",
            ),
        ],
        judgments=[
            CoordinateJudgment(
                "coordinate:result",
                coordinate_status,
                ("mechanism:result",),
                ("evidence:result",),
            ),
            CoordinateJudgment(
                "coordinate:sufficiency",
                CoordinateStatus.INDETERMINATE,
                ("mechanism:geometry",),
                ("evidence:geometry-observation",),
            ),
        ],
        horizons=[
            Horizon(
                "horizon:evidence",
                HorizonKind.EVIDENCE,
                "No observation exists beyond the declared fixture.",
                coordinate_id="coordinate:result",
            )
        ],
        residuals=[
            Residual(
                "residual:observation",
                ResidualType.BEHAVIORAL,
                "The missing observation is explicitly bounded.",
                observed="not captured",
                represented_or_reconstructed="declared fixture only",
                disposition=ResidualDisposition.HORIZON,
                coordinate_id="coordinate:result",
                horizon_id="horizon:evidence",
            )
        ],
        valences=[
            VerificationValence(
                "valence:exact-evidence",
                "COORDINATE",
                "coordinate:result",
                "HAS_EXACT_EVIDENCE",
                "Exact evidence remains available only up to the horizon.",
                status=ValenceStatus.HORIZON,
                horizon_id="horizon:evidence",
            )
        ],
        verification_layers=[
            VerificationLayer(
                "layer:v0",
                0,
                "subject:primary",
                coordinate_ids=("coordinate:result",),
                mechanism_ids=("mechanism:result",),
                evidence_ids=("evidence:result",),
            ),
            VerificationLayer(
                "layer:v1",
                1,
                "subject:geometry",
                verifies_layer_id="layer:v0",
                coordinate_ids=("coordinate:sufficiency",),
                mechanism_ids=("mechanism:geometry",),
                horizon_id="horizon:evidence",
            ),
        ],
        focus_coordinate_ids=("coordinate:result",),
        meta_focus_coordinate_ids=("coordinate:sufficiency",),
    )


def self_closed_geometry() -> VerificationGeometry:
    geometry = horizon_geometry()
    geometry.horizons.clear()
    geometry.residuals[0] = replace(
        geometry.residuals[0],
        disposition=ResidualDisposition.RESOLVED,
        horizon_id=None,
    )
    geometry.valences[0] = replace(
        geometry.valences[0],
        status=ValenceStatus.DISCHARGED,
        evidence_ids=("evidence:exact",),
        horizon_id=None,
    )
    geometry.mechanisms[0] = replace(
        geometry.mechanisms[0],
        post_verified=True,
        post_verification_evidence_ids=("evidence:result-mechanism",),
        boundary_horizon_id=None,
    )
    geometry.mechanisms[1] = replace(
        geometry.mechanisms[1],
        post_verified=True,
        post_verification_evidence_ids=("evidence:geometry-mechanism",),
        boundary_horizon_id=None,
    )
    geometry.judgments[1] = replace(
        geometry.judgments[1],
        status=CoordinateStatus.VERIFIED,
        evidence_ids=("evidence:geometry",),
    )
    geometry.verification_layers[1] = replace(
        geometry.verification_layers[1],
        evidence_ids=("evidence:geometry",),
        horizon_id=None,
    )
    return geometry


def component(
    component_id: str,
    *,
    relation: str = "HAS_EXACT_EVIDENCE",
    mechanism: str = "mechanism:candidate",
    schema: str = "VSTD-2",
    mode: InteractionMode = InteractionMode.STATIC,
    tags: tuple[str, ...] = (),
    optional_dependencies: tuple[str, ...] = (),
    trust_roots: tuple[str, ...] = (),
) -> InteroperabilityComponentDescriptor:
    return InteroperabilityComponentDescriptor(
        component_id=component_id,
        label=component_id,
        kind=ComponentKind.VERIFIER,
        lifecycle=ComponentLifecycle.IMPLEMENTED,
        implementation_ref=f"example:{component_id}",
        accepted_schema_ids=(schema,),
        supported_relations=(relation,),
        mechanism_ids=(mechanism,),
        interaction_modes=(mode,),
        domain_tags=tags,
        optional_dependencies=optional_dependencies,
        trust_roots=trust_roots,
        availability=ComponentAvailability.AVAILABLE,
        claim_boundary="Candidate association only.",
    )


@pytest.mark.parametrize(
    "status",
    [
        CoordinateStatus.INDETERMINATE,
        CoordinateStatus.UNSUPPORTED,
        CoordinateStatus.STALE,
    ],
)
def test_native_unknown_like_coordinate_statuses_are_not_collapsed(
    status: CoordinateStatus,
) -> None:
    analysis = analyze_verification_surface(horizon_geometry(status))
    holes = [
        hole
        for hole in analysis.holes
        if hole.source_id == "coordinate:result"
        and hole.kind is SurfaceHoleKind.COORDINATE_STATUS
    ]

    assert [hole.native_status for hole in holes] == [status.value]
    assert analysis.ordinary_closed is False
    assert "UNKNOWN" not in {hole.native_status for hole in holes}


def test_horizon_allows_ordinary_closure_but_remains_a_self_closure_hole() -> None:
    analysis = analyze_verification_surface(horizon_geometry())
    residual = next(
        hole for hole in analysis.holes if hole.kind is SurfaceHoleKind.RESIDUAL
    )
    horizon = next(
        hole for hole in analysis.holes if hole.kind is SurfaceHoleKind.HORIZON
    )

    assert analysis.validity_errors == ()
    assert analysis.ordinary_closed is True
    assert analysis.self_closed is False
    assert residual.native_status == ResidualDisposition.HORIZON.value
    assert residual.blocks_ordinary_closure is False
    assert residual.blocks_self_closure is True
    assert horizon.native_status == HorizonKind.EVIDENCE.value
    assert horizon.blocks_ordinary_closure is False
    assert horizon.blocks_self_closure is True
    assert analysis.scope == MODELED_SURFACE_SCOPE


def test_self_closed_geometry_has_no_modeled_holes() -> None:
    geometry = self_closed_geometry()
    analysis = analyze_verification_surface(geometry)

    assert geometry.validate() == []
    assert geometry.assess_closure().self_closed is True
    assert analysis.self_closed is True
    assert analysis.holes == ()


def test_analysis_accepts_only_typed_geometry_and_rejects_schema_substitution() -> None:
    geometry = horizon_geometry()

    with pytest.raises(SurfaceAnalysisError, match="VerificationGeometry"):
        analyze_verification_surface(geometry.to_dict())  # type: ignore[arg-type]
    with pytest.raises(SurfaceAnalysisError, match="exactly equal"):
        analyze_verification_surface(
            geometry,
            ControlSurfaceContext(schema_id="LOOKS-LIKE-VSTD-2"),
        )

    payload = analyze_verification_surface(geometry).to_dict()
    assert payload["input_mode"] == ANALYSIS_INPUT_MODE
    assert payload["strict_wire_loading_status"] == STRICT_WIRE_LOADING_STATUS
    assert payload["scope"] == "MODELED_SURFACE_ONLY"


def test_malformed_public_inputs_raise_surface_analysis_errors() -> None:
    analysis = analyze_verification_surface(horizon_geometry())
    registry = InteroperabilityComponentRegistry(
        "1.3.0", (component("component:a"),)
    )
    plan = plan_validation(analysis, registry)

    assert isinstance(analysis, SurfaceAnalysis)
    assert isinstance(plan, ValidationPlan)
    with pytest.raises(SurfaceAnalysisError, match="ControlSurfaceContext"):
        analyze_verification_surface(horizon_geometry(), object())  # type: ignore[arg-type]
    with pytest.raises(SurfaceAnalysisError, match="holes must be an array"):
        replace(analysis, holes=None)  # type: ignore[arg-type]
    with pytest.raises(SurfaceAnalysisError, match="validity_errors must be an array"):
        replace(analysis, validity_errors=None)  # type: ignore[arg-type]
    with pytest.raises(SurfaceAnalysisError, match="candidates must be an array"):
        replace(plan, candidates=None)  # type: ignore[arg-type]


def test_analysis_booleans_and_claim_boundaries_cannot_be_weakened() -> None:
    analysis = analyze_verification_surface(horizon_geometry())
    plan = plan_validation(
        analysis,
        InteroperabilityComponentRegistry("1.3.0", (component("component:a"),)),
    )

    with pytest.raises(SurfaceAnalysisError, match="ordinary_closed must be a boolean"):
        replace(analysis, ordinary_closed=1)
    with pytest.raises(SurfaceAnalysisError, match="self_closed must be a boolean"):
        replace(analysis, self_closed=0)
    with pytest.raises(SurfaceAnalysisError, match="claim_boundary is fixed"):
        replace(analysis, claim_boundary="Complete in the real world.")
    with pytest.raises(SurfaceAnalysisError, match="claim_boundary is fixed"):
        replace(plan, claim_boundary="Candidates establish assurance.")
    assert analysis.claim_boundary == ANALYSIS_CLAIM_BOUNDARY
    assert plan.claim_boundary == PLAN_CLAIM_BOUNDARY


def test_validation_candidate_states_have_coherent_coordinates_and_blockers() -> None:
    baseline = {
        "candidate_id": "candidate:example",
        "hole_id": "hole:example",
        "status": CandidateStatus.CANDIDATE,
        "component_id": "component:example",
        "mechanism_id": "mechanism:example",
        "relation_id": None,
        "matching_basis": ("schema_id=VSTD-2",),
        "execution_prerequisites": ("BOUND_PROPOSITION",),
        "blockers": (),
    }
    malformed_states = (
        {
            "status": CandidateStatus.UNMATCHED,
            "component_id": None,
            "mechanism_id": "mechanism:example",
            "blockers": ("no match",),
        },
        {
            "status": CandidateStatus.UNMATCHED,
            "component_id": None,
            "mechanism_id": None,
            "blockers": (),
        },
        {"mechanism_id": None, "relation_id": None},
        {"relation_id": "RELATION", "blockers": ("contradictory blocker",)},
        {
            "status": CandidateStatus.BLOCKED,
            "relation_id": "RELATION",
            "blockers": (),
        },
    )

    for changes in malformed_states:
        with pytest.raises(SurfaceAnalysisError):
            ValidationCandidate(**{**baseline, **changes})  # type: ignore[arg-type]


def test_joint_relation_and_mechanism_matching_rejects_partial_matches() -> None:
    analysis = analyze_verification_surface(horizon_geometry())
    horizon_hole = next(
        hole for hole in analysis.holes if hole.kind is SurfaceHoleKind.HORIZON
    )
    assert horizon_hole.required_relations == ("HAS_EXACT_EVIDENCE",)
    assert "mechanism:result" in horizon_hole.mechanism_ids
    registry = InteroperabilityComponentRegistry(
        "1.3.0",
        (
            component(
                "component:full-match",
                relation="HAS_EXACT_EVIDENCE",
                mechanism="mechanism:result",
            ),
            component(
                "component:relation-only",
                relation="HAS_EXACT_EVIDENCE",
                mechanism="mechanism:wrong",
            ),
            component(
                "component:mechanism-only",
                relation="WRONG_RELATION",
                mechanism="mechanism:result",
            ),
        ),
    )

    candidates = [
        item
        for item in plan_validation(analysis, registry).candidates
        if item.hole_id == horizon_hole.hole_id
    ]

    assert [
        (item.component_id, item.relation_id, item.mechanism_id)
        for item in candidates
    ] == [
        ("component:full-match", "HAS_EXACT_EVIDENCE", "mechanism:result")
    ]


def test_candidate_prerequisites_name_component_dependencies_and_trust_roots() -> None:
    analysis = analyze_verification_surface(horizon_geometry())
    valence_hole = next(
        hole for hole in analysis.holes if hole.kind is SurfaceHoleKind.VALENCE
    )
    registry = InteroperabilityComponentRegistry(
        "1.3.0",
        (
            component(
                "component:bounded",
                optional_dependencies=("package:optional",),
                trust_roots=("trust-root:local",),
            ),
        ),
    )
    candidate = next(
        item
        for item in plan_validation(analysis, registry).candidates
        if item.hole_id == valence_hole.hole_id
        and item.component_id == "component:bounded"
    )

    assert "DEPENDENCY:package:optional" in candidate.execution_prerequisites
    assert "TRUST_ROOT:trust-root:local" in candidate.execution_prerequisites


def test_planning_rejects_analysis_of_structurally_invalid_geometry() -> None:
    geometry = horizon_geometry()
    geometry.coordinates.clear()
    with pytest.raises(SurfaceAnalysisError, match="structurally invalid"):
        analyze_verification_surface(geometry)

    analysis = replace(
        analyze_verification_surface(horizon_geometry()),
        validity_errors=("dangling coordinate reference",),
    )

    with pytest.raises(SurfaceAnalysisError, match="structurally invalid"):
        plan_validation(
            analysis,
            InteroperabilityComponentRegistry(
                "1.3.0", (component("component:a"),)
            ),
        )


def test_exact_planning_retains_multiple_candidates_and_executes_nothing() -> None:
    context = ControlSurfaceContext(
        authority_requirements=("LOCAL_REVIEW",),
        domain_tags=("software",),
    )
    analysis = analyze_verification_surface(horizon_geometry(), context)
    registry = InteroperabilityComponentRegistry(
        "1.3.0",
        (
            component("component:z", mechanism="mechanism:z"),
            component("component:a", mechanism="mechanism:a"),
        ),
    )
    plan = plan_validation(analysis, registry)
    valence_hole = next(
        hole for hole in analysis.holes if hole.kind is SurfaceHoleKind.VALENCE
    )
    candidates = [
        item for item in plan.candidates if item.hole_id == valence_hole.hole_id
    ]

    assert [item.component_id for item in candidates] == [
        "component:a",
        "component:z",
    ]
    assert all(item.status is CandidateStatus.CANDIDATE for item in candidates)
    assert all(item.mechanism_id is not None for item in candidates)
    assert all("AUTHORITY:LOCAL_REVIEW" in item.execution_prerequisites for item in candidates)
    assert plan.plan_only is True
    assert plan.execution_performed is False
    assert all(item.plan_only is True for item in plan.candidates)
    assert all(item.execution_performed is False for item in plan.candidates)
    assert not hasattr(plan, "execute")


def test_zero_or_inexact_matches_remain_explicitly_unmatched() -> None:
    analysis = analyze_verification_surface(horizon_geometry())
    valence_hole = next(
        hole for hole in analysis.holes if hole.kind is SurfaceHoleKind.VALENCE
    )
    registries = (
        InteroperabilityComponentRegistry("1.3.0", ()),
        InteroperabilityComponentRegistry(
            "1.3.0", (component("wrong-schema", schema="vstd-2"),)
        ),
        InteroperabilityComponentRegistry(
            "1.3.0", (component("wrong-relation", relation="SIMILAR_RELATION"),)
        ),
        InteroperabilityComponentRegistry(
            "1.3.0",
            (
                component(
                    "wrong-mode",
                    mode=InteractionMode.OFFLINE_REPLAY,
                ),
            ),
        ),
    )

    for registry in registries:
        plan = plan_validation(analysis, registry)
        candidates = [
            item for item in plan.candidates if item.hole_id == valence_hole.hole_id
        ]
        assert len(candidates) == 1
        assert candidates[0].status is CandidateStatus.UNMATCHED
        assert candidates[0].component_id is None


def test_domain_tags_do_not_affect_matches_but_registry_bytes_bind_plan_id() -> None:
    software_analysis = analyze_verification_surface(
        horizon_geometry(),
        ControlSurfaceContext(domain_tags=("software",)),
    )
    biology_analysis = analyze_verification_surface(
        horizon_geometry(),
        ControlSurfaceContext(domain_tags=("biological",)),
    )
    software_registry = InteroperabilityComponentRegistry(
        "1.3.0", (component("component:a", tags=("software",)),)
    )
    biology_registry = InteroperabilityComponentRegistry(
        "1.3.0", (component("component:a", tags=("biological",)),)
    )
    software_plan = plan_validation(software_analysis, software_registry)
    biology_plan = plan_validation(biology_analysis, biology_registry)

    assert [hole.hole_id for hole in software_analysis.holes] == [
        hole.hole_id for hole in biology_analysis.holes
    ]
    assert [
        (item.candidate_id, item.hole_id, item.component_id, item.status)
        for item in software_plan.candidates
    ] == [
        (item.candidate_id, item.hole_id, item.component_id, item.status)
        for item in biology_plan.candidates
    ]
    assert software_plan.registry_digest == software_registry.canonical_digest()
    assert biology_plan.registry_digest == biology_registry.canonical_digest()
    assert software_plan.registry_digest != biology_plan.registry_digest
    assert software_plan.plan_id != biology_plan.plan_id


def test_analysis_and_plan_serialization_are_deterministic_and_have_no_pass() -> None:
    first_analysis = analyze_verification_surface(horizon_geometry())
    second_analysis = analyze_verification_surface(horizon_geometry())
    first_registry = InteroperabilityComponentRegistry(
        "1.3.0",
        (component("component:z"), component("component:a")),
    )
    second_registry = InteroperabilityComponentRegistry(
        "1.3.0",
        (component("component:a"), component("component:z")),
    )
    first_plan = plan_validation(first_analysis, first_registry)
    second_plan = plan_validation(second_analysis, second_registry)

    assert first_analysis.canonical_json_bytes() == second_analysis.canonical_json_bytes()
    assert first_plan.canonical_json_bytes() == second_plan.canonical_json_bytes()
    analysis_payload = json.loads(first_analysis.canonical_json_bytes())
    plan_payload = json.loads(first_plan.canonical_json_bytes())
    assert "expected_profile" not in analysis_payload
    assert "aggregate_result" not in analysis_payload
    assert "aggregate_result" not in plan_payload
    assert plan_payload["registry_version"] == "1.3.0"
    assert plan_payload["registry_digest"] == first_registry.canonical_digest()
    assert plan_payload["plan_only"] is True
    assert plan_payload["execution_performed"] is False
