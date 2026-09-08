"""Terminology: identifier (ID); Verifier Standard (VSTD).

Harmless, plan-only interoperability example over a sorted grocery list.

The native checker below is a real callable, but this example deliberately does
not invoke it. It detects modeled VSTD-2 surface holes and associates exact
experimental catalog candidates; it does not perform validation or establish
closure.
"""

from __future__ import annotations

import json
from typing import Any

from verifier.core.geometry import (
    Coordinate,
    CoordinateJudgment,
    CoordinateStatus,
    Facet,
    Grain,
    Locus,
    LocusKind,
    Stratum,
    Subject,
    VerificationGeometry,
    VerificationMechanism,
    VerificationSurface,
)
from verifier.interoperability import (
    CandidateStatus,
    ComponentAvailability,
    ComponentKind,
    ComponentLifecycle,
    InteractionMode,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
    analyze_verification_surface,
    plan_validation,
)


CHECKER_MECHANISM_ID = "mechanism:lexicographic-check"
_checker_invocations = 0


def check_lexicographic_order(items: object) -> str:
    """Return the checker's native result for a sequence of grocery-item strings."""

    global _checker_invocations
    _checker_invocations += 1
    if not isinstance(items, (list, tuple)) or not all(
        isinstance(item, str) for item in items
    ):
        return "INVALID_INPUT"
    return "ORDERED" if list(items) == sorted(items) else "OUT_OF_ORDER"


def build_geometry() -> VerificationGeometry:
    """Build the minimum typed geometry whose open coordinate is catalog-matchable."""

    subject_id = "subject:sorted-grocery-list"
    locus_id = "locus:grocery-list-sort"
    facet_id = "facet:lexicographic-order"
    coordinate_id = "coordinate:grocery-list-lexicographic-order"
    return VerificationGeometry(
        geometry_id="geometry:sorted-grocery-list",
        primary_subject_id=subject_id,
        subjects=[
            Subject(
                subject_id=subject_id,
                label="Sorted grocery list",
                version="1",
            )
        ],
        loci=[
            Locus(
                locus_id=locus_id,
                subject_id=subject_id,
                label="Grocery-list sorting function",
                kind=LocusKind.FUNCTION,
                grain=Grain.FUNCTION,
                stratum=Stratum.OUTPUT,
                address="examples/interoperability_planning/demo.py:check_lexicographic_order",
            )
        ],
        facets=[
            Facet(
                facet_id=facet_id,
                label="Declared lexicographic order",
                description=(
                    "Whether the supplied grocery-item strings occur in Python's "
                    "default lexicographic order."
                ),
            )
        ],
        coordinates=[
            Coordinate(
                coordinate_id=coordinate_id,
                locus_id=locus_id,
                facet_id=facet_id,
            )
        ],
        surface=VerificationSurface(
            surface_id="surface:sorted-grocery-list",
            subject_id=subject_id,
            coordinate_ids=(coordinate_id,),
            scope_statement=(
                "One non-critical text-ordering coordinate; no physical, safety, "
                "financial, medical, or operational claim."
            ),
        ),
        mechanisms=[
            VerificationMechanism(
                mechanism_id=CHECKER_MECHANISM_ID,
                label="Lexicographic grocery-list checker",
                version="experimental-0.1",
                post_verified=False,
            )
        ],
        judgments=[
            CoordinateJudgment(
                coordinate_id=coordinate_id,
                status=CoordinateStatus.INDETERMINATE,
                mechanism_ids=(CHECKER_MECHANISM_ID,),
                limitations=("The checker has not been executed.",),
            )
        ],
        focus_coordinate_ids=(coordinate_id,),
    )


def build_registry() -> InteroperabilityComponentRegistry:
    """Build the one-component experimental registry used by this example."""

    descriptor = InteroperabilityComponentDescriptor(
        component_id="component:lexicographic-check",
        label="Lexicographic grocery-list checker",
        kind=ComponentKind.VERIFIER,
        lifecycle=ComponentLifecycle.EXPERIMENTAL,
        implementation_ref=(
            "examples/interoperability_planning/demo.py:check_lexicographic_order"
        ),
        accepted_schema_ids=("VSTD-2",),
        native_system="Python sequence comparison",
        native_objects=("sequence-of-grocery-item-strings",),
        native_versions=("python-default-string-order",),
        native_inputs=("grocery-item-string-sequence",),
        native_outputs=("native-order-status",),
        native_result_vocabulary=("INVALID_INPUT", "ORDERED", "OUT_OF_ORDER"),
        mechanism_ids=(CHECKER_MECHANISM_ID,),
        interaction_modes=(InteractionMode.STATIC,),
        domain_tags=("demonstration", "non-critical", "text-processing"),
        freshness_behavior="No result is retained or refreshed during planning.",
        transformation_loss="Planning carries no native checker result.",
        failure_behavior="Malformed native input would return INVALID_INPUT if executed.",
        availability=ComponentAvailability.AVAILABLE,
        claim_boundary=(
            "Catalog matching identifies a plan candidate only; it does not run the "
            "checker or establish ordering, validation, closure, or safety."
        ),
    )
    return InteroperabilityComponentRegistry(
        registry_version="example:sorted-grocery-list:0.1",
        components=(descriptor,),
    )


def build_demo() -> dict[str, Any]:
    """Detect modeled holes and build a nonexecuting, registry-bound plan."""

    geometry = build_geometry()
    registry = build_registry()
    analysis = analyze_verification_surface(geometry)
    plan = plan_validation(analysis, registry)
    exact_candidates = tuple(
        candidate
        for candidate in plan.candidates
        if candidate.status is CandidateStatus.CANDIDATE
    )
    unmatched = tuple(
        candidate
        for candidate in plan.candidates
        if candidate.status is CandidateStatus.UNMATCHED
    )
    return {
        "example": "sorted-grocery-list",
        "analysis": analysis.to_dict(),
        "plan": plan.to_dict(),
        "summary": {
            "checker_invocations": _checker_invocations,
            "exact_candidate_count": len(exact_candidates),
            "execution_performed": plan.execution_performed,
            "hole_count": len(analysis.holes),
            "ordinary_closed": analysis.ordinary_closed,
            "plan_only": plan.plan_only,
            "self_closed": analysis.self_closed,
            "unmatched_hole_count": len(unmatched),
        },
    }


def render_demo() -> str:
    """Return a deterministic JavaScript Object Notation rendering of the plan."""

    return json.dumps(build_demo(), indent=2, sort_keys=True, allow_nan=False) + "\n"


if __name__ == "__main__":
    print(render_demo(), end="")
