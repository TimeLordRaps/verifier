"""Verifier Standard (VSTD) geometry-bound Boolean constraint example.

Boolean satisfiability problem (SAT); unsatisfiable (UNSAT); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Boolean values are
dimensionless choices in a fictional menu configuration, not observed facts.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from verifier.core.geometry import (
    Coordinate, CoordinateJudgment, CoordinateStatus, Facet, Grain, Locus,
    LocusKind, Stratum, Subject, VerificationGeometry, VerificationSurface,
)
from verifier.interoperability.geometry_conflicts import SharedPropositionIdentity
from verifier.interoperability.geometry_constraints import (
    GeometryClause, GeometryConstraintBounds, SignedProposition,
    prepare_geometry_constraints, recheck_geometry_constraints,
    solve_geometry_constraints,
)


def build_geometry() -> VerificationGeometry:
    """Describe two choices without asserting either choice has been verified."""
    return VerificationGeometry(
        geometry_id="geometry:menu-choices",
        primary_subject_id="subject:menu",
        subjects=[Subject("subject:menu", "Fictional menu configuration", "1")],
        loci=[Locus("locus:menu", "subject:menu", "Configuration", LocusKind.OBJECT,
                    Grain.SUBJECT, Stratum.REQUIREMENT, "menu")],
        facets=[Facet("facet:compact", "Compact layout", "Compact layout is selected."),
                Facet("facet:icons", "Icons", "Icons are selected.")],
        coordinates=[Coordinate("coordinate:compact", "locus:menu", "facet:compact"),
                     Coordinate("coordinate:icons", "locus:menu", "facet:icons")],
        surface=VerificationSurface(
            "surface:menu", "subject:menu", ("coordinate:compact", "coordinate:icons"),
            scope_statement="Only the two declared configuration choices.",
        ),
        judgments=[CoordinateJudgment("coordinate:compact", CoordinateStatus.INDETERMINATE),
                   CoordinateJudgment("coordinate:icons", CoordinateStatus.INDETERMINATE)],
    )


def build_report() -> dict[str, Any]:
    """Solve and separately recheck three interpretations of the same geometry."""
    geometry = build_geometry()
    original = json.dumps(geometry.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    bindings = tuple(
        SharedPropositionIdentity(name, geometry.canonical_digest(), "coordinate:" + name)
        for name in ("compact", "icons")
    )
    compact = SignedProposition("compact", True)
    icons = SignedProposition("icons", True)
    no_compact = SignedProposition("compact", False)
    no_icons = SignedProposition("icons", False)
    implication = GeometryClause("compact-requires-icons", (no_compact, icons))
    selected = GeometryClause("select-compact", (compact,))
    cases = (
        ("compatible", (selected, implication), GeometryConstraintBounds()),
        ("contradictory", (selected, implication,
                           GeometryClause("disable-icons", (no_icons,))),
         GeometryConstraintBounds()),
        ("search-budget", (GeometryClause("choice", (compact, icons)),),
         GeometryConstraintBounds(max_decision_depth=0)),
    )
    reports = []
    for name, clauses, bounds in cases:
        problem = prepare_geometry_constraints((original,), bindings, clauses)
        # The host selects this interpretation before asking the producer to solve it.
        expected = problem.canonical_digest()
        result = solve_geometry_constraints(problem, bounds=bounds)
        checked = recheck_geometry_constraints(
            problem, result, expected_problem_digest=expected, bounds=bounds,
        )
        proof = result.certificate_json
        reports.append({
            "case": name,
            "problem_digest": expected,
            "status": result.status,
            "rechecked_status": checked.status,
            "model": result.model,
            "certificate": None if proof is None else json.loads(proof),
            "certificate_sha256": None if proof is None else hashlib.sha256(proof).hexdigest(),
        })
    if json.dumps(geometry.to_dict(), sort_keys=True, separators=(",", ":"),
                  ensure_ascii=True, allow_nan=False).encode("ascii") != original:
        raise RuntimeError("constraint analysis changed the geometry")
    return {
        "cases": reports,
        "geometry_digest": geometry.canonical_digest(),
        "coordinate_statuses": [judgment.status.value for judgment in geometry.judgments],
        "claim_boundary": (
            "Only the explicit Boolean interpretation is checked. A satisfying model is "
            "not observed configuration; a refutation contradicts supplied constraints, "
            "not the physical world. No geometry hole is discharged, package-selected "
            "code loaded, independent operator established, or authority granted."
        ),
    }


if __name__ == "__main__":
    print(json.dumps(build_report(), indent=2, sort_keys=True, allow_nan=False))
