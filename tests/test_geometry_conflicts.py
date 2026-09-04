"""Adversarial tests for experimental multi-geometry conflict diagnostics."""

from __future__ import annotations

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
from verifier.interoperability.geometry_conflicts import (
    AcyclicPropositionDependency,
    ConflictWitnessKind,
    GeometryConflictStatus,
    SharedPropositionIdentity,
    analyze_geometry_conflicts,
)


def _geometry(name: str, statuses: tuple[CoordinateStatus, ...]) -> VerificationGeometry:
    coordinate_ids = tuple(f"coordinate:{name}:{index}" for index in range(len(statuses)))
    mechanism = VerificationMechanism(
        mechanism_id=f"mechanism:{name}",
        label="Bounded test mechanism",
        version="1",
    )
    return VerificationGeometry(
        geometry_id=f"geometry:{name}",
        primary_subject_id="subject:shared",
        subjects=[Subject("subject:shared", "Shared subject", "1")],
        loci=[
            Locus(
                locus_id=f"locus:{name}:{index}",
                subject_id="subject:shared",
                label=f"Claim {index}",
                kind=LocusKind.OBJECT,
                grain=Grain.SUBJECT,
                stratum=Stratum.REQUIREMENT,
                address=f"claim/{index}",
            )
            for index in range(len(statuses))
        ],
        facets=[
            Facet(f"facet:{name}:{index}", "Validity", "Bounded validity proposition")
            for index in range(len(statuses))
        ],
        coordinates=[
            Coordinate(coordinate_id, f"locus:{name}:{index}", f"facet:{name}:{index}")
            for index, coordinate_id in enumerate(coordinate_ids)
        ],
        surface=VerificationSurface(
            surface_id=f"surface:{name}",
            subject_id="subject:shared",
            coordinate_ids=coordinate_ids,
            scope_statement="Only the explicit test propositions.",
        ),
        mechanisms=[mechanism],
        judgments=[
            CoordinateJudgment(
                coordinate_id=coordinate_id,
                status=status,
                mechanism_ids=(mechanism.mechanism_id,),
                evidence_ids=(f"evidence:{name}:{index}",),
            )
            for index, (coordinate_id, status) in enumerate(zip(coordinate_ids, statuses))
        ],
    )


def _identities(
    first: VerificationGeometry,
    second: VerificationGeometry,
    proposition_ids: tuple[str, ...],
) -> tuple[SharedPropositionIdentity, ...]:
    return tuple(
        SharedPropositionIdentity(
            proposition_id=proposition_id,
            geometry_digest=geometry.canonical_digest(),
            coordinate_id=geometry.coordinates[index].coordinate_id,
        )
        for geometry in (first, second)
        for index, proposition_id in enumerate(proposition_ids)
    )


def test_matching_explicit_shared_judgments_are_consistent() -> None:
    first = _geometry("first", (CoordinateStatus.VERIFIED,))
    second = _geometry("second", (CoordinateStatus.VERIFIED,))

    report = analyze_geometry_conflicts(
        (first, second), _identities(first, second, ("proposition:one",))
    )

    assert report.status is GeometryConflictStatus.CONSISTENT
    assert report.shared_proposition_ids == ("proposition:one",)
    assert report.witnesses == ()
    assert "physical truth" in report.claim_boundary


def test_verified_versus_falsified_has_reproducible_bound_witness() -> None:
    verified = _geometry("verified", (CoordinateStatus.VERIFIED,))
    falsified = _geometry("falsified", (CoordinateStatus.FALSIFIED,))
    identities = _identities(verified, falsified, ("proposition:one",))

    first = analyze_geometry_conflicts((verified, falsified), identities)
    second = analyze_geometry_conflicts((falsified, verified), reversed(identities))

    assert first.status is GeometryConflictStatus.CONFLICTED
    assert first.canonical_json_bytes() == second.canonical_json_bytes()
    assert first.canonical_digest() == second.canonical_digest()
    assert len(first.witnesses) == 1
    witness = first.witnesses[0]
    assert witness.kind is ConflictWitnessKind.JUDGMENT_CONTRADICTION
    assert witness.proposition_ids == ("proposition:one",)
    assert {item.status for item in witness.observations} == {
        CoordinateStatus.VERIFIED,
        CoordinateStatus.FALSIFIED,
    }
    assert all(
        item.geometry_digest in first.geometry_digests for item in witness.observations
    )


def test_missing_cross_geometry_identity_is_not_established() -> None:
    first = _geometry("first", (CoordinateStatus.VERIFIED,))
    second = _geometry("second", (CoordinateStatus.VERIFIED,))
    only_first = SharedPropositionIdentity(
        proposition_id="proposition:one",
        geometry_digest=first.canonical_digest(),
        coordinate_id=first.coordinates[0].coordinate_id,
    )

    report = analyze_geometry_conflicts((first, second), (only_first,))

    assert report.status is GeometryConflictStatus.NOT_ESTABLISHED
    assert report.shared_proposition_ids == ()
    assert report.missing_identity_coordinates == (
        f"{second.canonical_digest()}:{second.coordinates[0].coordinate_id}",
    )
    assert report.unshared_identity_coordinates == (
        f"{first.canonical_digest()}:{first.coordinates[0].coordinate_id}",
    )
    assert any("no proposition identity is shared" in item for item in report.errors)


def test_local_only_identity_does_not_establish_cross_geometry_comparability() -> None:
    first = _geometry(
        "first", (CoordinateStatus.VERIFIED, CoordinateStatus.VERIFIED)
    )
    second = _geometry(
        "second", (CoordinateStatus.VERIFIED, CoordinateStatus.VERIFIED)
    )
    identities = _identities(
        first, second, ("proposition:shared", "proposition:temporarily-shared")
    )
    local_only = tuple(
        SharedPropositionIdentity(
            proposition_id=(
                "proposition:first-only"
                if item.geometry_digest == first.canonical_digest()
                else "proposition:second-only"
            ),
            geometry_digest=item.geometry_digest,
            coordinate_id=item.coordinate_id,
        )
        if item.proposition_id == "proposition:temporarily-shared"
        else item
        for item in identities
    )

    report = analyze_geometry_conflicts((first, second), local_only)

    assert report.status is GeometryConflictStatus.NOT_ESTABLISHED
    assert report.shared_proposition_ids == ("proposition:shared",)
    assert report.missing_identity_coordinates == ()
    assert report.unshared_identity_coordinates == tuple(
        sorted(
            (
                f"{first.canonical_digest()}:{first.coordinates[1].coordinate_id}",
                f"{second.canonical_digest()}:{second.coordinates[1].coordinate_id}",
            )
        )
    )


def test_indeterminate_shared_judgment_is_not_established() -> None:
    first = _geometry("first", (CoordinateStatus.VERIFIED,))
    second = _geometry("second", (CoordinateStatus.INDETERMINATE,))

    report = analyze_geometry_conflicts(
        (first, second), _identities(first, second, ("proposition:one",))
    )

    assert report.status is GeometryConflictStatus.NOT_ESTABLISHED
    assert report.unresolved_propositions == ("proposition:one",)
    assert report.witnesses == ()


def test_invalid_geometry_fails_closed_without_conflict_inference() -> None:
    valid = _geometry("valid", (CoordinateStatus.VERIFIED,))
    invalid = _geometry("invalid", (CoordinateStatus.VERIFIED,))
    invalid.surface = VerificationSurface(
        surface_id=invalid.surface.surface_id,
        subject_id=invalid.surface.subject_id,
        coordinate_ids=("coordinate:missing",),
        scope_statement=invalid.surface.scope_statement,
    )

    report = analyze_geometry_conflicts((valid, invalid), ())

    assert report.status is GeometryConflictStatus.INVALID
    assert report.witnesses == ()
    assert any("unknown coordinate" in item for item in report.errors)


def test_declared_acyclic_dependency_cycle_is_conflicted_and_deterministic() -> None:
    first = _geometry(
        "first", (CoordinateStatus.VERIFIED, CoordinateStatus.VERIFIED)
    )
    second = _geometry(
        "second", (CoordinateStatus.VERIFIED, CoordinateStatus.VERIFIED)
    )
    identities = _identities(
        first, second, ("proposition:alpha", "proposition:beta")
    )
    dependencies = (
        AcyclicPropositionDependency(
            "dependency:alpha-before-beta", "proposition:alpha", "proposition:beta"
        ),
        AcyclicPropositionDependency(
            "dependency:beta-before-alpha", "proposition:beta", "proposition:alpha"
        ),
    )

    first_report = analyze_geometry_conflicts(
        (first, second), identities, dependencies
    )
    second_report = analyze_geometry_conflicts(
        (second, first), reversed(identities), reversed(dependencies)
    )

    assert first_report.status is GeometryConflictStatus.CONFLICTED
    assert first_report.canonical_json_bytes() == second_report.canonical_json_bytes()
    cycle = next(
        item
        for item in first_report.witnesses
        if item.kind is ConflictWitnessKind.DEPENDENCY_CYCLE
    )
    assert cycle.proposition_ids == ("proposition:alpha", "proposition:beta")
    assert {item.dependency_id for item in cycle.dependencies} == {
        "dependency:alpha-before-beta",
        "dependency:beta-before-alpha",
    }


def test_unknown_geometry_digest_in_identity_is_invalid() -> None:
    first = _geometry("first", (CoordinateStatus.VERIFIED,))
    second = _geometry("second", (CoordinateStatus.VERIFIED,))
    identities = _identities(first, second, ("proposition:one",))
    tampered = SharedPropositionIdentity(
        proposition_id=identities[0].proposition_id,
        geometry_digest="0" * 64,
        coordinate_id=identities[0].coordinate_id,
    )

    report = analyze_geometry_conflicts((first, second), (tampered, identities[1]))

    assert report.status is GeometryConflictStatus.INVALID
    assert report.witnesses == ()
    assert any("unknown geometry digest" in item for item in report.errors)


def test_deep_acyclic_dependency_chain_does_not_exceed_recursion_limit() -> None:
    proposition_count = 1_100
    geometry = _geometry(
        "deep-chain", (CoordinateStatus.VERIFIED,) * proposition_count
    )
    geometry_digest = geometry.canonical_digest()
    identities = tuple(
        SharedPropositionIdentity(
            proposition_id=f"proposition:{index:04d}",
            geometry_digest=geometry_digest,
            coordinate_id=geometry.coordinates[index].coordinate_id,
        )
        for index in range(proposition_count)
    )
    dependencies = tuple(
        AcyclicPropositionDependency(
            dependency_id=f"dependency:{index:04d}",
            prerequisite_proposition_id=f"proposition:{index:04d}",
            dependent_proposition_id=f"proposition:{index + 1:04d}",
        )
        for index in range(proposition_count - 1)
    )

    report = analyze_geometry_conflicts((geometry,), identities, dependencies)

    assert report.status is GeometryConflictStatus.NOT_ESTABLISHED
    assert report.witnesses == ()
    assert "at least two distinct geometries are required" in report.errors
