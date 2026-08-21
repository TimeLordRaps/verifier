"""Semantic tests for the additive VSTD-0.2 verification geometry slice."""

import json
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

from verifiable.core.geometry import (
    Coordinate,
    CoordinateJudgment,
    CoordinateStatus,
    Facet,
    Grain,
    Horizon,
    HorizonKind,
    Locus,
    LocusKind,
    Novelty,
    NoveltyKind,
    ReconstructionAttempt,
    Residual,
    ResidualDisposition,
    ResidualType,
    Seam,
    Stratum,
    Subject,
    ValenceStatus,
    VerificationGeometry,
    VerificationLayer,
    VerificationMechanism,
    VerificationSurface,
    VerificationValence,
)


def geometry_with_reconstruction_horizon() -> VerificationGeometry:
    """A complete-looking formatter decomposition that reconstruction disproves."""

    return VerificationGeometry(
        geometry_id="geometry:formatter-v1",
        primary_subject_id="subject:formatter",
        secondary_subject_id="subject:geometry",
        subjects=[
            Subject("subject:formatter", "Number formatter", "1.0"),
            Subject(
                "subject:geometry",
                "Verification geometry for formatter",
                "1.0",
                parent_subject_id="subject:formatter",
            ),
        ],
        loci=[
            Locus(
                "locus:formatter",
                "subject:formatter",
                "formatter",
                LocusKind.PROCESS,
                Grain.SUBJECT,
                Stratum.EXECUTION,
                "formatter",
            ),
            Locus(
                "locus:parse",
                "subject:formatter",
                "parse number",
                LocusKind.FUNCTION,
                Grain.FUNCTION,
                Stratum.SOURCE,
                "formatter.py:parse",
                "locus:formatter",
            ),
            Locus(
                "locus:render",
                "subject:formatter",
                "render number",
                LocusKind.FUNCTION,
                Grain.FUNCTION,
                Stratum.EXECUTION,
                "formatter.py:render",
                "locus:formatter",
            ),
            # Reconstruction exposed this dependency; its state cannot be
            # observed in the current evidence package.
            Locus(
                "locus:locale",
                "subject:formatter",
                "runtime locale",
                LocusKind.OBJECT,
                Grain.SUBJECT,
                Stratum.EXECUTION,
                "process.environment.locale",
                "locus:formatter",
            ),
            Locus(
                "locus:geometry",
                "subject:geometry",
                "formatter verification geometry",
                LocusKind.VERIFICATION_GEOMETRY,
                Grain.SUBJECT,
                Stratum.VERIFICATION,
                "geometry:formatter-v1",
            ),
        ],
        facets=[
            Facet("facet:functional", "functional correctness", "Observed output matches the claim."),
            Facet("facet:provenance", "provenance", "Inputs and dependencies have evidenced origin."),
            Facet("facet:sufficiency", "closure sufficiency", "The declared surface accounts for its obligations."),
        ],
        coordinates=[
            Coordinate("coordinate:parse-functional", "locus:parse", "facet:functional"),
            Coordinate("coordinate:render-functional", "locus:render", "facet:functional"),
            Coordinate("coordinate:locale-provenance", "locus:locale", "facet:provenance"),
            Coordinate("coordinate:geometry-sufficiency", "locus:geometry", "facet:sufficiency"),
        ],
        seams=[
            Seam("seam:parse-render", "parsed value to renderer", "locus:parse", "locus:render", "DATA_FLOW"),
            Seam("seam:locale-render", "runtime locale to renderer", "locus:locale", "locus:render", "ENVIRONMENT_DEPENDENCY"),
        ],
        surface=VerificationSurface(
            "surface:formatter",
            "subject:formatter",
            (
                "coordinate:parse-functional",
                "coordinate:render-functional",
            ),
            ("seam:parse-render",),
            "Parse and render a decimal under the declared test fixture.",
        ),
        mechanisms=[
            VerificationMechanism(
                "mechanism:fixture-test",
                "fixed formatter test",
                "1",
                post_verified=False,
                boundary_horizon_id="horizon:locale-observation",
            ),
            VerificationMechanism(
                "mechanism:geometry-review",
                "verification geometry review",
                "1",
                post_verified=False,
                boundary_horizon_id="horizon:locale-observation",
            ),
        ],
        judgments=[
            CoordinateJudgment(
                "coordinate:parse-functional",
                CoordinateStatus.VERIFIED,
                ("mechanism:fixture-test",),
                ("evidence:parse-test",),
            ),
            CoordinateJudgment(
                "coordinate:render-functional",
                CoordinateStatus.VERIFIED,
                ("mechanism:fixture-test",),
                ("evidence:render-test",),
                limitations=("runtime locale was not captured",),
            ),
            CoordinateJudgment(
                "coordinate:geometry-sufficiency",
                CoordinateStatus.INDETERMINATE,
                ("mechanism:geometry-review",),
                ("evidence:geometry-review",),
                limitations=("locale-state valence remains at a horizon",),
            ),
        ],
        horizons=[
            Horizon(
                "horizon:locale-observation",
                HorizonKind.EVIDENCE,
                "The original runtime locale was not captured and cannot be recovered.",
                locus_id="locus:locale",
                seam_id="seam:locale-render",
            )
        ],
        residuals=[
            Residual(
                "residual:decimal-separator",
                ResidualType.BEHAVIORAL,
                "Reconstruction predicts a period but the observed output contains a comma.",
                observed="1,5",
                represented_or_reconstructed="1.5",
                disposition=ResidualDisposition.HORIZON,
                seam_id="seam:locale-render",
                horizon_id="horizon:locale-observation",
            )
        ],
        valences=[
            VerificationValence(
                "valence:locale-state",
                "SEAM",
                "seam:locale-render",
                "HAS_EVIDENCED_ENVIRONMENT_STATE",
                "The discovered environment seam requires a locale-state observation.",
                status=ValenceStatus.HORIZON,
                horizon_id="horizon:locale-observation",
            )
        ],
        reconstructions=[
            ReconstructionAttempt(
                "reconstruction:formatter",
                "subject:formatter",
                "Replay parsed value through the declared renderer model.",
                "evidence:observed-output",
                "evidence:reconstructed-output",
                ("residual:decimal-separator",),
            )
        ],
        verification_layers=[
            VerificationLayer(
                "layer:v0",
                0,
                "subject:formatter",
                coordinate_ids=(
                    "coordinate:parse-functional",
                    "coordinate:render-functional",
                ),
                mechanism_ids=("mechanism:fixture-test",),
                evidence_ids=("evidence:parse-test", "evidence:render-test"),
            ),
            VerificationLayer(
                "layer:v1",
                1,
                "subject:geometry",
                verifies_layer_id="layer:v0",
                coordinate_ids=("coordinate:geometry-sufficiency",),
                mechanism_ids=("mechanism:geometry-review",),
                horizon_id="horizon:locale-observation",
            ),
        ],
        novelties=[
            Novelty(
                "novelty:locale-seam",
                NoveltyKind.SEAM,
                "residual:decimal-separator",
                "The reconstruction residual required an environment-to-renderer seam.",
            )
        ],
        focus_coordinate_ids=("coordinate:parse-functional", "coordinate:render-functional"),
        meta_focus_coordinate_ids=("coordinate:geometry-sufficiency",),
    )


def test_locus_and_facet_are_distinct_and_grain_is_orthogonal_to_stratum() -> None:
    geometry = geometry_with_reconstruction_horizon()
    parse = next(locus for locus in geometry.loci if locus.locus_id == "locus:parse")
    render = next(locus for locus in geometry.loci if locus.locus_id == "locus:render")

    assert parse.grain is render.grain is Grain.FUNCTION
    assert parse.stratum is Stratum.SOURCE
    assert render.stratum is Stratum.EXECUTION
    assert geometry.coordinates[0].locus_id != geometry.coordinates[0].facet_id
    assert geometry.validate() == []


def test_assumptions_cannot_manufacture_a_verified_judgment() -> None:
    geometry = geometry_with_reconstruction_horizon()
    geometry.judgments[0] = CoordinateJudgment(
        "coordinate:parse-functional",
        CoordinateStatus.VERIFIED,
        assumptions=("the parser is correct",),
    )

    errors = geometry.validate()

    assert any("VERIFIED without a mechanism" in error for error in errors)
    assert any("VERIFIED without evidence; assumptions do not count" in error for error in errors)


def test_reconstruction_residual_can_bound_closure_but_refuses_self_closure() -> None:
    geometry = geometry_with_reconstruction_horizon()

    assessment = geometry.assess_closure()

    assert assessment.ordinary_closed is True
    assert assessment.self_closed is False
    assert any("residual:decimal-separator" in item for item in assessment.self_closure_blockers)
    assert any("valence:locale-state" in item for item in assessment.self_closure_blockers)
    assert any("horizon:locale-observation" in item for item in assessment.self_closure_blockers)


def test_refinement_can_resolve_residual_and_earn_bounded_self_closure() -> None:
    geometry = geometry_with_reconstruction_horizon()
    geometry.horizons.clear()
    geometry.residuals[0] = replace(
        geometry.residuals[0],
        disposition=ResidualDisposition.RESOLVED,
        horizon_id=None,
        represented_or_reconstructed="1,5 (locale dependency represented)",
    )
    geometry.valences[0] = replace(
        geometry.valences[0],
        status=ValenceStatus.DISCHARGED,
        evidence_ids=("evidence:captured-locale",),
        horizon_id=None,
    )
    geometry.mechanisms[0] = replace(
        geometry.mechanisms[0],
        post_verified=True,
        post_verification_evidence_ids=("evidence:fixture-test-review",),
        boundary_horizon_id=None,
    )
    geometry.mechanisms[1] = replace(
        geometry.mechanisms[1],
        post_verified=True,
        post_verification_evidence_ids=("evidence:geometry-review-mechanism-review",),
        boundary_horizon_id=None,
    )
    geometry.judgments[2] = replace(
        geometry.judgments[2],
        status=CoordinateStatus.VERIFIED,
        evidence_ids=("evidence:geometry-review", "evidence:captured-locale"),
        limitations=(),
    )
    geometry.verification_layers[1] = replace(
        geometry.verification_layers[1],
        evidence_ids=("evidence:geometry-review",),
        horizon_id=None,
    )

    assessment = geometry.assess_closure()

    assert geometry.validate() == []
    assert assessment.ordinary_closed is True
    assert assessment.self_closed is True


def test_verification_orders_must_be_adjacent_not_infinitely_abstracted() -> None:
    geometry = geometry_with_reconstruction_horizon()
    geometry.verification_layers[1] = replace(
        geometry.verification_layers[1], order=2, verifies_layer_id="layer:v0"
    )

    errors = geometry.validate()

    assert any("contiguous and start at 0" in error for error in errors)
    assert any("adjacent-layer invariant" in error for error in errors)


def test_geometry_digest_is_deterministic() -> None:
    first = geometry_with_reconstruction_horizon()
    second = geometry_with_reconstruction_horizon()

    assert first.canonical_digest() == second.canonical_digest()


def test_typed_geometry_matches_the_published_json_schema() -> None:
    schema = json.loads(
        Path("receipts/schema/verification_geometry_v0_2.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)

    Draft202012Validator(schema).validate(geometry_with_reconstruction_horizon().to_dict())
