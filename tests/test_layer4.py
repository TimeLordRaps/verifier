"""Terminology: Verifier Standard (VSTD).

Rungs 4.8 through 4.14 -- the parts of VSTD-4 outside the kernel.

Each test here pins one of the challenge-theater prohibitions:

* a hash that nobody can fetch is not availability (4.8);
* a claim nobody is permitted to refute is unfalsifiable, not strong (4.10);
* an envelope with an open degree of freedom is where the post-hoc choice will
  be made (4.11);
* a challenge mechanism that does not move verdict state is theater (4.12);
* a verdict that survives its evidence never degraded (4.13);
* refutability does not increase under composition (4.14).
"""

from __future__ import annotations

import hashlib

import pytest

from verifier.core.certificate import ClaimCoordinate
from verifier.data.models import ArtifactNode, ArtifactStatus, ArtifactType, ProvenanceHypergraph
from verifier.hardware.anchors import AnchorError, LocalAnchorProvider
from verifier.layer4.availability import (
    ArtifactAvailability,
    AvailabilityLevel,
    RetrievalObservation,
    RetentionPolicy,
    assess_bundle,
    rank,
    weakest,
)
from verifier.layer4.challenge import (
    Adjudication,
    Challenge,
    ChallengeError,
    ChallengeLedger,
    ChallengeOutcome,
    DEGRADATION_ORDER,
    admissibility,
    most_degraded,
)
from verifier.layer4.closure import (
    InputBinding,
    Locus,
    RefutabilityClosure,
    RefutationMapping,
    cap_output_depth,
)
from verifier.layer4.precommit import (
    Commitment,
    DegreeOfFreedom,
    ObservedSelection,
    PrecommitmentEnvelope,
    PrecommitmentError,
    PrecommitmentLedger,
    REQUIRED_DEGREES,
    audit_selections,
)
from verifier.layer4.surface import (
    AdmissibleRefutation,
    ExcludedClaim,
    PHYSICAL_WORLD_COMPLETENESS,
    RefutationSurface,
    RefutationType,
    default_exclusions,
    surface_from_types,
)

COORDINATE = ClaimCoordinate(
    "model:sha256:ab",
    "accuracy>=0.95",
    {"dataset": "sha256:d", "metric": "exact_match_v2"},
)


def _surface() -> RefutationSurface:
    return RefutationSurface(
        COORDINATE,
        (
            AdmissibleRefutation(
                RefutationType.METRIC_RECOMPUTATION_MISMATCH,
                ("dataset", "metric"),
                "recompute exact_match_v2 over sha256:d and obtain below 0.95",
            ),
            AdmissibleRefutation(
                RefutationType.EVIDENCE_HASH_MISMATCH,
                (),
                "produce evidence whose digest differs from the sealed root",
            ),
        ),
        default_exclusions(),
    )


def _envelope(envelope_id: str = "env:1", at: str = "2026-01-01T00:00:00Z"):
    return PrecommitmentEnvelope(
        envelope_id,
        tuple(Commitment(degree, f"sha256:{degree.value}", at) for degree in DegreeOfFreedom),
        anchor_reference="anchor:local:1",
    )


# --------------------------------------------------------------------------
# 4.8 availability
# --------------------------------------------------------------------------


def test_a_hash_alone_is_only_identified():
    bare = ArtifactAvailability("proof", "sha256:aa")
    assert bare.assess() is AvailabilityLevel.IDENTIFIED
    assert assess_bundle([bare]).accepted is False


def test_locator_and_retention_declarations_do_not_prove_retrieval():
    retained = ArtifactAvailability(
        "data",
        "sha256:bb",
        locator="https://example.invalid/bb",
        retention=RetentionPolicy("2030-01-01T00:00:00Z", "archive", 3),
    )
    assert retained.assess() is AvailabilityLevel.IDENTIFIED
    assert assess_bundle([retained]).accepted is False


def test_the_ladder_is_monotone_in_what_it_requires():
    proof_bytes = b"proof"
    data_bytes = b"retained data"
    index_bytes = b"portable index"
    embedded = ArtifactAvailability(
        "proof",
        f"sha256:{hashlib.sha256(proof_bytes).hexdigest()}",
        embedded_bytes=proof_bytes,
    )
    retained = ArtifactAvailability(
        "data",
        f"sha256:{hashlib.sha256(data_bytes).hexdigest()}",
        locator="https://example.invalid/bb",
        retention=RetentionPolicy("2030-01-01T00:00:00Z", "archive", 3),
    )
    anonymous = ArtifactAvailability(
        "index",
        f"sha256:{hashlib.sha256(index_bytes).hexdigest()}",
        locator="https://example.invalid/cc",
        anonymous_access=True,
        retrieval_procedure="GET, no credential",
        retention=RetentionPolicy("2030-01-01T00:00:00Z", "archive", 3),
    )
    observations = {
        "data": RetrievalObservation(
            "data", retained.locator, "2026-08-22T20:00:00Z", "checker-a", data_bytes
        ),
        "index": RetrievalObservation(
            "index", anonymous.locator, "2026-08-22T20:00:01Z", "checker-b", index_bytes
        ),
    }
    assert embedded.assess() is AvailabilityLevel.SELF_CONTAINED
    assert retained.assess(observations["data"]) is AvailabilityLevel.AVAILABLE
    assert anonymous.assess(observations["index"]) is AvailabilityLevel.PORTABLE
    assert rank(AvailabilityLevel.SELF_CONTAINED) > rank(AvailabilityLevel.PORTABLE)
    result = assess_bundle([embedded, retained], observations=observations)
    assert result.level is AvailabilityLevel.AVAILABLE
    assert result.accepted is True
    serialized = result.to_dict()
    retained_record = next(
        item for item in serialized["artifacts"] if item["artifact_id"] == "data"
    )
    assert retained_record["assessed_level"] == "AVAILABLE"
    assert retained_record["retrieval_observation"]["observer"] == "checker-a"


def test_failed_or_mismatched_retrieval_observation_does_not_elevate():
    artifact = ArtifactAvailability(
        "data",
        f"sha256:{hashlib.sha256(b'expected').hexdigest()}",
        locator="https://example.invalid/data",
        retention=RetentionPolicy("2030-01-01T00:00:00Z", "archive"),
    )
    wrong_bytes = RetrievalObservation(
        "data", artifact.locator, "2026-08-22T20:00:00Z", "checker", b"wrong"
    )
    wrong_locator = RetrievalObservation(
        "data", "https://example.invalid/other", "2026-08-22T20:00:00Z", "checker", b"expected"
    )
    assert artifact.assess(wrong_bytes) is AvailabilityLevel.IDENTIFIED
    assert artifact.assess(wrong_locator) is AvailabilityLevel.IDENTIFIED


def test_malformed_retention_declaration_does_not_elevate():
    data = b"expected"
    artifact = ArtifactAvailability(
        "data",
        f"sha256:{hashlib.sha256(data).hexdigest()}",
        locator="https://example.invalid/data",
        retention=RetentionPolicy("2030-01-01T00:00:00Z", "", 0),
    )
    observation = RetrievalObservation(
        "data", artifact.locator, "2026-08-22T20:00:00Z", "checker", data
    )
    assert artifact.assess(observation) is AvailabilityLevel.IDENTIFIED


def test_embedded_bytes_must_match_the_content_address():
    artifact = ArtifactAvailability(
        "proof",
        f"sha256:{hashlib.sha256(b'expected').hexdigest()}",
        embedded_bytes=b"wrong",
    )
    assert artifact.assess() is AvailabilityLevel.IDENTIFIED


def test_one_unobtainable_artifact_caps_the_whole_bundle():
    """Averaging would be a category error: a checker needs every one of them."""
    good = ArtifactAvailability(
        "proof",
        f"sha256:{hashlib.sha256(b'proof').hexdigest()}",
        embedded_bytes=b"proof",
    )
    missing = ArtifactAvailability("logs", "sha256:cc")
    result = assess_bundle([good, missing])
    assert result.level is AvailabilityLevel.IDENTIFIED
    assert result.accepted is False
    assert result.limiting_artifacts == ("logs",)


def test_a_non_critical_artifact_does_not_cap_the_bundle():
    good = ArtifactAvailability(
        "proof",
        f"sha256:{hashlib.sha256(b'proof').hexdigest()}",
        embedded_bytes=b"proof",
    )
    aside = ArtifactAvailability("notes", "sha256:cc", verdict_critical=False)
    assert assess_bundle([good, aside]).level is AvailabilityLevel.SELF_CONTAINED


def test_an_overstated_level_is_refused_rather_than_believed():
    lying = ArtifactAvailability(
        "proof", "sha256:aa", declared_level=AvailabilityLevel.PORTABLE
    )
    assert lying.overstated() is True
    result = assess_bundle([lying])
    assert result.accepted is False
    assert "overstated" in result.details


# --------------------------------------------------------------------------
# 4.10 refutation surface
# --------------------------------------------------------------------------


def test_a_surface_with_no_admissible_refutation_is_refused():
    """No portable certificate without an explicit falsifier."""
    check = RefutationSurface(COORDINATE, ()).validate()
    assert check.accepted is False
    assert "unfalsifiable" in check.details


def test_a_refutation_with_no_overturning_evidence_is_refused():
    surface = RefutationSurface(
        COORDINATE, (AdmissibleRefutation(RefutationType.ANCHOR_FORK, (), "   "),)
    )
    assert surface.validate().accepted is False


def test_a_refutation_cannot_range_over_a_coordinate_that_does_not_exist():
    surface = RefutationSurface(
        COORDINATE,
        (AdmissibleRefutation(RefutationType.ANCHOR_FORK, ("nonexistent",), "fork"),),
    )
    assert surface.validate().accepted is False
    assert "do not exist" in surface.validate().details


def test_physical_world_completeness_has_a_machine_readable_home():
    surface = _surface()
    assert surface.validate().accepted is True
    excluded = surface.excludes(PHYSICAL_WORLD_COMPLETENESS)
    assert excluded is not None
    assert "outside the declared observation boundary" in excluded.reason


def test_duplicate_declarations_are_refused():
    doubled = RefutationSurface(
        COORDINATE,
        (
            AdmissibleRefutation(RefutationType.ANCHOR_FORK, (), "a fork"),
            AdmissibleRefutation(RefutationType.ANCHOR_FORK, (), "another fork"),
        ),
    )
    assert doubled.validate().accepted is False
    twice = RefutationSurface(
        COORDINATE,
        (AdmissibleRefutation(RefutationType.ANCHOR_FORK, (), "a fork"),),
        (ExcludedClaim("x", "why"), ExcludedClaim("x", "why again")),
    )
    assert twice.validate().accepted is False


def test_surface_convenience_constructor_carries_the_default_exclusion():
    surface = surface_from_types(
        COORDINATE,
        (RefutationType.CERTIFICATE_VERIFICATION_FAILURE,),
        overturning_evidence="the kernel rejects the published certificate",
    )
    assert surface.validate().accepted is True
    assert surface.excludes(PHYSICAL_WORLD_COMPLETENESS) is not None


# --------------------------------------------------------------------------
# 4.11 precommitment
# --------------------------------------------------------------------------


def test_every_verdict_material_degree_of_freedom_must_be_committed():
    full = _envelope()
    assert full.validate().accepted is True
    assert len(REQUIRED_DEGREES) == len(DegreeOfFreedom)

    partial = PrecommitmentEnvelope("env:2", full.commitments[:5])
    check = partial.validate()
    assert check.accepted is False
    assert DegreeOfFreedom.VERIFIER_IDENTITY.value in check.missing


def test_substituting_a_committed_choice_is_caught():
    envelope = _envelope()
    selections = [
        ObservedSelection(degree, f"sha256:{degree.value}", "2026-01-02T00:00:00Z")
        for degree in DegreeOfFreedom
    ]
    assert audit_selections(envelope, selections).accepted is True

    selections[5] = ObservedSelection(
        selections[5].degree, "sha256:friendlier-evaluator", "2026-01-02T00:00:00Z"
    )
    audit = audit_selections(envelope, selections)
    assert audit.accepted is False
    assert [violation.kind for violation in audit.violations] == ["substitution"]


def test_choosing_after_seeing_the_evidence_is_caught_even_without_substitution():
    """The subtler cheat: nothing was swapped, the choice was just made late."""
    envelope = _envelope(at="2026-01-05T00:00:00Z")
    selections = [
        ObservedSelection(
            degree,
            f"sha256:{degree.value}",
            selected_at="2026-01-05T00:00:00Z",
            evidence_observed_at="2026-01-03T00:00:00Z",
        )
        for degree in DegreeOfFreedom
    ]
    audit = audit_selections(envelope, selections)
    assert audit.accepted is False
    kinds = {violation.kind for violation in audit.violations}
    assert kinds == {"post_hoc_selection", "post_hoc_commitment"}


def test_using_an_uncommitted_degree_of_freedom_is_caught():
    envelope = PrecommitmentEnvelope(
        "env:3", _envelope().commitments[:5]
    )
    audit = audit_selections(
        envelope,
        [ObservedSelection(DegreeOfFreedom.STOPPING_CONDITION, "sha256:x", "2026-01-02T00:00:00Z")],
    )
    assert audit.accepted is False
    assert any(v.kind == "uncommitted_selection" for v in audit.violations)


def test_the_ledger_rejects_a_precommitment_fork():
    """Same shape as ``LocalAnchorProvider``: one id holds one envelope."""
    ledger = PrecommitmentLedger()
    envelope = _envelope()
    ledger.record(envelope)
    ledger.record(envelope)  # idempotent, not a fork
    assert len(ledger) == 1
    assert ledger.get("env:1") == envelope

    with pytest.raises(PrecommitmentError, match="precommitment fork"):
        ledger.record(PrecommitmentEnvelope("env:1", envelope.commitments[:9]))


def test_precommitment_reuses_the_existing_anchor_provider_and_trust_root():
    provider = LocalAnchorProvider("claim-anchor", "test-key", b"a" * 32)
    envelope = _envelope()
    anchored = envelope.anchor(provider, anchored_at="2026-01-01T00:00:00Z")
    anchor = provider.get(anchored.anchor_reference)
    assert anchor is not None
    assert anchored.verify_anchor(provider, anchor) is True
    assert anchor.rolling_root == envelope.content_digest()

    fork = PrecommitmentEnvelope(envelope.envelope_id, envelope.commitments[:9])
    with pytest.raises(AnchorError, match="anchor fork"):
        fork.anchor(provider, anchored_at="2026-01-01T00:00:01Z")


# --------------------------------------------------------------------------
# 4.12 challenge handling
# --------------------------------------------------------------------------


def _challenge(challenge_id: str = "ch:1", claim_id: str = "claim:1") -> Challenge:
    return Challenge(
        challenge_id=challenge_id,
        target_claim_id=claim_id,
        target_certificate_id="cert:1",
        challenged_predicate="accuracy>=0.95",
        challenge_type=RefutationType.METRIC_RECOMPUTATION_MISMATCH,
        counterevidence="recomputation over sha256:d yields 0.91",
        filed_at="2026-02-01T00:00:00Z",
    )


def test_a_credible_challenge_actually_moves_verdict_state():
    """``ArtifactStatus.CHALLENGED`` finally has a producer."""
    ledger = ChallengeLedger()
    assert ledger.status("claim:1").status is ArtifactStatus.VALID

    admitted = ledger.file(_challenge(), _surface())
    assert admitted.admitted is True
    assert ledger.status("claim:1").status is ArtifactStatus.CHALLENGED

    ledger.adjudicate(
        Adjudication("ch:1", ChallengeOutcome.ACCEPTED, "confirmed", "2026-02-02T00:00:00Z")
    )
    assert ledger.status("claim:1").status is ArtifactStatus.REVOKED


def test_challenge_records_do_not_silently_mutate_graph_state():
    graph = ProvenanceHypergraph()
    graph.add_artifact(
        ArtifactNode(
            "claim:1",
            "claim",
            ArtifactType.MODEL,
            "a" * 64,
            status=ArtifactStatus.VALID,
        )
    )
    ledger = ChallengeLedger()
    ledger.file(_challenge(), _surface())
    ledger.adjudicate(
        Adjudication("ch:1", ChallengeOutcome.ACCEPTED, "confirmed", "2026-02-02T00:00:00Z")
    )

    assert ledger.status("claim:1").status is ArtifactStatus.REVOKED
    assert graph.artifacts["claim:1"].status is ArtifactStatus.VALID


def test_a_disproven_challenge_returns_the_claim_to_valid():
    ledger = ChallengeLedger()
    ledger.file(_challenge(), _surface())
    ledger.adjudicate(
        Adjudication("ch:1", ChallengeOutcome.REJECTED, "challenger erred", "2026-02-02T00:00:00Z")
    )
    status = ledger.status("claim:1")
    assert status.status is ArtifactStatus.VALID
    assert status.open_challenges == ()


def test_an_unresolved_challenge_is_not_evidence_of_validity():
    ledger = ChallengeLedger()
    ledger.file(_challenge(), _surface())
    ledger.adjudicate(
        Adjudication("ch:1", ChallengeOutcome.UNRESOLVED, "pending", "2026-02-02T00:00:00Z")
    )
    assert ledger.status("claim:1").status is ArtifactStatus.CHALLENGED


def test_revocation_is_terminal():
    """Rung 4.13 in the transition table: degradation that unwinds never happened."""
    ledger = ChallengeLedger()
    ledger.file(_challenge(), _surface())
    ledger.adjudicate(
        Adjudication("ch:1", ChallengeOutcome.ACCEPTED, "confirmed", "2026-02-02T00:00:00Z")
    )
    ledger.file(_challenge("ch:2"), _surface())
    ledger.adjudicate(
        Adjudication("ch:2", ChallengeOutcome.REJECTED, "this one failed", "2026-02-03T00:00:00Z")
    )
    assert ledger.status("claim:1").status is ArtifactStatus.REVOKED


def test_status_is_recomputed_from_the_record_set_not_stored():
    """4.12 must not contradict 4.3 by mutating something sealed inside C."""
    ledger = ChallengeLedger()
    ledger.file(_challenge(), _surface())
    before = len(ledger)
    first = ledger.status("claim:1")
    second = ledger.status("claim:1")
    assert first == second
    assert len(ledger) == before, "reading a status appended to the record set"

    records = ledger.records("claim:1")
    assert [record.kind for record in records] == ["FILED"]
    assert all(record.sequence == index for index, record in enumerate(records))


def test_records_are_append_only_and_adjudication_is_final():
    ledger = ChallengeLedger()
    ledger.file(_challenge(), _surface())
    ledger.adjudicate(
        Adjudication("ch:1", ChallengeOutcome.ACCEPTED, "confirmed", "2026-02-02T00:00:00Z")
    )
    with pytest.raises(ChallengeError, match="already adjudicated"):
        ledger.adjudicate(
            Adjudication("ch:1", ChallengeOutcome.REJECTED, "second thoughts", "2026-02-03T00:00:00Z")
        )
    with pytest.raises(ChallengeError, match="already filed"):
        ledger.file(_challenge(), _surface())


def test_an_out_of_scope_challenge_is_refused_and_leaves_the_claim_alone():
    """Inadmissible is not the same as disproven, and neither is a state change."""
    ledger = ChallengeLedger()
    off_surface = Challenge(
        "ch:9", "claim:9", "cert:9", "accuracy>=0.95",
        RefutationType.UNDECLARED_DEPENDENCY, "an unrelated dependency",
        "2026-02-01T00:00:00Z",
    )
    verdict = ledger.file(off_surface, _surface())
    assert verdict.admitted is False
    assert "not on this claim's declared refutation surface" in verdict.details
    assert ledger.status("claim:9").status is ArtifactStatus.VALID


def test_a_challenge_against_an_excluded_claim_quotes_the_exclusion():
    excluded = Challenge(
        "ch:8", "claim:8", "cert:8", PHYSICAL_WORLD_COMPLETENESS,
        RefutationType.METRIC_RECOMPUTATION_MISMATCH, "there might be hidden compute",
        "2026-02-01T00:00:00Z",
    )
    verdict = admissibility(excluded, _surface())
    assert verdict.admitted is False
    assert "outside the declared observation boundary" in verdict.details


def test_a_challenge_with_no_counterevidence_is_refused():
    empty = Challenge(
        "ch:7", "claim:7", "cert:7", "accuracy>=0.95",
        RefutationType.EVIDENCE_HASH_MISMATCH, "   ", "2026-02-01T00:00:00Z",
    )
    verdict = admissibility(empty, _surface())
    assert verdict.admitted is False
    assert "cites no counterevidence" in verdict.details


def test_the_most_degrading_confirmed_outcome_decides():
    assert most_degraded([]) is ArtifactStatus.VALID
    assert most_degraded(
        [ArtifactStatus.STALE, ArtifactStatus.REVOKED, ArtifactStatus.CHALLENGED]
    ) is ArtifactStatus.REVOKED
    assert DEGRADATION_ORDER[0] is ArtifactStatus.VALID
    assert DEGRADATION_ORDER[-1] is ArtifactStatus.REVOKED


# --------------------------------------------------------------------------
# 4.14 refutability closure
# --------------------------------------------------------------------------


def _closure(**overrides) -> RefutabilityClosure:
    return RefutabilityClosure(
        closure_id=overrides.get("closure_id", "closure:1"),
        inputs=overrides.get(
            "inputs", (InputBinding("A", "sha256:a", 14), InputBinding("B", "sha256:b", 9))
        ),
        transformation_certificate=overrides.get("transformation_certificate", "sha256:f"),
        transformation_depth=overrides.get("transformation_depth", 12),
        output_claim="claim:C",
        output_surface=_surface(),
        mappings=overrides.get(
            "mappings",
            (
                RefutationMapping(
                    RefutationType.METRIC_RECOMPUTATION_MISMATCH, Locus.INPUT, "A's metric", "A"
                ),
                RefutationMapping(
                    RefutationType.EVIDENCE_HASH_MISMATCH, Locus.TRANSFORMATION, "f's output hash"
                ),
            ),
        ),
    )


def test_the_output_is_capped_by_its_weakest_link():
    closure = _closure()
    check = closure.validate()
    assert check.accepted is True
    assert check.closed_depth == 9  # not 14, not the average, not the transformation
    assert check.conformance_status == "NOT_ESTABLISHED"


def test_refutability_does_not_increase_under_composition():
    closure = _closure()
    assert cap_output_depth(closure, 9).accepted is True
    denied = cap_output_depth(closure, 14)
    assert denied.accepted is False
    assert "does not increase under composition" in denied.details


def test_an_unevidenced_edge_does_not_yield_a_verified_output():
    """A graph is only as verified as its edges."""
    check = _closure(transformation_certificate="").validate()
    assert check.accepted is False
    assert "unevidenced edge" in check.details


def test_every_admissible_output_refutation_must_be_localizable():
    """A challenge that lands nowhere is not a challenge."""
    check = _closure(mappings=_closure().mappings[:1]).validate()
    assert check.accepted is False
    assert check.unmapped == ("evidence_hash_mismatch",)


def test_a_mapping_cannot_point_at_an_unbound_input():
    check = _closure(
        mappings=(
            RefutationMapping(
                RefutationType.METRIC_RECOMPUTATION_MISMATCH, Locus.INPUT, "?", "Z"
            ),
            RefutationMapping(
                RefutationType.EVIDENCE_HASH_MISMATCH, Locus.TRANSFORMATION, "f"
            ),
        )
    ).validate()
    assert check.accepted is False
    assert "not bound by this closure" in check.details


def test_a_challenge_to_the_output_localizes_to_a_named_place():
    closure = _closure()
    mapping = closure.localize(RefutationType.METRIC_RECOMPUTATION_MISMATCH)
    assert mapping is not None
    assert mapping.locus is Locus.INPUT
    assert mapping.input_id == "A"
    assert closure.localize(RefutationType.ANCHOR_FORK) is None


def test_a_closure_with_no_inputs_composes_nothing():
    assert _closure(inputs=()).validate().accepted is False
