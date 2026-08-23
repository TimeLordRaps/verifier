"""Validation suite for the experimental bounded identity disclosure profile.

Each test names the inference it exists to block. A test that starts passing because
a status was upgraded to something more favourable is a defect, not a fix.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

EXPERIMENT = Path(__file__).resolve().parents[1]
if str(EXPERIMENT) not in sys.path:
    sys.path.insert(0, str(EXPERIMENT))

from evaluate import (  # noqa: E402
    ACCEPTED_BOUNDED,
    ATTESTED,
    CONFLICTED,
    REFUTED,
    REJECTED,
    SUPPORTED,
    UNKNOWN,
    evaluate,
    load_model,
)

FIXTURES = sorted((EXPERIMENT / "fixtures").glob("*.json"))


def load(name: str) -> dict:
    return json.loads((EXPERIMENT / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))


def result(name: str):
    return evaluate(load(name)["record"])


def test_fixture_corpus_is_non_empty() -> None:
    assert FIXTURES, "the fixture corpus must not be empty"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_fixture_matches_declared_expectation(path: Path) -> None:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    outcome = evaluate(fixture["record"])
    assert outcome.verdict == fixture["expected"]["verdict"]
    assert outcome.properties == fixture["expected"]["properties"]
    assert outcome.reasons, "every evaluation must carry at least one stated reason"


def test_civil_identity_withheld_keeps_authorization_verifiable() -> None:
    outcome = result("positive_bounded_authorization")
    assert outcome.verdict == ACCEPTED_BOUNDED
    assert outcome.properties["civil_identity"] == "UNSUPPORTED_BY_DESIGN"
    assert outcome.properties["authorization"] == SUPPORTED


def test_bounded_acceptance_does_not_imply_uniqueness_or_independence() -> None:
    outcome = result("positive_bounded_authorization")
    assert outcome.properties["uniqueness"] == UNKNOWN
    assert outcome.properties["verifier_independence"] == UNKNOWN
    assert outcome.properties["unlinkability"] == UNKNOWN


def test_missing_authorization_stays_unknown() -> None:
    outcome = result("unknown_missing_authorization")
    assert outcome.verdict == UNKNOWN
    assert outcome.properties["authorization"] == UNKNOWN


def test_revoked_authority_is_refuted_not_unknown() -> None:
    outcome = result("rejected_revoked_authority")
    assert outcome.verdict == REJECTED
    assert outcome.properties["authority_active"] == REFUTED


def test_expired_authority_is_refuted() -> None:
    outcome = result("rejected_expired_authority")
    assert outcome.properties["authority_active"] == REFUTED


def test_shared_pseudonym_does_not_establish_actor_independence_or_nonindependence() -> None:
    outcome = result("unknown_shared_pseudonym_independence")
    assert outcome.properties["verifier_independence"] == UNKNOWN
    assert outcome.verdict == UNKNOWN


def test_distinct_pseudonyms_do_not_establish_distinct_actors() -> None:
    outcome = result("unknown_distinct_pseudonyms")
    assert outcome.properties["verifier_independence"] == UNKNOWN
    assert outcome.verdict == UNKNOWN


def test_minimization_cannot_delete_a_required_trust_root() -> None:
    outcome = result("rejected_unlinkability_erases_trust_root")
    assert outcome.verdict == REJECTED
    assert outcome.properties["authority_active"] == UNKNOWN
    assert any("revocation.source" in reason for reason in outcome.reasons)


def test_minimization_cannot_bypass_a_protected_leaf_by_deleting_its_parent() -> None:
    outcome = result("rejected_minimization_erases_key_binding")
    assert outcome.verdict == REJECTED
    assert outcome.properties["authentication"] == UNKNOWN
    assert any("actor.key_binding" in reason for reason in outcome.reasons)


def test_replayed_challenge_is_detected() -> None:
    outcome = result("rejected_replayed_challenge")
    assert outcome.properties["freshness"] == REFUTED
    assert outcome.verdict == REJECTED


def test_required_freshness_without_a_challenge_fails_closed() -> None:
    outcome = result("rejected_missing_challenge")
    assert outcome.properties["freshness"] == REFUTED


def test_absent_uniqueness_evidence_is_not_sybil_resistance() -> None:
    outcome = result("unknown_uniqueness_absent")
    assert outcome.properties["uniqueness"] == UNKNOWN
    assert outcome.verdict == UNKNOWN


def test_conflicting_identity_evidence_stays_conflicted() -> None:
    outcome = result("conflicted_identity_evidence")
    assert outcome.properties["civil_identity"] == CONFLICTED
    assert outcome.verdict == CONFLICTED


def test_minimization_may_not_widen_the_claim_boundary() -> None:
    outcome = result("rejected_minimization_widens_boundary")
    assert outcome.verdict == REJECTED
    assert any("widened" in reason for reason in outcome.reasons)


def test_minimization_that_narrows_keeps_the_bounded_result() -> None:
    outcome = result("positive_minimized_boundary_narrowed")
    assert outcome.verdict == ACCEPTED_BOUNDED
    assert outcome.properties["unlinkability"] == "ASSUMED"


def test_key_compromise_refutes_authentication() -> None:
    outcome = result("rejected_key_compromise")
    assert outcome.properties["authentication"] == REFUTED
    assert outcome.verdict == REJECTED


def test_unlinkability_is_never_supported() -> None:
    for path in FIXTURES:
        fixture = json.loads(path.read_text(encoding="utf-8"))
        assert evaluate(fixture["record"]).properties["unlinkability"] != SUPPORTED


def test_no_fixture_reaches_acceptance_with_a_refuted_property() -> None:
    for path in FIXTURES:
        outcome = evaluate(json.loads(path.read_text(encoding="utf-8"))["record"])
        if REFUTED in outcome.properties.values():
            assert outcome.verdict == REJECTED


def test_accountability_requires_a_bound_escalation_authority() -> None:
    record = load("positive_bounded_authorization")["record"]
    assert evaluate(record).properties["accountability"] == ATTESTED
    record.pop("escalation_authority")
    assert evaluate(record).properties["accountability"] == UNKNOWN


def test_recovery_absence_stays_unknown() -> None:
    record = load("positive_bounded_authorization")["record"]
    record.pop("recovery")
    assert evaluate(record).properties["recovery"] == UNKNOWN


def test_unknown_trust_root_does_not_authenticate() -> None:
    record = load("positive_bounded_authorization")["record"]
    record["trust_roots"] = ["root:other"]
    outcome = evaluate(record)
    assert outcome.properties["authentication"] == UNKNOWN
    assert outcome.verdict == UNKNOWN


@pytest.mark.parametrize("coordinate", ["pseudonym", "key_id", "issuer"])
def test_required_public_identity_coordinates_cannot_be_omitted(coordinate: str) -> None:
    record = load("positive_bounded_authorization")["record"]
    if coordinate == "pseudonym":
        record["actor"].pop("pseudonym")
    elif coordinate == "key_id":
        record["actor"]["key_binding"].pop("key_id")
    else:
        record["authorization"].pop("issuer")
    outcome = evaluate(record)
    assert outcome.verdict == UNKNOWN


def test_undeclared_issuer_does_not_authorize() -> None:
    record = load("positive_bounded_authorization")["record"]
    record["authorization"]["issuer"] = "root:undeclared"
    outcome = evaluate(record)
    assert outcome.properties["authorization"] == UNKNOWN
    assert outcome.verdict == UNKNOWN


def test_scope_mismatch_is_refuted() -> None:
    record = load("positive_bounded_authorization")["record"]
    record["claim_scope"] = "vstd4-availability-run"
    outcome = evaluate(record)
    assert outcome.properties["authorization"] == REFUTED


def test_signing_is_not_authorship() -> None:
    outcome = result("unknown_absent_authorship")
    assert outcome.properties["authorship_degree"] == UNKNOWN
    assert outcome.verdict == UNKNOWN


def test_relayed_claim_is_not_first_party_authorship() -> None:
    outcome = result("rejected_relay_claims_origination")
    assert outcome.properties["authorship_degree"] == REFUTED
    assert outcome.verdict == REJECTED


def test_declared_degree_must_agree_with_recorded_delegation_hops() -> None:
    outcome = result("conflicted_authorship_degree_vs_chain")
    assert outcome.properties["authorship_degree"] == CONFLICTED
    assert outcome.verdict == CONFLICTED


@pytest.mark.parametrize("degree", [True, -1])
def test_authorship_degree_must_be_a_nonnegative_integer(degree: object) -> None:
    record = load("positive_bounded_authorization")["record"]
    record["authorship"]["degree"] = degree
    assert evaluate(record).properties["authorship_degree"] == UNKNOWN


def test_unattested_ancestry_link_is_not_a_verified_chain() -> None:
    outcome = result("unknown_unattested_ancestry_link")
    assert outcome.properties["credential_ancestry"] == UNKNOWN


def test_authority_does_not_survive_a_revoked_ancestor() -> None:
    outcome = result("rejected_revoked_ancestor")
    assert outcome.properties["credential_ancestry"] == REFUTED
    assert outcome.verdict == REJECTED


def test_delegation_may_not_widen_scope_beyond_its_ancestor() -> None:
    outcome = result("rejected_delegation_widens_scope")
    assert outcome.properties["credential_ancestry"] == REFUTED


def test_unattested_rotation_does_not_merge_two_key_coordinates() -> None:
    outcome = result("unknown_unattested_rotation")
    assert outcome.properties["credential_ancestry"] == UNKNOWN


def test_absent_ancestry_chain_stays_unknown() -> None:
    record = load("positive_bounded_authorization")["record"]
    record.pop("credential_ancestry")
    assert evaluate(record).properties["credential_ancestry"] == UNKNOWN


def test_chain_must_terminate_at_the_signing_key() -> None:
    record = load("positive_bounded_authorization")["record"]
    record["credential_ancestry"][0]["child"] = "key:someone-else"
    assert evaluate(record).properties["credential_ancestry"] == UNKNOWN


def test_chain_must_begin_at_a_declared_trust_root() -> None:
    record = load("positive_bounded_authorization")["record"]
    record["credential_ancestry"][0]["parent"] = "root:undeclared"
    assert evaluate(record).properties["credential_ancestry"] == UNKNOWN


def test_authorship_and_ancestry_are_never_supported() -> None:
    for path in FIXTURES:
        outcome = evaluate(json.loads(path.read_text(encoding="utf-8"))["record"])
        assert outcome.properties["authorship_degree"] != SUPPORTED
        assert outcome.properties["credential_ancestry"] != SUPPORTED


def test_model_declares_the_terminology_decision_and_prohibited_inferences() -> None:
    model = load_model()
    assert model["status"] == "EXPERIMENTAL"
    assert model["wire_identifier"] is None
    decision = model["terminology_decision"]["public_label_zero_identity"]
    assert decision == "REJECTED_AS_UNQUALIFIED_PUBLIC_LABEL"
    assert "verdict_aggregation" in model
    assert "verdict_precedence" not in model
    assert len(model["prohibited_inferences"]) >= 10


def test_model_never_lists_unlinkability_as_supported() -> None:
    model = load_model()
    assert SUPPORTED not in model["properties"]["unlinkability"]["attainable_statuses"]


def test_experiment_declares_no_new_wire_identifier() -> None:
    for path in (EXPERIMENT / "fixtures").glob("*.json"):
        text = path.read_text(encoding="utf-8")
        for frozen in ("VSTD-0.1", "VSTD-0.2", "VSTD-3.0", "VSTD-DATA-0.1"):
            assert frozen not in text, f"{path.name} must not bind a frozen wire identifier"
