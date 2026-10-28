"""Policy decisions carry their kernel certificate and can be re-checked from evidence.

Before this change ``certify_policy_cnf`` returned a certificate that every
``ProvenancePolicyVerifier`` method discarded, so the returned
``PolicyEvaluationResult`` had no way to show the kernel-checkable proof behind
its verdict. These tests pin the carried evidence, the independent re-check, and
the refusal of substituted, stale, reordered, aliased, cross-policy and
malformed forms.
"""

from __future__ import annotations

import dataclasses

import pytest

from verifier.core.certificate import (
    CertificateError,
    CostTier,
    DecisionCertificate,
    Verdict,
)
from verifier.core.kernel import check as kernel_check
from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    RightsSpec,
    TransformationHyperedge,
    TransformationType,
)
from verifier.data.policy import (
    PolicyDecisionEvidence,
    PolicyEncodingError,
    ProvenancePolicyVerifier,
    certify_policy_cnf,
    check_policy_decision,
    ground_policy_cnf,
)

TARGET = "artifact:target"
ANCESTOR = "artifact:ancestor"


def _graph(ancestor_status: ArtifactStatus, *, ancestor_license: str | None = "MIT") -> ProvenanceHypergraph:
    graph = ProvenanceHypergraph()
    graph.add_rights(RightsSpec("rights:ancestor", ancestor_license or "PROPRIETARY"))
    graph.add_rights(RightsSpec("rights:target", "MIT"))
    graph.add_artifact(
        ArtifactNode(
            artifact_id=ANCESTOR,
            label=ANCESTOR,
            artifact_type=ArtifactType.RAW_SOURCE_FILE,
            content_digest="0" * 64,
            status=ancestor_status,
            rights_id="rights:ancestor" if ancestor_license is not None else None,
        )
    )
    graph.add_artifact(
        ArtifactNode(
            artifact_id=TARGET,
            label=TARGET,
            artifact_type=ArtifactType.RAW_SOURCE_FILE,
            content_digest="1" * 64,
            status=ArtifactStatus.VALID,
            rights_id="rights:target",
        )
    )
    graph.add_transformation(
        TransformationHyperedge(
            transformation_id="transform:derive",
            label="derive target from ancestor",
            transformation_type=TransformationType.EVALUATION,
            inputs=(HyperedgePort(ANCESTOR, "INPUT"),),
            outputs=(HyperedgePort(TARGET, "OUTPUT"),),
            software_provenance={},
            parameters={},
            execution_environment={},
        )
    )
    return graph


@pytest.fixture
def valid_result():
    return ProvenancePolicyVerifier.verify_all_ancestors_valid(_graph(ArtifactStatus.VALID), TARGET)


@pytest.fixture
def revoked_result():
    return ProvenancePolicyVerifier.verify_no_revoked_ancestors(_graph(ArtifactStatus.REVOKED), TARGET)


def test_pass_result_retains_the_kernel_certificate_that_proved_it(valid_result):
    certificate = valid_result.certificate
    assert isinstance(certificate, DecisionCertificate)
    assert certificate.header.verdict is Verdict.PASS
    assert kernel_check(certificate).accepted


def test_falsified_result_retains_the_refuting_certificate(revoked_result):
    assert revoked_result.passed is False
    assert revoked_result.certificate is not None
    assert revoked_result.certificate.header.verdict is Verdict.FAIL


def test_refused_and_indeterminate_results_synthesize_no_certificate():
    empty = ProvenancePolicyVerifier.verify_all_ancestors_valid(_graph(ArtifactStatus.VALID), "artifact:absent")
    assert empty.certificate is None
    assert empty.decision_evidence() is None


def test_decision_evidence_is_rechecked_from_evidence_alone(valid_result, revoked_result):
    for result in (valid_result, revoked_result):
        evidence = result.decision_evidence()
        assert isinstance(evidence, PolicyDecisionEvidence)
        assert evidence.passed is result.passed
        assert evidence.policy_id == result.policy_id
        assert evidence.certificate.digest() == result.certificate.digest()
        assert check_policy_decision(evidence) is True


def test_evidence_round_trips_through_its_closed_form(valid_result):
    evidence = valid_result.decision_evidence()
    parsed = PolicyDecisionEvidence.from_dict(evidence.to_dict())
    assert parsed == evidence
    assert check_policy_decision(parsed) is True


def test_result_with_a_substituted_certificate_fails_its_own_recheck(valid_result, revoked_result):
    """A PASS cannot survive being paired with the refuting certificate."""
    forged = dataclasses.replace(
        valid_result.decision_evidence(), certificate=revoked_result.certificate
    )
    assert check_policy_decision(forged) is False


def test_pass_flag_cannot_be_asserted_over_a_failing_certificate(revoked_result):
    forged = dataclasses.replace(revoked_result.decision_evidence(), passed=True)
    assert check_policy_decision(forged) is False


def test_cross_policy_certificate_substitution_is_rejected(valid_result):
    other_policy = ProvenancePolicyVerifier.verify_no_revoked_ancestors(
        _graph(ArtifactStatus.VALID), TARGET
    )
    forged = dataclasses.replace(
        valid_result.decision_evidence(), policy_id=other_policy.policy_id,
    )
    assert check_policy_decision(forged) is False


def test_stale_evidence_for_another_target_is_rejected(valid_result):
    forged = dataclasses.replace(valid_result.decision_evidence(), target_artifact_id="artifact:other")
    assert check_policy_decision(forged) is False


def test_reordered_clauses_are_rejected(valid_result):
    evidence = valid_result.decision_evidence()
    forged = dataclasses.replace(evidence, clauses=tuple(reversed(evidence.clauses)))
    assert check_policy_decision(forged) is False


def test_member_facts_that_differ_from_the_certificate_grounding_are_rejected(valid_result):
    """The clauses alone do not pin the facts; the grounding must match too."""
    evidence = valid_result.decision_evidence()
    forged = dataclasses.replace(evidence, member_values=((ANCESTOR, "REVOKED"),))
    assert check_policy_decision(forged) is False


def test_result_mutated_after_certification_fails_its_recheck(valid_result):
    evidence = valid_result.decision_evidence()
    valid_result.clauses[0][0] = -valid_result.clauses[0][0]
    assert check_policy_decision(evidence) is True  # evidence is a copy, not an alias
    assert check_policy_decision(valid_result.decision_evidence()) is False


def test_closed_form_refuses_unknown_missing_and_mistyped_fields(valid_result):
    base = valid_result.decision_evidence().to_dict()
    with pytest.raises(ValueError):
        PolicyDecisionEvidence.from_dict({**base, "unexpected": True})
    missing = dict(base)
    del missing["certificate"]
    with pytest.raises(ValueError):
        PolicyDecisionEvidence.from_dict(missing)
    with pytest.raises(ValueError):
        PolicyDecisionEvidence.from_dict({**base, "passed": 1})
    with pytest.raises(ValueError):
        PolicyDecisionEvidence.from_dict({**base, "clauses": [[True, 2]]})
    with pytest.raises((ValueError, CertificateError)):
        PolicyDecisionEvidence.from_dict({**base, "certificate": {**base["certificate"], "extra": 1}})


def test_evidence_and_result_are_immutable(valid_result):
    evidence = valid_result.decision_evidence()
    with pytest.raises(dataclasses.FrozenInstanceError):
        evidence.passed = False
    with pytest.raises(dataclasses.FrozenInstanceError):
        valid_result.certificate = None


def test_result_wire_form_is_unchanged_by_the_carried_certificate(valid_result):
    """The certificate travels beside the result, not inside its serialized form."""
    assert set(valid_result.to_dict()) == {
        "policy_id", "policy_name", "target_artifact_id", "passed", "verdict",
        "clauses", "variable_map", "explanation",
    }


def test_result_still_constructs_without_the_new_evidence_fields():
    from verifier.data.policy import PolicyEvaluationResult
    from verifier.core.checker import VerificationVerdict

    legacy = PolicyEvaluationResult(
        policy_id="POL-X", policy_name="x", target_artifact_id=TARGET, passed=False,
        verdict=VerificationVerdict.INDETERMINATE, clauses=[], variable_map={}, explanation="x",
    )
    assert legacy.certificate is None
    assert legacy.decision_evidence() is None


def test_aliased_variable_index_cannot_silently_drop_a_variable():
    """Two names on index 2 used to keep only the later name, unseen."""
    with pytest.raises(PolicyEncodingError, match="share index 2"):
        ground_policy_cnf(
            [[-1, 2], [2], [1]],
            {"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2, "CLEAN_b": 2},
            TARGET,
        )


def test_clause_literal_over_an_undeclared_variable_is_a_refusal():
    with pytest.raises(PolicyEncodingError, match="undeclared variable 3"):
        ground_policy_cnf([[-1, 2], [3], [1]], {"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2}, TARGET)


def test_member_fact_for_an_unrecorded_subject_is_refused():
    """An extra fact used to be ignored, so the evidence would overstate its inputs."""
    with pytest.raises(PolicyEncodingError, match="name no variable"):
        ground_policy_cnf(
            [[-1, 2], [2], [1]],
            {"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2},
            TARGET,
            member_value={"artifact:unrecorded": "REVOKED"},
        )


def test_certify_policy_cnf_still_returns_the_original_pair():
    passed, certificate = certify_policy_cnf(
        satisfiable=True,
        direct_result=True,
        policy_id="POL-TEST",
        target_artifact_id=TARGET,
        clauses=[[-1, 2], [2], [1]],
        var_map={"TARGET_ADMISSIBLE": 1, "CLEAN_a": 2},
        member_value={},
    )
    assert passed is True
    assert certificate.header.verdict is Verdict.PASS
    assert certificate.header.tier is CostTier.UP
