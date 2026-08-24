"""Adversarial tests for the experimental VSTD/SCITT composition boundary."""

from __future__ import annotations

import json

import pytest

from verifier.interoperability.scitt import (
    CompositionStatus,
    InteropError,
    ScittEvidenceState,
    ScittVerificationEvidence,
    VstdCoordinates,
    VstdScittPayload,
    VstdVerificationEvidence,
    VstdVerificationState,
    compose_results,
    consume_scitt_evidence,
    create_scitt_registration_template,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
ISSUER = "https://issuer.example"
SUBJECT = "artifact:sha256:" + DIGEST_A


def _receipt(*, result: str = "PASS") -> dict:
    return {
        "schema_version": "VSTD-4",
        "receipt_id": "VFY-4-scitt-interop-test",
        "canonical_digest": DIGEST_B,
        "claim_id": "SCITT-INTEROP-TEST",
        "binding": {
            "claim": "the bounded predicate holds for the named artifact",
            "coordinate": {
                "subject": SUBJECT,
                "predicate": "bounded_predicate",
                "parameters": {"policy": "test-policy-v1"},
            },
            "bounds": {
                "verification_cost_bound": 100,
                "memory_bound": 10,
                "certificate_size_bound": 10000,
            },
        },
        "decision": {"verdict": result, "certificate": "fixture-only"},
    }


def _coordinates(*, result: str = "PASS") -> VstdCoordinates:
    return VstdCoordinates(
        receipt_id="VFY-4-scitt-interop-test",
        schema_version="VSTD-4",
        claim_id="SCITT-INTEROP-TEST",
        subject=SUBJECT,
        predicate="bounded_predicate",
        parameters={"policy": "test-policy-v1"},
        native_result=result,
        native_canonical_digest=DIGEST_B,
        evidence_bounds={
            "verification_cost_bound": 100,
            "memory_bound": 10,
            "certificate_size_bound": 10000,
        },
        artifact_digests={"primary": DIGEST_A},
        provenance_references=("urn:example:provenance:1",),
    )


def _payload(*, result: str = "PASS") -> VstdScittPayload:
    return VstdScittPayload.create(_receipt(result=result), _coordinates(result=result))


def _scitt(
    payload: VstdScittPayload,
    *,
    state: ScittEvidenceState = ScittEvidenceState.REGISTERED,
    signed: bool = True,
    receipt: bool = True,
    payload_digest: str | None = None,
    issuer: str = ISSUER,
    subject: str = SUBJECT,
) -> ScittVerificationEvidence:
    return ScittVerificationEvidence(
        state=state,
        statement_sha256=DIGEST_C,
        payload_sha256=payload_digest or payload.payload_sha256(),
        issuer=issuer,
        subject=subject,
        signed_statement_verified=signed,
        receipt_verified=receipt,
        verification_profile="RFC9943+RFC9942",
        registration_policy="urn:example:registration-policy:v1",
        transparency_service="https://transparency.example",
        vds="RFC9162_SHA256",
        native_result=state.value.lower(),
        reason="native verifier fixture result",
        registered_at="2026-08-23T00:00:00Z",
    )


def _vstd(
    payload: VstdScittPayload,
    *,
    state: VstdVerificationState = VstdVerificationState.VERIFIED,
    result: str | None = None,
    receipt_digest: str | None = None,
) -> VstdVerificationEvidence:
    return VstdVerificationEvidence(
        state=state,
        receipt_sha256=receipt_digest or payload.receipt_sha256,
        native_result=result or payload.coordinates.native_result,
        checker="verifier.core.kernel.check",
        verification_profile="VSTD4-GDC-1/reference-kernel",
        reason="native checker fixture result",
    )


def _compose(
    payload: VstdScittPayload,
    scitt: ScittVerificationEvidence,
    *,
    artifacts: dict[str, str] | None = None,
):
    return compose_results(
        payload,
        _vstd(payload),
        scitt,
        artifact_digests=artifacts or {"primary": DIGEST_A},
        accepted_issuers=[ISSUER],
    )


def test_deterministic_serialization_and_round_trip_preserve_coordinates():
    payload = _payload()
    encoded = payload.to_bytes()
    assert encoded == payload.to_bytes()
    assert b'": ' not in encoded
    assert b", " not in encoded

    decoded = VstdScittPayload.from_bytes(encoded)
    assert decoded.to_bytes() == encoded
    assert decoded.coordinates.to_dict() == payload.coordinates.to_dict()
    assert decoded.receipt_sha256 == payload.receipt_sha256
    assert decoded.coordinates.evidence_bounds["memory_bound"] == 10
    assert decoded.coordinates.provenance_references == (
        "urn:example:provenance:1",
    )


def test_native_vstd_payload_does_not_require_scitt_identity_or_log_coordinates():
    payload = _payload().to_dict()
    serialized = json.dumps(payload, sort_keys=True)
    for scitt_coordinate in (
        "issuer",
        "transparency_service",
        "registration_policy",
        "registered_at",
    ):
        assert scitt_coordinate not in payload
        assert f'"{scitt_coordinate}"' not in serialized

    template = create_scitt_registration_template(
        _receipt(), _coordinates(), issuer=ISSUER, subject=SUBJECT
    ).to_dict()
    assert template["required_protected_header_projection"]["issuer"] == ISSUER


def test_noncanonical_or_extra_payload_fields_are_rejected():
    payload = _payload().to_dict()
    payload["unexpected"] = True
    with pytest.raises(InteropError, match="not in canonical form"):
        VstdScittPayload.from_bytes(json.dumps(payload).encode())

    canonical_with_extra = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()
    with pytest.raises(InteropError, match="keys mismatch"):
        VstdScittPayload.from_bytes(canonical_with_extra)


def test_version_mismatch_and_unsupported_profile_fail_closed():
    payload = _payload().to_dict()
    payload["mapping_version"] = "9.9"
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(InteropError, match="unsupported mapping version"):
        VstdScittPayload.from_bytes(encoded)

    payload["mapping_version"] = "0.1"
    payload["profile"] = "unknown-profile"
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(InteropError, match="unsupported profile"):
        VstdScittPayload.from_bytes(encoded)


def test_receipt_identity_and_claim_coordinate_mismatch_are_rejected():
    receipt = _receipt()
    receipt["receipt_id"] = "VFY-4-other"
    with pytest.raises(InteropError, match="receipt_id"):
        VstdScittPayload.create(receipt, _coordinates())

    receipt = _receipt()
    receipt["binding"]["coordinate"]["predicate"] = "other_predicate"
    with pytest.raises(InteropError, match="binding coordinate"):
        VstdScittPayload.create(receipt, _coordinates())


def test_mutating_nested_receipt_after_creation_does_not_change_payload():
    receipt = _receipt()
    payload = VstdScittPayload.create(receipt, _coordinates())
    before = payload.to_bytes()
    receipt["binding"]["claim"] = "mutated by caller"
    assert payload.to_bytes() == before


def test_registration_template_is_explicitly_not_cose_and_binds_subject():
    template = create_scitt_registration_template(
        _receipt(), _coordinates(), issuer=ISSUER, subject=SUBJECT
    )
    data = template.to_dict()
    assert data["representation"] == "normalized-registration-input-not-cose"
    assert data["payload_sha256"] == template.payload.payload_sha256()
    assert data["required_protected_header_projection"]["issuer"] == ISSUER
    assert data["required_protected_header_projection"]["subject"] == SUBJECT

    with pytest.raises(InteropError, match="subject must equal"):
        create_scitt_registration_template(
            _receipt(), _coordinates(), issuer=ISSUER, subject="artifact:other"
        )


def test_registered_vstd_pass_composes_to_pass_only_for_exact_artifact():
    payload = _payload()
    result = _compose(payload, _scitt(payload))
    assert result.status is CompositionStatus.PASS
    assert result.native_vstd_result == "PASS"
    assert result.native_scitt_result == "registered"


def test_registered_scitt_cannot_create_pass_without_bound_vstd_verification():
    payload = _payload()
    result = compose_results(
        payload,
        _vstd(payload, state=VstdVerificationState.NOT_EVALUATED),
        _scitt(payload),
        artifact_digests={"primary": DIGEST_A},
        accepted_issuers=[ISSUER],
    )
    assert result.status is CompositionStatus.UNKNOWN
    assert result.reason == "native VSTD receipt was not evaluated"


def test_vstd_checker_result_must_bind_exact_receipt_and_native_result():
    payload = _payload()
    wrong_receipt = compose_results(
        payload,
        _vstd(payload, receipt_digest=DIGEST_C),
        _scitt(payload),
        artifact_digests={"primary": DIGEST_A},
        accepted_issuers=[ISSUER],
    )
    assert wrong_receipt.status is CompositionStatus.FAIL
    assert "embedded receipt" in wrong_receipt.reason

    wrong_result = compose_results(
        payload,
        _vstd(payload, result="UNKNOWN"),
        _scitt(payload),
        artifact_digests={"primary": DIGEST_A},
        accepted_issuers=[ISSUER],
    )
    assert wrong_result.status is CompositionStatus.FAIL
    assert "payload result" in wrong_result.reason


def test_rejected_vstd_receipt_cannot_be_repaired_by_scitt_registration():
    payload = _payload()
    result = compose_results(
        payload,
        _vstd(payload, state=VstdVerificationState.REJECTED),
        _scitt(payload),
        artifact_digests={"primary": DIGEST_A},
        accepted_issuers=[ISSUER],
    )
    assert result.status is CompositionStatus.FAIL
    assert "checker rejected" in result.reason


def test_registered_scitt_preserves_vstd_resource_indeterminacy():
    payload = _payload()
    result = compose_results(
        payload,
        _vstd(
            payload,
            state=VstdVerificationState.INDETERMINATE,
            result="UNKNOWN",
        ),
        _scitt(payload),
        artifact_digests={"primary": DIGEST_A},
        accepted_issuers=[ISSUER],
    )
    assert result.status is CompositionStatus.UNKNOWN
    assert result.native_vstd_result == "UNKNOWN"
    assert "unable to decide" in result.reason


def test_artifact_substitution_fails_even_when_scitt_registration_is_valid():
    payload = _payload()
    result = _compose(payload, _scitt(payload), artifacts={"primary": DIGEST_B})
    assert result.status is CompositionStatus.FAIL
    assert result.reason == "artifact binding mismatch"


def test_valid_registration_does_not_upgrade_failed_vstd_claim():
    payload = _payload(result="FAIL")
    result = _compose(payload, _scitt(payload))
    assert result.status is CompositionStatus.FAIL
    assert result.native_vstd_result == "FAIL"


@pytest.mark.parametrize("native", ["UNKNOWN", "INDETERMINATE", "UNSUPPORTED"])
def test_registered_statement_preserves_vstd_indeterminacy(native):
    payload = _payload(result=native)
    result = _compose(payload, _scitt(payload))
    assert result.status is CompositionStatus.UNKNOWN
    assert result.native_vstd_result == native


@pytest.mark.parametrize(
    "state",
    [
        ScittEvidenceState.MISSING,
        ScittEvidenceState.STALE,
        ScittEvidenceState.REVOKED,
        ScittEvidenceState.SUPERSEDED,
        ScittEvidenceState.UNKNOWN,
    ],
)
def test_noncurrent_scitt_evidence_caps_vstd_pass_at_unknown(state):
    payload = _payload()
    result = _compose(payload, _scitt(payload, state=state))
    assert result.status is CompositionStatus.UNKNOWN
    assert state.value in result.reason


def test_conflicted_evidence_is_not_collapsed_to_unknown_or_pass():
    payload = _payload()
    result = _compose(
        payload, _scitt(payload, state=ScittEvidenceState.CONFLICTED)
    )
    assert result.status is CompositionStatus.CONFLICTED


def test_payload_transplant_is_detected_despite_verified_scitt_receipt():
    payload = _payload()
    evidence = _scitt(payload, payload_digest=DIGEST_B)
    result = _compose(payload, evidence)
    assert result.status is CompositionStatus.FAIL
    assert "payload" in result.reason


def test_wrong_issuer_and_subject_fail_relying_party_policy():
    payload = _payload()
    wrong_issuer = _scitt(payload, issuer="https://other.example")
    assert _compose(payload, wrong_issuer).status is CompositionStatus.FAIL

    wrong_subject = _scitt(payload, subject="artifact:other")
    assert _compose(payload, wrong_subject).status is CompositionStatus.FAIL


def test_unverified_statement_or_receipt_cannot_be_called_registered():
    payload = _payload()
    with pytest.raises(InteropError, match="REGISTERED requires"):
        _scitt(payload, signed=False)
    with pytest.raises(InteropError, match="REGISTERED requires"):
        _scitt(payload, receipt=False)


def test_scitt_evidence_adapter_never_emits_computational_verdict():
    payload = _payload()
    evidence = consume_scitt_evidence(
        _scitt(payload),
        expected_payload_sha256=payload.payload_sha256(),
        expected_subject=SUBJECT,
        accepted_issuers=[ISSUER],
    )
    assert evidence["normalized_state"] == "REGISTERED"
    assert evidence["computational_verdict"] == "NOT_EVALUATED"


def test_malformed_evidence_and_unknown_vstd_result_are_rejected():
    payload = _payload()
    malformed = _scitt(payload).to_dict()
    malformed["extra"] = "guess me"
    with pytest.raises(InteropError, match="keys mismatch"):
        ScittVerificationEvidence.from_dict(malformed)

    unsupported = _payload(result="VALID")
    with pytest.raises(InteropError, match="refusing to guess"):
        _compose(unsupported, _scitt(unsupported))


def test_scitt_verification_evidence_round_trip():
    payload = _payload()
    evidence = _scitt(payload)
    decoded = ScittVerificationEvidence.from_dict(evidence.to_dict())
    assert decoded == evidence


def test_vstd_verification_evidence_round_trip_and_closed_shape():
    evidence = _vstd(_payload())
    assert VstdVerificationEvidence.from_dict(evidence.to_dict()) == evidence

    malformed = evidence.to_dict()
    malformed["extra"] = "guess me"
    with pytest.raises(InteropError, match="keys mismatch"):
        VstdVerificationEvidence.from_dict(malformed)
