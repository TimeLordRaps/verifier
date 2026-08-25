"""Terminology: hash-based message authentication code (HMAC);
Security Protocol and Data Model (SPDM); Verifier Standard (VSTD).

Canonical binding and independent verification for VSTD 3 attestations."""

from __future__ import annotations

from dataclasses import replace
from typing import Optional

from .canonical import canonical_digest
from .continuity import KeyResolver, TEST_SIGNATURE_ALGORITHM, verify_hmac_signature
from .models import AttestationEvidence, VerificationState


ATTESTATION_DOMAIN = "VSTD3-ATTESTATION-EVIDENCE-1"


def attestation_signed_payload(evidence: AttestationEvidence) -> dict[str, object]:
    """Return every semantic attestation field covered by its signature.

    ``signature`` and the collector's ``verification_state`` are deliberately not
    self-authenticating inputs. The latter is independently recomputed by a verifier.
    """

    return {
        "domain": ATTESTATION_DOMAIN,
        "evidence_id": evidence.evidence_id,
        "subject_identity_id": evidence.subject_identity_id,
        "challenge_id": evidence.challenge_id,
        "nonce_b64": evidence.nonce_b64,
        "issued_at": evidence.issued_at,
        "expires_at": evidence.expires_at,
        "evidence_source_id": evidence.evidence_source_id,
        "firmware_measurements": [item.to_dict() for item in evidence.firmware_measurements],
        "runtime_measurements": [item.to_dict() for item in evidence.runtime_measurements],
        "device_certificate": (
            evidence.device_certificate.to_dict() if evidence.device_certificate is not None else None
        ),
        "demonstrated_capabilities": [item.value for item in evidence.demonstrated_capabilities],
    }


def attestation_signed_digest(evidence: AttestationEvidence) -> str:
    return canonical_digest(attestation_signed_payload(evidence))


def independently_verify_attestation(
    evidence: AttestationEvidence,
    *,
    key_resolver: Optional[KeyResolver],
) -> tuple[AttestationEvidence, str]:
    """Recompute verification state for algorithms implemented by the core.

    The reference package implements only its explicitly test-only HMAC envelope.
    Vendor/SPDM evidence must be verified by an adapter that supplies an independently
    checked result; unknown algorithms remain NOT_VERIFIED rather than being guessed.
    """

    signature = evidence.signature
    if signature is None:
        return replace(evidence, verification_state=VerificationState.NOT_VERIFIED), "missing signature"
    expected_digest = attestation_signed_digest(evidence)
    if signature.signed_digest != expected_digest:
        return replace(evidence, verification_state=VerificationState.FAILED), "signature covers the wrong digest"
    if signature.algorithm != TEST_SIGNATURE_ALGORITHM:
        return (
            replace(evidence, verification_state=VerificationState.NOT_VERIFIED),
            f"unsupported signature verifier {signature.algorithm}",
        )
    if key_resolver is None:
        return replace(evidence, verification_state=VerificationState.NOT_VERIFIED), "verification key unavailable"
    key = key_resolver(signature.key_id)
    if key is None:
        return replace(evidence, verification_state=VerificationState.NOT_VERIFIED), "verification key unavailable"
    if not verify_hmac_signature(signature, key):
        return replace(evidence, verification_state=VerificationState.FAILED), "signature verification failed"
    return replace(evidence, verification_state=VerificationState.VERIFIED), "signature verified"
