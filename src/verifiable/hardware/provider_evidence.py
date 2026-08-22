"""Canonical binding and independent verification of provider control-plane evidence."""

from __future__ import annotations

from dataclasses import replace
from typing import Optional

from .canonical import canonical_digest
from .continuity import KeyResolver, TEST_SIGNATURE_ALGORITHM, verify_hmac_signature
from .models import ProviderEvidence, VerificationState


def provider_signed_payload(evidence: ProviderEvidence) -> dict[str, object]:
    return {
        "schema_version": "VSTD3-PROVIDER-EVIDENCE-1.0",
        "evidence_id": evidence.evidence_id,
        "provider": evidence.provider,
        "resource_id": evidence.resource_id,
        "issued_at": evidence.issued_at,
        "expires_at": evidence.expires_at,
        "claims": evidence.claims,
        "key_id": evidence.signature.key_id if evidence.signature else "",
        "hardware_evidence_refs": list(evidence.hardware_evidence_refs),
    }


def independently_verify_provider_evidence(
    evidence: ProviderEvidence,
    *,
    key_resolver: Optional[KeyResolver],
) -> tuple[ProviderEvidence, str]:
    signature = evidence.signature
    if signature is None:
        return replace(evidence, verification_state=VerificationState.NOT_VERIFIED), "missing signature"
    expected_digest = canonical_digest(provider_signed_payload(evidence))
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
