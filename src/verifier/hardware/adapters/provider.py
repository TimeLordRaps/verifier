"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Cloud/provider control-plane evidence kept separate from hardware attestation."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
from typing import Mapping

from ..canonical import canonical_digest
from ..continuity import TEST_SIGNATURE_ALGORITHM, hmac_sign_digest
from ..models import (
    Capability,
    EvidenceProducer,
    EvidenceSource,
    ProviderEvidence,
    SignatureEnvelope,
    VerificationState,
)
from .base import AdapterError, evidence_source_from_bytes


@dataclass(frozen=True)
class ProviderNormalization:
    evidence: ProviderEvidence
    source_id: str
    source: EvidenceSource


def normalize_provider_evidence(
    raw: bytes,
    *,
    verification_key: bytes | None = None,
) -> tuple[ProviderEvidence, EvidenceSource]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AdapterError(f"malformed provider evidence: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise AdapterError("provider evidence must be a JSON object")
    allowed = {
        "schema_version",
        "evidence_id",
        "provider",
        "resource_id",
        "issued_at",
        "expires_at",
        "claims",
        "key_id",
        "signature_b64",
        "hardware_evidence_refs",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise AdapterError(f"provider evidence has unknown fields: {', '.join(unknown)}")
    if payload.get("schema_version") != "VSTD3-PROVIDER-EVIDENCE-1.0":
        raise AdapterError("unsupported provider evidence schema")
    missing = sorted(allowed - set(payload))
    if missing:
        raise AdapterError(f"provider evidence is missing fields: {', '.join(missing)}")
    string_fields = ("evidence_id", "provider", "resource_id", "issued_at", "expires_at", "key_id", "signature_b64")
    if any(not isinstance(payload[field], str) for field in string_fields):
        raise AdapterError("provider identity, time, key, and signature fields must be strings")
    if any(not payload[field] for field in ("evidence_id", "provider", "resource_id", "issued_at", "expires_at")):
        raise AdapterError("provider evidence identity and time fields must not be empty")
    claims = payload.get("claims")
    if not isinstance(claims, dict):
        raise AdapterError("provider claims must be an object")
    hardware_refs = payload.get("hardware_evidence_refs")
    if not isinstance(hardware_refs, list) or any(not isinstance(item, str) for item in hardware_refs):
        raise AdapterError("hardware_evidence_refs must be an array of strings")
    signed_payload = {key: payload[key] for key in payload if key not in {"signature_b64"}}
    signed_digest = canonical_digest(signed_payload)
    envelope = SignatureEnvelope(
        algorithm=TEST_SIGNATURE_ALGORITHM,
        key_id=str(payload.get("key_id", "")),
        signed_digest=signed_digest,
        signature_b64=str(payload.get("signature_b64", "")),
    )
    state = VerificationState.NOT_VERIFIED
    if verification_key is not None:
        try:
            observed = base64.b64decode(envelope.signature_b64, validate=True)
        except ValueError:
            state = VerificationState.FAILED
        else:
            expected = hmac.new(
                verification_key, signed_digest.encode("ascii"), hashlib.sha256
            ).digest()
            state = VerificationState.VERIFIED if hmac.compare_digest(observed, expected) else VerificationState.FAILED
    source_id = f"evidence:provider:{hashlib.sha256(raw).hexdigest()[:16]}"
    source = evidence_source_from_bytes(
        source_id=source_id,
        producer=EvidenceProducer.PROVIDER_CONTROL_PLANE,
        mechanism="provider control-plane evidence",
        observed_at=str(payload.get("issued_at", "")),
        capabilities=(Capability.PROVIDER_ATTESTED,),
        raw=raw,
        media_type="application/json",
        original_format="VSTD3-PROVIDER-EVIDENCE-1.0",
        verification_state=state,
        limitations=(
            "Provider evidence is not physical-device or firmware attestation unless it references separately verified hardware evidence.",
        ),
    )
    evidence = ProviderEvidence(
        evidence_id=str(payload.get("evidence_id", "")),
        provider=str(payload.get("provider", "")),
        resource_id=str(payload.get("resource_id", "")),
        issued_at=str(payload.get("issued_at", "")),
        expires_at=str(payload.get("expires_at", "")),
        claims=claims,
        evidence_source_id=source_id,
        signature=envelope,
        verification_state=state,
        hardware_evidence_refs=tuple(str(item) for item in payload.get("hardware_evidence_refs", [])),
    )
    return evidence, source


def sign_provider_fixture(payload_without_signature: Mapping[str, object], key: bytes) -> dict:
    payload = dict(payload_without_signature)
    digest = canonical_digest(payload)
    envelope = hmac_sign_digest(digest, key_id=str(payload.get("key_id", "provider-test-key")), key=key)
    payload["signature_b64"] = envelope.signature_b64
    return payload


@dataclass
class ProviderEvidenceAdapter:
    """Fixture/offline boundary for a named provider control plane."""

    fixture_path: Path
    expected_provider: str
    verification_key: bytes | None = None

    def collect(self) -> ProviderNormalization:
        raw = self.fixture_path.read_bytes()
        evidence, source = normalize_provider_evidence(raw, verification_key=self.verification_key)
        if evidence.provider != self.expected_provider:
            raise AdapterError(
                f"provider fixture names {evidence.provider}, expected {self.expected_provider}"
            )
        return ProviderNormalization(evidence=evidence, source_id=source.source_id, source=source)


@dataclass
class GoogleTpuProviderAdapter(ProviderEvidenceAdapter):
    expected_provider: str = "google-cloud-tpu"


@dataclass
class AwsNeuronProviderAdapter(ProviderEvidenceAdapter):
    expected_provider: str = "aws-neuron"


@dataclass
class MicrosoftMaiaProviderAdapter(ProviderEvidenceAdapter):
    expected_provider: str = "microsoft-azure-maia"
