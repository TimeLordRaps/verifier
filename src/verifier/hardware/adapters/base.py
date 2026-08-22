"""Vendor-neutral accelerator evidence-adapter protocol and shared helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Mapping, Protocol

from ..models import (
    AdapterResult,
    Capability,
    EvidenceGap,
    EvidenceProducer,
    EvidenceSource,
    VerificationState,
)
from ..registry import AcceleratorRegistry


class AdapterError(ValueError):
    pass


class EvidenceAdapter(Protocol):
    adapter_id: str

    def discover(self) -> AdapterResult: ...


def evidence_source_from_bytes(
    *,
    source_id: str,
    producer: EvidenceProducer,
    mechanism: str,
    observed_at: str,
    capabilities: tuple,
    raw: bytes,
    media_type: str,
    original_format: str,
    verification_state: VerificationState = VerificationState.NOT_VERIFIED,
    limitations: tuple[str, ...] = (),
    attributes: dict | None = None,
) -> EvidenceSource:
    return EvidenceSource(
        source_id=source_id,
        producer=producer,
        mechanism=mechanism,
        observed_at=observed_at,
        capabilities=capabilities,
        raw_evidence_b64=base64.b64encode(raw).decode("ascii"),
        raw_evidence_digest=hashlib.sha256(raw).hexdigest(),
        media_type=media_type,
        original_format=original_format,
        verification_state=verification_state,
        limitations=limitations,
        attributes=attributes or {},
    )


def unsupported_result(
    *,
    adapter_id: str,
    profile_id: str,
    registry: AcceleratorRegistry,
    reason: str,
) -> AdapterResult:
    profile = registry.get(profile_id)
    return AdapterResult(
        adapter_id=adapter_id,
        profile_id=profile_id,
        descriptors=(),
        physical_identities=(),
        logical_identities=(),
        partitions=(),
        topology_snapshots=(),
        evidence_sources=(),
        attestation_challenges=(),
        attestation_evidence=(),
        capability_declarations=profile.capability_declarations,
        evidence_gaps=(
            EvidenceGap(
                gap_id=f"gap:{adapter_id}:unsupported",
                gap_type="UNSUPPORTED_HARDWARE_OR_COLLECTOR",
                subject_id=profile_id,
                explanation=reason,
            ),
        ),
    )


def normalize_opaque_vendor_evidence(
    items: object,
    *,
    vendor: str,
    default_observed_at: str,
) -> tuple[tuple[EvidenceSource, ...], tuple[EvidenceGap, ...]]:
    """Preserve opaque vendor evidence without interpreting or promoting it."""

    if items is None:
        return (), ()
    if not isinstance(items, list):
        raise AdapterError(f"{vendor} opaque attestation evidence must be an array")
    sources: list[EvidenceSource] = []
    gaps: list[EvidenceGap] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise AdapterError(f"{vendor} opaque evidence item {index} must be an object")
        allowed = {"evidence_id", "format", "raw_evidence_b64", "observed_at", "subject_hint"}
        if set(item) != allowed:
            raise AdapterError(
                f"{vendor} opaque evidence item {index} requires exactly "
                "evidence_id/format/raw_evidence_b64/observed_at/subject_hint"
            )
        if any(not isinstance(item[field], str) for field in allowed):
            raise AdapterError(f"{vendor} opaque evidence item {index} fields must be strings")
        try:
            raw = base64.b64decode(item["raw_evidence_b64"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise AdapterError(f"{vendor} opaque evidence item {index} has invalid base64") from exc
        if not raw:
            raise AdapterError(f"{vendor} opaque evidence item {index} is empty")
        evidence_id = item["evidence_id"]
        source_id = f"evidence:{vendor.lower()}-opaque:{evidence_id}"
        sources.append(
            evidence_source_from_bytes(
                source_id=source_id,
                producer=EvidenceProducer.SOFTWARE_COLLECTOR,
                mechanism=f"opaque {vendor} vendor evidence preservation",
                observed_at=item["observed_at"] or default_observed_at,
                capabilities=(Capability.HOST_OBSERVED,),
                raw=raw,
                media_type="application/octet-stream",
                original_format=item["format"],
                limitations=(
                    "Original vendor evidence is preserved but not cryptographically verified by the core package.",
                    "The subject hint is untrusted metadata until a vendor verifier authenticates the envelope.",
                ),
                attributes={"subject_hint": item["subject_hint"], "opaque_evidence_id": evidence_id},
            )
        )
        gaps.append(
            EvidenceGap(
                gap_id=f"gap:{vendor.lower()}-opaque:{evidence_id}",
                gap_type="UNVERIFIED_VENDOR_ATTESTATION",
                subject_id=item["subject_hint"],
                explanation=(
                    f"{vendor} evidence bytes were preserved, but no configured verifier authenticated "
                    "the signature, certificate path, nonce, or reference measurements."
                ),
            )
        )
    return tuple(sources), tuple(gaps)
