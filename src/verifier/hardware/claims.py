"""Terminology: Verifier Standard (VSTD).

Evidence-monotone VSTD 3 claim evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .continuity import ContinuityVerification
from .models import (
    AttestationEvidence,
    Capability,
    CapabilityDeclaration,
    CapabilitySupport,
    ClaimEvaluation,
    ClaimKind,
    ClaimStatus,
    EvidenceProducer,
    EvidenceSource,
    VerificationState,
)


CAPABILITY_IMPLICATIONS: dict[Capability, frozenset[Capability]] = {
    Capability.SELF_REPORTED: frozenset(),
    Capability.HOST_OBSERVED: frozenset(),
    Capability.EXECUTION_OBSERVED: frozenset(),
    Capability.SOFTWARE_SIGNED: frozenset({Capability.SELF_REPORTED}),
    Capability.PROVIDER_ATTESTED: frozenset(),
    Capability.DEVICE_IDENTITY_ATTESTED: frozenset({Capability.SOFTWARE_SIGNED}),
    Capability.FIRMWARE_ATTESTED: frozenset({Capability.DEVICE_IDENTITY_ATTESTED}),
    Capability.EXECUTION_ATTESTED: frozenset(
        {Capability.DEVICE_IDENTITY_ATTESTED, Capability.EXECUTION_OBSERVED}
    ),
    Capability.EXECUTION_ACCOUNTING_EVIDENCED: frozenset(),
    Capability.CONTINUITY_ATTESTED: frozenset({Capability.EXECUTION_ATTESTED}),
    Capability.COMPLETE_MEDIATION_ATTESTED: frozenset(
        {
            Capability.FIRMWARE_ATTESTED,
            Capability.EXECUTION_ATTESTED,
            Capability.EXECUTION_ACCOUNTING_EVIDENCED,
            Capability.CONTINUITY_ATTESTED,
        }
    ),
    Capability.FLEET_BOUNDARY_ATTESTED: frozenset(),
}


CLAIM_REQUIREMENTS: dict[ClaimKind, frozenset[Capability]] = {
    ClaimKind.DEVICE_IDENTITY: frozenset({Capability.DEVICE_IDENTITY_ATTESTED}),
    ClaimKind.FIRMWARE_INTEGRITY: frozenset({Capability.FIRMWARE_ATTESTED}),
    ClaimKind.EXECUTION_OBSERVED: frozenset({Capability.EXECUTION_OBSERVED}),
    ClaimKind.EXECUTION_ATTESTATION: frozenset({Capability.EXECUTION_ATTESTED}),
    ClaimKind.EXECUTION_ACCOUNTING: frozenset({Capability.EXECUTION_ACCOUNTING_EVIDENCED}),
    ClaimKind.ACCOUNTING_CONTINUITY: frozenset({Capability.CONTINUITY_ATTESTED}),
    ClaimKind.COMPLETE_MEDIATION: frozenset({Capability.COMPLETE_MEDIATION_ATTESTED}),
    ClaimKind.FLEET_COMPLETENESS: frozenset({Capability.FLEET_BOUNDARY_ATTESTED}),
    ClaimKind.PHYSICAL_WORLD_COMPLETENESS: frozenset(),
}


PROHIBITED_INFERENCES: dict[ClaimKind, str] = {
    ClaimKind.DEVICE_IDENTITY: "Authenticated device identity does not prove workload execution or complete mediation.",
    ClaimKind.FIRMWARE_INTEGRITY: "Measured firmware does not prove that every execution was recorded.",
    ClaimKind.EXECUTION_OBSERVED: "Host observation does not prove device-originated execution evidence.",
    ClaimKind.EXECUTION_ATTESTATION: "Execution attestation does not quantify exact compute unless accounting evidence does.",
    ClaimKind.EXECUTION_ACCOUNTING: "An estimate or scoped counter is not exact physical compute outside its declared scope.",
    ClaimKind.ACCOUNTING_CONTINUITY: "Continuity between evidenced anchors does not prove history outside that interval.",
    ClaimKind.COMPLETE_MEDIATION: "Complete mediation is bounded to the identified governed accelerator paths and epoch.",
    ClaimKind.FLEET_COMPLETENESS: "Fleet completeness is relative to the enrolled boundary, not all physical hardware.",
    ClaimKind.PHYSICAL_WORLD_COMPLETENESS: "No ordinary VSTD receipt proves that no undeclared compute occurred anywhere.",
}


def expand_capabilities(capabilities: Iterable[Capability]) -> frozenset[Capability]:
    expanded = set(capabilities)
    changed = True
    while changed:
        changed = False
        for capability in tuple(expanded):
            before = len(expanded)
            expanded.update(CAPABILITY_IMPLICATIONS[capability])
            changed = changed or len(expanded) != before
    return frozenset(expanded)


def demonstrated_capabilities(
    sources: Iterable[EvidenceSource],
    attestation: Iterable[AttestationEvidence] = (),
) -> frozenset[Capability]:
    observed: set[Capability] = set()
    for source in sources:
        weak = {Capability.SELF_REPORTED, Capability.HOST_OBSERVED, Capability.EXECUTION_OBSERVED}
        observed.update(capability for capability in source.capabilities if capability in weak)
        if source.verification_state is VerificationState.VERIFIED:
            observed.update(source.capabilities)
    for evidence in attestation:
        if evidence.verification_state is VerificationState.VERIFIED:
            observed.update(evidence.demonstrated_capabilities)
    return expand_capabilities(observed)


@dataclass(frozen=True)
class ClaimContext:
    sources: tuple[EvidenceSource, ...]
    attestation: tuple[AttestationEvidence, ...] = ()
    capability_declarations: tuple[CapabilityDeclaration, ...] = ()
    continuity: ContinuityVerification | None = None
    gap_ids: tuple[str, ...] = ()
    violation: str = ""
    fleet_boundary_verified: bool = False


def evaluate_claim(
    *,
    claim_id: str,
    claim_kind: ClaimKind,
    subject_id: str,
    context: ClaimContext,
) -> ClaimEvaluation:
    required = CLAIM_REQUIREMENTS[claim_kind]
    observed = set(demonstrated_capabilities(context.sources, context.attestation))
    evidence_ids = [source.source_id for source in context.sources]
    evidence_ids.extend(evidence.evidence_id for evidence in context.attestation)

    if context.continuity is not None and context.continuity.status is ClaimStatus.PASS:
        observed.add(Capability.CONTINUITY_ATTESTED)
    if claim_kind is ClaimKind.FLEET_COMPLETENESS and context.fleet_boundary_verified:
        observed.add(Capability.FLEET_BOUNDARY_ATTESTED)
    observed = set(expand_capabilities(observed))

    if claim_kind is ClaimKind.PHYSICAL_WORLD_COMPLETENESS:
        status = ClaimStatus.UNSUPPORTED
        explanation = "VSTD has no observable boundary that enumerates every physical accelerator in the world."
    elif context.violation:
        status = ClaimStatus.FAIL
        explanation = context.violation
    elif required.issubset(observed):
        if claim_kind is ClaimKind.COMPLETE_MEDIATION:
            producer_ok = any(
                Capability.COMPLETE_MEDIATION_ATTESTED in source.capabilities
                and source.verification_state is VerificationState.VERIFIED
                and source.producer in {EvidenceProducer.DEVICE, EvidenceProducer.FIRMWARE, EvidenceProducer.TEST_EMULATOR}
                for source in context.sources
            )
            continuity_ok = context.continuity is not None and context.continuity.status is ClaimStatus.PASS
            if not producer_ok or not continuity_ok:
                status = ClaimStatus.UNKNOWN
                explanation = (
                    "Complete mediation requires verified device/firmware-originated capability evidence and "
                    "a passing authenticated continuity chain; host or provider telemetry is insufficient."
                )
            else:
                status = ClaimStatus.PASS
                explanation = "The identified mechanism supports complete mediation within the declared boundary and continuity passed."
        else:
            status = ClaimStatus.PASS
            explanation = "All required capabilities were demonstrated for the declared subject and boundary."
    else:
        declaration_by_capability = {
            declaration.capability: declaration.support for declaration in context.capability_declarations
        }
        missing = required - observed
        if missing and all(
            declaration_by_capability.get(capability) is CapabilitySupport.UNSUPPORTED
            for capability in missing
        ):
            status = ClaimStatus.UNSUPPORTED
            explanation = "The collector declares the required capability unsupported."
        else:
            status = ClaimStatus.UNKNOWN
            explanation = "Available evidence does not demonstrate every capability required by this claim."

    return ClaimEvaluation(
        claim_id=claim_id,
        claim_kind=claim_kind,
        subject_id=subject_id,
        status=status,
        required_capabilities=tuple(sorted(required, key=lambda item: item.value)),
        observed_capabilities=tuple(sorted(observed, key=lambda item: item.value)),
        evidence_ids=tuple(dict.fromkeys(evidence_ids)),
        gap_ids=context.gap_ids,
        explanation=explanation,
        prohibited_inference=PROHIBITED_INFERENCES[claim_kind],
    )


def explain_claim(claim_kind: ClaimKind) -> Mapping[str, object]:
    return {
        "claim_kind": claim_kind.value,
        "required_capabilities": sorted(item.value for item in CLAIM_REQUIREMENTS[claim_kind]),
        "prohibited_inference": PROHIBITED_INFERENCES[claim_kind],
        "unknown_behavior": "UNKNOWN when support may exist but the receipt lacks sufficient verified evidence.",
        "unsupported_behavior": "UNSUPPORTED when the mechanism explicitly lacks the required capability.",
        "failure_behavior": "FAIL only when evidence proves a violation or inconsistency.",
    }
