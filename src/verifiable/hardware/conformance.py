"""Incremental, evidence-bounded VSTD 3 conformance profiles."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .claims import demonstrated_capabilities, expand_capabilities
from .continuity import ContinuityVerification
from .models import (
    AttestationEvidence,
    Capability,
    CapabilityDeclaration,
    CapabilitySupport,
    ClaimStatus,
    EvidenceProducer,
    EvidenceSource,
    VerificationState,
)


class ConformanceProfile(str, Enum):
    DISCOVERY = "VSTD3-DISCOVERY"
    DEVICE_IDENTITY = "VSTD3-DEVICE-IDENTITY"
    FIRMWARE_ATTESTATION = "VSTD3-FIRMWARE-ATTESTATION"
    EXECUTION_EVIDENCE = "VSTD3-EXECUTION-EVIDENCE"
    EXECUTION_ACCOUNTING = "VSTD3-EXECUTION-ACCOUNTING"
    CONTINUITY = "VSTD3-CONTINUITY"
    COMPLETE_MEDIATION = "VSTD3-COMPLETE-MEDIATION"
    FLEET = "VSTD3-FLEET"


PROFILE_REQUIREMENTS: dict[ConformanceProfile, frozenset[Capability]] = {
    ConformanceProfile.DISCOVERY: frozenset({Capability.HOST_OBSERVED}),
    ConformanceProfile.DEVICE_IDENTITY: frozenset({Capability.DEVICE_IDENTITY_ATTESTED}),
    ConformanceProfile.FIRMWARE_ATTESTATION: frozenset({Capability.FIRMWARE_ATTESTED}),
    ConformanceProfile.EXECUTION_EVIDENCE: frozenset({Capability.EXECUTION_ATTESTED}),
    ConformanceProfile.EXECUTION_ACCOUNTING: frozenset(
        {Capability.EXECUTION_ACCOUNTING_EVIDENCED}
    ),
    ConformanceProfile.CONTINUITY: frozenset({Capability.CONTINUITY_ATTESTED}),
    ConformanceProfile.COMPLETE_MEDIATION: frozenset(
        {Capability.COMPLETE_MEDIATION_ATTESTED}
    ),
    ConformanceProfile.FLEET: frozenset({Capability.FLEET_BOUNDARY_ATTESTED}),
}


@dataclass(frozen=True)
class ConformanceEvaluation:
    profile: ConformanceProfile
    status: ClaimStatus
    required_capabilities: tuple[Capability, ...]
    observed_capabilities: tuple[Capability, ...]
    explanation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile.value,
            "status": self.status.value,
            "required_capabilities": [item.value for item in self.required_capabilities],
            "observed_capabilities": [item.value for item in self.observed_capabilities],
            "explanation": self.explanation,
        }


def evaluate_conformance(
    profile: ConformanceProfile,
    *,
    sources: tuple[EvidenceSource, ...],
    attestation: tuple[AttestationEvidence, ...] = (),
    declarations: tuple[CapabilityDeclaration, ...] = (),
    continuity: ContinuityVerification | None = None,
    fleet_boundary_verified: bool = False,
) -> ConformanceEvaluation:
    required = PROFILE_REQUIREMENTS[profile]
    observed = set(demonstrated_capabilities(sources, attestation))
    if continuity is not None and continuity.status is ClaimStatus.PASS:
        observed.add(Capability.CONTINUITY_ATTESTED)
    if fleet_boundary_verified:
        observed.add(Capability.FLEET_BOUNDARY_ATTESTED)
    observed = set(expand_capabilities(observed))

    if required.issubset(observed):
        if profile is ConformanceProfile.COMPLETE_MEDIATION:
            producer_ok = any(
                Capability.COMPLETE_MEDIATION_ATTESTED in source.capabilities
                and source.verification_state is VerificationState.VERIFIED
                and source.producer
                in {EvidenceProducer.DEVICE, EvidenceProducer.FIRMWARE, EvidenceProducer.TEST_EMULATOR}
                for source in sources
            )
            continuity_ok = continuity is not None and continuity.status is ClaimStatus.PASS
            if not producer_ok or not continuity_ok:
                status = ClaimStatus.UNKNOWN
                explanation = "Complete-mediation conformance requires verified device/firmware evidence and passing continuity."
            else:
                status = ClaimStatus.PASS
                explanation = "All complete-mediation profile requirements passed within the declared boundary."
        else:
            status = ClaimStatus.PASS
            explanation = "All profile capabilities were demonstrated."
    else:
        declared = {item.capability: item.support for item in declarations}
        missing = required - observed
        if missing and all(declared.get(item) is CapabilitySupport.UNSUPPORTED for item in missing):
            status = ClaimStatus.UNSUPPORTED
            explanation = "The mechanism explicitly declares a required capability unsupported."
        else:
            status = ClaimStatus.UNKNOWN
            explanation = "Available evidence does not demonstrate every profile capability."
    return ConformanceEvaluation(
        profile=profile,
        status=status,
        required_capabilities=tuple(sorted(required, key=lambda item: item.value)),
        observed_capabilities=tuple(sorted(observed, key=lambda item: item.value)),
        explanation=explanation,
    )
