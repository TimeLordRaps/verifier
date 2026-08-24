"""Experimental, non-normative VSTD/SCITT interoperability surface.

This package does not implement COSE or a SCITT Transparency Service.  It
defines the application payload carried by a SCITT Signed Statement and the
strict boundary at which a native SCITT verifier's result can become bounded
VSTD evidence.
"""

from .adapter import (
    EXPERIMENTAL_CONTENT_TYPE,
    EXPERIMENTAL_PROFILE,
    MAPPING_VERSION,
    CompositionResult,
    CompositionStatus,
    InteropError,
    ScittEvidenceState,
    ScittRegistrationTemplate,
    ScittVerificationEvidence,
    VstdCoordinates,
    VstdVerificationEvidence,
    VstdVerificationState,
    VstdScittPayload,
    compose_results,
    consume_scitt_evidence,
    create_scitt_registration_template,
)

__all__ = [
    "EXPERIMENTAL_CONTENT_TYPE",
    "EXPERIMENTAL_PROFILE",
    "MAPPING_VERSION",
    "CompositionResult",
    "CompositionStatus",
    "InteropError",
    "ScittEvidenceState",
    "ScittRegistrationTemplate",
    "ScittVerificationEvidence",
    "VstdCoordinates",
    "VstdVerificationEvidence",
    "VstdVerificationState",
    "VstdScittPayload",
    "compose_results",
    "consume_scitt_evidence",
    "create_scitt_registration_template",
]
