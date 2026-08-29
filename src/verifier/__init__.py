"""Terminology: application programming interface (API); Verifier Standard (VSTD).

VSTD reference implementation public API."""

from __future__ import annotations

from importlib import import_module
import warnings
from typing import TYPE_CHECKING, Any

__version__ = "1.2.0"
# This names the highest project-specification coordinate exposed by the package;
# it is not a conformance claim. Keep the adjacent status when presenting it.
__standard__ = "VSTD-4"
__standard_status__ = "CANDIDATE; CONFORMANCE NOT_ESTABLISHED"

_LAZY_EXPORTS = {
    "ArtifactControlError": ("verifier.artifact_control", "ArtifactControlError"),
    "ArtifactVerification": ("verifier.artifact_control", "ArtifactVerification"),
    "freeze_artifact": ("verifier.artifact_control", "freeze_artifact"),
    "seal_artifact": ("verifier.artifact_control", "seal_artifact"),
    "thaw_artifact": ("verifier.artifact_control", "thaw_artifact"),
    "thawed_artifact_status": (
        "verifier.artifact_control",
        "thawed_artifact_status",
    ),
    "verify_frozen_artifact": (
        "verifier.artifact_control",
        "verify_frozen_artifact",
    ),
    "VerificationVerdict": ("verifier.core.checker", "VerificationVerdict"),
    "VstdReceipt": ("verifier.core.receipt", "VstdReceipt"),
    "compute_canonical_digest": ("verifier.core.receipt", "compute_canonical_digest"),
    "ReproducibilityLevel": ("verifier.core.reproducibility", "ReproducibilityLevel"),
    "capture_run": ("verifier.core.run", "capture_run"),
    "validate_run_receipt": ("verifier.core.run", "validate_run_receipt"),
    "VerificationGeometry": ("verifier.core.geometry", "VerificationGeometry"),
    "DecisionCertificate": ("verifier.core.certificate", "DecisionCertificate"),
    "certificate_from_canonical_bytes": (
        "verifier.core.certificate",
        "certificate_from_canonical_bytes",
    ),
    "vstd4_depth": ("verifier.core.depth", "vstd4_depth"),
    "require_vstd5_entry": ("verifier.core.depth", "require_vstd5_entry"),
}

# Supported names remain in _LAZY_EXPORTS while deprecated. Each entry records the
# first release carrying the warning and the supported replacement.
_API_DEPRECATIONS: dict[str, tuple[str, str]] = {}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    deprecation = _API_DEPRECATIONS.get(name)
    if deprecation is not None:
        since, replacement = deprecation
        warnings.warn(
            f"verifier.{name} is deprecated since {since}; use {replacement}",
            DeprecationWarning,
            stacklevel=2,
        )
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


if TYPE_CHECKING:
    from verifier.artifact_control import (
        ArtifactControlError as ArtifactControlError,
        ArtifactVerification as ArtifactVerification,
        freeze_artifact as freeze_artifact,
        seal_artifact as seal_artifact,
        thaw_artifact as thaw_artifact,
        thawed_artifact_status as thawed_artifact_status,
        verify_frozen_artifact as verify_frozen_artifact,
    )
    from verifier.core.checker import VerificationVerdict as VerificationVerdict
    from verifier.core.geometry import VerificationGeometry as VerificationGeometry
    from verifier.core.certificate import (
        DecisionCertificate as DecisionCertificate,
        certificate_from_canonical_bytes as certificate_from_canonical_bytes,
    )
    from verifier.core.depth import (
        require_vstd5_entry as require_vstd5_entry,
        vstd4_depth as vstd4_depth,
    )
    from verifier.core.receipt import (
        VstdReceipt as VstdReceipt,
        compute_canonical_digest as compute_canonical_digest,
    )
    from verifier.core.reproducibility import ReproducibilityLevel as ReproducibilityLevel
    from verifier.core.run import capture_run as capture_run, validate_run_receipt as validate_run_receipt
