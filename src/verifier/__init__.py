"""Terminology: application programming interface (API); Verifier Standard (VSTD).

VSTD reference implementation public API."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__version__ = "1.2.0"
__standard__ = "VSTD-4"

_LAZY_EXPORTS = {
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

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


if TYPE_CHECKING:
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
