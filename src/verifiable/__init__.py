"""VSTD reference implementation public API."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__version__ = "1.0.0"
__standard__ = "VSTD-4"

_LAZY_EXPORTS = {
    "VerificationVerdict": ("verifiable.core.checker", "VerificationVerdict"),
    "VerifiableReceipt": ("verifiable.core.receipt", "VerifiableReceipt"),
    "compute_canonical_digest": ("verifiable.core.receipt", "compute_canonical_digest"),
    "ReproducibilityLevel": ("verifiable.core.reproducibility", "ReproducibilityLevel"),
    "capture_run": ("verifiable.core.run", "capture_run"),
    "validate_run_receipt": ("verifiable.core.run", "validate_run_receipt"),
    "VerificationGeometry": ("verifiable.core.geometry", "VerificationGeometry"),
    "DecisionCertificate": ("verifiable.core.certificate", "DecisionCertificate"),
    "certificate_from_canonical_bytes": (
        "verifiable.core.certificate",
        "certificate_from_canonical_bytes",
    ),
    "vstd4_depth": ("verifiable.core.depth", "vstd4_depth"),
    "require_vstd5_entry": ("verifiable.core.depth", "require_vstd5_entry"),
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
    from verifiable.core.checker import VerificationVerdict as VerificationVerdict
    from verifiable.core.geometry import VerificationGeometry as VerificationGeometry
    from verifiable.core.certificate import (
        DecisionCertificate as DecisionCertificate,
        certificate_from_canonical_bytes as certificate_from_canonical_bytes,
    )
    from verifiable.core.depth import (
        require_vstd5_entry as require_vstd5_entry,
        vstd4_depth as vstd4_depth,
    )
    from verifiable.core.receipt import (
        VerifiableReceipt as VerifiableReceipt,
        compute_canonical_digest as compute_canonical_digest,
    )
    from verifiable.core.reproducibility import ReproducibilityLevel as ReproducibilityLevel
    from verifiable.core.run import capture_run as capture_run, validate_run_receipt as validate_run_receipt
