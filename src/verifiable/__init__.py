"""VSTD reference implementation public API."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__version__ = "0.2.0"
__standard__ = "VSTD-3.0"

_LAZY_EXPORTS = {
    "VerificationVerdict": ("verifiable.core.checker", "VerificationVerdict"),
    "VerifiableReceipt": ("verifiable.core.receipt", "VerifiableReceipt"),
    "compute_canonical_digest": ("verifiable.core.receipt", "compute_canonical_digest"),
    "ReproducibilityLevel": ("verifiable.core.reproducibility", "ReproducibilityLevel"),
    "capture_run": ("verifiable.core.run", "capture_run"),
    "validate_run_receipt": ("verifiable.core.run", "validate_run_receipt"),
    "VerificationGeometry": ("verifiable.core.geometry", "VerificationGeometry"),
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
    from verifiable.core.receipt import (
        VerifiableReceipt as VerifiableReceipt,
        compute_canonical_digest as compute_canonical_digest,
    )
    from verifiable.core.reproducibility import ReproducibilityLevel as ReproducibilityLevel
    from verifiable.core.run import capture_run as capture_run, validate_run_receipt as validate_run_receipt
