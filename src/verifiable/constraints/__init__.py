"""Backend-neutral constraints with lazy, independently installable adapters."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

_LAZY_EXPORTS = {
    "ConstraintCompilationError": ("verifiable.constraints.kernel", "ConstraintCompilationError"),
    "ConstraintKind": ("verifiable.constraints.kernel", "ConstraintKind"),
    "ConstraintRunTrace": ("verifiable.constraints.kernel", "ConstraintRunTrace"),
    "ConstraintSpec": ("verifiable.constraints.kernel", "ConstraintSpec"),
    "ConstraintTransitionError": ("verifiable.constraints.kernel", "ConstraintTransitionError"),
    "KernelOutcome": ("verifiable.constraints.kernel", "KernelOutcome"),
    "MaskObservation": ("verifiable.constraints.kernel", "MaskObservation"),
    "PostValidationResult": ("verifiable.constraints.kernel", "PostValidationResult"),
    "TokenObservation": ("verifiable.constraints.kernel", "TokenObservation"),
    "iter_allowed_token_ids": ("verifiable.constraints.kernel", "iter_allowed_token_ids"),
    "LLGuidanceBackend": ("verifiable.constraints.llguidance_backend", "LLGuidanceBackend"),
    "LLGuidanceCompiledConstraint": (
        "verifiable.constraints.llguidance_backend",
        "LLGuidanceCompiledConstraint",
    ),
    "LLGuidanceConstraintSession": (
        "verifiable.constraints.llguidance_backend",
        "LLGuidanceConstraintSession",
    ),
    "SingleSequenceLogitsProcessor": (
        "verifiable.constraints.llguidance_backend",
        "SingleSequenceLogitsProcessor",
    ),
    "validate_json_schema_output": ("verifiable.constraints.postvalidate", "validate_json_schema_output"),
    "apply_packed_token_mask_inplace": (
        "verifiable.constraints.torch_mask",
        "apply_packed_token_mask_inplace",
    ),
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
    from verifiable.constraints.kernel import (  # noqa: F401
        ConstraintCompilationError,
        ConstraintKind,
        ConstraintRunTrace,
        ConstraintSpec,
        ConstraintTransitionError,
        KernelOutcome,
        MaskObservation,
        PostValidationResult,
        TokenObservation,
        iter_allowed_token_ids,
    )
    from verifiable.constraints.llguidance_backend import (  # noqa: F401
        LLGuidanceBackend,
        LLGuidanceCompiledConstraint,
        LLGuidanceConstraintSession,
        SingleSequenceLogitsProcessor,
    )
    from verifiable.constraints.postvalidate import validate_json_schema_output  # noqa: F401
    from verifiable.constraints.torch_mask import apply_packed_token_mask_inplace  # noqa: F401
