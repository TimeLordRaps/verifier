"""Backend-neutral constraints with lazy, independently installable adapters."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

_LAZY_EXPORTS = {
    "ConstraintCompilationError": ("verifier.constraints.kernel", "ConstraintCompilationError"),
    "ConstraintKind": ("verifier.constraints.kernel", "ConstraintKind"),
    "ConstraintRunTrace": ("verifier.constraints.kernel", "ConstraintRunTrace"),
    "ConstraintSpec": ("verifier.constraints.kernel", "ConstraintSpec"),
    "ConstraintTransitionError": ("verifier.constraints.kernel", "ConstraintTransitionError"),
    "KernelOutcome": ("verifier.constraints.kernel", "KernelOutcome"),
    "MaskObservation": ("verifier.constraints.kernel", "MaskObservation"),
    "PostValidationResult": ("verifier.constraints.kernel", "PostValidationResult"),
    "TokenObservation": ("verifier.constraints.kernel", "TokenObservation"),
    "iter_allowed_token_ids": ("verifier.constraints.kernel", "iter_allowed_token_ids"),
    "LLGuidanceBackend": ("verifier.constraints.llguidance_backend", "LLGuidanceBackend"),
    "LLGuidanceCompiledConstraint": (
        "verifier.constraints.llguidance_backend",
        "LLGuidanceCompiledConstraint",
    ),
    "LLGuidanceConstraintSession": (
        "verifier.constraints.llguidance_backend",
        "LLGuidanceConstraintSession",
    ),
    "SingleSequenceLogitsProcessor": (
        "verifier.constraints.llguidance_backend",
        "SingleSequenceLogitsProcessor",
    ),
    "validate_json_schema_output": ("verifier.constraints.postvalidate", "validate_json_schema_output"),
    "apply_packed_token_mask_inplace": (
        "verifier.constraints.torch_mask",
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
    from verifier.constraints.kernel import (  # noqa: F401
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
    from verifier.constraints.llguidance_backend import (  # noqa: F401
        LLGuidanceBackend,
        LLGuidanceCompiledConstraint,
        LLGuidanceConstraintSession,
        SingleSequenceLogitsProcessor,
    )
    from verifier.constraints.postvalidate import validate_json_schema_output  # noqa: F401
    from verifier.constraints.torch_mask import apply_packed_token_mask_inplace  # noqa: F401
