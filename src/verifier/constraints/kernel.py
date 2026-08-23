"""Small common contract around native constrained-decoding engines.

This is intentionally not a universal grammar IR.  The source constraint remains
in its native language and the selected engine owns compilation.  VSTD
standardizes only the adjacent observable seam: source identity, compiled-object
identity, tokenizer identity, per-step token masks, state transitions, and optional
independent post-validation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterator, Mapping, Optional


class ConstraintKind(str, Enum):
    JSON_SCHEMA = "JSON_SCHEMA"
    REGEX = "REGEX"
    LARK = "LARK"


class KernelOutcome(str, Enum):
    INCOMPLETE = "INCOMPLETE"
    MASK_ACCEPTING = "MASK_ACCEPTING"
    POST_VALIDATED = "POST_VALIDATED"
    FAILED_CLOSED = "FAILED_CLOSED"


class ConstraintCompilationError(RuntimeError):
    """The native engine could not compile a constraint without ambiguity."""


class ConstraintTransitionError(RuntimeError):
    """A token was presented that the current native-engine state rejects."""


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def iter_allowed_token_ids(packed_mask: bytes, vocabulary_size: int) -> Iterator[int]:
    """Yield allowed token ids from a little-endian packed mask using stdlib only."""

    if vocabulary_size < 0:
        raise ValueError("vocabulary_size must be non-negative")
    expected_bytes = (vocabulary_size + 7) // 8
    if len(packed_mask) < expected_bytes:
        raise ValueError(
            f"packed mask has {len(packed_mask)} bytes but vocabulary size {vocabulary_size} requires {expected_bytes}"
        )
    for token_id in range(vocabulary_size):
        if packed_mask[token_id // 8] & (1 << (token_id % 8)):
            yield token_id


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"constraint source contains non-JSON value {type(value).__name__}")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True)
class ConstraintSpec:
    constraint_id: str
    kind: ConstraintKind
    source: Mapping[str, Any] | str

    def __post_init__(self) -> None:
        if not self.constraint_id:
            raise ValueError("constraint_id must not be empty")
        if self.kind == ConstraintKind.JSON_SCHEMA and not isinstance(self.source, Mapping):
            raise TypeError("JSON_SCHEMA source must be a mapping")
        if self.kind in (ConstraintKind.REGEX, ConstraintKind.LARK) and not isinstance(self.source, str):
            raise TypeError(f"{self.kind.value} source must be a string")
        if isinstance(self.source, Mapping):
            object.__setattr__(self, "source", _freeze_json(self.source))

    def to_dict(self) -> dict[str, Any]:
        return {
            "constraint_id": self.constraint_id,
            "kind": self.kind.value,
            "source": _thaw_json(self.source),
        }

    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass(frozen=True)
class MaskObservation:
    step: int
    prefix_token_count: int
    packed_mask_sha256: str
    allowed_token_count: int
    vocabulary_size: int
    accepting_before_sample: bool
    stopped_before_sample: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "prefix_token_count": self.prefix_token_count,
            "packed_mask_sha256": self.packed_mask_sha256,
            "allowed_token_count": self.allowed_token_count,
            "vocabulary_size": self.vocabulary_size,
            "accepting_before_sample": self.accepting_before_sample,
            "stopped_before_sample": self.stopped_before_sample,
        }


@dataclass(frozen=True)
class TokenObservation:
    step: int
    token_id: int
    accepted: bool
    accepting_after_token: bool
    stopped_after_token: bool
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "token_id": self.token_id,
            "accepted": self.accepted,
            "accepting_after_token": self.accepting_after_token,
            "stopped_after_token": self.stopped_after_token,
            "error": self.error,
        }


@dataclass(frozen=True)
class PostValidationResult:
    validator_name: str
    validator_version: str
    passed: bool
    output_digest: str
    constraint_source_digest: str
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "validator_name": self.validator_name,
            "validator_version": self.validator_version,
            "passed": self.passed,
            "output_digest": self.output_digest,
            "constraint_source_digest": self.constraint_source_digest,
            "details": self.details,
        }


@dataclass(frozen=True)
class ConstraintRunTrace:
    constraint: ConstraintSpec
    backend_name: str
    backend_version: str
    compiled_constraint_digest: str
    tokenizer_identity: str
    tokenizer_digest: str
    vocabulary_size: int
    accepted_output_digest: str
    mask_coverage_complete: bool
    mask_observations: tuple[MaskObservation, ...]
    token_observations: tuple[TokenObservation, ...]
    outcome: KernelOutcome
    post_validation: Optional[PostValidationResult] = None
    limitations: tuple[str, ...] = (
        "The compiler and matcher implementation are identified dependencies, not post-verified by this trace.",
        "A token-mask trace does not by itself establish source-to-grammar translation fidelity.",
        "Model inference and sampling behavior outside the selected logits-mask seam are outside this trace.",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_kind": "logits_constraint_trace",
            "format_version": "0.1-experimental",
            "constraint": self.constraint.to_dict(),
            "constraint_digest": self.constraint.digest(),
            "backend": {"name": self.backend_name, "version": self.backend_version},
            "compiled_constraint_digest": self.compiled_constraint_digest,
            "tokenizer": {
                "identity": self.tokenizer_identity,
                "digest": self.tokenizer_digest,
                "vocabulary_size": self.vocabulary_size,
            },
            "accepted_output_digest": self.accepted_output_digest,
            "mask_coverage_complete": self.mask_coverage_complete,
            "mask_observations": [item.to_dict() for item in self.mask_observations],
            "token_observations": [item.to_dict() for item in self.token_observations],
            "outcome": self.outcome.value,
            "post_validation": self.post_validation.to_dict() if self.post_validation else None,
            "limitations": list(self.limitations),
        }

    def canonical_digest(self) -> str:
        return canonical_digest(self.to_dict())
