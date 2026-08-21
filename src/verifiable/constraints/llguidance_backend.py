"""Strict llguidance backend for the VERIFIABLE logits constraint seam."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional

from verifiable.constraints.kernel import (
    ConstraintCompilationError,
    ConstraintKind,
    ConstraintRunTrace,
    ConstraintSpec,
    ConstraintTransitionError,
    KernelOutcome,
    MaskObservation,
    PostValidationResult,
    TokenObservation,
    canonical_digest,
    iter_allowed_token_ids,
)
from verifiable.constraints.torch_mask import apply_packed_token_mask_inplace


def _load_llguidance() -> Any:
    try:
        import llguidance
    except ImportError as exc:  # pragma: no cover - exercised only without the optional extra
        raise RuntimeError("llguidance is required; install VERIFIABLE with the 'llguidance' extra") from exc
    return llguidance


def _observable_tokenizer_digest(tokenizer: Any) -> str:
    hasher = hashlib.sha256()
    hasher.update(str(tokenizer.vocab_size).encode("ascii"))
    for token_id in range(tokenizer.vocab_size):
        hasher.update(token_id.to_bytes(8, "little", signed=False))
        hasher.update(b"\x01" if tokenizer.is_special_token(token_id) else b"\x00")
        token_bytes = tokenizer.decode_bytes([token_id])
        hasher.update(len(token_bytes).to_bytes(8, "little", signed=False))
        hasher.update(token_bytes)
    return hasher.hexdigest()


@dataclass(frozen=True)
class LLGuidanceCompiledConstraint:
    spec: ConstraintSpec
    grammar: str
    grammar_digest: str
    backend_version: str
    tokenizer: Any
    tokenizer_identity: str
    tokenizer_digest: str

    @property
    def vocabulary_size(self) -> int:
        return int(self.tokenizer.vocab_size)

    def new_session(self) -> "LLGuidanceConstraintSession":
        llguidance = _load_llguidance()
        matcher = llguidance.LLMatcher(self.tokenizer, self.grammar, log_level=0)
        if matcher.is_error():
            raise ConstraintCompilationError(matcher.get_error())
        return LLGuidanceConstraintSession(self, matcher)


class LLGuidanceBackend:
    """Compile native JSON Schema, regex, or Lark constraints strictly."""

    supported_kinds = frozenset({ConstraintKind.JSON_SCHEMA, ConstraintKind.REGEX, ConstraintKind.LARK})

    def __init__(self, tokenizer: Any, *, tokenizer_identity: str, tokenizer_digest: str) -> None:
        if not tokenizer_identity or not tokenizer_digest:
            raise ValueError("tokenizer_identity and tokenizer_digest are required")
        self.tokenizer = tokenizer
        self.tokenizer_identity = tokenizer_identity
        self.tokenizer_digest = tokenizer_digest
        self._llguidance = _load_llguidance()

    @classmethod
    def for_byte_tokenizer(cls) -> "LLGuidanceBackend":
        llguidance = _load_llguidance()
        tokenizer = llguidance.LLTokenizer("byte")
        return cls(
            tokenizer,
            tokenizer_identity="llguidance:builtin-byte-tokenizer",
            tokenizer_digest=_observable_tokenizer_digest(tokenizer),
        )

    @classmethod
    def from_huggingface(cls, hf_tokenizer: Any, *, n_vocab: Optional[int] = None) -> "LLGuidanceBackend":
        _load_llguidance()
        try:
            from llguidance.hf import from_tokenizer
        except ImportError as exc:
            raise RuntimeError(
                "the Hugging Face tokenizer bridge requires transformers in the host runtime; "
                "VERIFIABLE does not install it automatically"
            ) from exc

        backend_json = hf_tokenizer.backend_tokenizer.to_str()
        digest_payload = {
            "backend_tokenizer": json.loads(backend_json),
            "eos_token_id": hf_tokenizer.eos_token_id,
            "n_vocab": n_vocab,
        }
        digest = hashlib.sha256(
            json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        tokenizer = from_tokenizer(hf_tokenizer, n_vocab=n_vocab)
        name = getattr(hf_tokenizer, "name_or_path", type(hf_tokenizer).__name__)
        return cls(tokenizer, tokenizer_identity=f"huggingface:{name}", tokenizer_digest=digest)

    def compile(self, spec: ConstraintSpec) -> LLGuidanceCompiledConstraint:
        if spec.kind not in self.supported_kinds:
            raise ConstraintCompilationError(f"unsupported constraint kind: {spec.kind.value}")

        matcher_class = self._llguidance.LLMatcher
        try:
            if spec.kind == ConstraintKind.JSON_SCHEMA:
                grammar = matcher_class.grammar_from_json_schema(spec.to_dict()["source"], overrides={"lenient": False})
            elif spec.kind == ConstraintKind.REGEX:
                grammar = matcher_class.grammar_from_regex(str(spec.source))
            else:
                grammar = matcher_class.grammar_from_lark(str(spec.source))
        except (TypeError, ValueError) as exc:
            raise ConstraintCompilationError(f"native compiler rejected {spec.kind.value}: {exc}") from exc

        matcher = matcher_class(self.tokenizer, grammar, log_level=0)
        if matcher.is_error():
            raise ConstraintCompilationError(matcher.get_error())
        warnings = matcher.get_grammar_warnings()
        if warnings:
            raise ConstraintCompilationError("native compiler emitted warnings in strict mode: " + "; ".join(warnings))

        return LLGuidanceCompiledConstraint(
            spec=spec,
            grammar=grammar,
            grammar_digest=hashlib.sha256(grammar.encode("utf-8")).hexdigest(),
            backend_version=self._llguidance.__version__,
            tokenizer=self.tokenizer,
            tokenizer_identity=self.tokenizer_identity,
            tokenizer_digest=self.tokenizer_digest,
        )


class LLGuidanceConstraintSession:
    def __init__(self, compiled: LLGuidanceCompiledConstraint, matcher: Any) -> None:
        self.compiled = compiled
        self.matcher = matcher
        self._mask_observations: list[MaskObservation] = []
        self._token_observations: list[TokenObservation] = []
        self._accepted_token_ids: list[int] = []

    @property
    def accepted_token_ids(self) -> tuple[int, ...]:
        return tuple(self._accepted_token_ids)

    @property
    def is_accepting(self) -> bool:
        return bool(self.matcher.is_accepting())

    @property
    def is_stopped(self) -> bool:
        return bool(self.matcher.is_stopped())

    def current_packed_mask(self) -> bytes:
        if self.matcher.is_error():
            raise ConstraintTransitionError(self.matcher.get_error())
        return bytes(self.matcher.compute_bitmask())

    def allowed_token_ids(self) -> tuple[int, ...]:
        """Inspect the native mask without importing a tensor framework."""

        return tuple(iter_allowed_token_ids(self.current_packed_mask(), self.compiled.vocabulary_size))

    def mask_logits(self, logits: Any) -> tuple[int, ...]:
        vocabulary_size = self.compiled.vocabulary_size
        if logits.shape[-1] != vocabulary_size:
            raise ValueError(
                f"logits vocabulary {logits.shape[-1]} does not match bound tokenizer vocabulary {vocabulary_size}"
            )
        if logits.ndim == 2 and logits.shape[0] != 1:
            raise ValueError("one LLGuidanceConstraintSession can mask exactly one logits row")
        packed_mask = self.current_packed_mask()
        allowed_counts = apply_packed_token_mask_inplace(logits, packed_mask)
        self._mask_observations.append(
            MaskObservation(
                step=len(self._mask_observations),
                prefix_token_count=len(self._accepted_token_ids),
                packed_mask_sha256=hashlib.sha256(packed_mask).hexdigest(),
                allowed_token_count=allowed_counts[0],
                vocabulary_size=vocabulary_size,
                accepting_before_sample=self.is_accepting,
                stopped_before_sample=self.is_stopped,
            )
        )
        return allowed_counts

    def accept_token(self, token_id: int) -> None:
        token_id = int(token_id)
        accepted = bool(self.matcher.consume_token(token_id))
        error = self.matcher.get_error() if self.matcher.is_error() else ""
        observation = TokenObservation(
            step=len(self._token_observations),
            token_id=token_id,
            accepted=accepted,
            accepting_after_token=self.is_accepting,
            stopped_after_token=self.is_stopped,
            error=error,
        )
        self._token_observations.append(observation)
        if not accepted:
            raise ConstraintTransitionError(error or f"token {token_id} rejected by native matcher")
        self._accepted_token_ids.append(token_id)

    def accept_tokens(self, token_ids: list[int] | tuple[int, ...]) -> None:
        for token_id in token_ids:
            self.accept_token(token_id)

    def rollback(self, token_count: int) -> None:
        if token_count < 0 or token_count > len(self._accepted_token_ids):
            raise ValueError("rollback token_count is outside the accepted prefix")
        if token_count == 0:
            return
        self.matcher.rollback(token_count)
        del self._accepted_token_ids[-token_count:]
        del self._token_observations[-token_count:]

    def trace(self, post_validation: Optional[PostValidationResult] = None) -> ConstraintRunTrace:
        accepted_bytes = self.compiled.tokenizer.decode_bytes(self._accepted_token_ids)
        accepted_output_digest = hashlib.sha256(accepted_bytes).hexdigest()
        observed_prefixes = {item.prefix_token_count for item in self._mask_observations}
        mask_coverage_complete = all(prefix in observed_prefixes for prefix in range(len(self._accepted_token_ids)))
        source_digest = canonical_digest(self.compiled.spec.to_dict()["source"])
        post_validation_bound = post_validation is not None and (
            post_validation.output_digest == accepted_output_digest
            and post_validation.constraint_source_digest == source_digest
        )

        if (
            self.matcher.is_error()
            or (post_validation is not None and not post_validation.passed)
            or (post_validation is not None and not post_validation_bound)
        ):
            outcome = KernelOutcome.FAILED_CLOSED
        elif post_validation is not None and self.is_accepting and mask_coverage_complete:
            outcome = KernelOutcome.POST_VALIDATED
        elif self.is_accepting and mask_coverage_complete:
            outcome = KernelOutcome.MASK_ACCEPTING
        else:
            outcome = KernelOutcome.INCOMPLETE
        return ConstraintRunTrace(
            constraint=self.compiled.spec,
            backend_name="llguidance",
            backend_version=self.compiled.backend_version,
            compiled_constraint_digest=self.compiled.grammar_digest,
            tokenizer_identity=self.compiled.tokenizer_identity,
            tokenizer_digest=self.compiled.tokenizer_digest,
            vocabulary_size=self.compiled.vocabulary_size,
            accepted_output_digest=accepted_output_digest,
            mask_coverage_complete=mask_coverage_complete,
            mask_observations=tuple(self._mask_observations),
            token_observations=tuple(self._token_observations),
            outcome=outcome,
            post_validation=post_validation,
        )


class SingleSequenceLogitsProcessor:
    """Transformers-compatible callable for one non-beam generation sequence.

    Prefix divergence, batching, and beam expansion fail closed instead of silently
    sharing one parser state across unrelated sequences.
    """

    def __init__(self, compiled: LLGuidanceCompiledConstraint, *, prompt_length: Optional[int] = None) -> None:
        self.session = compiled.new_session()
        self.prompt_length = prompt_length
        self._observed_input_ids: Optional[tuple[int, ...]] = None

    def __call__(self, input_ids: Any, scores: Any) -> Any:
        if input_ids.ndim != 2 or input_ids.shape[0] != 1:
            raise ValueError("SingleSequenceLogitsProcessor supports batch size 1 and no beam expansion")
        if scores.ndim != 2 or scores.shape[0] != 1:
            raise ValueError("scores must have shape [1, vocabulary]")

        current = tuple(int(item) for item in input_ids[0].tolist())
        if self.prompt_length is None:
            self.prompt_length = len(current)
        if len(current) < self.prompt_length:
            raise ValueError("input sequence is shorter than the bound prompt")

        if self._observed_input_ids is None:
            self._observed_input_ids = current[: self.prompt_length]
        if current[: len(self._observed_input_ids)] != self._observed_input_ids:
            raise ConstraintTransitionError("generation prefix diverged from the bound parser state")

        for token_id in current[len(self._observed_input_ids) :]:
            self.session.accept_token(token_id)
        self._observed_input_ids = current
        self.session.mask_logits(scores)
        return scores
