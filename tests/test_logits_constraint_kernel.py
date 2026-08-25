"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Real logits-level constraint tests against llguidance, not an engine simulation."""

from __future__ import annotations

import math
import json
from pathlib import Path

import pytest

llguidance = pytest.importorskip("llguidance", reason="install the optional 'llguidance' extra")
torch = pytest.importorskip("torch", reason="install the optional 'torch' extra")

from verifier.constraints import (  # noqa: E402
    ConstraintCompilationError,
    ConstraintKind,
    ConstraintSpec,
    ConstraintTransitionError,
    KernelOutcome,
    LLGuidanceBackend,
    SingleSequenceLogitsProcessor,
    apply_packed_token_mask_inplace,
    validate_json_schema_output,
)
from verifier.constraints.kernel import canonical_digest  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def backend() -> LLGuidanceBackend:
    return LLGuidanceBackend.for_byte_tokenizer()


def test_pattern_properties_is_enforced_at_each_logits_step(backend: LLGuidanceBackend) -> None:
    schema = {
        "type": "object",
        "patternProperties": {"^x_": {"type": "integer"}},
        "additionalProperties": False,
    }
    spec = ConstraintSpec("pattern-properties", ConstraintKind.JSON_SCHEMA, schema)
    compiled = backend.compile(spec)
    session = compiled.new_session()
    output = '{"x_a":1}'

    for token_id in backend.tokenizer.tokenize_str(output):
        logits = torch.zeros(compiled.vocabulary_size, dtype=torch.float32)
        (allowed_count,) = session.mask_logits(logits)
        assert 0 < allowed_count <= compiled.vocabulary_size
        assert math.isfinite(float(logits[token_id]))
        session.accept_token(token_id)

    post_validation = validate_json_schema_output(output, schema)
    trace = session.trace(post_validation)
    assert session.is_accepting
    assert session.is_stopped
    assert trace.outcome == KernelOutcome.POST_VALIDATED
    assert len(trace.mask_observations) == len(output.encode("utf-8"))
    assert len(trace.token_observations) == len(output.encode("utf-8"))
    assert trace.constraint.digest() == spec.digest()
    assert len(trace.canonical_digest()) == 64


def test_native_compiler_rejects_unsupported_keyword_in_strict_mode(backend: LLGuidanceBackend) -> None:
    unsupported = ConstraintSpec(
        "unsupported-not",
        ConstraintKind.JSON_SCHEMA,
        {"not": {"type": "object"}},
    )
    with pytest.raises(ConstraintCompilationError, match="Unimplemented keys"):
        backend.compile(unsupported)


def test_disallowed_token_is_masked_and_rejected(backend: LLGuidanceBackend) -> None:
    compiled = backend.compile(ConstraintSpec("letters", ConstraintKind.REGEX, "[ab]+"))
    session = compiled.new_session()
    token_a = backend.tokenizer.tokenize_str("a")[0]
    token_z = backend.tokenizer.tokenize_str("z")[0]
    logits = torch.zeros(compiled.vocabulary_size, dtype=torch.float32)

    session.mask_logits(logits)
    assert math.isfinite(float(logits[token_a]))
    assert logits[token_z] == float("-inf")
    with pytest.raises(ConstraintTransitionError):
        session.accept_token(token_z)
    assert session.trace().outcome == KernelOutcome.FAILED_CLOSED


def test_portable_mask_does_not_call_torch_compile() -> None:
    logits = torch.tensor([4.0, 3.0, 2.0, 1.0])
    # Bits 0 and 2 are allowed.
    counts = apply_packed_token_mask_inplace(logits, bytes([0b00000101]))
    assert counts == (2,)
    assert logits.tolist() == [4.0, float("-inf"), 2.0, float("-inf")]


def test_transformers_callable_tracks_one_sequence_and_masks_scores(backend: LLGuidanceBackend) -> None:
    compiled = backend.compile(ConstraintSpec("letters", ConstraintKind.REGEX, "[ab]+"))
    processor = SingleSequenceLogitsProcessor(compiled)
    token_a = backend.tokenizer.tokenize_str("a")[0]
    token_z = backend.tokenizer.tokenize_str("z")[0]
    prompt = torch.tensor([[42, 43]], dtype=torch.long)
    scores = torch.zeros((1, compiled.vocabulary_size), dtype=torch.float32)

    returned = processor(prompt, scores)
    assert returned is scores
    assert math.isfinite(float(scores[0, token_a]))
    assert scores[0, token_z] == float("-inf")

    next_input = torch.tensor([[42, 43, token_a]], dtype=torch.long)
    processor(next_input, torch.zeros_like(scores))
    assert processor.session.accepted_token_ids == (token_a,)

    diverged = torch.tensor([[42, 99, token_a]], dtype=torch.long)
    with pytest.raises(ConstraintTransitionError, match="diverged"):
        processor(diverged, torch.zeros_like(scores))


def test_callable_runs_inside_transformers_logits_processor_list(backend: LLGuidanceBackend) -> None:
    transformers = pytest.importorskip("transformers", reason="use a host runtime that already provides transformers")
    compiled = backend.compile(ConstraintSpec("letter", ConstraintKind.REGEX, "a"))
    processor = SingleSequenceLogitsProcessor(compiled)
    processors = transformers.LogitsProcessorList([processor])
    scores = torch.zeros((1, compiled.vocabulary_size), dtype=torch.float32)
    input_ids = torch.tensor([[42]], dtype=torch.long)

    returned = processors(input_ids, scores)
    token_a = backend.tokenizer.tokenize_str("a")[0]
    token_z = backend.tokenizer.tokenize_str("z")[0]
    assert math.isfinite(float(returned[0, token_a]))
    assert returned[0, token_z] == float("-inf")


def test_post_validation_failure_is_not_promoted(backend: LLGuidanceBackend) -> None:
    schema = {"type": "object", "required": ["answer"]}
    failed = validate_json_schema_output("{}", schema)
    compiled = backend.compile(ConstraintSpec("answer", ConstraintKind.JSON_SCHEMA, {"type": "object"}))
    session = compiled.new_session()
    session.accept_tokens(backend.tokenizer.tokenize_str("{}"))

    assert failed.passed is False
    assert session.trace(failed).outcome == KernelOutcome.FAILED_CLOSED


def test_post_validation_must_bind_same_tokens_and_constraint(backend: LLGuidanceBackend) -> None:
    schema = {"type": "object"}
    compiled = backend.compile(ConstraintSpec("object", ConstraintKind.JSON_SCHEMA, schema))
    session = compiled.new_session()
    for token_id in backend.tokenizer.tokenize_str("{}"):
        session.mask_logits(torch.zeros(compiled.vocabulary_size))
        session.accept_token(token_id)

    wrong_output = validate_json_schema_output('{"different":true}', schema)
    wrong_schema = validate_json_schema_output("{}", {"type": "object", "maxProperties": 1})
    assert session.trace(wrong_output).outcome == KernelOutcome.FAILED_CLOSED
    assert session.trace(wrong_schema).outcome == KernelOutcome.FAILED_CLOSED


def test_accepted_tokens_without_observed_masks_remain_incomplete(backend: LLGuidanceBackend) -> None:
    compiled = backend.compile(ConstraintSpec("letter", ConstraintKind.REGEX, "a"))
    session = compiled.new_session()
    session.accept_token(backend.tokenizer.tokenize_str("a")[0])

    trace = session.trace()
    assert session.is_accepting
    assert trace.mask_coverage_complete is False
    assert trace.outcome == KernelOutcome.INCOMPLETE


def test_constraint_spec_freezes_nested_source_before_compilation() -> None:
    source = {"type": "array", "items": {"type": "integer"}}
    spec = ConstraintSpec("frozen", ConstraintKind.JSON_SCHEMA, source)
    digest = spec.digest()
    source["items"]["type"] = "string"

    assert spec.digest() == digest
    assert spec.to_dict()["source"]["items"]["type"] == "integer"


def test_trace_digest_changes_when_observation_changes(backend: LLGuidanceBackend) -> None:
    compiled = backend.compile(ConstraintSpec("letters", ConstraintKind.REGEX, "a"))
    empty_trace = compiled.new_session().trace()
    observed_session = compiled.new_session()
    observed_session.mask_logits(torch.zeros(compiled.vocabulary_size))
    observed_trace = observed_session.trace()

    assert empty_trace.canonical_digest() != observed_trace.canonical_digest()


def test_committed_demo_trace_digest_and_result() -> None:
    payload = json.loads((REPO_ROOT / "examples" / "logits_constraint_kernel" / "trace.json").read_text())
    stored_digest = payload.pop("record_digest")

    assert canonical_digest(payload) == stored_digest
    assert payload["outcome"] == KernelOutcome.POST_VALIDATED.value
    assert payload["mask_coverage_complete"] is True
    assert len(payload["mask_observations"]) == len(payload["token_observations"]) == 15
