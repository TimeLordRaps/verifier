"""Emit a real llguidance logits-mask trace for a schema Outlines 0.2.14 dropped."""

from __future__ import annotations

import json
from pathlib import Path

import torch

from verifier.constraints import (
    ConstraintKind,
    ConstraintSpec,
    LLGuidanceBackend,
    validate_json_schema_output,
)


HERE = Path(__file__).resolve().parent


def main() -> int:
    schema = {
        "type": "object",
        "patternProperties": {"^x_": {"type": "integer"}},
        "additionalProperties": False,
    }
    output = '{"x_answer":42}'
    backend = LLGuidanceBackend.for_byte_tokenizer()
    compiled = backend.compile(ConstraintSpec("pattern-properties-demo", ConstraintKind.JSON_SCHEMA, schema))
    session = compiled.new_session()

    for token_id in backend.tokenizer.tokenize_str(output):
        logits = torch.zeros(compiled.vocabulary_size, dtype=torch.float32)
        session.mask_logits(logits)
        if not torch.isfinite(logits[token_id]):
            raise RuntimeError(f"known-valid token {token_id} was masked")
        session.accept_token(token_id)

    trace = session.trace(validate_json_schema_output(output, schema))
    trace_payload = trace.to_dict()
    trace_payload["record_digest"] = trace.canonical_digest()
    destination = HERE / "trace.json"
    destination.write_text(json.dumps(trace_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{trace.outcome.value}: {destination}")
    print(f"record_digest={trace.canonical_digest()}")
    return 0 if trace.post_validation and trace.post_validation.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
