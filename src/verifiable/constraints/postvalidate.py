"""Independent whole-output checks adjacent to logits-time constraints."""

from __future__ import annotations

import hashlib
import json
from importlib.metadata import version
from typing import Any, Mapping

from verifiable.constraints.kernel import PostValidationResult, canonical_digest


def validate_json_schema_output(output_text: str, schema: Mapping[str, Any]) -> PostValidationResult:
    """Validate parsed output with jsonschema Draft 2020-12 after decoding."""

    try:
        import jsonschema  # type: ignore[import-untyped]
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - exercised only without test/runtime dependency
        raise RuntimeError("jsonschema is required for independent JSON Schema post-validation") from exc

    output_digest = hashlib.sha256(output_text.encode("utf-8")).hexdigest()
    constraint_source_digest = canonical_digest(dict(schema))
    try:
        instance = json.loads(output_text)
        Draft202012Validator.check_schema(dict(schema))
        Draft202012Validator(dict(schema)).validate(instance)
    except (json.JSONDecodeError, jsonschema.exceptions.SchemaError, jsonschema.exceptions.ValidationError) as exc:
        return PostValidationResult(
            validator_name="jsonschema.Draft202012Validator",
            validator_version=version("jsonschema"),
            passed=False,
            output_digest=output_digest,
            constraint_source_digest=constraint_source_digest,
            details=f"{type(exc).__name__}: {exc}",
        )
    return PostValidationResult(
        validator_name="jsonschema.Draft202012Validator",
        validator_version=version("jsonschema"),
        passed=True,
        output_digest=output_digest,
        constraint_source_digest=constraint_source_digest,
        details="Parsed output satisfies the declared Draft 2020-12 schema.",
    )
