"""Deterministic JSON Schema generation for the normative VSTD 3 records."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
import types
from typing import Any, Union, get_args, get_origin, get_type_hints

from .models import AcceleratorProfile, VSTD3Receipt


SCHEMA_BASE = "https://timelordraps.github.io/verifier/schemas/"


class _SchemaBuilder:
    def __init__(self) -> None:
        self.definitions: dict[str, dict[str, object]] = {
            "CanonicalValue": {
                "description": "A deterministic signed value. JSON floating-point numbers are forbidden.",
                "oneOf": [
                    {"type": "null"},
                    {"type": "boolean"},
                    {"type": "integer"},
                    {"type": "string"},
                    {"type": "array", "items": {"$ref": "#/$defs/CanonicalValue"}},
                    {
                        "type": "object",
                        "additionalProperties": {"$ref": "#/$defs/CanonicalValue"},
                    },
                ],
            }
        }

    def reference(self, model_type: type) -> dict[str, object]:
        self._ensure_definition(model_type)
        return {"$ref": f"#/$defs/{model_type.__name__}"}

    def _ensure_definition(self, model_type: type) -> None:
        name = model_type.__name__
        if name in self.definitions:
            return
        if isinstance(model_type, type) and issubclass(model_type, Enum):
            self.definitions[name] = {
                "type": "string",
                "enum": [member.value for member in model_type],
            }
            return
        if not is_dataclass(model_type):
            raise TypeError(f"cannot generate schema for {model_type!r}")
        self.definitions[name] = {}
        hints = get_type_hints(model_type)
        properties = {
            field.name: self._field_schema(model_type, field.name, hints[field.name])
            for field in fields(model_type)
        }
        self.definitions[name] = {
            "type": "object",
            "additionalProperties": False,
            "required": [field.name for field in fields(model_type)],
            "properties": properties,
        }

    def _field_schema(self, owner: type, field_name: str, annotation: Any) -> dict[str, object]:
        schema = self._type_schema(annotation)
        if owner is VSTD3Receipt and field_name == "schema_version":
            return {"const": "VSTD-3.0"}
        if field_name == "capacity_fraction_ppm":
            return {"type": "integer", "minimum": 1, "maximum": 1_000_000}
        if field_name in {"epoch", "sequence"}:
            result: dict[str, object] = {"type": "integer", "minimum": 0}
            if field_name == "sequence":
                result["maximum"] = 2**64 - 1
            return result
        exact_digest_fields = {
            "canonical_digest",
            "configuration_digest",
            "event_payload_digest",
            "previous_root",
            "rolling_root",
            "raw_evidence_digest",
            "signed_digest",
        }
        if field_name in exact_digest_fields:
            return {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        return schema

    def _type_schema(self, annotation: Any) -> dict[str, object]:
        if annotation is Any:
            return {"$ref": "#/$defs/CanonicalValue"}
        if annotation is str:
            return {"type": "string"}
        if annotation is int:
            return {"type": "integer"}
        if annotation is bool:
            return {"type": "boolean"}
        if annotation is type(None):
            return {"type": "null"}
        origin = get_origin(annotation)
        args = get_args(annotation)
        if origin in (Union, types.UnionType):
            return {"oneOf": [self._type_schema(argument) for argument in args]}
        if origin in (tuple, list):
            item_type = args[0] if args else Any
            return {"type": "array", "items": self._type_schema(item_type)}
        if origin is dict:
            return {
                "type": "object",
                "additionalProperties": self._type_schema(args[1] if len(args) == 2 else Any),
            }
        if isinstance(annotation, type) and (is_dataclass(annotation) or issubclass(annotation, Enum)):
            return self.reference(annotation)
        raise TypeError(f"unsupported schema annotation {annotation!r}")


def schema_for(model_type: type, *, schema_id: str, title: str) -> dict[str, object]:
    builder = _SchemaBuilder()
    root = builder.reference(model_type)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_BASE + schema_id,
        "title": title,
        "description": (
            "Normative VSTD 3 signed-record schema. Unknown dataclass fields are rejected; "
            "semantic and cryptographic verification is additionally required."
        ),
        **root,
        "$defs": {name: builder.definitions[name] for name in sorted(builder.definitions)},
    }


def receipt_schema() -> dict[str, object]:
    return schema_for(
        VSTD3Receipt,
        schema_id="vstd3_receipt.json",
        title="VSTD 3 Universal Accelerator Accountability Receipt",
    )


def accelerator_profile_schema() -> dict[str, object]:
    return schema_for(
        AcceleratorProfile,
        schema_id="vstd3_accelerator_profile.json",
        title="VSTD 3 Accelerator Registry Profile",
    )
