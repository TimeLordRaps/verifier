"""Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD).

Strict deterministic serialization primitives for VSTD 3 signed records."""

from __future__ import annotations

from collections.abc import Mapping as ABCMapping
from dataclasses import MISSING, fields, is_dataclass
from enum import Enum
import hashlib
import json
import math
import types
from typing import Any, Mapping, TypeVar, Union, get_args, get_origin, get_type_hints


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented in the VSTD canonical JSON profile."""


class StrictDecodingError(ValueError):
    """Raised when a signed record contains unknown, missing, or mistyped fields."""


def to_jsonable(value: Any) -> Any:
    """Convert typed VSTD records to JSON values without losing signed fields."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: to_jsonable(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise CanonicalizationError("canonical mappings require string keys")
        return {key: to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [to_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("NaN and infinity are forbidden")
        raise CanonicalizationError(
            "binary floating-point values are forbidden in signed VSTD 3 records; use a decimal string"
        )
    raise CanonicalizationError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    normalized = to_jsonable(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def require_sha256(value: str, *, field_name: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 hex digest")


T = TypeVar("T")


def strict_decode(cls: type[T], payload: Mapping[str, Any]) -> T:
    """Decode a dataclass recursively and reject every unrecognized signed field."""
    if not is_dataclass(cls):
        raise TypeError(f"{cls!r} is not a dataclass")
    if not isinstance(payload, Mapping):
        raise StrictDecodingError(f"{cls.__name__} must be a JSON object")
    known = {field.name for field in fields(cls)}
    unknown = sorted(set(payload) - known)
    if unknown:
        raise StrictDecodingError(f"{cls.__name__} has unknown fields: {', '.join(unknown)}")
    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for field in fields(cls):
        if field.name not in payload:
            if field.default is not MISSING or field.default_factory is not MISSING:
                continue
            raise StrictDecodingError(f"{cls.__name__} is missing field {field.name}")
        kwargs[field.name] = _decode_value(hints.get(field.name, Any), payload[field.name], field.name)
    try:
        return cls(**kwargs)
    except (TypeError, ValueError) as exc:
        raise StrictDecodingError(f"invalid {cls.__name__}: {exc}") from exc


def _decode_value(annotation: Any, value: Any, field_name: str) -> Any:
    if annotation is Any:
        return value
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in (Union, types.UnionType):
        errors: list[str] = []
        for candidate in args:
            if candidate is type(None) and value is None:
                return None
            try:
                return _decode_value(candidate, value, field_name)
            except StrictDecodingError as exc:
                errors.append(str(exc))
        raise StrictDecodingError(f"{field_name} does not match its union type: {'; '.join(errors)}")
    if origin is tuple:
        if not isinstance(value, list):
            raise StrictDecodingError(f"{field_name} must be an array")
        item_type = args[0] if args else Any
        return tuple(_decode_value(item_type, item, field_name) for item in value)
    if origin is list:
        if not isinstance(value, list):
            raise StrictDecodingError(f"{field_name} must be an array")
        item_type = args[0] if args else Any
        return [_decode_value(item_type, item, field_name) for item in value]
    if origin in (dict, Mapping, ABCMapping):
        if not isinstance(value, Mapping):
            raise StrictDecodingError(f"{field_name} must be an object")
        key_type, item_type = args if args else (str, Any)
        if key_type is str and not all(isinstance(key, str) for key in value):
            raise StrictDecodingError(f"{field_name} must use string keys")
        return {
            _decode_value(key_type, key, field_name): _decode_value(item_type, item, field_name)
            for key, item in value.items()
        }
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        try:
            return annotation(value)
        except ValueError as exc:
            raise StrictDecodingError(f"{field_name} has unsupported value {value!r}") from exc
    if isinstance(annotation, type) and is_dataclass(annotation):
        if not isinstance(value, Mapping):
            raise StrictDecodingError(f"{field_name} must be an object")
        return strict_decode(annotation, value)
    if annotation is bool:
        if type(value) is not bool:
            raise StrictDecodingError(f"{field_name} must be a boolean")
        return value
    if annotation is int:
        if type(value) is not int:
            raise StrictDecodingError(f"{field_name} must be an integer")
        return value
    if annotation is str:
        if not isinstance(value, str):
            raise StrictDecodingError(f"{field_name} must be a string")
        return value
    return value
