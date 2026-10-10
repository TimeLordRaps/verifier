"""Read-only native replay operation metadata for Verifier Standard (VSTD).

application programming interface (API); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256). This module exports descriptor schemas,
not native witness schemas. Available metadata does not establish runtime replay,
execution, effects, cancellation, authority or a complete obligation census.
"""
from __future__ import annotations

import ast
from asyncio import CancelledError
import hashlib
import inspect
import math
from pathlib import Path
import re
from types import FunctionType, ModuleType
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import current_object_routes as routes


DESCRIPTOR = "verifier-native-replay-operation-descriptor-1"
LOOKUP = "verifier-native-replay-operation-lookup-1"
CATALOG = "verifier-native-replay-operation-catalog-1"
HISTORICAL = "verifier-current-object-obligations-1"
TEN_TIER = "verifier-current-ten-tier-object-obligations-1"
INTERFACE = "verifier.domains.contracts.current_object_routes.replay_current_object_certificate"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_SCHEMA_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SCHEMAS = {
    DESCRIPTOR: "schemas/native-replay-operation-descriptor-1.schema.json",
    LOOKUP: "schemas/native-replay-operation-lookup-1.schema.json",
}
_SCHEMA_BASE = "https://timelordraps.github.io/verifier/schemas/"
_DESCRIPTOR_FIELDS = {
    "schema_version", "operation_id", "operation_version", "category", "interface",
    "selector", "route", "binding", "native_signature", "interface_signature",
    "transport_limits", "owner_wire_identifiers", "schemas", "qualification",
}
_LOOKUP_FIELDS = {"schema_version", "status", "metadata_status", "reason", "selector",
                  "descriptor", "descriptor_digest", "pin_comparison", "native_replay",
                  "full_execution_qualification", "mandatory_obligation_census"}


class NativeOperationRefusal(ValueError):
    """An exact selector or external pin is unsupported or malformed."""


class NativeOperationUnavailable(RuntimeError):
    """Required installed metadata or schema bytes cannot be reached or described."""


def _text(value: Any, maximum: int = 256) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum or not value.strip():
        raise NativeOperationRefusal("BOUNDED_PLAIN_TEXT_REQUIRED")
    return value


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash(value: Any) -> str:
    if type(value) is not str or len(value) != 71 or _HASH.fullmatch(value) is None:
        raise NativeOperationRefusal("CANONICAL_PIN_REQUIRED")
    return value


def _capture(value: Any) -> Any:
    """Copy bounded exact primitive values; never invoke a foreign conversion."""
    active: set[int] = set()
    nodes, text_bytes = 0, 0

    def copy(item: Any, depth: int) -> Any:
        nonlocal nodes, text_bytes
        nodes += 1
        if nodes > 20000 or depth > 48:
            raise NativeOperationRefusal("METADATA_CAPTURE_BOUND")
        kind = type(item)
        if item is None or kind is bool:
            return item
        if kind is int:
            if item.bit_length() > 4096:
                raise NativeOperationRefusal("METADATA_INTEGER_BOUND")
            return item
        if kind is float:
            if not math.isfinite(item):
                raise NativeOperationRefusal("METADATA_NONFINITE")
            return item
        if kind is str:
            if len(item) > MAX_OUTPUT_BYTES - text_bytes:
                raise NativeOperationRefusal("METADATA_TEXT_BOUND")
            text_bytes += len(item.encode("utf-8"))
            if text_bytes > MAX_OUTPUT_BYTES:
                raise NativeOperationRefusal("METADATA_TEXT_BOUND")
            return item
        if kind not in (dict, list) or len(item) > 4096:
            raise NativeOperationRefusal("METADATA_PLAIN_COLLECTION_REQUIRED")
        identity = id(item)
        if identity in active:
            raise NativeOperationRefusal("METADATA_CYCLE")
        active.add(identity)
        try:
            if kind is list:
                return [copy(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise NativeOperationRefusal("METADATA_PLAIN_KEYS_REQUIRED")
                result[copy(key, depth + 1)] = copy(child, depth + 1)
            return result
        finally:
            active.remove(identity)

    try:
        return copy(value, 0)
    except (RecursionError, UnicodeError, RuntimeError) as exc:
        raise NativeOperationRefusal("METADATA_CAPTURE_UNAVAILABLE") from exc


def _family(value: Any) -> str:
    selected = _text(value)
    if selected not in (HISTORICAL, TEN_TIER):
        raise NativeOperationRefusal("SEMANTIC_FAMILY_UNSUPPORTED")
    return selected


def _selector(semantic_version: Any, objective: Any, represented_kind: Any) -> dict[str, str]:
    selected = {"semantic_version": _family(semantic_version),
                "objective": _text(objective), "represented_kind": _text(represented_kind)}
    if selected["represented_kind"] not in {kind.value for kind in ObjectKind}:
        raise NativeOperationRefusal("REPRESENTED_KIND_UNSUPPORTED")
    # Refuse known contradictions before the new family's lazy import or file reads.
    if selected["semantic_version"] == TEN_TIER and (
            selected["objective"] not in ("VERIFIER-6.1", "VERIFIER-10.1") or selected["represented_kind"] != "VERIFIER"):
        raise NativeOperationRefusal("TEN_TIER_SELECTOR_UNSUPPORTED")
    return selected


def _package_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _read_package(relative: str, maximum: int = MAX_SOURCE_BYTES) -> bytes:
    root = _package_root()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise NativeOperationUnavailable("INSTALLED_SOURCE_OUTSIDE_PACKAGE")
    with path.open("rb") as handle:
        chunks, remaining = [], maximum
        while True:
            chunk = handle.read(min(8192, remaining + 1))
            if not chunk:
                return b"".join(chunks)
            if len(chunk) > remaining:
                raise NativeOperationUnavailable("INSTALLED_SOURCE_BOUND")
            chunks.append(chunk)
            remaining -= len(chunk)


def _schema_bytes(selected: str, raw: bytes) -> bytes:
    try:
        schema = _capture(strict_json_loads(raw.decode("utf-8")))
        fields = _DESCRIPTOR_FIELDS if selected == DESCRIPTOR else _LOOKUP_FIELDS
        if (type(schema) is not dict or schema.get("$id") != _SCHEMA_BASE + _SCHEMAS[selected].split("/")[-1]
                or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
                or schema.get("type") != "object" or schema.get("additionalProperties") is not False
                or type(schema.get("required")) is not list or set(schema["required"]) != fields
                or type(schema.get("properties")) is not dict or set(schema["properties"]) != fields
                or schema["properties"].get("schema_version") != {"const": selected}):
            raise NativeOperationUnavailable("DESCRIPTOR_SCHEMA_CONTRACT_DIFFERS")
        return canonical_bytes(schema)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError, MemoryError) as exc:
        raise NativeOperationUnavailable("DESCRIPTOR_SCHEMA_UNAVAILABLE") from exc


def export_native_operation_schema(schema_version: str) -> bytes:
    """Export actual packaged descriptor/result schema bytes in canonical form."""
    selected = _text(schema_version)
    if selected not in _SCHEMAS:
        raise NativeOperationRefusal("DESCRIPTOR_SCHEMA_UNSUPPORTED")
    try:
        return _schema_bytes(selected, _read_package(_SCHEMAS[selected], MAX_SCHEMA_BYTES))
    except (OSError, CancelledError, MemoryError) as exc:
        raise NativeOperationUnavailable("DESCRIPTOR_SCHEMA_UNAVAILABLE") from exc


def native_replay_operation_catalog(*, semantic_version: str = HISTORICAL) -> dict[str, Any]:
    """Enumerate one closed registry; rows are metadata, not runtime qualification."""
    selected = _family(semantic_version)
    try:
        rows = (routes.current_object_route_catalog() if selected == HISTORICAL
                else routes.current_ten_tier_route_catalog())
        captured = _capture(rows)
        if any(row.get("semantic_version") != selected for row in captured):
            raise NativeOperationUnavailable("REGISTERED_CATALOG_FAMILY_DIFFERS")
        return {"schema_version": CATALOG, "status": "PASS", "metadata_status": "AVAILABLE",
                "semantic_version": selected, "routes": captured,
                "catalog_digest": _digest(canonical_bytes(captured)), "native_replay": "NOT_RUN",
                "mandatory_obligation_census": "UNKNOWN"}
    except (CancelledError, ImportError, OSError, MemoryError, NativeOperationUnavailable,
            routes.CurrentObjectRouteRefusal, ValueError, TypeError, AttributeError,
            KeyError, UnicodeError, RecursionError, OverflowError):
        return {"schema_version": CATALOG, "status": "UNKNOWN", "metadata_status": "UNAVAILABLE",
                "semantic_version": selected, "routes": [], "catalog_digest": None,
                "native_replay": "NOT_RUN", "mandatory_obligation_census": "UNKNOWN"}


def _annotation(value: Any) -> str | None:
    if value is inspect.Signature.empty:
        return None
    if type(value) is str:
        return _text(value, 1024)
    if value is None:
        return "None"
    if type(value) is type and value in (bytes, str, int, bool, dict, list):
        return value.__name__
    raise NativeOperationUnavailable("REGISTERED_ANNOTATION_UNSUPPORTED")


def _signature(function: FunctionType) -> dict[str, Any]:
    signature = inspect.signature(function, follow_wrapped=False, eval_str=False)
    if len(signature.parameters) > 16:
        raise NativeOperationUnavailable("REGISTERED_SIGNATURE_BOUND")
    return {"parameters": [{"name": _text(parameter.name), "kind": parameter.kind.name,
                            "required": parameter.default is inspect.Signature.empty,
                            "annotation": _annotation(parameter.annotation)}
                           for parameter in signature.parameters.values()],
            "return_annotation": _annotation(signature.return_annotation)}


def _registered(route: Any) -> tuple[ModuleType, str]:
    function = route.replay
    module = inspect.getmodule(function)
    if (type(function) is not FunctionType or type(module) is not ModuleType
            or not _text(module.__name__).startswith("verifier.domains.contracts.")
            or function.__module__ != module.__name__):
        raise NativeOperationUnavailable("REGISTERED_FUNCTION_UNSUPPORTED")
    root = _package_root()
    source = inspect.getsourcefile(function)
    if type(source) is not str:
        raise NativeOperationUnavailable("REGISTERED_SOURCE_MISSING")
    path = Path(source).resolve()
    if not path.is_relative_to(root):
        raise NativeOperationUnavailable("REGISTERED_SOURCE_OUTSIDE_PACKAGE")
    relative = path.relative_to(root).as_posix()
    if not relative.startswith("domains/contracts/") or not relative.endswith(".py"):
        raise NativeOperationUnavailable("REGISTERED_SOURCE_UNSUPPORTED")
    return module, relative


def _function_source(function: FunctionType, raw: bytes) -> str:
    source = raw.decode("utf-8")
    tree = ast.parse(source)
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
               and node.name == function.__name__ and node.lineno == function.__code__.co_firstlineno]
    if len(matches) != 1:
        raise NativeOperationUnavailable("REGISTERED_FUNCTION_SOURCE_UNAVAILABLE")
    segment = ast.get_source_segment(source, matches[0])
    if segment is None:
        raise NativeOperationUnavailable("REGISTERED_FUNCTION_SOURCE_UNAVAILABLE")
    return _digest(segment.encode("utf-8"))


def _external_pins(expected_source_bindings: Any) -> dict[str, str] | None:
    if expected_source_bindings is None:
        return None
    if type(expected_source_bindings) is not dict or len(expected_source_bindings) > 16:
        raise NativeOperationRefusal("PLAIN_SOURCE_PIN_MAP_REQUIRED")
    return {_text(name): _hash(digest) for name, digest in expected_source_bindings.items()}


def lookup_native_replay_operation(*, semantic_version: str, objective: str,
        represented_kind: str, expected_descriptor_digest: str | None = None,
        expected_mechanism_digest: str | None = None,
        expected_source_bindings: dict[str, str] | None = None,
        cancelled: bool = False) -> dict[str, Any]:
    """Describe one exact registered replay; no certificate or effect is invoked."""
    selected = _selector(semantic_version, objective, represented_kind)
    if type(cancelled) is not bool:
        raise NativeOperationRefusal("PLAIN_CANCELLATION_FLAG_REQUIRED")
    for pin in (expected_descriptor_digest, expected_mechanism_digest):
        if pin is not None:
            _hash(pin)
    source_pins = _external_pins(expected_source_bindings)
    result: dict[str, Any] = {"schema_version": LOOKUP, "status": "UNKNOWN",
        "metadata_status": "UNAVAILABLE", "reason": "INSTALLED_METADATA_UNAVAILABLE",
        "selector": selected, "descriptor": None, "descriptor_digest": None,
        "pin_comparison": "UNAVAILABLE" if any(pin is not None for pin in
            (expected_descriptor_digest, expected_mechanism_digest, source_pins)) else "NOT_SELECTED",
        "native_replay": "NOT_RUN",
        "full_execution_qualification": "UNKNOWN", "mandatory_obligation_census": "UNKNOWN"}
    try:
        route = routes.select_current_object_route(**selected)
    except routes.CurrentObjectRouteUnavailable:
        return result
    except routes.CurrentObjectRouteRefusal as exc:
        raise NativeOperationRefusal("REGISTERED_SELECTOR_UNSUPPORTED") from exc
    except (CancelledError, ImportError, OSError, MemoryError):
        return result
    if cancelled:
        result["reason"] = "METADATA_LOOKUP_CANCELLED"
        return result
    try:
        module, native_source = _registered(route)
        names = sorted({native_source, "domains/contracts/current_object_routes.py",
                        "runtime/native_operation_contracts.py", "standard/CURRENT_NATIVE_OPERATION_CONTRACTS.md",
                        "core/certificate.py", "core/namespace.py", "core/receipt.py", *_SCHEMAS.values()})
        if source_pins is not None and set(source_pins) != set(names):
            result.update(status="FAIL", pin_comparison="DIFFERS", reason="SOURCE_PIN_SET_DIFFERS")
            return result
        sources, schema_files, native_bytes = {}, {}, None
        for name in names:
            raw = _read_package(name, MAX_SCHEMA_BYTES if name in _SCHEMAS.values() else MAX_SOURCE_BYTES)
            sources[name] = _digest(raw)
            if source_pins is not None and source_pins[name] != sources[name]:
                result.update(status="FAIL", pin_comparison="DIFFERS", reason="SOURCE_PIN_DIFFERS")
                return result  # Later cancellation or outage cannot erase this known refutation.
            if name == native_source:
                native_bytes = raw
            if name in _SCHEMAS.values():
                schema_files[name] = raw
        schemas = {version: {"schema_version": version,
                             "digest": _digest(_schema_bytes(version, schema_files[_SCHEMAS[version]]))}
                   for version in _SCHEMAS}
        mechanism = getattr(module, "mechanism_digest", None)
        if type(mechanism) is not FunctionType:
            raise NativeOperationUnavailable("REGISTERED_MECHANISM_BINDING_UNSUPPORTED")
        arguments = (represented_kind,) if module.__name__ == "verifier.domains.contracts.subject_security" else ()
        inspect.signature(mechanism, follow_wrapped=False, eval_str=False).bind(*arguments)
        mechanism_pin = _hash(mechanism(*arguments))
        if expected_mechanism_digest is not None and expected_mechanism_digest != mechanism_pin:
            result.update(status="FAIL", pin_comparison="DIFFERS", reason="MECHANISM_PIN_DIFFERS")
            return result
        owner_wires = {name: _text(vars(module)[name]) for name in
                       ("REQUEST_VERSION", "POLICY_VERSION", "EVIDENCE_VERSION", "CERTIFICATE_VERSION",
                        "ASSESSMENT_VERSION", "RESULT_VERSION") if name in vars(module)}
        descriptor = {"schema_version": DESCRIPTOR,
            "operation_id": "native-replay:" + hashlib.sha256(canonical_bytes(selected)).hexdigest(),
            "operation_version": "1", "category": "finite_native_certificate_replay", "interface": INTERFACE,
            "selector": selected, "route": {"certificate_schema_version": _text(route.module.CERTIFICATE_VERSION),
                "proposition_digest": _hash(route.module.PROPOSITION_DIGEST), "scope": _text(route.scope, 1024),
                "represented_kind_rule": route.fixed_kind},
            "binding": {"mechanism_id": _text(module.MECHANISM_ID), "mechanism_digest": mechanism_pin,
                "module": module.__name__, "function": _text(route.replay.__name__),
                "function_source_digest": _function_source(route.replay, native_bytes), "sources": sources},
            "native_signature": _signature(route.replay),
            "interface_signature": _signature(routes.replay_current_object_certificate),
            "transport_limits": {"certificate_bytes": routes.MAX_CERTIFICATE_BYTES,
                "selection_text_bytes_per_request_or_policy": routes.MAX_SELECTION_TEXT_BYTES,
                "selection_nodes_per_request_or_policy": routes._MAX_SELECTION_NODES,
                "selection_depth": routes._MAX_SELECTION_DEPTH, "integer_bits": routes._MAX_INTEGER_BITS,
                "container_items": routes._MAX_CONTAINER_ITEMS, "native_additional_bounds": "UNKNOWN"},
            "owner_wire_identifiers": owner_wires,
            "schemas": {"descriptor": schemas[DESCRIPTOR], "lookup_result": schemas[LOOKUP],
                "native_request": "UNSUPPORTED", "native_policy": "UNSUPPORTED", "native_evidence": "UNSUPPORTED",
                "native_result": "UNSUPPORTED", "native_error": "UNSUPPORTED"},
            "qualification": {"metadata": "AVAILABLE", "native_replay": "NOT_RUN", "runtime_availability": "UNKNOWN",
                "effects": "UNSUPPORTED", "disclosures": "UNSUPPORTED", "idempotency": "UNSUPPORTED",
                "cancellation": "UNSUPPORTED", "budget": "UNSUPPORTED", "full_execution": "UNKNOWN",
                "mandatory_obligation_census": "UNKNOWN", "whole_tier_conformance": "NOT_ESTABLISHED",
                "authority": "NOT_ESTABLISHED", "production_admission": "NOT_ESTABLISHED"}}
        descriptor = _capture(descriptor)
        raw_descriptor = canonical_bytes(descriptor)
        if len(raw_descriptor) > MAX_OUTPUT_BYTES:
            raise NativeOperationUnavailable("DESCRIPTOR_OUTPUT_BOUND")
        descriptor_pin = _digest(raw_descriptor)
        if expected_descriptor_digest is not None and descriptor_pin != expected_descriptor_digest:
            result.update(status="FAIL", pin_comparison="DIFFERS", reason="DESCRIPTOR_PIN_DIFFERS")
            return result
        pinned = any(pin is not None for pin in (expected_descriptor_digest, expected_mechanism_digest, source_pins))
        result.update(status="PASS", metadata_status="AVAILABLE", reason="REGISTERED_METADATA_DESCRIBED",
                      descriptor=descriptor, descriptor_digest=descriptor_pin,
                      pin_comparison="MATCH" if pinned else "NOT_SELECTED")
    except CancelledError:
        result["reason"] = "METADATA_LOOKUP_CANCELLED"
    except (ImportError, OSError, NativeOperationUnavailable, NativeOperationRefusal,
            ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError,
            SyntaxError, MemoryError):
        result["reason"] = "INSTALLED_METADATA_UNAVAILABLE"
    return result


__all__ = ["DESCRIPTOR", "LOOKUP", "CATALOG", "HISTORICAL", "TEN_TIER", "NativeOperationRefusal",
           "NativeOperationUnavailable", "native_replay_operation_catalog", "lookup_native_replay_operation",
           "export_native_operation_schema"]
