"""Dependency-free publication validation for package-polish reports.

Terminology: JavaScript Object Notation (JSON).

The package-polish schemas are normative output contracts, so a numeric
``vstd polish`` command must not publish a report which contradicts the schema
it names.  Verifier intentionally has no runtime dependencies; this module
therefore implements only the exact Draft 2020-12 keyword surface used by the
three bundled package-polish schemas.  An unknown schema, reference, keyword,
or malformed schema fails closed instead of being treated as an annotation.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
import json
import math
import re
from typing import Any

from verifier.core.receipt import strict_json_loads
from verifier.runtime import core_obligation_union, package_verifier_graph


SCHEMA_FILENAMES = {
    "verifier-manifest-package-polish-1": (
        "verifier-manifest-package-polish-1.schema.json"
    ),
    "verifier-manifest-package-polish-2": (
        "verifier-manifest-package-polish-2.schema.json"
    ),
    "verifier-manifest-package-polish-capacity-2": (
        "verifier-manifest-package-polish-capacity-2.schema.json"
    ),
}
REJECTION_SCHEMA_VERSION = (
    "verifier-manifest-package-polish-publication-rejected-1"
)
REJECTION_SCHEMA_FILENAME = (
    "verifier-manifest-package-polish-publication-rejected-1.schema.json"
)

MAX_VALIDATION_ERRORS = 32
MAX_SCHEMA_BYTES = 128 * 1024
MAX_VALIDATION_DEPTH = 256
MAX_VALIDATION_WORK = 8_000_000

# Conditional source adaptations are checked against the installed route
# catalog as well as their same-object companion.  The import is lazy so this
# validator retains its zero-third-party-dependency publication boundary.  The
# companion row does not authenticate an unsigned report; source replay or a
# trusted signature is still required for authority.
_SOURCE_ADAPTATION_SLUGS = {
    1: "source-representation-facets",
    2: "source-representation-dynamics",
    3: "source-representation-statics",
}
_SOURCE_CHECKING_MECHANISM = (
    "verifier.runtime.package_source_contracts.SourceContractAssessment.evaluate"
)
_PASS_TABLE_OBJECT_FIELDS = (
    "object_id", "object_digest", "object_kind", "declared_kind",
    "specializations",
)
_PASS_TABLE_ROUTE_FIELDS = (
    "coordinate", "tier", "proposition_digest", "checking_mechanism", "scope",
)
_PASS_TABLE_ENTRY_FIELDS = (
    "source_index", "object_index", "route_index", "instance_digest",
    "semantic_definition_index", "kind_requirement_definition_index",
    "complete_instance_digest", "native_specimen_is_instance_evidence",
    "package_graph_replay_is_instance_evidence", "check_definition_index",
    "full_check_digest", "adaptation_result_digest", "result_digest",
)
_PASS_CHECK_IDENTITY_FIELDS = (
    "object_id", "object_digest", "coordinate", "proposition_digest",
    "checking_mechanism", "native_coordinate", "conditional_coordinate",
)
_PASS_CHECK_IDENTITY_MARKER = "projection_identity_fields"
_PASS_CHECK_RESULT_MARKER = "projection_recompute_result_digest"

_ANNOTATION_KEYWORDS = {"$schema", "$id", "title"}
_ASSERTION_KEYWORDS = {
    "$defs",
    "$ref",
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "contains",
    "else",
    "enum",
    "if",
    "items",
    "maxItems",
    "maxLength",
    "maximum",
    "minItems",
    "minLength",
    "minProperties",
    "minimum",
    "not",
    "oneOf",
    "pattern",
    "prefixItems",
    "properties",
    "required",
    "then",
    "type",
    "uniqueItems",
}
_SUPPORTED_KEYWORDS = _ANNOTATION_KEYWORDS | _ASSERTION_KEYWORDS
_JSON_TYPES = {"array", "boolean", "integer", "null", "number", "object", "string"}


@dataclass(frozen=True)
class PackagePolishSchemaValidation:
    """Bounded result of validating one report against its declared schema."""

    schema_version: str | None
    schema_supported: bool
    valid: bool
    errors: tuple[str, ...]
    selected_schema_digest: str | None = None
    validator_mechanism_digest: str | None = None
    errors_at_limit: bool = False


class _ValidationWorkExhausted(RuntimeError):
    pass


class _WorkBudget:
    def __init__(self, limit: int | None = None) -> None:
        self.limit = MAX_VALIDATION_WORK if limit is None else limit
        self.used = 0

    def consume(self, amount: int = 1) -> None:
        self.used += amount
        if self.used > self.limit:
            raise _ValidationWorkExhausted


class _Issues:
    def __init__(self, limit: int = MAX_VALIDATION_ERRORS) -> None:
        self.limit = limit
        self.values: list[str] = []

    @property
    def full(self) -> bool:
        return len(self.values) >= self.limit

    def add(self, path: str, keyword: str, message: str) -> None:
        if not self.full:
            self.values.append(f"{path}: {keyword}: {message}")


def _pointer_part(value: object) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _child_path(path: str, value: object) -> str:
    return f"{path}/{_pointer_part(value)}" if path != "/" else f"/{_pointer_part(value)}"


def _json_kind(value: Any) -> str | None:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number" if math.isfinite(value) else None
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return None


def _has_type(value: Any, expected: str) -> bool:
    kind = _json_kind(value)
    if expected == "integer":
        return kind == "integer" or (
            kind == "number"
            and isinstance(value, float)
            and value.is_integer()
        )
    if expected == "number":
        return kind in {"integer", "number"}
    return kind == expected


def _json_equal(left: Any, right: Any) -> bool:
    left_kind = _json_kind(left)
    right_kind = _json_kind(right)
    if left_kind in {"integer", "number"} and right_kind in {"integer", "number"}:
        return left == right
    if left_kind != right_kind:
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    return left == right


def _json_unique_key(value: Any, budget: _WorkBudget) -> tuple[Any, ...]:
    """Return an exact hashable JSON-equivalence key in linear total size."""
    budget.consume()
    kind = _json_kind(value)
    if kind == "null":
        return ("null",)
    if kind == "boolean":
        return ("boolean", value)
    if kind in {"integer", "number"}:
        # Python numeric equality and hashing give Draft 2020-12's intended
        # JSON-number equivalence here: 1 and 1.0 are the same unique item.
        return ("number", value)
    if kind == "string":
        return ("string", value)
    if kind == "array":
        return (
            "array",
            tuple(_json_unique_key(item, budget) for item in value),
        )
    if kind == "object":
        return (
            "object",
            tuple(
                (name, _json_unique_key(item, budget))
                for name, item in sorted(value.items())
            ),
        )
    return ("unsupported", type(value).__qualname__, repr(value))


@lru_cache(maxsize=1)
def validator_mechanism_digest() -> str | None:
    """Digest the exact dependency-free validator source when it is readable."""
    try:
        raw = files("verifier").joinpath(
            "runtime", "package_polish_schema_validation.py"
        ).read_bytes()
    except Exception:
        return None
    return core_obligation_union.bytes_digest(raw)


def _resolve_ref(root_schema: dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        raise ValueError("only local JSON Pointer references are supported")
    selected: Any = root_schema
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(selected, dict) or part not in selected:
            raise ValueError(f"unresolved local reference {ref!r}")
        selected = selected[part]
    return selected


def _schema_children(schema: dict[str, Any]) -> list[tuple[str, Any]]:
    children: list[tuple[str, Any]] = []
    for map_keyword in ("$defs", "properties"):
        value = schema.get(map_keyword)
        if isinstance(value, dict):
            children.extend(
                (f"{map_keyword}/{_pointer_part(name)}", child)
                for name, child in value.items()
            )
    for list_keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        value = schema.get(list_keyword)
        if isinstance(value, list):
            children.extend(
                (f"{list_keyword}/{index}", child)
                for index, child in enumerate(value)
            )
    for schema_keyword in (
        "additionalProperties", "contains", "else", "if", "items", "not", "then",
    ):
        if schema_keyword in schema:
            children.append((schema_keyword, schema[schema_keyword]))
    return children


def _check_schema_document(root_schema: Any) -> tuple[str, ...]:
    issues = _Issues()

    def malformed(path: str, keyword: str, expected: str) -> None:
        issues.add(path, keyword, f"keyword value must be {expected}")

    def is_schema(value: Any) -> bool:
        return isinstance(value, (bool, dict))

    def is_nonnegative_integer(value: Any) -> bool:
        return (
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and (not isinstance(value, float) or math.isfinite(value))
            and value >= 0
            and int(value) == value
        )

    def is_number(value: Any) -> bool:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (not isinstance(value, float) or math.isfinite(value))
        )

    def is_json_value(value: Any) -> bool:
        try:
            json.dumps(value, allow_nan=False)
        except (TypeError, ValueError, OverflowError):
            return False
        return True

    def visit(schema: Any, path: str, depth: int) -> None:
        if issues.full:
            return
        if depth > MAX_VALIDATION_DEPTH:
            issues.add(path, "schema", "schema nesting exceeds the supported bound")
            return
        if isinstance(schema, bool):
            return
        if not isinstance(schema, dict):
            issues.add(path, "schema", "schema node must be an object or boolean")
            return
        for keyword in schema:
            if keyword not in _SUPPORTED_KEYWORDS:
                issues.add(path, keyword, "unsupported schema keyword")
        for keyword in _ANNOTATION_KEYWORDS:
            if keyword in schema and not isinstance(schema[keyword], str):
                malformed(path, keyword, "a string")
        for keyword in ("$defs", "properties"):
            value = schema.get(keyword)
            if value is not None and (
                not isinstance(value, dict)
                or not all(isinstance(name, str) for name in value)
            ):
                malformed(path, keyword, "an object of schema values")
        for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
            value = schema.get(keyword)
            if value is not None and (
                not isinstance(value, list)
                or not value
                or not all(is_schema(child) for child in value)
            ):
                malformed(path, keyword, "a non-empty array of schemas")
        for keyword in (
            "additionalProperties", "contains", "else", "if", "items",
            "not", "then",
        ):
            if keyword in schema and not is_schema(schema[keyword]):
                malformed(path, keyword, "a schema object or boolean")
        ref = schema.get("$ref")
        if "$ref" in schema:
            if not isinstance(ref, str):
                issues.add(path, "$ref", "reference must be a string")
            else:
                try:
                    _resolve_ref(root_schema, ref)
                except ValueError as exc:
                    issues.add(path, "$ref", str(exc))
        declared_type = schema.get("type")
        if declared_type is not None:
            types = declared_type if isinstance(declared_type, list) else [declared_type]
            if (
                not isinstance(declared_type, (str, list))
                or not types
                or not all(isinstance(item, str) for item in types)
                or any(item not in _JSON_TYPES for item in types)
                or len(set(types)) != len(types)
            ):
                issues.add(path, "type", "type declaration is unsupported or malformed")
        required = schema.get("required")
        if required is not None and (
            not isinstance(required, list)
            or not all(isinstance(name, str) for name in required)
            or len(set(required)) != len(required)
        ):
            malformed(path, "required", "an array of unique strings")
        enum = schema.get("enum")
        if enum is not None and (
            not isinstance(enum, list)
            or not enum
            or not all(is_json_value(item) for item in enum)
        ):
            malformed(path, "enum", "a non-empty array of JSON values")
        if "const" in schema and not is_json_value(schema["const"]):
            malformed(path, "const", "a JSON value")
        for keyword in (
            "maxItems", "maxLength", "minItems", "minLength", "minProperties",
        ):
            if keyword in schema and not is_nonnegative_integer(schema[keyword]):
                malformed(path, keyword, "a non-negative integer")
        for keyword in ("maximum", "minimum"):
            if keyword in schema and not is_number(schema[keyword]):
                malformed(path, keyword, "a finite JSON number")
        if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
            malformed(path, "uniqueItems", "a boolean")
        pattern = schema.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                issues.add(path, "pattern", "pattern must be a string")
            else:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    issues.add(path, "pattern", f"invalid regular expression: {exc}")
        for name, child in _schema_children(schema):
            visit(child, _child_path(path, name), depth + 1)

    visit(root_schema, "/", 0)
    return tuple(issues.values)


@lru_cache(maxsize=len(SCHEMA_FILENAMES) + 1)
def _load_named_schema(
    schema_version: str,
    filename: str,
) -> tuple[dict[str, Any] | None, tuple[str, ...], str | None]:
    try:
        raw = files("verifier").joinpath("schemas", filename).read_bytes()
    except (FileNotFoundError, OSError) as exc:
        return None, (
            f"/: schema: bundled schema unavailable: {type(exc).__name__}",
        ), None
    schema_digest = core_obligation_union.bytes_digest(raw)
    if len(raw) > MAX_SCHEMA_BYTES:
        return None, (
            f"/: schema: bundled schema exceeds {MAX_SCHEMA_BYTES} bytes",
        ), schema_digest
    try:
        text = raw.decode("utf-8")
        schema = strict_json_loads(text)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return None, (
            f"/: schema: bundled schema is invalid JSON: {type(exc).__name__}",
        ), schema_digest
    if not isinstance(schema, dict):
        return None, (
            "/: schema: bundled schema root must be an object",
        ), schema_digest
    try:
        schema_issues = _check_schema_document(schema)
    except Exception as exc:
        schema_issues = (
            "/: schema: schema preflight raised " + type(exc).__name__,
        )
    properties = schema.get("properties")
    schema_version_schema = (
        properties.get("schema_version") if isinstance(properties, dict) else None
    )
    declared_schema_version = (
        schema_version_schema.get("const")
        if isinstance(schema_version_schema, dict)
        else None
    )
    if declared_schema_version != schema_version:
        schema_issues = (
            *schema_issues,
            "/: schema_version: bundled schema does not bind its selected version",
        )
    return schema, schema_issues, schema_digest


def _load_schema(
    schema_version: str,
) -> tuple[dict[str, Any] | None, tuple[str, ...], str | None]:
    return _load_named_schema(schema_version, SCHEMA_FILENAMES[schema_version])


def _matches(
    instance: Any,
    schema: Any,
    root_schema: dict[str, Any],
    depth: int,
    budget: _WorkBudget,
) -> bool:
    issues = _Issues(limit=1)
    _validate(instance, schema, root_schema, "/", issues, depth, budget)
    return not issues.values


def _validate(
    instance: Any,
    schema: Any,
    root_schema: dict[str, Any],
    path: str,
    issues: _Issues,
    depth: int,
    budget: _WorkBudget,
) -> None:
    if issues.full:
        return
    # Charge each schema-node visit once.  Array items and declared/additional
    # object properties are charged when the validator actually descends into
    # them below; pre-charging the container length here counted every visited
    # child twice and rejected valid under-wire-cap capacity receipts.  A
    # schema that only performs O(1) length/type checks likewise should not be
    # charged as though it had traversed an otherwise opaque container.
    work = 1
    if isinstance(instance, str):
        work += len(instance) // 1024
    budget.consume(work)
    if depth > MAX_VALIDATION_DEPTH:
        issues.add(path, "schema", "validation nesting exceeds the supported bound")
        return
    if schema is False:
        issues.add(path, "false", "value is forbidden")
        return
    if schema is True:
        return
    if not isinstance(schema, dict):
        issues.add(path, "schema", "schema node is malformed")
        return

    ref = schema.get("$ref")
    if ref is not None:
        try:
            target = _resolve_ref(root_schema, ref)
        except ValueError as exc:
            issues.add(path, "$ref", str(exc))
            return
        _validate(
            instance, target, root_schema, path, issues, depth + 1, budget
        )

    for subschema in schema.get("allOf", []):
        if issues.full:
            break
        _validate(
            instance, subschema, root_schema, path, issues, depth + 1, budget
        )
    if "anyOf" in schema and not any(
        _matches(instance, subschema, root_schema, depth + 1, budget)
        for subschema in schema["anyOf"]
    ):
        issues.add(path, "anyOf", "value does not match any alternative")
    if "oneOf" in schema:
        count = sum(
            _matches(instance, subschema, root_schema, depth + 1, budget)
            for subschema in schema["oneOf"]
        )
        if count != 1:
            issues.add(path, "oneOf", f"value matches {count} alternatives, expected exactly one")
    if "not" in schema and _matches(
        instance, schema["not"], root_schema, depth + 1, budget
    ):
        issues.add(path, "not", "value matches the forbidden schema")
    if "if" in schema:
        branch = (
            "then"
            if _matches(
                instance, schema["if"], root_schema, depth + 1, budget
            )
            else "else"
        )
        if branch in schema:
            _validate(
                instance, schema[branch], root_schema, path, issues,
                depth + 1, budget,
            )

    declared_type = schema.get("type")
    if declared_type is not None:
        types = declared_type if isinstance(declared_type, list) else [declared_type]
        if not any(_has_type(instance, selected) for selected in types):
            issues.add(path, "type", f"expected {types!r}, observed {_json_kind(instance)!r}")
            return
    if "const" in schema and not _json_equal(instance, schema["const"]):
        issues.add(path, "const", "value does not equal the required constant")
    if "enum" in schema and not any(_json_equal(instance, item) for item in schema["enum"]):
        issues.add(path, "enum", "value is not one of the admitted values")

    if isinstance(instance, str):
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            issues.add(
                path, "maxLength",
                f"length {len(instance)} exceeds maximum {schema['maxLength']}",
            )
        if "minLength" in schema and len(instance) < schema["minLength"]:
            issues.add(path, "minLength", f"length {len(instance)} is below {schema['minLength']}")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            issues.add(path, "pattern", "string does not match the required pattern")
    if _json_kind(instance) in {"integer", "number"}:
        if "minimum" in schema and instance < schema["minimum"]:
            issues.add(path, "minimum", f"value {instance!r} is below {schema['minimum']!r}")
        if "maximum" in schema and instance > schema["maximum"]:
            issues.add(path, "maximum", f"value {instance!r} exceeds {schema['maximum']!r}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            issues.add(path, "minItems", f"item count {len(instance)} is below {schema['minItems']}")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            issues.add(path, "maxItems", f"item count {len(instance)} exceeds {schema['maxItems']}")
        if schema.get("uniqueItems") is True:
            observed: set[tuple[Any, ...]] = set()
            for index, item in enumerate(instance):
                if issues.full:
                    break
                key = _json_unique_key(item, budget)
                if key in observed:
                    issues.add(_child_path(path, index), "uniqueItems", "item duplicates an earlier value")
                    break
                observed.add(key)
        prefix = schema.get("prefixItems", [])
        for index, item_schema in enumerate(prefix[:len(instance)]):
            if issues.full:
                break
            _validate(
                instance[index], item_schema, root_schema,
                _child_path(path, index), issues, depth + 1, budget,
            )
        if "items" in schema:
            for index in range(len(prefix), len(instance)):
                if issues.full:
                    break
                _validate(
                    instance[index], schema["items"], root_schema,
                    _child_path(path, index), issues, depth + 1, budget,
                )
        if "contains" in schema and not any(
            _matches(
                item, schema["contains"], root_schema, depth + 1, budget
            )
            for item in instance
        ):
            issues.add(path, "contains", "array has no item matching the required schema")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for name in required:
            if issues.full:
                break
            if name not in instance:
                issues.add(path, "required", f"missing property {name!r}")
        properties = schema.get("properties", {})
        for name, property_schema in properties.items():
            if issues.full:
                break
            if name in instance:
                _validate(
                    instance[name], property_schema, root_schema,
                    _child_path(path, name), issues, depth + 1, budget,
                )
        if "minProperties" in schema and len(instance) < schema["minProperties"]:
            issues.add(
                path, "minProperties",
                f"property count {len(instance)} is below {schema['minProperties']}",
            )
        if "additionalProperties" in schema:
            additional_schema = schema["additionalProperties"]
            for name in instance.keys() - properties.keys():
                if issues.full:
                    break
                if additional_schema is False:
                    issues.add(
                        _child_path(path, name),
                        "additionalProperties",
                        "property is not declared",
                    )
                else:
                    _validate(
                        instance[name], additional_schema, root_schema,
                        _child_path(path, name), issues, depth + 1, budget,
                    )


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _conditional_source_binding_matches(
    report: dict[str, Any],
    row: dict[str, Any],
    check: dict[str, Any],
    semantic_definition: dict[str, Any],
    rows_by_key: dict[tuple[Any, Any], list[dict[str, Any]]],
) -> bool:
    """Check the zero-byte cross-row binding for one conditional PASS.

    The source assessment itself was consumed before projection.  Its complete
    canonical digest remains on the same-object source-route companion.  Exact
    local coordinate, reason and condition rules prevent a report-local
    conditional body from drifting independently. They do not authenticate a
    fully rewritten unsigned report.
    """

    object_kind = row.get("object_kind")
    tier = row.get("tier")
    slug = _SOURCE_ADAPTATION_SLUGS.get(tier)
    if slug is None:
        return False
    try:
        from verifier.runtime import package_source_contracts

        source_route = package_source_contracts.source_route_for_obligation(
            check.get("adaptation_obligation_id")
        )
    except (ImportError, AttributeError, TypeError, ValueError):
        source_route = None
    if (
        not isinstance(source_route, dict)
        or source_route.get("tier") != tier
        or source_route.get("scope")
            != "exact_installed_source_representation_" + slug.replace("-", "_")
    ):
        return False
    source_coordinate = source_route["coordinate"]
    source_obligation_id = source_route["obligation_id"]
    source_kind = source_route["object_kind"]
    candidates = rows_by_key.get((row.get("object_id"), source_coordinate), [])
    if len(candidates) != 1:
        return False
    companion = candidates[0]
    companion_check = companion.get("selected_package_check")
    expected_scope = (
        "exact_installed_source_representation_" + slug.replace("-", "_")
    )
    if not (
        row.get("coordinate") != source_coordinate
        and check.get("adaptation_obligation_id") == source_obligation_id
        and companion.get("object_digest") == row.get("object_digest")
        and companion.get("object_kind") == source_kind
        and companion.get("tier") == tier
        and companion.get("status") == "PASS"
        and companion.get("checker_status") == "PASS"
        and companion.get("blockers") == []
        and companion.get("checking_mechanism") == _SOURCE_CHECKING_MECHANISM
        and companion.get("scope") == expected_scope
        and isinstance(companion_check, dict)
        and companion_check.get("schema_version")
        == "verifier-package-check-reference-1"
        and companion_check.get("status") == "PASS"
        and companion_check.get("transport") == "DIGEST_BOUND_REFERENCE"
        and companion_check.get("evidence_origin")
        == "INSTALLED_SOURCE_REVIEW_AND_FRESH_DISCOVERY"
        and companion_check.get("full_check_digest")
        == check.get("adaptation_result_digest")
    ):
        return False

    try:
        from verifier.runtime import manifest_gate
        from verifier.runtime.tier_zero_profile import (
            validate_applicability_binding,
        )

        routes = [
            route for route in manifest_gate.obligation_catalog()
            if route.get("object_kind") == object_kind
            and route.get("tier") == tier
            and route.get("coordinate") == row.get("coordinate")
            and route.get("proposition_digest")
            == row.get("proposition_digest")
            and route.get("checking_mechanism")
            == row.get("checking_mechanism")
            and route.get("scope") == row.get("scope")
        ]
        declaration = (
            validate_applicability_binding(routes[0])
            if len(routes) == 1 else None
        )
    except (ImportError, AttributeError, TypeError, ValueError):
        declaration = None
    applicability = semantic_definition.get("applicability")
    source_coordinate_value = report.get("source_coordinate")
    verifier_execution = report.get("verifier_execution")
    package_graph = report.get("package_graph")
    manifest = report.get("manifest")
    return bool(
        isinstance(declaration, dict)
        and declaration.get("mode") == "CONDITIONAL"
        and check.get("condition") == declaration.get("condition")
        and check.get("applicability_digest")
        == routes[0].get("applicability_digest")
        and isinstance(check.get("reason"), str)
        and bool(check["reason"].strip())
        and isinstance(applicability, dict)
        and applicability.get("status") == "PASS"
        and applicability.get("classification") == "CONDITION_NOT_MET"
        and applicability.get("assessment_required") is True
        and applicability.get("reason") == check.get("reason")
        and isinstance(source_coordinate_value, dict)
        and report.get("source_coordinate_digest")
        == core_obligation_union.value_digest(source_coordinate_value)
        and report.get("post_replay_source_recapture") == "PASS"
        and report.get("post_replay_manifest_recapture") == "PASS"
        and isinstance(verifier_execution, dict)
        and isinstance(package_graph, dict)
        and isinstance(manifest, dict)
        and verifier_execution.get("manifest_digest") == manifest.get("digest")
        and package_graph.get("manifest_digest") == manifest.get("digest")
    )


def _validate_package_graph_fresh_replays(
    report: dict[str, Any],
    issues: _Issues,
    budget: _WorkBudget,
) -> None:
    """Rehash each inline package-root GRAPH adapter result and its route binding.

    JSON Schema owns the exact wire shape.  These equality checks keep an
    unsigned, schema-shaped report from substituting another object, route,
    projection, or native result while retaining digest-shaped strings.
    Projected PASS rows carry a ``verifier-package-check-reference-1`` instead;
    their complete source check remains bound by ``full_check_digest`` and the
    existing projection commitment replay.
    """

    rows = report.get("obligation_instances")
    if not isinstance(rows, list):
        return
    package_graph = report.get("package_graph")
    for index, row in enumerate(rows):
        budget.consume()
        if not isinstance(row, dict):
            continue
        check = row.get("selected_package_check")
        path = f"/obligation_instances/{index}/selected_package_check"
        package_root_graph_pass = (
            row.get("status") == "PASS"
            and row.get("coordinate") == "GRAPH-3.1"
            and isinstance(package_graph, dict)
            and package_graph.get("root_kind") == "GRAPH"
            and package_graph.get("root_id") == row.get("object_id")
        )
        if package_root_graph_pass and not (
            isinstance(check, dict)
            and check.get("evidence_origin")
            == "PACKAGE_GRAPH_BOUND_FRESH_REPLAY"
        ):
            issues.add(
                path + "/evidence_origin",
                "packageGraphReplayExclusivity",
                "package-root GRAPH-3.1 PASS requires the fresh package GRAPH replay origin",
            )
            continue
        if not (
            isinstance(check, dict)
            and check.get("schema_version")
            == "verifier-package-graph-fresh-adapter-1"
            and check.get("evidence_origin")
            == "PACKAGE_GRAPH_BOUND_FRESH_REPLAY"
        ):
            continue
        result_body = {
            key: value for key, value in check.items() if key != "result_digest"
        }
        try:
            expected_result_digest = core_obligation_union.value_digest(result_body)
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            expected_result_digest = None
        if check.get("result_digest") != expected_result_digest:
            issues.add(
                path + "/result_digest",
                "packageGraphReplayCommitment",
                "digest does not seal the complete adapter result",
            )

        # A FAIL or UNKNOWN adapter result is an honest non-establishment
        # envelope: it has no selected projection or native PASS replay to
        # bind.  Its complete result remains self-committed above, while the
        # stronger route and package-root equalities below apply only when the
        # adapter claims PASS.
        if check.get("status") != "PASS":
            continue

        selection = check.get("selection")
        try:
            expected_selection_digest = core_obligation_union.value_digest(selection)
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            expected_selection_digest = None
        if check.get("selection_digest") != expected_selection_digest:
            issues.add(
                path + "/selection_digest",
                "packageGraphReplayCommitment",
                "digest does not seal the package GRAPH projection selection",
            )
        if not isinstance(selection, dict):
            continue

        if not (
            selection.get("original_object_digest") == row.get("object_digest")
            and selection.get("coordinate") == row.get("coordinate")
            and selection.get("proposition_digest")
            == row.get("proposition_digest")
        ):
            issues.add(
                path + "/selection",
                "packageGraphReplayBinding",
                "selection differs from the exact obligation-row object or route",
            )

        replay = check.get("replay")
        route_selection = (
            replay.get("selection") if isinstance(replay, dict) else None
        )
        native_result = (
            replay.get("native_result") if isinstance(replay, dict) else None
        )
        semantic_version = selection.get("semantic_version")
        if not (
            isinstance(replay, dict)
            and isinstance(route_selection, dict)
            and isinstance(native_result, dict)
            and replay.get("computational_status") == "PASS"
            and replay.get("replay_status") == "REPRODUCED"
            and native_result.get("status") == "PASS"
            and route_selection.get("semantic_version") == semantic_version
            and native_result.get("semantic_version") == semantic_version
            and route_selection.get("objective") == row.get("coordinate")
            and native_result.get("coordinate") == row.get("coordinate")
            and route_selection.get("represented_kind") == "GRAPH"
            and native_result.get("object_kind") == "GRAPH"
            and replay.get("certificate_sha256")
            == selection.get("certificate_digest")
            and replay.get("request_sha256") == selection.get("request_digest")
            and replay.get("policy_sha256") == selection.get("policy_digest")
        ):
            issues.add(
                path + "/replay",
                "packageGraphReplayBinding",
                "native GRAPH-3.1 PASS does not bind the selected route and artifacts",
            )

        if not (
            row.get("object_kind") == "GRAPH"
            and row.get("checker_status") == "PASS"
            and row.get("status") == "PASS"
            and row.get("package_graph_replay_is_instance_evidence") is True
            and isinstance(package_graph, dict)
            and package_graph.get("root_id") == row.get("object_id")
            and package_graph.get("root_kind") == "GRAPH"
            and package_graph.get("collection_digest")
            == selection.get("original_collection_digest")
        ):
            issues.add(
                path,
                "packageGraphReplayBinding",
                "fresh GRAPH replay is not bound exclusively to the package root",
            )

        if not (
            check.get("reason") == check.get("adaptation_reason")
            == selection.get("adaptation_reason")
            and check.get("claim_boundary") == selection.get("claim_boundary")
        ):
            issues.add(
                path,
                "packageGraphReplayBinding",
                "adapter reason or claim boundary differs from its selection",
            )


def _is_plain_integer(value: Any) -> bool:
    """Return whether a JSON value is an integer rather than a boolean."""

    return isinstance(value, int) and not isinstance(value, bool)


def _projection_catalog_is_unique(
    values: list[Any],
    *,
    path: str,
    issues: _Issues,
    budget: _WorkBudget,
) -> bool:
    """Reject duplicate table values using Verifier's canonical JSON identity."""

    retained: set[str] = set()
    valid = True
    for index, value in enumerate(values):
        budget.consume()
        try:
            digest = core_obligation_union.value_digest(value)
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            issues.add(
                f"{path}/{index}", "projectionCommitment",
                "table value is not canonically digestible",
            )
            valid = False
            continue
        if digest in retained:
            issues.add(
                f"{path}/{index}", "projectionCommitment",
                "table value duplicates an earlier canonical value",
            )
            valid = False
        retained.add(digest)
    return valid


def _reconstruct_pass_table_projection(
    report: dict[str, Any],
    definitions: list[Any],
    projection: dict[str, Any],
    expanded_rows: list[Any],
    issues: _Issues,
    budget: _WorkBudget,
) -> list[dict[str, Any]] | None:
    """Validate and expand the v3 PASS-only table transport.

    The producer evaluates complete package rows before transport projection.
    This independent reconstruction treats the tables only as a compact wire
    encoding: all indexes, table order, digest slots and row commitments must
    reproduce the same normalized rows consumed by the v2 commitment replay.
    It does not turn portable unsigned digests into source or signatory
    authority.
    """

    base_path = "/obligation_instance_projection"
    object_table = projection.get("object_table")
    route_table = projection.get("route_table")
    check_definitions = projection.get("check_definitions")
    pass_entries = projection.get("pass_entries")
    expanded_indexes = projection.get("expanded_nonpass_source_indexes")
    if not all(isinstance(value, list) for value in (
        object_table, route_table, check_definitions, pass_entries,
        expanded_indexes,
    )):
        return None

    if projection.get("object_field_order") != list(_PASS_TABLE_OBJECT_FIELDS):
        issues.add(
            base_path + "/object_field_order", "projectionCommitment",
            "field order differs from the normative object table order",
        )
    if projection.get("route_field_order") != list(_PASS_TABLE_ROUTE_FIELDS):
        issues.add(
            base_path + "/route_field_order", "projectionCommitment",
            "field order differs from the normative route table order",
        )
    if projection.get("pass_entry_field_order") != list(
        _PASS_TABLE_ENTRY_FIELDS
    ):
        issues.add(
            base_path + "/pass_entry_field_order", "projectionCommitment",
            "field order differs from the normative PASS-entry order",
        )

    digest_catalogs = (
        ("object_table", object_table, "object_table_digest"),
        ("route_table", route_table, "route_table_digest"),
        ("check_definitions", check_definitions, "check_definitions_digest"),
        ("pass_entries", pass_entries, "pass_entries_digest"),
    )
    for field, values, digest_field in digest_catalogs:
        try:
            expected = core_obligation_union.value_digest(values)
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            expected = None
        if projection.get(digest_field) != expected:
            issues.add(
                f"{base_path}/{digest_field}", "projectionCommitment",
                f"digest does not seal {field}",
            )

    if projection.get("check_definition_count") != len(check_definitions):
        issues.add(
            base_path + "/check_definition_count", "projectionCommitment",
            f"value must equal {len(check_definitions)}",
        )
    if projection.get("pass_reference_count") != len(pass_entries):
        issues.add(
            base_path + "/pass_reference_count", "projectionCommitment",
            f"value must equal {len(pass_entries)}",
        )
    if projection.get("expanded_nonpass_count") != len(expanded_rows):
        issues.add(
            base_path + "/expanded_nonpass_count", "projectionCommitment",
            f"value must equal {len(expanded_rows)}",
        )
    if len(expanded_indexes) != len(expanded_rows):
        issues.add(
            base_path + "/expanded_nonpass_source_indexes",
            "projectionCommitment",
            "source-index count must equal the expanded non-PASS row count",
        )

    _projection_catalog_is_unique(
        object_table, path=base_path + "/object_table",
        issues=issues, budget=budget,
    )
    _projection_catalog_is_unique(
        route_table, path=base_path + "/route_table",
        issues=issues, budget=budget,
    )

    definition_digests = [
        definition.get("definition_digest")
        if isinstance(definition, dict) else None
        for definition in definitions
    ]
    if definition_digests != sorted(
        value for value in definition_digests if isinstance(value, str)
    ):
        issues.add(
            "/pass_instance_definitions", "projectionCommitment",
            "v3 definition catalog must be sorted by definition digest",
        )

    retained_check_digests: list[Any] = []
    for index, definition in enumerate(check_definitions):
        budget.consume()
        if not isinstance(definition, dict):
            continue
        retained = definition.get("definition_digest")
        retained_check_digests.append(retained)
        body = {
            "checker_status": definition.get("checker_status"),
            "template": definition.get("template"),
        }
        try:
            expected = core_obligation_union.value_digest(body)
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            expected = None
        if retained != expected:
            issues.add(
                f"{base_path}/check_definitions/{index}/definition_digest",
                "projectionCommitment",
                "digest does not seal checker status and template",
            )
        template = definition.get("template")
        if isinstance(template, dict) and any(
            field in template for field in (
                "full_check_digest", "adaptation_result_digest", "result_digest",
            )
        ):
            issues.add(
                f"{base_path}/check_definitions/{index}/template",
                "projectionCommitment",
                "per-entry digest slots may not be retained in a shared template",
            )
        if isinstance(template, dict):
            identity_fields = template.get(_PASS_CHECK_IDENTITY_MARKER)
            recompute_result = template.get(_PASS_CHECK_RESULT_MARKER)
            canonical_identity_fields = (
                [
                    field for field in _PASS_CHECK_IDENTITY_FIELDS
                    if isinstance(identity_fields, list)
                    and field in identity_fields
                ]
            )
            if not (
                isinstance(identity_fields, list)
                and identity_fields == canonical_identity_fields
                and len(identity_fields) == len(set(identity_fields))
                and not any(field in template for field in identity_fields)
            ):
                issues.add(
                    f"{base_path}/check_definitions/{index}/template/"
                    + _PASS_CHECK_IDENTITY_MARKER,
                    "projectionCommitment",
                    "projected identity fields must be a unique canonical subset and absent from the shared template",
                )
            if not isinstance(recompute_result, bool):
                issues.add(
                    f"{base_path}/check_definitions/{index}/template/"
                    + _PASS_CHECK_RESULT_MARKER,
                    "projectionCommitment",
                    "result-digest recomputation marker must be boolean",
                )
    if retained_check_digests != sorted(
        value for value in retained_check_digests if isinstance(value, str)
    ):
        issues.add(
            base_path + "/check_definitions", "projectionCommitment",
            "check definitions must be sorted by definition digest",
        )
    _projection_catalog_is_unique(
        check_definitions, path=base_path + "/check_definitions",
        issues=issues, budget=budget,
    )

    source_count = projection.get("source_instance_count")
    verifier_id = projection.get("verifier_id")
    if not _is_plain_integer(source_count) or source_count < 1:
        return None
    source_rows: list[dict[str, Any] | None] = [None] * source_count
    source_indexes: set[int] = set()
    previous_expanded_index = -1
    for row_offset, (source_index, row) in enumerate(
        zip(expanded_indexes, expanded_rows)
    ):
        budget.consume()
        path = f"{base_path}/expanded_nonpass_source_indexes/{row_offset}"
        if not _is_plain_integer(source_index) or not 0 <= source_index < source_count:
            issues.add(
                path, "projectionCommitment",
                "expanded source index is outside the source denominator",
            )
            continue
        if source_index <= previous_expanded_index:
            issues.add(
                path, "projectionCommitment",
                "expanded source indexes must preserve original relative order",
            )
        previous_expanded_index = source_index
        if source_index in source_indexes:
            issues.add(path, "projectionCommitment", "source index is duplicated")
            continue
        source_indexes.add(source_index)
        if isinstance(row, dict):
            if row.get("status") == "PASS" and row.get("blockers") == []:
                issues.add(
                    f"/obligation_instances/{row_offset}",
                    "projectionCommitment",
                    "v3 obligation_instances may contain only expanded non-PASS rows",
                )
            realization = row.get("repository_realization")
            if (
                isinstance(realization, dict)
                and realization.get("schema_version")
                == "verifier-pass-instance-definition-reference-2"
            ):
                issues.add(
                    f"/obligation_instances/{row_offset}/repository_realization",
                    "projectionCommitment",
                    "an expanded non-PASS row may not use a PASS projection reference",
                )
            source_rows[source_index] = row

    used_object_indexes: set[int] = set()
    used_route_indexes: set[int] = set()
    used_check_indexes: set[int] = set()
    first_object_indexes: list[int] = []
    first_route_indexes: list[int] = []
    previous_pass_source_index = -1
    for entry_offset, entry in enumerate(pass_entries):
        budget.consume()
        entry_path = f"{base_path}/pass_entries/{entry_offset}"
        if not isinstance(entry, list) or len(entry) != len(_PASS_TABLE_ENTRY_FIELDS):
            continue
        values = dict(zip(_PASS_TABLE_ENTRY_FIELDS, entry))
        source_index = values["source_index"]
        object_index = values["object_index"]
        route_index = values["route_index"]
        semantic_index = values["semantic_definition_index"]
        kind_index = values["kind_requirement_definition_index"]
        check_index = values["check_definition_index"]
        indexed_values = (
            ("source_index", source_index, source_count),
            ("object_index", object_index, len(object_table)),
            ("route_index", route_index, len(route_table)),
            ("semantic_definition_index", semantic_index, len(definitions)),
            ("check_definition_index", check_index, len(check_definitions)),
        )
        indexes_valid = True
        for field, value, upper_bound in indexed_values:
            if not _is_plain_integer(value) or not 0 <= value < upper_bound:
                issues.add(
                    entry_path + "/" + str(_PASS_TABLE_ENTRY_FIELDS.index(field)),
                    "projectionCommitment",
                    f"{field} is outside its retained table",
                )
                indexes_valid = False
        if kind_index is not None and (
            not _is_plain_integer(kind_index)
            or not 0 <= kind_index < len(definitions)
        ):
            issues.add(
                entry_path + "/5", "projectionCommitment",
                "kind_requirement_definition_index is neither null nor a retained index",
            )
            indexes_valid = False
        if not indexes_valid:
            continue
        if source_index <= previous_pass_source_index:
            issues.add(
                entry_path + "/0", "projectionCommitment",
                "PASS entries must preserve original source order",
            )
        previous_pass_source_index = source_index
        if source_index in source_indexes:
            issues.add(
                entry_path + "/0", "projectionCommitment",
                "source index duplicates an expanded or projected row",
            )
            continue
        source_indexes.add(source_index)

        if object_index not in used_object_indexes:
            first_object_indexes.append(object_index)
        if route_index not in used_route_indexes:
            first_route_indexes.append(route_index)
        used_object_indexes.add(object_index)
        used_route_indexes.add(route_index)
        used_check_indexes.add(check_index)

        object_values = object_table[object_index]
        route_values = route_table[route_index]
        semantic_definition = definitions[semantic_index]
        kind_definition = definitions[kind_index] if kind_index is not None else None
        check_definition = check_definitions[check_index]
        if not (
            isinstance(object_values, list)
            and len(object_values) == len(_PASS_TABLE_OBJECT_FIELDS)
            and isinstance(route_values, list)
            and len(route_values) == len(_PASS_TABLE_ROUTE_FIELDS)
            and isinstance(semantic_definition, dict)
            and semantic_definition.get("definition_kind") == "SEMANTIC"
            and (
                kind_definition is None
                or isinstance(kind_definition, dict)
                and kind_definition.get("definition_kind") == "KIND_REQUIREMENT"
            )
            and isinstance(check_definition, dict)
            and isinstance(check_definition.get("template"), dict)
        ):
            issues.add(
                entry_path, "projectionCommitment",
                "entry does not reference the required object, route, semantic, kind and check table shapes",
            )
            continue

        checker_status = check_definition.get("checker_status")
        full_check_digest = values["full_check_digest"]
        adaptation_result_digest = values["adaptation_result_digest"]
        result_digest = values["result_digest"]
        selected_check = dict(check_definition["template"])
        identity_fields = selected_check.pop(
            _PASS_CHECK_IDENTITY_MARKER, None
        )
        recompute_result = selected_check.pop(
            _PASS_CHECK_RESULT_MARKER, None
        )
        if not (
            isinstance(identity_fields, list)
            and identity_fields == [
                field for field in _PASS_CHECK_IDENTITY_FIELDS
                if field in identity_fields
            ]
            and len(identity_fields) == len(set(identity_fields))
            and isinstance(recompute_result, bool)
            and not any(field in selected_check for field in identity_fields)
        ):
            issues.add(
                entry_path, "projectionCommitment",
                "entry references an invalid projected check identity template",
            )
            continue
        object_binding = dict(zip(_PASS_TABLE_OBJECT_FIELDS, object_values))
        route_binding = dict(zip(_PASS_TABLE_ROUTE_FIELDS, route_values))
        identity_values = {
            "object_id": object_binding["object_id"],
            "object_digest": object_binding["object_digest"],
            "coordinate": route_binding["coordinate"],
            "proposition_digest": route_binding["proposition_digest"],
            "checking_mechanism": route_binding["checking_mechanism"],
            "native_coordinate": route_binding["coordinate"],
            "conditional_coordinate": route_binding["coordinate"],
        }
        for field in identity_fields:
            selected_check[field] = identity_values[field]
        if checker_status == "PASS":
            if not (
                _is_digest(full_check_digest)
                and adaptation_result_digest is None
                and result_digest is None
            ):
                issues.add(
                    entry_path, "projectionCommitment",
                    "PASS checker entry requires only full_check_digest",
                )
                continue
            selected_check["full_check_digest"] = full_check_digest
            if recompute_result:
                selected_check["result_digest"] = (
                    core_obligation_union.value_digest(selected_check)
                )
        elif checker_status == "NOT_REQUIRED":
            if not (
                full_check_digest is None
                and _is_digest(adaptation_result_digest)
                and _is_digest(result_digest)
                and recompute_result is False
            ):
                issues.add(
                    entry_path, "projectionCommitment",
                    "NOT_REQUIRED checker entry requires adaptation and result digests only",
                )
                continue
            selected_check["adaptation_result_digest"] = adaptation_result_digest
            selected_check["result_digest"] = result_digest
        else:
            issues.add(
                entry_path, "projectionCommitment",
                "projected PASS entry checker status must be PASS or NOT_REQUIRED",
            )
            continue

        semantic_digest = semantic_definition.get("definition_digest")
        complete_instance_digest = values["complete_instance_digest"]
        realization = {
            "schema_version": "verifier-pass-instance-definition-reference-2",
            "semantic_definition_digest": semantic_digest,
            "complete_instance_digest": complete_instance_digest,
            "transport": "REPORT_PASS_INSTANCE_FACTORED_DEFINITIONS",
        }
        if kind_definition is not None:
            realization["kind_requirement_definition_digest"] = (
                kind_definition.get("definition_digest")
            )
        reference_reason = (
            "See pass_instance_definitions semantic definition "
            + str(semantic_digest) + "."
        )
        source_applicability = semantic_definition.get("applicability")
        applicability = {
            "status": (
                source_applicability.get("status")
                if isinstance(source_applicability, dict) else None
            ),
            "classification": (
                source_applicability.get("classification")
                if isinstance(source_applicability, dict) else None
            ),
            "assessment_required": True,
            "reason": reference_reason,
        }
        row = {
            **dict(zip(_PASS_TABLE_OBJECT_FIELDS, object_values)),
            **dict(zip(_PASS_TABLE_ROUTE_FIELDS, route_values)),
            "instance_digest": values["instance_digest"],
            "verifier_id": verifier_id,
            "reason": reference_reason,
            "repository_realization": realization,
            "applicability": applicability,
            "selected_package_check": selected_check,
            "checker_status": checker_status,
            "status": "PASS",
            "blockers": [],
            "native_specimen_is_instance_evidence": values[
                "native_specimen_is_instance_evidence"
            ],
            "package_graph_replay_is_instance_evidence": values[
                "package_graph_replay_is_instance_evidence"
            ],
        }
        source_rows[source_index] = row

    if first_object_indexes != list(range(len(object_table))):
        issues.add(
            base_path + "/object_table", "projectionCommitment",
            "object table must contain exactly the unique values in first-use order",
        )
    if first_route_indexes != list(range(len(route_table))):
        issues.add(
            base_path + "/route_table", "projectionCommitment",
            "route table must contain exactly the unique values in first-use order",
        )
    if used_check_indexes != set(range(len(check_definitions))):
        issues.add(
            base_path + "/check_definitions", "projectionCommitment",
            "every retained check definition must be used by a PASS entry",
        )
    if source_indexes != set(range(source_count)) or any(
        row is None for row in source_rows
    ):
        issues.add(
            base_path, "projectionCommitment",
            "expanded and projected rows must cover the exact source denominator once",
        )
        return None
    return [row for row in source_rows if row is not None]


def _validate_pass_coordinate_commitments(
    report: dict[str, Any],
    issues: _Issues,
    budget: _WorkBudget,
) -> None:
    """Replay cross-record coordinates only when the report claims PASS.

    The schema establishes each field's shape, while these comparisons establish
    that the fields describe one assessment snapshot.  A FAIL or UNKNOWN report
    is an honest non-establishment envelope and need not carry mutually passing
    coordinates, so this stronger closure rule must not reinterpret it.
    """

    budget.consume()
    if report.get("status") != "PASS":
        return

    source_coordinate = report.get("source_coordinate")
    try:
        expected_source_digest = core_obligation_union.value_digest(
            source_coordinate
        )
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        expected_source_digest = None
    if report.get("source_coordinate_digest") != expected_source_digest:
        issues.add(
            "/source_coordinate_digest",
            "passCoordinateCommitment",
            "PACKAGE_PASS_SOURCE_COORDINATE_DIGEST_DIFFERS: digest does not "
            "seal the selected source coordinate",
        )

    manifest = report.get("manifest")
    package_graph = report.get("package_graph")
    verifier_execution = report.get("verifier_execution")
    native = report.get("native_diagnostics")
    if not all(
        isinstance(value, dict)
        for value in (manifest, package_graph, verifier_execution, native)
    ):
        # The schema reports missing PASS structures. Avoid inventing equality
        # errors for fields which are not present to compare.
        return

    manifest_digest = manifest.get("digest")
    manifest_coordinates = (
        ("/package_graph/manifest_digest", package_graph.get("manifest_digest")),
        (
            "/verifier_execution/manifest_digest",
            verifier_execution.get("manifest_digest"),
        ),
    )
    prerequisites = native.get("prerequisites")
    if isinstance(prerequisites, dict):
        tier_zero = prerequisites.get("0")
        if isinstance(tier_zero, dict):
            manifest_coordinates += ((
                "/native_diagnostics/prerequisites/0/manifest_digest",
                tier_zero.get("manifest_digest"),
            ),)
    for path, retained in manifest_coordinates:
        budget.consume()
        if retained != manifest_digest:
            issues.add(
                path,
                "passCoordinateCommitment",
                "PACKAGE_PASS_MANIFEST_COORDINATE_DIFFERS: manifest coordinate "
                "does not equal the selected manifest digest",
            )

    if (
        package_graph.get("collection_digest")
        != verifier_execution.get("subject_collection_digest")
    ):
        issues.add(
            "/verifier_execution/subject_collection_digest",
            "passCoordinateCommitment",
            "PACKAGE_PASS_COLLECTION_COORDINATE_DIFFERS: verifier subject "
            "collection does not equal the package GRAPH collection",
        )

    if (
        verifier_execution.get("native_diagnostic_report_digest")
        != native.get("report_digest")
    ):
        issues.add(
            "/verifier_execution/native_diagnostic_report_digest",
            "passCoordinateCommitment",
            "PACKAGE_PASS_NATIVE_DIAGNOSTIC_DIGEST_DIFFERS: verifier execution "
            "does not bind the retained native diagnostic report",
        )

    if isinstance(prerequisites, dict):
        for depth in ("1", "2"):
            budget.consume()
            prerequisite = prerequisites.get(depth)
            if not isinstance(prerequisite, dict):
                continue
            if (
                prerequisite.get("source_coordinate_digest")
                != report.get("source_coordinate_digest")
            ):
                issues.add(
                    "/native_diagnostics/prerequisites/"
                    + depth
                    + "/source_coordinate_digest",
                    "passCoordinateCommitment",
                    "PACKAGE_PASS_NATIVE_SOURCE_COORDINATE_DIFFERS: native Tier "
                    + depth
                    + " does not bind the selected source coordinate",
                )


def _validate_manifest_refresh_binding(
    report: dict[str, Any],
    issues: _Issues,
    budget: _WorkBudget,
) -> None:
    """Replay the digest and cross-coordinate refresh commitments.

    JSON Schema constrains the reference shape but cannot recompute its digest
    or express equality with the separately retained package coordinates. A
    failed binding is an honest negative report, so only its reference digest
    is replayed; a claimed PASS must close every equality below.
    """

    budget.consume()
    selected = report.get("manifest_refresh")
    if not isinstance(selected, dict):
        issues.add(
            "/manifest_refresh",
            "refreshBindingCommitment",
            "PACKAGE_REFRESH_BINDING_MISSING: schema-v2 report does not retain "
            "an explicit refresh disposition",
        )
        return
    reference = selected.get("receipt_reference")
    if isinstance(reference, dict):
        retained_digest = reference.get("reference_digest")
        body = dict(reference)
        body.pop("reference_digest", None)
        try:
            expected_digest = core_obligation_union.value_digest(body)
        except (
            TypeError,
            ValueError,
            UnicodeError,
            RecursionError,
            OverflowError,
        ):
            expected_digest = None
        if retained_digest != expected_digest:
            issues.add(
                "/manifest_refresh/receipt_reference/reference_digest",
                "refreshBindingCommitment",
                "PACKAGE_REFRESH_REFERENCE_DIGEST_DIFFERS: digest does not "
                "seal the retained path-free refresh reference",
            )
            return
    if selected.get("status") != "PASS":
        return

    manifest = report.get("manifest")
    manifest_digest = manifest.get("digest") if isinstance(manifest, dict) else None
    if selected.get("assessed_manifest_digest") != manifest_digest:
        issues.add(
            "/manifest_refresh/assessed_manifest_digest",
            "refreshBindingCommitment",
            "PACKAGE_REFRESH_MANIFEST_DIGEST_DIFFERS: refresh binding does not "
            "name the selected objects.vstd digest",
        )
        return
    if (
        selected.get("assessed_source_coordinate_digest")
        != report.get("source_coordinate_digest")
    ):
        issues.add(
            "/manifest_refresh/assessed_source_coordinate_digest",
            "refreshBindingCommitment",
            "PACKAGE_REFRESH_SOURCE_COORDINATE_DIFFERS: refresh binding does "
            "not name the assessed source coordinate",
        )
        return

    disposition = selected.get("disposition")
    if disposition == "NOT_REQUESTED":
        return
    if not isinstance(reference, dict) or reference.get("status") != disposition:
        issues.add(
            "/manifest_refresh/receipt_reference/status",
            "refreshBindingCommitment",
            "PACKAGE_REFRESH_DISPOSITION_DIFFERS: retained receipt status does "
            "not equal the declared refresh disposition",
        )
        return
    if reference.get("after_digest") != selected.get(
        "assessed_manifest_digest"
    ):
        issues.add(
            "/manifest_refresh/receipt_reference/after_digest",
            "refreshBindingCommitment",
            "PACKAGE_REFRESH_AFTER_DIGEST_DIFFERS: accepted receipt does not "
            "name the assessed objects.vstd bytes",
        )
        return
    if reference.get("source_census_digest") != selected.get(
        "assessed_source_census_digest"
    ):
        issues.add(
            "/manifest_refresh/receipt_reference/source_census_digest",
            "refreshBindingCommitment",
            "PACKAGE_REFRESH_SOURCE_CENSUS_DIFFERS: accepted receipt does not "
            "name the assessed source-refresh census",
        )


def _validate_report_commitments(
    report: dict[str, Any],
    issues: _Issues,
    budget: _WorkBudget,
) -> None:
    """Replay digest and projection commitments omitted by JSON Schema.

    Draft 2020-12 validates shapes but cannot express equality between counts,
    digests, definition references and projected rows.  Those relationships are
    part of the publication contract: a malformed producer must not publish a
    schema-shaped PASS report with weakened evidence.
    """

    budget.consume()
    retained_report_digest = report.get("report_digest")
    report_body = dict(report)
    report_body.pop("report_digest", None)
    try:
        expected_report_digest = core_obligation_union.value_digest(report_body)
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        issues.add(
            "/report_digest", "commitment",
            "report body cannot be encoded by the canonical digest mechanism",
        )
        return
    if retained_report_digest != expected_report_digest:
        issues.add(
            "/report_digest", "commitment",
            "digest does not seal the published report body",
        )

    execution = report.get("verifier_execution")
    package_graph = report.get("package_graph")
    self_polish = (
        execution.get("self_polish") if isinstance(execution, dict) else None
    )
    if self_polish is not None:
        if not isinstance(package_graph, dict):
            issues.add(
                "/verifier_execution/self_polish", "selfPolishGraph",
                "PACKAGE_SELF_POLISH_GRAPH_SUBJECT_MISSING: retained recursive "
                "graph has no selected package GRAPH",
            )
        else:
            try:
                package_verifier_graph.validate_self_polish_graph(
                    self_polish,
                    aggregate_verifier_id=execution.get("object_id"),
                    aggregate_verifier_digest=execution.get("object_digest"),
                    package_graph_id=package_graph.get("root_id"),
                    package_graph_digest=package_graph.get("collection_digest"),
                    requested_tier=report.get("requested_tier"),
                    obligation_rows=(
                        report.get("obligation_instances")
                        if "obligation_instance_projection" not in report
                        else None
                    ),
                )
            except package_verifier_graph.VerifierGraphError as exc:
                issues.add(
                    "/verifier_execution/self_polish", "selfPolishGraph",
                    str(exc),
                )
            if (
                execution.get("subject_id") != execution.get("object_id")
                or execution.get("subject_kind") != "VERIFIER"
                or execution.get("verified_graph_id")
                != package_graph.get("root_id")
                or execution.get("verified_graph_kind") != "GRAPH"
            ):
                issues.add(
                    "/verifier_execution/subject_id", "selfPolishGraph",
                    "PACKAGE_SELF_POLISH_SUBJECT_DIFFERS: polish must assess the "
                    "aggregate VERIFIER while binding its represented GRAPH",
                )

    if report.get("schema_version") != "verifier-manifest-package-polish-2":
        return
    _validate_manifest_refresh_binding(report, issues, budget)
    _validate_pass_coordinate_commitments(report, issues, budget)
    _validate_package_graph_fresh_replays(report, issues, budget)
    definitions_present = "pass_instance_definitions" in report
    projection_present = "obligation_instance_projection" in report
    if definitions_present != projection_present:
        issues.add(
            "/", "projectionCommitment",
            "pass definitions and projection profile must occur together",
        )
        return
    if not definitions_present:
        execution = report.get("verifier_execution")
        commitment = (
            execution.get("obligation_denominator_commitment")
            if isinstance(execution, dict) else None
        )
        if (
            isinstance(commitment, dict)
            and commitment.get("schema_version")
            == "verifier-package-obligation-denominator-commitment-2"
        ):
            issues.add(
                "/verifier_execution/obligation_denominator_commitment",
                "projectionCommitment",
                "row-reconstructed denominator transport requires a projection",
            )
        return

    definitions = report.get("pass_instance_definitions")
    projection = report.get("obligation_instance_projection")
    rows = report.get("obligation_instances")
    if not (
        isinstance(definitions, list)
        and isinstance(projection, dict)
        and isinstance(rows, list)
    ):
        return

    definition_by_digest: dict[str, dict[str, Any]] = {}
    for index, definition in enumerate(definitions):
        budget.consume()
        if not isinstance(definition, dict):
            continue
        retained = definition.get("definition_digest")
        body = {
            key: value for key, value in definition.items()
            if key != "definition_digest"
        }
        try:
            expected = core_obligation_union.value_digest(body)
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            issues.add(
                f"/pass_instance_definitions/{index}/definition_digest",
                "projectionCommitment",
                "definition body is not canonically digestible",
            )
            continue
        if retained != expected:
            issues.add(
                f"/pass_instance_definitions/{index}/definition_digest",
                "projectionCommitment",
                "digest does not seal the definition body",
            )
        if isinstance(retained, str):
            if retained in definition_by_digest:
                issues.add(
                    f"/pass_instance_definitions/{index}/definition_digest",
                    "projectionCommitment", "definition digest is duplicated",
                )
            definition_by_digest[retained] = definition

    if projection.get("schema_version") == "verifier-pass-instance-projection-3":
        reconstructed_rows = _reconstruct_pass_table_projection(
            report, definitions, projection, rows, issues, budget
        )
        if reconstructed_rows is None:
            return
        rows = reconstructed_rows

    pass_rows = [
        row for row in rows
        if isinstance(row, dict)
        and row.get("status") == "PASS"
        and row.get("blockers") == []
    ]
    expected_profile_values = {
        "source_instance_count": len(rows),
        "pass_reference_count": len(pass_rows),
        "expanded_nonpass_count": len(rows) - len(pass_rows),
        "definition_count": len(definitions),
    }
    for field, expected in expected_profile_values.items():
        if projection.get(field) != expected:
            issues.add(
                f"/obligation_instance_projection/{field}",
                "projectionCommitment", f"value must equal {expected}",
            )
    try:
        definitions_digest = core_obligation_union.value_digest(definitions)
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        definitions_digest = None
    if projection.get("definitions_digest") != definitions_digest:
        issues.add(
            "/obligation_instance_projection/definitions_digest",
            "projectionCommitment",
            "digest does not seal the retained definition array",
        )

    used_definition_digests: set[str] = set()
    selected_keys: set[tuple[Any, Any]] = set()
    committed_rows: list[dict[str, Any]] = []
    rows_by_key: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
    for candidate in rows:
        if isinstance(candidate, dict):
            rows_by_key.setdefault(
                (candidate.get("object_id"), candidate.get("coordinate")), []
            ).append(candidate)
    for index, row in enumerate(rows):
        budget.consume()
        if not isinstance(row, dict):
            continue
        selected_key = (row.get("object_id"), row.get("coordinate"))
        if selected_key in selected_keys:
            issues.add(
                f"/obligation_instances/{index}",
                "projectionCommitment",
                "object and obligation coordinate duplicates an earlier row",
            )
        selected_keys.add(selected_key)
        identity = {
            key: row.get(key) for key in (
                "object_id", "object_digest", "coordinate", "tier",
                "proposition_digest",
            )
        }
        try:
            expected_instance_digest = core_obligation_union.value_digest(identity)
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            expected_instance_digest = None
        if row.get("instance_digest") != expected_instance_digest:
            issues.add(
                f"/obligation_instances/{index}/instance_digest",
                "projectionCommitment",
                "digest does not seal the instance identity",
            )
        projected_pass = (
            row.get("status") == "PASS" and row.get("blockers") == []
        )
        realization = row.get("repository_realization")
        if not projected_pass:
            committed_rows.append(row)
            if (
                isinstance(realization, dict)
                and realization.get("schema_version")
                == "verifier-pass-instance-definition-reference-2"
            ):
                issues.add(
                    f"/obligation_instances/{index}/repository_realization",
                    "projectionCommitment",
                    "a non-PASS row may not use the PASS projection transport",
                )
            continue
        if not (
            isinstance(realization, dict)
            and realization.get("schema_version")
            == "verifier-pass-instance-definition-reference-2"
            and realization.get("transport")
            == "REPORT_PASS_INSTANCE_FACTORED_DEFINITIONS"
            and _is_digest(realization.get("semantic_definition_digest"))
            and _is_digest(realization.get("complete_instance_digest"))
        ):
            issues.add(
                f"/obligation_instances/{index}/repository_realization",
                "projectionCommitment",
                "projected PASS row lacks its exact definition reference",
            )
            continue
        semantic_definition_digest = realization.get(
            "semantic_definition_digest"
        )
        semantic_definition = definition_by_digest.get(
            semantic_definition_digest
        )
        if (
            semantic_definition is None
            or semantic_definition.get("definition_kind") != "SEMANTIC"
        ):
            issues.add(
                f"/obligation_instances/{index}/repository_realization/semantic_definition_digest",
                "projectionCommitment",
                "semantic definition reference is not retained by this report",
            )
            continue
        used_definition_digests.add(str(semantic_definition_digest))
        kind_definition_digest = realization.get(
            "kind_requirement_definition_digest"
        )
        kind_definition = None
        if kind_definition_digest is not None:
            kind_definition = definition_by_digest.get(kind_definition_digest)
            if (
                kind_definition is None
                or kind_definition.get("definition_kind")
                != "KIND_REQUIREMENT"
            ):
                issues.add(
                    f"/obligation_instances/{index}/repository_realization/kind_requirement_definition_digest",
                    "projectionCommitment",
                    "kind-requirement definition is not retained by this report",
                )
                continue
            used_definition_digests.add(str(kind_definition_digest))
        reference_reason = (
            "See pass_instance_definitions semantic definition "
            + str(semantic_definition_digest) + "."
        )
        if row.get("reason") != reference_reason:
            issues.add(
                f"/obligation_instances/{index}/reason",
                "projectionCommitment",
                "projected reason does not name its retained definition",
            )
        applicability = row.get("applicability")
        source_applicability = semantic_definition.get("applicability")
        if not (
            isinstance(applicability, dict)
            and isinstance(source_applicability, dict)
            and applicability.get("status") == source_applicability.get("status")
            and applicability.get("classification")
            == source_applicability.get("classification")
            and applicability.get("assessment_required") is True
            and applicability.get("reason") == reference_reason
        ):
            issues.add(
                f"/obligation_instances/{index}/applicability",
                "projectionCommitment",
                "projected applicability differs from its retained definition",
            )
        if "kind_requirement" in row:
            issues.add(
                f"/obligation_instances/{index}/kind_requirement",
                "projectionCommitment",
                "projected row must retain kind requirements in its definition",
            )
        check = row.get("selected_package_check")
        if row.get("checker_status") == "NOT_REQUIRED":
            if not (
                isinstance(check, dict)
                and check.get("schema_version")
                != "verifier-package-check-reference-1"
                and check.get("status") == "PASS"
                and check.get("evidence_origin")
                == "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW"
                and check.get("applicability_established") is True
                and check.get("applicability_classification")
                == "CONDITION_NOT_MET"
                and check.get("fulfillment_required") is False
                and check.get("native_coordinate") == row.get("coordinate")
                and check.get("conditional_coordinate") == row.get("coordinate")
                and isinstance(check.get("adaptation_obligation_id"), str)
                and bool(check["adaptation_obligation_id"].strip())
                and _is_digest(check.get("adaptation_result_digest"))
                and isinstance(check.get("condition"), str)
                and bool(check["condition"].strip())
                and check.get("condition_status") == "NOT_TRIGGERED"
                and isinstance(check.get("reason"), str)
                and bool(check["reason"].strip())
                and _is_digest(check.get("result_digest"))
                and check["result_digest"] == core_obligation_union.value_digest({
                    key: value for key, value in check.items()
                    if key != "result_digest"
                })
            ):
                issues.add(
                    f"/obligation_instances/{index}/selected_package_check",
                    "projectionCommitment",
                    "projected conditional check is not a complete self-bound non-trigger",
                )
            elif not _conditional_source_binding_matches(
                report, row, check, semantic_definition, rows_by_key
            ):
                issues.add(
                    f"/obligation_instances/{index}/selected_package_check",
                    "projectionCommitment",
                    "projected conditional source binding differs from its "
                    "same-object companion row",
                )
        elif not (
            isinstance(check, dict)
            and check.get("schema_version")
            == "verifier-package-check-reference-1"
            and check.get("status") == "PASS"
            and check.get("transport") == "DIGEST_BOUND_REFERENCE"
            and _is_digest(check.get("full_check_digest"))
            and isinstance(check.get("full_check_bytes"), int)
            and not isinstance(check.get("full_check_bytes"), bool)
            and check["full_check_bytes"] > 0
        ):
            issues.add(
                f"/obligation_instances/{index}/selected_package_check",
                "projectionCommitment",
                "projected PASS check lacks its original digest binding",
            )
        committed_row = dict(row)
        committed_row["reason"] = semantic_definition.get("reason")
        committed_row["repository_realization"] = semantic_definition.get(
            "repository_realization"
        )
        committed_row["applicability"] = semantic_definition.get(
            "applicability"
        )
        if kind_definition is not None:
            committed_row["kind_requirement"] = kind_definition[
                "kind_requirement"
            ]
        else:
            committed_row.pop("kind_requirement", None)
        committed_rows.append(committed_row)
        try:
            expected_complete_instance_digest = (
                core_obligation_union.value_digest(committed_row)
            )
        except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
            expected_complete_instance_digest = None
        if realization.get(
            "complete_instance_digest"
        ) != expected_complete_instance_digest:
            issues.add(
                f"/obligation_instances/{index}/repository_realization/complete_instance_digest",
                "projectionCommitment",
                "digest does not seal the reconstructable normalized source row",
            )

    if used_definition_digests != set(definition_by_digest):
        issues.add(
            "/pass_instance_definitions",
            "projectionCommitment",
            "definitions must be used by at least one projected PASS row",
        )
    try:
        source_instances_digest = core_obligation_union.value_digest(
            committed_rows
        )
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        source_instances_digest = None
    if projection.get("source_instances_digest") != source_instances_digest:
        issues.add(
            "/obligation_instance_projection/source_instances_digest",
            "projectionCommitment",
            "digest does not seal the reconstructable normalized source rows",
        )

    execution = report.get("verifier_execution")
    commitment = (
        execution.get("obligation_denominator_commitment")
        if isinstance(execution, dict) else None
    )
    if not isinstance(commitment, dict):
        issues.add(
            "/verifier_execution/obligation_denominator_commitment",
            "projectionCommitment",
            "projected report requires its committed denominator",
        )
        return
    expected_commitment_fields = {
        "schema_version", "status", "selected_instance_count",
        "selected_instance_index_digest", "conditional_refutation_count",
        "conditional_refutations_digest", "conditional_refutations_transport",
        "claim_boundary", "commitment_digest",
    }
    if commitment.get("schema_version") != (
        "verifier-package-obligation-denominator-commitment-2"
    ):
        issues.add(
            "/verifier_execution/obligation_denominator_commitment/schema_version",
            "projectionCommitment",
            "projected report requires the row-reconstructed denominator schema",
        )
    if commitment.get("conditional_refutations_transport") != (
        "RECONSTRUCT_FROM_PROJECTED_ROWS"
    ):
        issues.add(
            "/verifier_execution/obligation_denominator_commitment/conditional_refutations_transport",
            "projectionCommitment",
            "projected conditional ledger must be reconstructed from projected rows",
        )
    if set(commitment) != expected_commitment_fields:
        issues.add(
            "/verifier_execution/obligation_denominator_commitment",
            "projectionCommitment",
            "projected denominator must contain only its reconstructable commitment",
        )
    selected_index = [
        {
            "object_id": row.get("object_id"),
            "object_kind": row.get("object_kind"),
            "coordinate": row.get("coordinate"),
            "tier": row.get("tier"),
            "instance_digest": row.get("instance_digest"),
        }
        for row in rows if isinstance(row, dict)
    ]
    selected_index.sort(key=lambda item: (
        item["tier"] if isinstance(item["tier"], int) else -1,
        item["object_id"] or "", item["coordinate"] or "",
        item["object_kind"] or "", item["instance_digest"] or "",
    ))
    if commitment.get("selected_instance_count") != len(selected_index):
        issues.add(
            "/verifier_execution/obligation_denominator_commitment/selected_instance_count",
            "projectionCommitment",
            "count does not equal the projected package denominator",
        )
    if commitment.get(
        "selected_instance_index_digest"
    ) != core_obligation_union.value_digest(selected_index):
        issues.add(
            "/verifier_execution/obligation_denominator_commitment/selected_instance_index_digest",
            "projectionCommitment",
            "digest does not seal the projected package denominator",
        )
    conditional_refutations = []
    for row in rows:
        if not isinstance(row, dict) or row.get("checker_status") != "NOT_REQUIRED":
            continue
        check = row.get("selected_package_check")
        if not isinstance(check, dict):
            continue
        if "result_digest" in check:
            evidence_digest = core_obligation_union.value_digest(check)
        else:
            evidence_digest = check.get("full_check_digest")
        conditional_refutations.append({
            "object_id": row.get("object_id"),
            "object_kind": row.get("object_kind"),
            "coordinate": row.get("coordinate"),
            "tier": row.get("tier"),
            "instance_digest": row.get("instance_digest"),
            "status": row.get("status"),
            "checker_status": row.get("checker_status"),
            "reason": check.get("reason"),
            "evidence_digest": evidence_digest,
        })
    conditional_refutations.sort(key=lambda item: (
        item["tier"] if isinstance(item["tier"], int) else -1,
        item["object_id"] or "", item["coordinate"] or "",
        item["instance_digest"] or "",
    ))
    if commitment.get("conditional_refutation_count") != len(
        conditional_refutations
    ):
        issues.add(
            "/verifier_execution/obligation_denominator_commitment/conditional_refutation_count",
            "projectionCommitment",
            "count does not equal the projected conditional ledger",
        )
    if commitment.get(
        "conditional_refutations_digest"
    ) != core_obligation_union.value_digest(conditional_refutations):
        issues.add(
            "/verifier_execution/obligation_denominator_commitment/conditional_refutations_digest",
            "projectionCommitment",
            "conditional ledger differs from the projected NOT_REQUIRED rows",
        )
    commitment_body = {
        key: value for key, value in commitment.items()
        if key != "commitment_digest"
    }
    if commitment.get("commitment_digest") != core_obligation_union.value_digest(
        commitment_body
    ):
        issues.add(
            "/verifier_execution/obligation_denominator_commitment/commitment_digest",
            "projectionCommitment",
            "digest does not seal the denominator commitment",
        )


def validate_package_polish_report(report: Any) -> PackagePolishSchemaValidation:
    """Validate a final report against exactly the bundled schema it declares."""
    schema_version = report.get("schema_version") if isinstance(report, dict) else None
    if not isinstance(schema_version, str) or schema_version not in SCHEMA_FILENAMES:
        return PackagePolishSchemaValidation(
            schema_version=schema_version if isinstance(schema_version, str) else None,
            schema_supported=False,
            valid=False,
            errors=("/: schema_version: unsupported or missing package-polish schema",),
            validator_mechanism_digest=validator_mechanism_digest(),
        )
    try:
        schema, schema_issues, schema_digest = _load_schema(schema_version)
    except Exception as exc:
        return PackagePolishSchemaValidation(
            schema_version=schema_version,
            schema_supported=True,
            valid=False,
            errors=(
                "/: validatorException: schema loading raised "
                + type(exc).__name__,
            ),
            validator_mechanism_digest=validator_mechanism_digest(),
        )
    if schema is None or schema_issues:
        return PackagePolishSchemaValidation(
            schema_version=schema_version,
            schema_supported=True,
            valid=False,
            errors=schema_issues,
            selected_schema_digest=schema_digest,
            validator_mechanism_digest=validator_mechanism_digest(),
            errors_at_limit=len(schema_issues) >= MAX_VALIDATION_ERRORS,
        )
    issues = _Issues()
    budget = _WorkBudget()
    try:
        _validate(report, schema, schema, "/", issues, 0, budget)
        if isinstance(report, dict) and not issues.full:
            _validate_report_commitments(report, issues, budget)
    except _ValidationWorkExhausted:
        issues.add(
            "/", "workBudget",
            f"validation exceeded {MAX_VALIDATION_WORK} bounded work units",
        )
    except Exception as exc:
        issues.add(
            "/", "validatorException",
            "dependency-free validation raised " + type(exc).__name__,
        )
    return PackagePolishSchemaValidation(
        schema_version=schema_version,
        schema_supported=True,
        valid=not issues.values,
        errors=tuple(issues.values),
        selected_schema_digest=schema_digest,
        validator_mechanism_digest=validator_mechanism_digest(),
        errors_at_limit=issues.full,
    )


def validate_publication_rejection_receipt(
    receipt: Any,
) -> PackagePolishSchemaValidation:
    """Validate and replay the strict publication-rejection receipt contract."""
    try:
        schema, schema_issues, receipt_schema_digest = _load_named_schema(
            REJECTION_SCHEMA_VERSION, REJECTION_SCHEMA_FILENAME
        )
    except Exception as exc:
        return PackagePolishSchemaValidation(
            schema_version=REJECTION_SCHEMA_VERSION,
            schema_supported=True,
            valid=False,
            errors=(
                "/: validatorException: rejection schema loading raised "
                + type(exc).__name__,
            ),
            validator_mechanism_digest=validator_mechanism_digest(),
        )
    issues = _Issues()
    if schema is None or schema_issues:
        return PackagePolishSchemaValidation(
            schema_version=REJECTION_SCHEMA_VERSION,
            schema_supported=True,
            valid=False,
            errors=schema_issues,
            selected_schema_digest=receipt_schema_digest,
            validator_mechanism_digest=validator_mechanism_digest(),
            errors_at_limit=len(schema_issues) >= MAX_VALIDATION_ERRORS,
        )
    budget = _WorkBudget()
    try:
        _validate(receipt, schema, schema, "/", issues, 0, budget)
        if isinstance(receipt, dict):
            errors = receipt.get("validation_errors")
            if isinstance(errors, list) and receipt.get(
                "validation_error_count"
            ) != len(errors):
                issues.add(
                    "/validation_error_count", "commitment",
                    "count does not equal the retained validation error array",
                )
            source_schema = receipt.get("source_report_schema")
            expected_schema_digest = None
            if source_schema in SCHEMA_FILENAMES:
                _, _, expected_schema_digest = _load_schema(source_schema)
            if receipt.get("selected_schema_digest") != expected_schema_digest:
                issues.add(
                    "/selected_schema_digest", "commitment",
                    "digest does not identify the selected bundled schema",
                )
            if receipt.get(
                "validator_mechanism_digest"
            ) != validator_mechanism_digest():
                issues.add(
                    "/validator_mechanism_digest", "commitment",
                    "digest does not identify the executing validator source",
                )
            retained_digest = receipt.get("report_digest")
            body = dict(receipt)
            body.pop("report_digest", None)
            if retained_digest != core_obligation_union.value_digest(body):
                issues.add(
                    "/report_digest", "commitment",
                    "digest does not seal the rejection receipt body",
                )
    except _ValidationWorkExhausted:
        issues.add(
            "/", "workBudget",
            f"validation exceeded {MAX_VALIDATION_WORK} bounded work units",
        )
    except Exception as exc:
        issues.add(
            "/", "validatorException",
            "rejection receipt validation raised " + type(exc).__name__,
        )
    return PackagePolishSchemaValidation(
        schema_version=REJECTION_SCHEMA_VERSION,
        schema_supported=True,
        valid=not issues.values,
        errors=tuple(issues.values),
        selected_schema_digest=receipt_schema_digest,
        validator_mechanism_digest=validator_mechanism_digest(),
        errors_at_limit=issues.full,
    )
