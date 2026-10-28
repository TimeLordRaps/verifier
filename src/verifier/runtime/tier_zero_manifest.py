"""Strict ``objects.vstd`` admission and installed package-graph validation.

The manifest is canonical JavaScript Object Notation (JSON) with one trailing
line feed.  This module proves
only the structural subset of Tier zero: the selected bytes, object
denominator, and typed relation graph.  Surface, obligation, reason, freshness,
and independent-reconciler closure are evaluated by the Tier-zero orchestrator.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path, PurePosixPath
import re
from typing import Any

from verifier.core.certificate import Verdict
from verifier.core.namespace import (
    NamespaceObject, ObjectKind, assess_composition, composition_digest,
)
from verifier.runtime import self_polish_estate, tier_zero_profile
from verifier.runtime import core_obligation_union, core_tier_progression


MANIFEST_SCHEMA = tier_zero_profile.MANIFEST_SCHEMA
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
# Extended envelopes enumerate individual source identities as well as the
# retained contract. Their larger transport bound changes no obligation or
# legacy receipt semantics; unknown versions keep the original byte ceiling.
MAX_EXTENDED_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PACKAGE_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_NODES = 250_000
MAX_PACKAGE_MANIFEST_NODES = 1_000_000
_EXTENDED_SCHEMAS = frozenset({"verifier-objects-manifest-2", "verifier-objects-manifest-3",
                               "verifier-objects-manifest-4"})
_PACKAGE_SCHEMAS = frozenset({
    "verifier-objects-manifest-5",
    "verifier-objects-manifest-6",
})
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}\Z")
_DISPOSITIONS = {"OWNED", "EXCLUDED", "UNRESOLVED"}
_ADVERSARIAL_FIXTURES = (
    ("duplicate-key", b'{"a":1,"a":2}\n',
     "TIER_ZERO_MANIFEST_DUPLICATE_KEY"),
    ("nonfinite-number", b'{"a":NaN}\n',
     "TIER_ZERO_MANIFEST_NONFINITE_NUMBER"),
    ("noncanonical-whitespace", b'{ "a":1}\n',
     "TIER_ZERO_MANIFEST_NOT_CANONICAL"),
)


class TierZeroManifestError(ValueError):
    """Stable fail-closed manifest refusal."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise TierZeroManifestError(code)


def _document_bytes(value: Any) -> bytes:
    return tier_zero_profile.canonical_bytes(value) + b"\n"


def _structure_node_count(
    value: Any,
    *,
    limit: int,
    code: str = "TIER_ZERO_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED",
) -> int:
    """Count a decoded document iteratively before canonical re-encoding."""
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        _require(depth <= 64 and nodes <= limit, code)
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return nodes


def _strict_json_document(
    raw: bytes,
    *,
    require_canonical: bool = True,
    structure_code: str = "TIER_ZERO_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED",
) -> dict[str, Any]:
    # The parser must discover the version before it can select that version's
    # transport ceiling.  The largest recognized ceiling is still finite; the
    # post-parse check below preserves the 4 MiB legacy and 8 MiB v2-v4 bounds.
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_PACKAGE_MANIFEST_BYTES,
             "TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            _require(key not in result, "TIER_ZERO_MANIFEST_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_: str) -> Any:
        raise TierZeroManifestError("TIER_ZERO_MANIFEST_NONFINITE_NUMBER")

    def integer(token: str) -> int:
        # CPython can reject very long integer tokens with a runtime-specific
        # digit-limit ValueError.  JavaScript instead observes those tokens as
        # non-finite Numbers.  Normalize that boundary before either runtime's
        # implementation detail can escape into the admission contract.
        try:
            finite = math.isfinite(float(token))
        except (OverflowError, ValueError):
            finite = False
        _require(finite, "TIER_ZERO_MANIFEST_NONFINITE_NUMBER")
        try:
            return int(token)
        except ValueError as exc:
            raise TierZeroManifestError(
                "TIER_ZERO_MANIFEST_NONFINITE_NUMBER"
            ) from exc

    def real(token: str) -> float:
        try:
            value = float(token)
        except (OverflowError, ValueError) as exc:
            raise TierZeroManifestError(
                "TIER_ZERO_MANIFEST_NONFINITE_NUMBER"
            ) from exc
        _require(math.isfinite(value), "TIER_ZERO_MANIFEST_NONFINITE_NUMBER")
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=constant, parse_int=integer, parse_float=real,
        )
    except TierZeroManifestError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise TierZeroManifestError("TIER_ZERO_MANIFEST_INVALID_JSON") from exc
    _require(type(value) is dict, "TIER_ZERO_MANIFEST_ROOT_INVALID")
    # Match the independent parser's global parse envelope before selecting a
    # version-specific transport profile.  The returned count is reused below
    # so large documents are never walked twice merely to select v5.
    structure_nodes = _structure_node_count(
        value,
        limit=MAX_PACKAGE_MANIFEST_NODES,
        code=structure_code,
    )
    version = value.get("schema_version")
    limit = (
        MAX_PACKAGE_MANIFEST_BYTES
        if type(version) is str and version in _PACKAGE_SCHEMAS
        else MAX_EXTENDED_MANIFEST_BYTES
        if type(version) is str and version in _EXTENDED_SCHEMAS
        else MAX_MANIFEST_BYTES
    )
    _require(len(raw) <= limit,
             "TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED")
    _require(
        structure_nodes <= (
            MAX_PACKAGE_MANIFEST_NODES
            if type(version) is str and version in _PACKAGE_SCHEMAS
            else MAX_MANIFEST_NODES
        ),
        structure_code,
    )
    if require_canonical:
        _require(raw == _document_bytes(value), "TIER_ZERO_MANIFEST_NOT_CANONICAL")
    return value


# This is a declarative mirror of the package graph checked independently by
# package_self_polish_recheck.  A regression test compares the two definitions,
# so drift is a refusal rather than a silent denominator change.
_GRAPH_TEMPLATE: dict[str, tuple[str, str, dict[str, list[str]]]] = {
    "HUMAN": ("vstd-human", "responsible-human", {}),
    "ROLE": ("vstd-role", "package-maintainer-role", {}),
    "OBJECT": ("vstd-package-object", "package-subject", {}),
    "HARDWARE": ("vstd-hardware", "execution-hardware", {}),
    "SPACE": ("vstd-space", "execution-space", {}),
    "TIME": ("vstd-time", "assessment-time", {}),
    "ENV": ("vstd-environment", "execution-environment", {}),
    "DATA": ("vstd-data", "package-data", {}),
    "VERIFIER": (
        "verifier-core-self", "vstd-polish-1-and-package-gate-mechanisms",
        {"harness": ["vstd-harness"]},
    ),
    "ARCH": ("vstd-architecture", "package-architecture", {}),
    "HARNESS": ("vstd-harness", "verification-harness", {}),
    "TOKEN": ("vstd-token", "bounded-token", {}),
    "ACTOR": (
        "vstd-actor", "responsible-actor",
        {"representation": ["vstd-human"], "root_human": ["vstd-human"]},
    ),
    "COLLECTIVE": (
        "vstd-collective", "maintainer-collective", {"roles": ["vstd-role"]},
    ),
    "IDENTITY": (
        "vstd-identity", "actor-role-identity",
        {"actor": ["vstd-actor"], "role": ["vstd-role"]},
    ),
    "OWNER": (
        "vstd-owner", "package-owner-binding",
        {"actor": ["vstd-actor"], "object": ["vstd-package-object"]},
    ),
    "RECEIPT": (
        "vstd-receipt", "assessment-receipt",
        {"hardware": ["vstd-hardware"], "subject": ["vstd-package-object"]},
    ),
    "EVENT": (
        "vstd-event", "polish-assessment-event",
        {
            "meaning": ["vstd-package-object"], "space": ["vstd-space"],
            "time": ["vstd-time"],
        },
    ),
    "BENCH": (
        "vstd-benchmark", "package-benchmark",
        {"data": ["vstd-data"], "verifier": ["verifier-core-self"]},
    ),
    "TRAIN": (
        "vstd-training", "training-representation",
        {
            "arch": ["vstd-architecture"], "bench": ["vstd-benchmark"],
            "data": ["vstd-data"], "events": ["vstd-event"],
        },
    ),
    "HYPER": (
        "vstd-hypergraph", "package-relation",
        {"subjects": ["vstd-package-object", "verifier-core-self"]},
    ),
    "MODEL": (
        "vstd-model", "model-representation",
        {
            "arch": ["vstd-architecture"], "bench": ["vstd-benchmark"],
            "data": ["vstd-data"], "env": ["vstd-environment"],
            "events": ["vstd-event"], "hardware": ["vstd-hardware"],
            "train": ["vstd-training"],
        },
    ),
    "AGENT": (
        "vstd-agent", "agent-representation",
        {
            "env": ["vstd-environment"], "harness": ["vstd-harness"],
            "model": ["vstd-model"],
        },
    ),
    "SIM": (
        "vstd-simulation", "simulation-representation",
        {
            "data": ["vstd-data"], "env": ["vstd-environment"],
            "objects": ["vstd-package-object"],
            "verifier": ["verifier-core-self"],
        },
    ),
    "BOT": (
        "vstd-bot", "situated-agent-representation",
        {
            "agent": ["vstd-agent"], "env": ["vstd-environment"],
            "sim": ["vstd-simulation"],
        },
    ),
    "GRAPH": (
        "vstd-package-graph", "complete-vstd-package-representation", {},
    ),
}


def installed_object_declarations() -> list[dict[str, Any]]:
    """Return the exact installed 26-object declarative graph."""
    member_ids = sorted(
        object_id for kind, (object_id, _, _) in _GRAPH_TEMPLATE.items()
        if kind != "GRAPH"
    )
    rows = []
    for kind in ObjectKind:
        object_id, role, edges = _GRAPH_TEMPLATE[kind.value]
        rows.append({
            "object_id": object_id,
            "object_kind": kind.value,
            "role": role,
            "edges": (
                {"members": member_ids} if kind is ObjectKind.GRAPH else edges
            ),
        })
    return rows


def installed_obligation_denominator() -> dict[str, Any]:
    inventory = core_tier_progression.installed_core_route_inventory()
    cells = inventory["family_cells"]
    route_ids = sorted(
        f"installed-route:{cell['object_kind']}:{route['coordinate']}"
        for cell in cells for route in cell["registered_route_memberships"]
    )
    return {
        "semantic_version": inventory["semantic_version"],
        "slot_count": len(cells),
        "route_count": len(route_ids),
        "slot_digest": core_obligation_union.value_digest(cells),
        "route_identity_digest": core_obligation_union.value_digest(route_ids),
    }


def adversarial_corpus_receipt() -> dict[str, Any]:
    rows = []
    for name, raw, expected in _ADVERSARIAL_FIXTURES:
        observed = "ACCEPTED"
        try:
            _strict_json_document(raw)
        except TierZeroManifestError as exc:
            observed = str(exc)
        rows.append({
            "name": name,
            "input_digest": "sha256:" + sha256(raw).hexdigest(),
            "expected": expected,
            "observed": observed,
            "status": "PASS" if observed == expected else "FAIL",
        })
    body = {
        "schema_version": "verifier-tier-zero-parser-corpus-1",
        "status": "PASS" if all(row["status"] == "PASS" for row in rows)
            else "FAIL",
        "rows": rows,
    }
    return {**body, "corpus_digest": tier_zero_profile.value_digest(body)}


def manifest_template(*, repository: str, revision: str) -> dict[str, Any]:
    """Return a canonical authoring template without claiming selected evidence."""
    profile = tier_zero_profile.installed_tier_zero_profile()
    node_reconciler = Path(__file__).with_name("tier_zero_reconcile.mjs")
    reason_provider = Path(__file__).resolve().parents[3] / "reasons.vstd"
    return {
        "schema_version": MANIFEST_SCHEMA,
        "profile_id": profile["profile_id"],
        "profile_digest": profile["profile_digest"],
        "repository": {
            "remote": repository,
            "revision": revision,
            "source_root": ".",
        },
        "objects": installed_object_declarations(),
        "obligation_denominator": installed_obligation_denominator(),
        "surface_rules": [
            {
                "category": category,
                "disposition": (
                    "EXCLUDED" if category == "unresolved_surface" else "OWNED"
                ),
                "owner_object_id": (
                    None if category == "unresolved_surface" else "verifier-core-self"
                ),
                "reason": (
                    "These markers name external plugins, ignored generated outputs, and runtime-environment state outside source-owned repository admission; their identities and uncertainty remain explicit and no runtime or semantic claim is inferred."
                    if category == "unresolved_surface" else
                    "The repository-level VERIFIER owns reconciliation of this installed census category."
                ),
            }
            for category in self_polish_estate.REQUIRED_CATEGORIES
        ],
        "obligation_reason_provider": {
            "selection_status": "SELECTED",
            "path": "reasons.vstd",
            "sha256": "sha256:" + sha256(reason_provider.read_bytes()).hexdigest(),
        },
        "node_reconciler": {
            "selection_status": "SELECTED",
            "path": "src/verifier/runtime/tier_zero_reconcile.mjs",
            "sha256": "sha256:" + sha256(node_reconciler.read_bytes()).hexdigest(),
        },
        "claim_boundary": profile["claim_boundary"],
    }


def _relative_path(value: Any) -> bool:
    if type(value) is not str or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and "." not in path.parts


def _validate_selection(value: Any, code: str) -> None:
    _require(type(value) is dict and set(value) == {
        "selection_status", "path", "sha256",
    }, f"{code}_FIELDS_DIFFER")
    status = value["selection_status"]
    _require(status in {"SELECTED", "NOT_SELECTED"}, f"{code}_STATUS_INVALID")
    if status == "SELECTED":
        _require(_relative_path(value["path"]), f"{code}_PATH_INVALID")
        _require(type(value["sha256"]) is str
                 and _SHA256.fullmatch(value["sha256"]) is not None,
                 f"{code}_DIGEST_INVALID")
    else:
        _require(value["path"] is None and value["sha256"] is None,
                 f"{code}_UNSELECTED_BINDING_PRESENT")


def _namespace_objects(rows: list[dict[str, Any]]) -> tuple[NamespaceObject, ...]:
    return tuple(NamespaceObject.create(
        row["object_id"], row["object_kind"],
        {
            "representation_role": row["role"],
            **({"element_kind": "OBJECT"}
               if row["object_kind"] == "GRAPH" else {}),
        },
        row["edges"],
    ) for row in rows)


def validate_manifest(value: dict[str, Any], *, expected_repository: str,
                      expected_revision: str,
                      _installed_objects: list[dict[str, Any]] | None = None
                      ) -> dict[str, Any]:
    """Validate the manifest shape and installed structural denominators."""
    _require(set(value) == {
        "schema_version", "profile_id", "profile_digest", "repository",
        "objects", "obligation_denominator", "surface_rules",
        "obligation_reason_provider",
        "node_reconciler", "claim_boundary",
    }, "TIER_ZERO_MANIFEST_FIELDS_DIFFER")
    profile = tier_zero_profile.installed_tier_zero_profile()
    _require(
        value["schema_version"] == MANIFEST_SCHEMA
        and value["profile_id"] == profile["profile_id"]
        and value["profile_digest"] == profile["profile_digest"]
        and value["claim_boundary"] == profile["claim_boundary"],
        "TIER_ZERO_MANIFEST_PROFILE_DIFFERS",
    )
    repository = value["repository"]
    _require(type(repository) is dict and set(repository) == {
        "remote", "revision", "source_root",
    }, "TIER_ZERO_MANIFEST_REPOSITORY_FIELDS_DIFFER")
    _require(repository == {
        "remote": expected_repository,
        "revision": expected_revision,
        "source_root": ".",
    } and _REVISION.fullmatch(expected_revision) is not None,
             "TIER_ZERO_MANIFEST_SOURCE_COORDINATE_DIFFERS")

    expected_objects = (
        installed_object_declarations()
        if _installed_objects is None
        else deepcopy(_installed_objects)
    )
    rows = value["objects"]
    _require(type(rows) is list and len(rows) == len(ObjectKind),
             "TIER_ZERO_OBJECT_DENOMINATOR_DIFFERS")
    for row in rows:
        _require(type(row) is dict and set(row) == {
            "object_id", "object_kind", "role", "edges",
        }, "TIER_ZERO_OBJECT_FIELDS_DIFFER")
    _require(rows == expected_objects,
             "TIER_ZERO_OBJECT_GRAPH_DIFFERS")
    denominator = value["obligation_denominator"]
    _require(type(denominator) is dict and set(denominator) == {
        "semantic_version", "slot_count", "route_count", "slot_digest",
        "route_identity_digest",
    }, "TIER_ZERO_OBLIGATION_DENOMINATOR_FIELDS_DIFFER")
    _require(denominator == installed_obligation_denominator(),
             "TIER_ZERO_OBLIGATION_DENOMINATOR_DIFFERS")

    rules = value["surface_rules"]
    _require(type(rules) is list
             and len(rules) == len(self_polish_estate.REQUIRED_CATEGORIES),
             "TIER_ZERO_SURFACE_RULE_DENOMINATOR_DIFFERS")
    categories: list[str] = []
    object_ids = {row["object_id"] for row in rows}
    for rule in rules:
        _require(type(rule) is dict and set(rule) == {
            "category", "disposition", "owner_object_id", "reason",
        }, "TIER_ZERO_SURFACE_RULE_FIELDS_DIFFER")
        categories.append(rule["category"])
        _require(rule["disposition"] in _DISPOSITIONS
                 and type(rule["reason"]) is str
                 and 0 < len(rule["reason"]) <= 4096,
                 "TIER_ZERO_SURFACE_RULE_INVALID")
        if rule["disposition"] == "OWNED":
            _require(rule["owner_object_id"] in object_ids,
                     "TIER_ZERO_SURFACE_OWNER_INVALID")
        else:
            _require(rule["owner_object_id"] is None,
                     "TIER_ZERO_SURFACE_NONOWNER_PRESENT")
    _require(categories == list(self_polish_estate.REQUIRED_CATEGORIES),
             "TIER_ZERO_SURFACE_CATEGORY_SET_DIFFERS")
    _validate_selection(value["obligation_reason_provider"],
                        "TIER_ZERO_REASON_PROVIDER")
    _require(
        value["obligation_reason_provider"]["selection_status"] == "SELECTED"
        and value["obligation_reason_provider"]["path"] == "reasons.vstd",
        "TIER_ZERO_REASON_AUTHORITY_DIFFERS",
    )
    _validate_selection(value["node_reconciler"], "TIER_ZERO_NODE_RECONCILER")

    objects = _namespace_objects(rows)
    expected = composition_digest(objects)
    assessment = assess_composition(objects, expected_digest=expected)
    _require(assessment.verdict is Verdict.PASS,
             "TIER_ZERO_OBJECT_COMPOSITION_REFUTED")
    corpus = adversarial_corpus_receipt()
    _require(corpus["status"] == "PASS",
             "TIER_ZERO_PYTHON_ADVERSARIAL_CORPUS_FAILED")
    return {
        "schema_version": "verifier-tier-zero-manifest-validation-1",
        "status": "PASS",
        "profile_digest": profile["profile_digest"],
        "object_count": len(rows),
        "object_kind_digest": tier_zero_profile.value_digest(
            [row["object_kind"] for row in rows]
        ),
        "graph_digest": expected,
        **denominator,
        "surface_rule_count": len(rules),
        "surface_rule_digest": tier_zero_profile.value_digest(rules),
        "reason_provider_selection_status": value[
            "obligation_reason_provider"
        ]["selection_status"],
        "node_reconciler_selection_status": value[
            "node_reconciler"
        ]["selection_status"],
        "attachment_selection_digest": tier_zero_profile.value_digest({
            "obligation_reason_provider": value["obligation_reason_provider"],
            "node_reconciler": value["node_reconciler"],
        }),
        "adversarial_corpus_status": corpus["status"],
        "adversarial_corpus_digest": corpus["corpus_digest"],
        "claim_boundary": (
            "PASS establishes only canonical manifest shape, the installed "
            "26-object denominator, and finite typed graph composition. It "
            "does not establish surface, obligation, reason, freshness, "
            "independent-reconciler, Tier-1-plus, polish, or release closure."
        ),
    }


def load_manifest(path: str | Path, *, expected_repository: str,
                  expected_revision: str) -> tuple[dict[str, Any], dict[str, Any]]:
    selected = Path(path)
    try:
        with selected.open("rb") as stream:
            raw = stream.read(MAX_PACKAGE_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise TierZeroManifestError("TIER_ZERO_MANIFEST_UNAVAILABLE") from exc
    value = _strict_json_document(raw)
    # Version 3 retains this entire contract. Bind the outer bytes as well as
    # the retained value; the package orchestrator also checks the extension.
    from verifier.runtime.package_manifest import retained_contract
    value = retained_contract(value)
    result = validate_manifest(
        value, expected_repository=expected_repository,
        expected_revision=expected_revision,
    )
    return value, {
        **result,
        "manifest_digest": "sha256:" + sha256(raw).hexdigest(),
        "manifest_value_digest": tier_zero_profile.value_digest(value),
    }


__all__ = [
    "MANIFEST_SCHEMA", "MAX_MANIFEST_BYTES", "MAX_EXTENDED_MANIFEST_BYTES",
    "MAX_PACKAGE_MANIFEST_BYTES", "MAX_MANIFEST_NODES",
    "MAX_PACKAGE_MANIFEST_NODES", "TierZeroManifestError",
    "adversarial_corpus_receipt", "installed_object_declarations",
    "installed_obligation_denominator", "load_manifest", "manifest_template",
    "validate_manifest",
]
