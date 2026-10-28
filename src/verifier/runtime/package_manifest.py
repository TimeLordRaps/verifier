"""Additive package manifests: retain admission, extend the actual object graph.

Version 3 contains the entire version-1 package contract plus a version-2
namespace declaration. Neither component is a fallback for the other. The
bridge below proves that namespace extension preserves every original object,
payload and edge, and that all additional objects belong to the same root GRAPH.
Version 4 additionally permits explicit, digest-bound current payloads while
retaining the original records and all kind/operand obligations separately.
Version 5 preserves that exact contract under a larger, still finite transport
profile for repositories whose complete source-owned graph cannot fit in v4.
Version 6 changes only the nested namespace transport: compact evidence-set
pointers are expanded to the exact version-2 inline form before any bridge or
composition semantics run.
No repository code executes while interpreting the declaration.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from verifier.core.namespace import NamespaceObject
from verifier.runtime import namespace_manifest, tier_zero_manifest
from verifier.runtime.namespace_contracts import ancestors, namespace_registry


SCHEMA = "verifier-objects-manifest-3"
REPRESENTATION_SCHEMA = "verifier-objects-manifest-4"
PACKAGE_REPRESENTATION_SCHEMA = "verifier-objects-manifest-5"
COMPACT_PACKAGE_REPRESENTATION_SCHEMA = "verifier-objects-manifest-6"
REPRESENTATION_SCHEMAS = frozenset({
    REPRESENTATION_SCHEMA,
    PACKAGE_REPRESENTATION_SCHEMA,
    COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
})
SCHEMAS = frozenset({SCHEMA, *REPRESENTATION_SCHEMAS})


def retained_contract(document: dict[str, Any]) -> dict[str, Any]:
    """Select the explicit retained contract, never infer a version from fields."""
    if document.get("schema_version") not in SCHEMAS:
        return document
    omitted = {"namespace"}
    if document["schema_version"] in REPRESENTATION_SCHEMAS:
        omitted.add("representation_updates")
    result = {key: value for key, value in document.items() if key not in omitted}
    result["schema_version"] = tier_zero_manifest.MANIFEST_SCHEMA
    return result


def validate_bridge(document: dict[str, Any]) -> tuple[NamespaceObject, ...]:
    """Preserve the old graph as a subgraph; permit only additive root members."""
    require = namespace_manifest.require
    require(document.get("schema_version") in SCHEMAS, "PACKAGE_NAMESPACE_VERSION")
    declared = document.get("namespace")
    require(type(declared) is dict, "PACKAGE_NAMESPACE_REQUIRED")
    if document["schema_version"] == COMPACT_PACKAGE_REPRESENTATION_SCHEMA:
        require(declared.get("schema_version") == namespace_manifest.COMPACT_SCHEMA,
                "NAMESPACE_MANIFEST_VERSION")
        declared = namespace_manifest.normalize_manifest(declared)
        # normalize_manifest has already validated the registry digest and the
        # complete compact declaration. Rebuild only the immutable contracts;
        # no digest pointer survives into the semantic bridge below.
        registry = namespace_registry(declared["extensions"])
    else:
        # Versions 3-5 retain their original version-2 namespace contract.
        require(declared.get("schema_version") == namespace_manifest.SCHEMA,
                "NAMESPACE_MANIFEST_VERSION")
        registry = namespace_manifest.validate_manifest(declared)
    rows = {row["object_id"]: row for row in declared["objects"]}
    retained = tier_zero_manifest._namespace_objects(document["objects"])
    original_ids = {item.object_id for item in retained}
    require(original_ids <= rows.keys(), "PACKAGE_NAMESPACE_OBJECT_REMOVED")
    graph = next(item for item in retained if item.kind.value == "GRAPH")
    changed = set()
    for item in retained:
        row = rows[item.object_id]
        require(row["kind"] == item.kind.value, "PACKAGE_NAMESPACE_KIND_CHANGED")
        if row["payload"] != dict(item.payload):
            require(document["schema_version"] in REPRESENTATION_SCHEMAS,
                    "PACKAGE_NAMESPACE_PAYLOAD_CHANGED")
            changed.add(item.object_id)
        expected = item.to_dict()["operands"]
        if item.object_id == graph.object_id:
            require(set(row["operands"]) == {"members"}, "PACKAGE_NAMESPACE_GRAPH_ROLES_CHANGED")
            require(set(row["operands"]["members"]) == set(rows) - {graph.object_id},
                    "PACKAGE_NAMESPACE_GRAPH_NOT_COMPLETE")
            require(set(expected["members"]) <= set(row["operands"]["members"]),
                    "PACKAGE_NAMESPACE_EDGE_REMOVED")
            require([target for target in row["operands"]["members"] if target in original_ids]
                    == expected["members"], "PACKAGE_NAMESPACE_EDGE_ORDER_CHANGED")
        else:
            require(row["operands"] == expected, "PACKAGE_NAMESPACE_EDGES_CHANGED")
    composition = namespace_manifest.check_composition(declared["objects"], registry)
    require(composition["status"] == "PASS", "PACKAGE_NAMESPACE_COMPOSITION_NOT_PASS")
    objects = []
    for row in declared["objects"]:
        payload = deepcopy(row["payload"])
        base = ancestors(registry, row["kind"])[-1]
        if base == "GRAPH":
            payload["element_kind"] = ancestors(registry, payload["element_kind"])[-1]
        objects.append(NamespaceObject.create(row["object_id"], base, payload, row["operands"]))
    if document["schema_version"] in REPRESENTATION_SCHEMAS:
        _validate_representations(document.get("representation_updates"), retained, tuple(objects), changed)
    return tuple(objects)


def _validate_representations(updates: Any, retained: tuple[NamespaceObject, ...],
                              objects: tuple[NamespaceObject, ...], changed: set[str]) -> None:
    """A current payload never silently acquires the prior record's evidence."""
    from verifier.runtime.package_instance_evidence import _path, _HASH
    require = namespace_manifest.require
    require(type(updates) is list and len(updates) <= len(retained), "PACKAGE_REPRESENTATION_UPDATES_REQUIRED")
    before, after = ({item.object_id: item for item in rows} for rows in (retained, objects))
    selected = set()
    fields = {"object_id", "retained_object_digest", "current_object_digest", "reason", "evidence"}
    for update in updates:
        require(type(update) is dict and set(update) == fields, "PACKAGE_REPRESENTATION_FIELDS")
        identifier = update["object_id"]
        require(type(identifier) is str and identifier in before and identifier not in selected,
                "PACKAGE_REPRESENTATION_OBJECT_INVALID")
        selected.add(identifier)
        require(update["retained_object_digest"] == before[identifier].digest
                and update["current_object_digest"] == after[identifier].digest,
                "PACKAGE_REPRESENTATION_DIGEST_DIFFERS")
        require(type(update["reason"]) is str and bool(update["reason"].strip()) and len(update["reason"]) <= 8192,
                "PACKAGE_REPRESENTATION_REASON_REQUIRED")
        refs = update["evidence"]
        require(type(refs) is list and len(refs) <= 256, "PACKAGE_REPRESENTATION_EVIDENCE_INVALID")
        for ref in refs:
            require(type(ref) is dict and set(ref) == {"path", "sha256"} and type(ref["path"]) is str
                    and type(ref["sha256"]) is str and _HASH.fullmatch(ref["sha256"]) is not None,
                    "PACKAGE_REPRESENTATION_REFERENCE_INVALID")
            _path(ref["path"])
    require(selected == changed, "PACKAGE_REPRESENTATION_DENOMINATOR_DIFFERS")


def select(document: dict[str, Any], *, repository: str, revision: str
           ) -> tuple[dict[str, Any], dict[str, Any], tuple[NamespaceObject, ...]]:
    """One selection path shared by all package tiers; no discarded refinements."""
    retained = retained_contract(document)
    validation = tier_zero_manifest.validate_manifest(
        retained, expected_repository=repository, expected_revision=revision)
    objects = (validate_bridge(document) if document.get("schema_version") in SCHEMAS
               else tier_zero_manifest._namespace_objects(retained["objects"]))
    return retained, validation, objects
