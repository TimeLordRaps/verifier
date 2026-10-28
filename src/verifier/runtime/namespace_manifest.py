"""Version-2 manifest shape, compact transport, and typed base composition.

Verifier Standard (VSTD); JavaScript Object Notation (JSON).
No manifest field grants a verdict. Reasons and evidence references are admitted
here as declarations; their completeness and current-byte binding are assessed by
namespace_admission. Missing text is a useful draft, not a hidden default PASS.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
from typing import Any

from verifier.core.namespace import NamespaceObject, assess_composition, composition_digest
from verifier.runtime.namespace_contracts import (
    KindContract, ancestors, compatible_specialization, namespace_registry, registry_document,
)
from verifier.runtime.namespace_refutation import MAX_WITNESS_BYTES as MAX_REFUTATION_BYTES
from verifier.runtime.tier_zero_manifest import (
    MAX_MANIFEST_NODES as MAX_NAMESPACE_NODES,
    MAX_PACKAGE_MANIFEST_BYTES,
    MAX_PACKAGE_MANIFEST_NODES as MAX_PACKAGE_NAMESPACE_NODES,
    _strict_json_document,
    _structure_node_count,
)
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


SCHEMA = "verifier-objects-manifest-2"
COMPACT_SCHEMA = "verifier-namespace-manifest-3"
PACKAGE_SCHEMA = "verifier-objects-manifest-5"
OBJECT_FIELDS = {"object_id", "kind", "specializations", "payload", "operands", "surfaces",
                 "reason", "classification", "obligations"}
COMPACT_OBJECT_FIELDS = OBJECT_FIELDS | {"evidence_sets"}
# An optional typed DOES_NOT_APPLY witness.  Only its shape and size are checked
# here; digest, identity and currency are judged by namespace_admission against
# exact inputs, so a present witness is never an authority by itself.
REFUTATION = "refutation"
CLASSIFICATION_FIELDS = {"status", "reason", "evidence", REFUTATION}
MAX_EVIDENCE_REFERENCES = 4096
MAX_EVIDENCE_SETS_PER_OBJECT = 4096
MAX_COMPACT_EVIDENCE_REFERENCES_PER_OBJECT = 65_536
MAX_COMPACT_SELECTORS_PER_OBJECT = 65_536
MAX_COMPACT_SELECTORS = MAX_PACKAGE_NAMESPACE_NODES
MAX_COMPACT_EXPANDED_EVIDENCE_REFERENCES = MAX_PACKAGE_NAMESPACE_NODES
_CONTENT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def structure_node_count(
    value: Any,
    *,
    limit: int = MAX_PACKAGE_NAMESPACE_NODES,
    validate_portable: bool = False,
) -> int:
    """Count a portable document iteratively under one explicit hard ceiling."""
    nodes = _structure_node_count(
        value,
        limit=limit,
        code="NAMESPACE_MANIFEST_STRUCTURE_CAPACITY",
    )
    if validate_portable:
        _validate_portable_values(value)
    return nodes


def _validate_portable_values(value: Any) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
        elif type(item) is int:
            require(abs(item) <= 2**53 - 1, "NAMESPACE_INTEGER_NOT_PORTABLE")
        else:
            require(
                item is None or type(item) in (str, bool),
                "NAMESPACE_NUMBER_NOT_PORTABLE",
            )


def read_manifest(path: Path, *, require_canonical: bool = True) -> tuple[bytes, dict[str, Any]]:
    require(not path.is_symlink() and path.is_file(), "NAMESPACE_MANIFEST_UNAVAILABLE")
    with path.open("rb") as stream:
        raw = stream.read(MAX_PACKAGE_MANIFEST_BYTES + 1)
    value = _strict_json_document(
        raw,
        require_canonical=require_canonical,
        structure_code="NAMESPACE_MANIFEST_STRUCTURE_CAPACITY",
    )
    # Keep the portable declaration language exact across Python and JavaScript.
    # Financial amounts belong in evidence, or decimal strings, not binary floats.
    _validate_portable_values(value)
    return raw, value


def _strings(value: Any) -> bool:
    return type(value) is list and all(isinstance(item, str) and item.strip() for item in value) \
        and len(value) <= 65_536 and all(len(item) <= 4096 for item in value) \
        and len(value) == len(set(value))


def _refutation_field(decision: dict[str, Any]) -> bool:
    """Admit the witness field syntactically, and only beside DOES_NOT_APPLY."""
    if REFUTATION not in decision:
        return True
    witness = decision[REFUTATION]
    return (decision["status"] == "DOES_NOT_APPLY" and type(witness) is dict
            and _canonical_size(witness) <= MAX_REFUTATION_BYTES)


def _binding(value: Any, *, obligation: bool = False) -> bool:
    required = {"reason", "evidence"}
    allowed = required | {"declaration"} if obligation else required
    return (type(value) is dict and required <= set(value) <= allowed
            and isinstance(value["reason"], str) and len(value["reason"]) <= 8192
            # The pre-split package catchall legitimately carries more than
            # 1,400 exact path/digest references.  Keep that migration input
            # admissible while the document-wide byte and node limits remain
            # the primary amplification bounds.
            and type(value["evidence"]) is list
            and len(value["evidence"]) <= MAX_EVIDENCE_REFERENCES
            and all(type(ref) is dict and set(ref) == {"path", "sha256"}
                    and all(isinstance(part, str) and len(part) <= 4096
                            for part in ref.values()) for ref in value["evidence"])
            and ("declaration" not in value or (type(value["declaration"]) is dict
                 and len(value["declaration"]) <= 32
                 and all(isinstance(field, str) and len(field) <= 64
                         and isinstance(text, str) and len(text) <= 8192
                         for field, text in value["declaration"].items()))))


def _validate_manifest_v2(value: dict[str, Any]) -> dict[str, KindContract]:
    """Validate the established version-2 inline representation unchanged."""
    fields = {"schema_version", "registry_digest", "extensions", "objects"}
    require(fields <= set(value) <= fields | {"consequence_graph", "instance_checks", "execution_checks"}, "NAMESPACE_MANIFEST_FIELDS")
    require(value["schema_version"] == SCHEMA, "NAMESPACE_MANIFEST_VERSION")
    require(type(value["extensions"]) is list, "NAMESPACE_EXTENSIONS_INVALID")
    registry = namespace_registry(value["extensions"])
    require(value["registry_digest"] == registry_document(registry)["digest"], "NAMESPACE_REGISTRY_DIGEST_DIFFERS")
    rows = value["objects"]
    require(type(rows) is list and 1 <= len(rows) <= 4096, "NAMESPACE_OBJECT_COUNT_INVALID")
    identifiers: set[str] = set()
    for row in rows:
        require(type(row) is dict and set(row) == OBJECT_FIELDS, "NAMESPACE_OBJECT_FIELDS")
        identifier = row["object_id"]
        require(isinstance(identifier, str) and bool(identifier.strip()) and len(identifier) <= 256,
                "NAMESPACE_OBJECT_ID_INVALID")
        require(identifier not in identifiers, "NAMESPACE_OBJECT_ID_DUPLICATED")
        identifiers.add(identifier)
        require(isinstance(row["kind"], str) and row["kind"] in registry, "NAMESPACE_KIND_UNREGISTERED")
        require(_strings(row["specializations"]) and _strings(row["surfaces"]), "NAMESPACE_OBJECT_LIST_INVALID")
        require(type(row["payload"]) is dict and type(row["operands"]) is dict
                and all(_strings(targets) for targets in row["operands"].values()), "NAMESPACE_OPERANDS_INVALID")
        require(isinstance(row["reason"], str) and len(row["reason"]) <= 8192,
                "NAMESPACE_OBJECT_REASON_INVALID")
        for kind in row["specializations"]:
            require(kind in registry and registry[kind].extends is not None, "NAMESPACE_SPECIALIZATION_UNREGISTERED")
            require(compatible_specialization(registry, row["kind"], kind),
                    "NAMESPACE_SPECIALIZATION_BASE_DIFFERS")
        require(type(row["classification"]) is dict and type(row["obligations"]) is dict,
                "NAMESPACE_BINDINGS_INVALID")
        for kind, decision in row["classification"].items():
            require(kind in registry and type(decision) is dict
                    and {"status", "reason", "evidence"} <= set(decision) <= CLASSIFICATION_FIELDS
                    and decision["status"] in {"APPLIES", "DOES_NOT_APPLY", "UNRESOLVED"}
                    and _refutation_field(decision)
                    and _binding({key: item for key, item in decision.items()
                                  if key not in {"status", REFUTATION}}),
                    "NAMESPACE_CLASSIFICATION_FIELDS")
        require(all(_binding(binding, obligation=True) for binding in row["obligations"].values()),
                "NAMESPACE_OBLIGATION_BINDING_FIELDS")
    if "consequence_graph" in value:
        from verifier.runtime.namespace_consequences import validate_graph
        validate_graph(value["consequence_graph"], identifiers)
    if "instance_checks" in value:
        from verifier.runtime.package_instance_evidence import validate_checks
        validate_checks(value["instance_checks"], rows, registry)
    if "execution_checks" in value:
        from verifier.runtime.package_execution import validate_bindings
        validate_bindings(value["execution_checks"], rows)
    return registry


def _compact_evidence(value: Any) -> None:
    """Validate one ordered, exact evidence array used by compact transport."""
    require(type(value) is list and len(value) <= MAX_EVIDENCE_REFERENCES,
            "NAMESPACE_COMPACT_EVIDENCE_INVALID")
    paths: set[str] = set()
    for reference in value:
        require(type(reference) is dict and set(reference) == {"path", "sha256"},
                "NAMESPACE_COMPACT_EVIDENCE_REFERENCE_FIELDS")
        path = reference["path"]
        digest = reference["sha256"]
        require(isinstance(path, str) and bool(path.strip()) and len(path) <= 4096,
                "NAMESPACE_COMPACT_EVIDENCE_PATH_INVALID")
        require(isinstance(digest, str) and _CONTENT_DIGEST.fullmatch(digest) is not None,
                "NAMESPACE_COMPACT_EVIDENCE_DIGEST_INVALID")
        require(path not in paths, "NAMESPACE_COMPACT_EVIDENCE_PATH_DUPLICATED")
        paths.add(path)


def _compact_binding_selector(value: Any, *, obligation: bool) -> str | None:
    """Return a digest selector, or ``None`` for an inline compact binding."""
    require(type(value) is dict, "NAMESPACE_COMPACT_BINDING_FIELDS")
    allowed_common = {"reason", "declaration"} if obligation else {"reason", REFUTATION}
    common = set(value) - {"evidence", "evidence_set_digest"}
    require(common <= allowed_common and "reason" in common, "NAMESPACE_COMPACT_BINDING_FIELDS")
    has_inline = "evidence" in value
    has_digest = "evidence_set_digest" in value
    require(has_inline != has_digest, "NAMESPACE_COMPACT_BINDING_SELECTOR")
    expected = common | ({"evidence"} if has_inline else {"evidence_set_digest"})
    require(set(value) == expected, "NAMESPACE_COMPACT_BINDING_FIELDS")
    require(isinstance(value["reason"], str) and len(value["reason"]) <= 8192,
            "NAMESPACE_COMPACT_BINDING_REASON_INVALID")
    if "declaration" in value:
        declaration = value["declaration"]
        require(type(declaration) is dict and len(declaration) <= 32
                and all(isinstance(field, str) and len(field) <= 64
                        and isinstance(text, str) and len(text) <= 8192
                        for field, text in declaration.items()),
                "NAMESPACE_COMPACT_BINDING_DECLARATION_INVALID")
    if REFUTATION in value:
        require(type(value[REFUTATION]) is dict
                and _canonical_size(value[REFUTATION]) <= MAX_REFUTATION_BYTES,
                "NAMESPACE_COMPACT_BINDING_REFUTATION_INVALID")
    if has_inline:
        _compact_evidence(value["evidence"])
        return None
    digest = value["evidence_set_digest"]
    require(isinstance(digest, str) and _CONTENT_DIGEST.fullmatch(digest) is not None,
            "NAMESPACE_COMPACT_BINDING_DIGEST_INVALID")
    return digest


def _canonical_size(value: Any) -> int:
    """Return exact canonical JSON byte length without assembling the document."""
    if type(value) is dict:
        require(all(type(key) is str for key in value),
                "NAMESPACE_MANIFEST_KEY_INVALID")
        fields = sum(
            _canonical_size(key) + 1 + _canonical_size(item)
            for key, item in value.items()
        )
        return 2 + fields + max(0, len(value) - 1)
    if type(value) is list:
        return 2 + sum(_canonical_size(item) for item in value) \
            + max(0, len(value) - 1)
    return len(canonical_bytes(value))


def _evidence_set_size(
    evidence_sets: dict[str, Any], evidence_bytes: dict[str, int],
) -> int:
    """Return exact canonical size of one already-validated evidence-set map."""
    fields = sum(
        _canonical_size(digest) + 1 + evidence_bytes[digest]
        for digest in evidence_sets
    )
    return 2 + fields + max(0, len(evidence_sets) - 1)


def _compact_expansion_plan(value: dict[str, Any]) -> list[dict[str, dict[str, str]]]:
    """Validate and bound exact semantic expansion before copying any selector.

    The raw compact document and its projected inline form independently stay
    within the 32 MiB and 1,000,000-node package envelopes. Selector counts and
    expanded evidence references are also counted globally and per object, so
    one small evidence table cannot be amplified through repeated selectors.
    """
    compact_nodes = structure_node_count(
        value, limit=MAX_PACKAGE_NAMESPACE_NODES, validate_portable=True,
    )
    compact_bytes = _canonical_size(value) + 1
    require(compact_bytes <= MAX_PACKAGE_MANIFEST_BYTES,
            "NAMESPACE_COMPACT_TRANSPORT_BYTE_CAPACITY")
    projected_nodes = compact_nodes
    projected_bytes = compact_bytes + (
        _canonical_size(SCHEMA) - _canonical_size(COMPACT_SCHEMA)
    )
    expanded_references = 0
    selector_count = 0
    plans: list[dict[str, dict[str, str]]] = []

    for row in value["objects"]:
        require(type(row) is dict and set(row) == COMPACT_OBJECT_FIELDS,
                "NAMESPACE_COMPACT_OBJECT_FIELDS")
        evidence_sets = row["evidence_sets"]
        require(type(evidence_sets) is dict
                and len(evidence_sets) <= MAX_EVIDENCE_SETS_PER_OBJECT,
                "NAMESPACE_COMPACT_EVIDENCE_SET_COUNT_INVALID")
        evidence_nodes: dict[str, int] = {}
        evidence_bytes: dict[str, int] = {}
        unique_references = 0
        for digest, evidence in evidence_sets.items():
            require(isinstance(digest, str)
                    and _CONTENT_DIGEST.fullmatch(digest) is not None,
                    "NAMESPACE_COMPACT_EVIDENCE_SET_DIGEST_INVALID")
            _compact_evidence(evidence)
            unique_references += len(evidence)
            require(unique_references <= MAX_COMPACT_EVIDENCE_REFERENCES_PER_OBJECT,
                    "NAMESPACE_COMPACT_EVIDENCE_REFERENCE_CAPACITY")
            require(value_digest(evidence) == digest,
                    "NAMESPACE_COMPACT_EVIDENCE_SET_DIGEST_DIFFERS")
            evidence_nodes[digest] = _structure_node_count(
                evidence,
                limit=MAX_PACKAGE_NAMESPACE_NODES,
                code="NAMESPACE_COMPACT_EXPANDED_STRUCTURE_CAPACITY",
            )
            evidence_bytes[digest] = _canonical_size(evidence)

        require(type(row["classification"]) is dict
                and type(row["obligations"]) is dict,
                "NAMESPACE_BINDINGS_INVALID")
        used: set[str] = set()
        plan = {"classification": {}, "obligations": {}}
        object_references = 0
        object_selectors = 0
        object_nodes = _structure_node_count(
            row,
            limit=MAX_PACKAGE_NAMESPACE_NODES,
            code="NAMESPACE_COMPACT_EXPANDED_STRUCTURE_CAPACITY",
        )
        object_bytes = _canonical_size(row)
        table_nodes = 1 + sum(evidence_nodes.values())
        table_bytes = _evidence_set_size(evidence_sets, evidence_bytes)
        # Every compact object has other required fields, so deleting the table
        # removes exactly one adjacent comma in canonical JSON as well.
        object_nodes -= table_nodes
        projected_nodes -= table_nodes
        removed_table_bytes = (
            _canonical_size("evidence_sets") + 1 + table_bytes + 1
        )
        object_bytes -= removed_table_bytes
        projected_bytes -= removed_table_bytes

        sections = (
            ("classification", row["classification"], False),
            ("obligations", row["obligations"], True),
        )
        for section_name, bindings, obligation in sections:
            for identifier, binding in bindings.items():
                require(type(identifier) is str,
                        "NAMESPACE_COMPACT_BINDING_IDENTIFIER_INVALID")
                if not obligation:
                    require(type(binding) is dict and "status" in binding,
                            "NAMESPACE_COMPACT_CLASSIFICATION_FIELDS")
                    selected = {
                        key: item for key, item in binding.items()
                        if key != "status"
                    }
                else:
                    selected = binding
                if not obligation:
                    require(REFUTATION not in selected or binding["status"] == "DOES_NOT_APPLY",
                            "NAMESPACE_COMPACT_REFUTATION_STATUS_INVALID")
                selector = _compact_binding_selector(
                    selected, obligation=obligation,
                )
                if selector is None:
                    object_references += len(selected["evidence"])
                    continue
                require(selector in evidence_sets,
                        "NAMESPACE_COMPACT_EVIDENCE_SET_REFERENCE_MISSING")
                used.add(selector)
                plan[section_name][identifier] = selector
                object_selectors += 1
                selected_references = len(evidence_sets[selector])
                object_references += selected_references
                node_delta = evidence_nodes[selector] - 1
                byte_delta = (
                    _canonical_size("evidence") + 1
                    + evidence_bytes[selector]
                    - _canonical_size("evidence_set_digest") - 1
                    - _canonical_size(selector)
                )
                object_nodes += node_delta
                projected_nodes += node_delta
                object_bytes += byte_delta
                projected_bytes += byte_delta

        require(used == set(evidence_sets),
                "NAMESPACE_COMPACT_EVIDENCE_SET_UNUSED")
        require(object_selectors <= MAX_COMPACT_SELECTORS_PER_OBJECT,
                "NAMESPACE_COMPACT_SELECTOR_CAPACITY")
        require(object_references
                <= MAX_COMPACT_EVIDENCE_REFERENCES_PER_OBJECT,
                "NAMESPACE_COMPACT_EXPANDED_EVIDENCE_CAPACITY")
        require(object_nodes <= MAX_PACKAGE_NAMESPACE_NODES,
                "NAMESPACE_COMPACT_EXPANDED_STRUCTURE_CAPACITY")
        require(object_bytes + 1 <= MAX_PACKAGE_MANIFEST_BYTES,
                "NAMESPACE_COMPACT_EXPANDED_BYTE_CAPACITY")
        selector_count += object_selectors
        expanded_references += object_references
        require(selector_count <= MAX_COMPACT_SELECTORS,
                "NAMESPACE_COMPACT_SELECTOR_CAPACITY")
        require(expanded_references
                <= MAX_COMPACT_EXPANDED_EVIDENCE_REFERENCES,
                "NAMESPACE_COMPACT_EXPANDED_EVIDENCE_CAPACITY")
        require(projected_nodes <= MAX_PACKAGE_NAMESPACE_NODES,
                "NAMESPACE_COMPACT_EXPANDED_STRUCTURE_CAPACITY")
        require(projected_bytes <= MAX_PACKAGE_MANIFEST_BYTES,
                "NAMESPACE_COMPACT_EXPANDED_BYTE_CAPACITY")
        plans.append(plan)
    return plans


def _normalize_compact_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Expand compact pointers without allowing a digest to become evidence itself."""
    fields = {"schema_version", "registry_digest", "extensions", "objects"}
    require(type(value) is dict
            and fields <= set(value) <= fields | {"consequence_graph", "instance_checks", "execution_checks"},
            "NAMESPACE_MANIFEST_FIELDS")
    require(value["schema_version"] == COMPACT_SCHEMA, "NAMESPACE_MANIFEST_VERSION")
    rows = value["objects"]
    require(type(rows) is list and 1 <= len(rows) <= 4096, "NAMESPACE_OBJECT_COUNT_INVALID")
    plans = _compact_expansion_plan(value)
    normalized = deepcopy(value)

    for row, target, plan in zip(rows, normalized["objects"], plans):
        evidence_sets = row["evidence_sets"]
        for section_name in ("classification", "obligations"):
            for identifier, selector in plan[section_name].items():
                expanded = target[section_name][identifier]
                expanded["evidence"] = deepcopy(evidence_sets[selector])
                del expanded["evidence_set_digest"]
        del target["evidence_sets"]

    normalized["schema_version"] = SCHEMA
    return normalized


def compact_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Encode exact inline v2 evidence as deterministic compact v3 transport.

    Evidence arrays are deduplicated only within their object. A digest is a
    selector for an exact ordered array and never evidence itself. The encoder
    validates both its inline input and its emitted compact document, and then
    requires normalization to reproduce the exact input semantics.
    """
    _validate_manifest_v2(value)
    structure_node_count(
        value, limit=MAX_PACKAGE_NAMESPACE_NODES, validate_portable=True,
    )
    require(_canonical_size(value) + 1 <= MAX_PACKAGE_MANIFEST_BYTES,
            "NAMESPACE_COMPACT_EXPANDED_BYTE_CAPACITY")
    compact = deepcopy(value)
    compact["schema_version"] = COMPACT_SCHEMA
    for row in compact["objects"]:
        evidence_sets: dict[str, list[dict[str, str]]] = {}
        for section_name in ("classification", "obligations"):
            for binding in row[section_name].values():
                evidence = binding.pop("evidence")
                digest = value_digest(evidence)
                retained = evidence_sets.get(digest)
                require(retained is None or retained == evidence,
                        "NAMESPACE_COMPACT_EVIDENCE_SET_DIGEST_COLLISION")
                if retained is None:
                    evidence_sets[digest] = deepcopy(evidence)
                binding["evidence_set_digest"] = digest
        row["evidence_sets"] = evidence_sets
    normalized = _normalize_compact_manifest(compact)
    _validate_manifest_v2(normalized)
    require(normalized == value
            and canonical_bytes(normalized) == canonical_bytes(value),
            "NAMESPACE_COMPACT_ROUND_TRIP_DIFFERS")
    return compact


def normalize_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Return a validated, independent version-2 inline semantic document.

    Compact content digests are transport pointers only.  Every reference is
    replaced with a deep copy of its ordered evidence array before semantic
    consumers receive the manifest.
    """
    if type(value) is dict and value.get("schema_version") == COMPACT_SCHEMA:
        normalized = _normalize_compact_manifest(value)
        _validate_manifest_v2(normalized)
        return normalized
    _validate_manifest_v2(value)
    return deepcopy(value)


def validate_manifest(value: dict[str, Any]) -> dict[str, KindContract]:
    """Validate either exact v2 inline form or the distinct compact transport."""
    if type(value) is dict and value.get("schema_version") == COMPACT_SCHEMA:
        return _validate_manifest_v2(_normalize_compact_manifest(value))
    return _validate_manifest_v2(value)


def check_composition(rows: list[dict[str, Any]], registry: dict[str, KindContract]) -> dict[str, Any]:
    """Check the base graph while retaining, never replacing, specialization labels.

    Extension objects currently refine an existing composition shape. Relationships
    between ledger and transaction objects can be expressed by HYPER or GRAPH;
    declaring LEDGER does not invent or alter the legacy primitive's operand roles.
    """
    objects = []
    typed_graphs = []
    by_id = {row["object_id"]: row for row in rows}
    for row in rows:
        base = ancestors(registry, row["kind"])[-1]
        payload = dict(row["payload"])
        if base == "GRAPH":
            element = payload.get("element_kind")
            require(isinstance(element, str) and element in registry, "NAMESPACE_GRAPH_ELEMENT_UNREGISTERED")
            if registry[element].extends is not None:
                typed_graphs.append((row, element))
                payload["element_kind"] = ancestors(registry, element)[-1]
        objects.append(NamespaceObject.create(row["object_id"], base, payload, row["operands"]))
    result = assess_composition(objects, expected_digest=composition_digest(objects))
    # Base projection must not erase a financial element constraint. Validate
    # the refinement membership as well as the already-checked base graph.
    if result.verdict.value == "PASS":
        operations = 0
        for graph, element in typed_graphs:
            pending = list(graph["operands"]["members"])
            seen: set[str] = set()
            while pending:
                identifier = pending.pop()
                if identifier in seen:
                    continue
                seen.add(identifier)
                operations += 1
                require(operations <= 100_000, "NAMESPACE_GRAPH_REFINEMENT_CAPACITY")
                child = by_id[identifier]
                if ancestors(registry, child["kind"])[-1] == "GRAPH":
                    require(element in ancestors(registry, child["payload"]["element_kind"]),
                            "NAMESPACE_NESTED_GRAPH_REFINEMENT_DIFFERS")
                    pending.extend(child["operands"]["members"])
                else:
                    labels = {name for kind in [child["kind"], *child["specializations"]]
                              for name in ancestors(registry, kind)}
                    require(element in labels, "NAMESPACE_GRAPH_REFINEMENT_DIFFERS")
    return {"status": result.verdict.value, "reason": result.reason,
            "base_composition_digest": result.collection_digest,
            "claim_boundary": "Finite base typed composition only; all refinement obligations remain separately required."}
