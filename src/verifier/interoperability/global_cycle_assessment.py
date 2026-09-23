"""Receipt-bound, bounded classification of cycles in a Verifier Standard graph.

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256),
Unicode Transformation Format, 8-bit (UTF-8), and Verifier Standard (VSTD) are
expanded here at first use.  ``tick`` is a dimensionless integer logical-time
unit; ``nanosecond`` is an integer duration unit equal to 1e-9 seconds.  A
serialized identifier (ID) names a relation, proposition, or clock.

This experimental sidecar replays every referenced relation-boundary receipt
before using its exact source and target coordinates.  It keeps three meanings
separate: directed support/dependency cycles, simultaneous constraint loops
without a chosen causal direction, and explicitly declared backward-time
relations.  The latter is a statement about a declared coordinate equation,
not evidence of physical retrocausation.  No result establishes truth,
causation, correctness, completeness, provenance admission, or trust.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping


DECLARATION_SCHEMA = "verifier-global-cycle-assessment-1"
RECEIPT_SCHEMA = "verifier-global-cycle-assessment-receipt-1"
SEMANTICS_SCHEMA = "verifier-cycle-relation-semantics-1"
CHECKER_IMPLEMENTATION = "verifier.interoperability.global_cycle_assessment"
CHECKER_VERSION = "0.1"
MAX_DECLARATION_BYTES = 2 * 1024 * 1024
MAX_RELATIONS = 512
MAX_PROPOSITIONS = 1024
MAX_MATERIALS = 512
MAX_RELATION_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_ENTRIES = 256
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_MATERIAL_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_VALUES = 100_000
MAX_WORK = 65_536
MAX_ABS_OFFSET = 10**12
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_RELATION_KINDS = {
    "SUPPORT_DEPENDENCY",
    "SIMULTANEOUS_CONSTRAINT",
    "EXPLICIT_TEMPORAL",
}
_RESIDUALS = (
    "CAUSATION_NOT_ESTABLISHED",
    "COMPLETENESS_NOT_ESTABLISHED",
    "CORRECTNESS_NOT_ESTABLISHED",
    "DENOMINATOR_AUTHORITY_NOT_ESTABLISHED",
    "HISTORICAL_EXECUTION_NOT_ESTABLISHED",
    "ISSUER_IDENTITY_NOT_ESTABLISHED",
    "PHYSICAL_RETROCAUSATION_NOT_ESTABLISHED",
    "SIGNATURE_AUTHENTICITY_NOT_ESTABLISHED",
    "TRUTH_NOT_ESTABLISHED",
)


class GlobalCycleError(ValueError):
    """A cycle declaration or retained evidence coordinate is malformed."""


class _Limit(GlobalCycleError):
    """A declared byte, graph, or work bound was exceeded."""


class AssessmentState(str, Enum):
    """Facet-independent outcome; ASSESSED is not a correctness verdict."""

    ASSESSED = "ASSESSED"
    CONFLICTED = "CONFLICTED"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


def canonical_bytes(value: Any, *, upper: int = MAX_DECLARATION_BYTES) -> bytes:
    """Return bounded canonical JSON bytes while rejecting non-JSON coercions."""

    stack = [(value, 0)]
    count = size = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_VALUES:
            raise _Limit("JSON depth or value-count bound exceeded")
        if isinstance(item, Mapping):
            if len(item) + count > MAX_JSON_VALUES:
                raise _Limit("JSON value-count bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise GlobalCycleError("JSON object keys must be strings")
                stack.extend(((key, depth + 1), (child, depth + 1)))
        elif isinstance(item, (list, tuple)):
            if len(item) + count > MAX_JSON_VALUES:
                raise _Limit("JSON value-count bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            try:
                size += len(item.encode("utf-8"))
            except UnicodeError as error:
                raise GlobalCycleError("JSON contains invalid Unicode") from error
        elif item is None or type(item) is bool:
            size += 5
        elif type(item) is int:
            if item.bit_length() > 4096:
                raise _Limit("JSON integer-size bound exceeded")
            size += len(str(item))
        elif type(item) is float and math.isfinite(item):
            size += 32
        else:
            raise GlobalCycleError("record contains a non-JSON value")
        if size > upper:
            raise _Limit("JSON byte bound exceeded")
    try:
        document = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise GlobalCycleError("record cannot be serialized exactly") from error
    if len(document) > upper:
        raise _Limit("JSON byte bound exceeded")
    return document


def digest_bytes(value: bytes) -> str:
    if type(value) is not bytes:
        raise GlobalCycleError("digest input must be bytes")
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _decode(document: bytes, *, upper: int = MAX_DECLARATION_BYTES) -> dict[str, Any]:
    if type(document) is not bytes:
        raise GlobalCycleError("record document must be bytes")
    if len(document) > upper:
        raise _Limit("record document byte bound exceeded")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GlobalCycleError("record contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(document, object_pairs_hook=unique_object)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise GlobalCycleError("record is not unambiguous JSON") from error
    if type(value) is not dict:
        raise GlobalCycleError("record must contain an object")
    if canonical_bytes(value, upper=upper) != document:
        raise GlobalCycleError("record must use canonical JSON encoding")
    return value


def _object(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise GlobalCycleError(f"{label} must have exactly {sorted(keys)}")
    return value


def _text(value: Any, label: str, *, upper: int = 256) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > upper
    ):
        raise GlobalCycleError(
            f"{label} must be a nonempty trimmed string <= {upper} characters"
        )
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise GlobalCycleError(f"{label} must be a lowercase sha256: digest")
    return value


@dataclass(frozen=True)
class CycleRelationMaterial:
    """Immutable exact inputs for relation and semantic-grounding replay."""

    relation_declaration_bytes: bytes
    relation_receipt_bytes: bytes
    relation_evidence: tuple[tuple[str, bytes], ...]
    semantic_source_bytes: bytes
    grounding_declaration_bytes: bytes
    grounding_receipt_bytes: bytes
    grounding_evidence: tuple[tuple[str, bytes], ...]

    def __post_init__(self) -> None:
        byte_fields = (
            self.relation_declaration_bytes,
            self.relation_receipt_bytes,
            self.semantic_source_bytes,
            self.grounding_declaration_bytes,
            self.grounding_receipt_bytes,
        )
        if any(type(value) is not bytes for value in byte_fields):
            raise GlobalCycleError("cycle relation documents must be bytes")
        if any(len(value) > MAX_RELATION_DOCUMENT_BYTES for value in byte_fields):
            raise _Limit("cycle relation document byte bound exceeded")
        total = sum(len(value) for value in byte_fields)
        for label, evidence in (
            ("relation", self.relation_evidence),
            ("grounding", self.grounding_evidence),
        ):
            if type(evidence) is not tuple or len(evidence) > MAX_EVIDENCE_ENTRIES:
                raise _Limit(f"{label} evidence entry bound exceeded")
            previous: str | None = None
            for raw in evidence:
                if type(raw) is not tuple or len(raw) != 2:
                    raise GlobalCycleError(f"{label} evidence rows must be coordinate/bytes pairs")
                coordinate = _digest(raw[0], f"{label} evidence coordinate")
                value = raw[1]
                if type(value) is not bytes:
                    raise GlobalCycleError(f"{label} evidence values must be bytes")
                if digest_bytes(value) != coordinate:
                    raise GlobalCycleError(f"{label} evidence coordinate does not bind its bytes")
                if previous is not None and coordinate <= previous:
                    raise GlobalCycleError(f"{label} evidence coordinates must be unique and sorted")
                previous = coordinate
                total += len(value)
        if total > MAX_EVIDENCE_BYTES:
            raise _Limit("cycle relation material byte bound exceeded")

    @classmethod
    def from_parts(
        cls,
        relation_declaration_bytes: bytes,
        relation_receipt_bytes: bytes,
        relation_evidence: Mapping[str, bytes],
        semantic_source_bytes: bytes,
        grounding_declaration_bytes: bytes,
        grounding_receipt_bytes: bytes,
        grounding_evidence: Mapping[str, bytes],
    ) -> CycleRelationMaterial:
        def rows(value: Mapping[str, bytes], label: str) -> tuple[tuple[str, bytes], ...]:
            if not isinstance(value, Mapping) or len(value) > MAX_EVIDENCE_ENTRIES:
                raise _Limit(f"{label} evidence entry bound exceeded")
            unsorted = list(value.items())
            if any(type(key) is not str for key, _item in unsorted):
                raise GlobalCycleError(f"{label} evidence coordinates must be strings")
            result = tuple(sorted(unsorted, key=lambda item: item[0].encode("utf-8")))
            return result

        return cls(
            relation_declaration_bytes,
            relation_receipt_bytes,
            rows(relation_evidence, "relation"),
            semantic_source_bytes,
            grounding_declaration_bytes,
            grounding_receipt_bytes,
            rows(grounding_evidence, "grounding"),
        )

    @property
    def declaration_digest(self) -> str:
        return digest_bytes(self.relation_declaration_bytes)

    @property
    def receipt_digest(self) -> str:
        return digest_bytes(self.relation_receipt_bytes)

    @property
    def semantic_source_digest(self) -> str:
        return digest_bytes(self.semantic_source_bytes)

    @property
    def grounding_declaration_digest(self) -> str:
        return digest_bytes(self.grounding_declaration_bytes)

    @property
    def grounding_receipt_digest(self) -> str:
        return digest_bytes(self.grounding_receipt_bytes)


@dataclass(frozen=True)
class GlobalCycleDeclaration:
    """Canonical cycle interpretation bound to exact relation receipts."""

    _document: bytes

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> GlobalCycleDeclaration:
        data = _object(value, {"relations", "schema_version"}, "cycle declaration")
        if data["schema_version"] != DECLARATION_SCHEMA:
            raise GlobalCycleError("unsupported global-cycle declaration schema_version")
        raw_relations = data["relations"]
        if type(raw_relations) is not list:
            raise GlobalCycleError("relations must be an array")
        if not raw_relations or len(raw_relations) > MAX_RELATIONS:
            raise _Limit("relation count must be within 1..512")
        relations: list[dict[str, Any]] = []
        identifiers: set[str] = set()
        receipt_digests: set[str] = set()
        for raw in raw_relations:
            row = dict(_object(raw, {
                "grounding_declaration_digest",
                "grounding_receipt_digest",
                "relation_id",
                "relation_declaration_digest",
                "receipt_digest",
                "semantic_source_digest",
            }, "cycle relation"))
            identifier = _text(row["relation_id"], "relation_id")
            if identifier in identifiers:
                raise GlobalCycleError("relation_id values must be unique")
            identifiers.add(identifier)
            row["relation_id"] = identifier
            row["relation_declaration_digest"] = _digest(
                row["relation_declaration_digest"], "relation_declaration_digest"
            )
            row["receipt_digest"] = _digest(row["receipt_digest"], "receipt_digest")
            row["semantic_source_digest"] = _digest(
                row["semantic_source_digest"], "semantic_source_digest"
            )
            row["grounding_declaration_digest"] = _digest(
                row["grounding_declaration_digest"], "grounding_declaration_digest"
            )
            row["grounding_receipt_digest"] = _digest(
                row["grounding_receipt_digest"], "grounding_receipt_digest"
            )
            if row["receipt_digest"] in receipt_digests:
                raise GlobalCycleError("each relation must reference a distinct receipt_digest")
            receipt_digests.add(row["receipt_digest"])
            relations.append(row)
        relations.sort(key=lambda row: row["relation_id"].encode("utf-8"))
        return cls(canonical_bytes({
            "relations": relations,
            "schema_version": DECLARATION_SCHEMA,
        }))

    @classmethod
    def from_bytes(cls, document: bytes) -> GlobalCycleDeclaration:
        return cls.from_dict(_decode(document))

    def to_dict(self) -> dict[str, Any]:
        return _decode(self._document)

    def canonical_bytes(self) -> bytes:
        return self._document

    def canonical_digest(self) -> str:
        return digest_bytes(self._document)


@dataclass(frozen=True)
class GlobalCycleReceipt:
    """Canonical assessment output; no aggregate verification implication."""

    _document: bytes

    def to_dict(self) -> dict[str, Any]:
        return _decode(self._document)

    def canonical_bytes(self) -> bytes:
        return self._document

    def canonical_digest(self) -> str:
        return digest_bytes(self._document)


@dataclass
class _Budget:
    remaining: int

    def spend(self, amount: int = 1) -> None:
        if type(amount) is not int or amount < 0:
            raise GlobalCycleError("work amount must be a nonnegative integer")
        self.remaining -= amount
        if self.remaining < 0:
            raise _Limit("cycle assessment work budget exhausted")


def _relation_boundary_module() -> Any:
    """Load the separately versioned relation mechanism only when assessing."""

    from . import relation_boundary

    return relation_boundary


def _source_grounding_module() -> Any:
    """Load the separately versioned grounding mechanism only when assessing."""

    from . import source_grounding

    return source_grounding


def _decode_semantic_source(document: bytes, grounding_module: Any) -> dict[str, Any]:
    """Decode exact grounded semantics and derive every interpretation field."""

    if type(document) is not bytes or len(document) > MAX_RELATION_DOCUMENT_BYTES:
        raise GlobalCycleError("semantic source must be bounded bytes")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GlobalCycleError("semantic source contains a duplicate key")
            result[key] = value
        return result

    try:
        source = json.loads(document.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise GlobalCycleError("semantic source is not exact JSON") from error
    if type(source) is not dict or grounding_module.canonical_bytes(source) != document:
        raise GlobalCycleError("semantic source must be a canonical JSON object")
    wrapper = _object(
        source, {"cycle_relation_semantics"}, "semantic source wrapper"
    )
    body = wrapper["cycle_relation_semantics"]
    if not isinstance(body, Mapping):
        raise GlobalCycleError("cycle_relation_semantics must be an object")
    common = {
        "relation_declaration_digest",
        "relation_receipt_digest",
        "schema_version",
        "source_endpoint",
        "target_endpoint",
    }
    kind_fields = set(body) - common
    if kind_fields not in ({"support"}, {"constraint"}, {"temporal"}):
        raise GlobalCycleError("semantic source must contain exactly one kind-specific interpretation")
    data = _object(body, common | kind_fields, "cycle relation semantics")
    if data["schema_version"] != SEMANTICS_SCHEMA:
        raise GlobalCycleError("unsupported cycle relation semantics schema_version")

    def endpoint(raw: Any, label: str) -> dict[str, str]:
        value = _object(raw, {"artifact_digest", "proposition_id"}, label)
        return {
            "artifact_digest": _digest(value["artifact_digest"], f"{label}.artifact_digest"),
            "proposition_id": _text(value["proposition_id"], f"{label}.proposition_id"),
        }

    result: dict[str, Any] = {
        "clock_id": None,
        "constraint_polarity": None,
        "relation_declaration_digest": _digest(
            data["relation_declaration_digest"], "semantic relation_declaration_digest"
        ),
        "relation_kind": "",
        "relation_receipt_digest": _digest(
            data["relation_receipt_digest"], "semantic relation_receipt_digest"
        ),
        "source_endpoint": endpoint(data["source_endpoint"], "source_endpoint"),
        "target_endpoint": endpoint(data["target_endpoint"], "target_endpoint"),
        "temporal_offset": None,
        "temporal_unit": None,
    }
    if kind_fields == {"support"}:
        support = _object(data["support"], {"direction", "relation"}, "support semantics")
        if support["direction"] != "SOURCE_TO_TARGET" or support["relation"] != "DEPENDENCY":
            raise GlobalCycleError("unsupported support dependency semantics")
        result["relation_kind"] = "SUPPORT_DEPENDENCY"
    elif kind_fields == {"constraint"}:
        constraint = _object(data["constraint"], {"polarity"}, "constraint semantics")
        if constraint["polarity"] not in {"SAME", "INVERTED"}:
            raise GlobalCycleError("constraint polarity must be SAME or INVERTED")
        result["relation_kind"] = "SIMULTANEOUS_CONSTRAINT"
        result["constraint_polarity"] = constraint["polarity"]
    else:
        temporal = _object(
            data["temporal"], {"clock_id", "offset", "unit"}, "temporal semantics"
        )
        result["relation_kind"] = "EXPLICIT_TEMPORAL"
        result["clock_id"] = _text(temporal["clock_id"], "temporal.clock_id")
        if temporal["unit"] not in {"tick", "nanosecond"}:
            raise GlobalCycleError("temporal unit must be tick or nanosecond")
        if type(temporal["offset"]) is not int:
            raise GlobalCycleError("temporal offset must be an integer, not a Boolean")
        if abs(temporal["offset"]) > MAX_ABS_OFFSET:
            raise _Limit("temporal offset bound exceeded")
        result["temporal_unit"] = temporal["unit"]
        result["temporal_offset"] = temporal["offset"]
    return result


def _strongly_connected(
    nodes: set[str], edges: list[tuple[str, str, str]], budget: _Budget
) -> list[list[str]]:
    adjacency = {node: [] for node in nodes}
    reverse = {node: [] for node in nodes}
    self_nodes: set[str] = set()
    for identifier, source, target in edges:
        budget.spend()
        adjacency[source].append(target)
        reverse[target].append(source)
        if source == target:
            self_nodes.add(source)
    for table in (adjacency, reverse):
        for node in table:
            table[node].sort()
    seen: set[str] = set()
    finished: list[str] = []
    for start in sorted(nodes):
        if start in seen:
            continue
        seen.add(start)
        stack = [(start, 0)]
        while stack:
            budget.spend()
            node, offset = stack[-1]
            if offset == len(adjacency[node]):
                finished.append(node)
                stack.pop()
                continue
            child = adjacency[node][offset]
            stack[-1] = (node, offset + 1)
            if child not in seen:
                seen.add(child)
                stack.append((child, 0))
    groups: list[list[str]] = []
    seen.clear()
    for start in reversed(finished):
        if start in seen:
            continue
        group: list[str] = []
        pending = [start]
        seen.add(start)
        while pending:
            budget.spend()
            node = pending.pop()
            group.append(node)
            for child in reversed(reverse[node]):
                if child not in seen:
                    seen.add(child)
                    pending.append(child)
        if len(group) > 1 or start in self_nodes:
            groups.append(sorted(group))
    return sorted(groups)


def _support_facet(
    rows: list[dict[str, Any]], nodes: set[str], budget: _Budget
) -> dict[str, Any]:
    edges = [(row["relation_id"], row["source_id"], row["target_id"])
             for row in rows if row["relation_kind"] == "SUPPORT_DEPENDENCY"]
    if not edges:
        return {"cycle_groups": [], "relation_ids": [], "status": "NOT_APPLICABLE"}
    groups = _strongly_connected(nodes, edges, budget)
    return {
        "cycle_groups": groups,
        "relation_ids": sorted(identifier for identifier, _source, _target in edges),
        "status": "CYCLES_PRESENT" if groups else "ACYCLIC",
    }


class _ParitySet:
    def __init__(self, nodes: set[str], budget: _Budget) -> None:
        self.parent = {node: node for node in nodes}
        self.rank = {node: 0 for node in nodes}
        self.parity = {node: 0 for node in nodes}
        self.budget = budget

    def find(self, node: str) -> tuple[str, int]:
        self.budget.spend()
        current = node
        value = 0
        path: list[tuple[str, int]] = []
        while self.parent[current] != current:
            self.budget.spend()
            path.append((current, value))
            value ^= self.parity[current]
            current = self.parent[current]
        root = current
        running = value
        for child, prefix in path:
            self.parent[child] = root
            self.parity[child] = running ^ prefix
        return root, value

    def add(self, left: str, right: str, polarity: int) -> tuple[bool, bool]:
        left_root, left_value = self.find(left)
        right_root, right_value = self.find(right)
        if left_root == right_root:
            return True, (left_value ^ right_value) == polarity
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
            left_value, right_value = right_value, left_value
        self.parent[right_root] = left_root
        self.parity[right_root] = left_value ^ right_value ^ polarity
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1
        return False, True


def _constraint_facet(
    rows: list[dict[str, Any]], nodes: set[str], budget: _Budget
) -> dict[str, Any]:
    selected = [row for row in rows if row["relation_kind"] == "SIMULTANEOUS_CONSTRAINT"]
    if not selected:
        return {
            "conflicting_relation_ids": [],
            "loop_closing_relation_ids": [],
            "relation_ids": [],
            "status": "NOT_APPLICABLE",
        }
    sets = _ParitySet(nodes, budget)
    loops: list[str] = []
    conflicts: list[str] = []
    for row in selected:
        closed, consistent = sets.add(
            row["source_id"],
            row["target_id"],
            0 if row["constraint_polarity"] == "SAME" else 1,
        )
        if closed:
            loops.append(row["relation_id"])
        if not consistent:
            conflicts.append(row["relation_id"])
    return {
        "conflicting_relation_ids": conflicts,
        "loop_closing_relation_ids": loops,
        "relation_ids": [row["relation_id"] for row in selected],
        "status": "CONFLICTED" if conflicts else "CONSISTENT",
    }


class _WeightedSet:
    def __init__(self, nodes: set[str], budget: _Budget) -> None:
        self.parent = {node: node for node in nodes}
        self.rank = {node: 0 for node in nodes}
        self.delta = {node: 0 for node in nodes}
        self.budget = budget

    def find(self, node: str) -> tuple[str, int]:
        self.budget.spend()
        current = node
        total = 0
        trail: list[tuple[str, int]] = []
        while self.parent[current] != current:
            self.budget.spend()
            trail.append((current, total))
            total += self.delta[current]
            current = self.parent[current]
        root = current
        for child, prefix in trail:
            self.parent[child] = root
            self.delta[child] = total - prefix
        return root, total

    def add(self, source: str, target: str, offset: int) -> tuple[bool, bool]:
        source_root, source_delta = self.find(source)
        target_root, target_delta = self.find(target)
        if source_root == target_root:
            return True, target_delta - source_delta == offset
        # Required equation: time(target) = time(source) + offset.
        if self.rank[source_root] < self.rank[target_root]:
            self.parent[source_root] = target_root
            self.delta[source_root] = target_delta - source_delta - offset
        else:
            self.parent[target_root] = source_root
            self.delta[target_root] = source_delta + offset - target_delta
            if self.rank[source_root] == self.rank[target_root]:
                self.rank[source_root] += 1
        return False, True


def _temporal_facet(
    rows: list[dict[str, Any]], nodes: set[str], budget: _Budget
) -> tuple[dict[str, Any], bool]:
    selected = [row for row in rows if row["relation_kind"] == "EXPLICIT_TEMPORAL"]
    if not selected:
        return ({
            "backward_time_relation_ids": [],
            "clocks": [],
            "status": "NOT_APPLICABLE",
        }, False)
    units: dict[str, str] = {}
    mixed = False
    for row in selected:
        clock = row["clock_id"]
        unit = row["temporal_unit"]
        if clock in units and units[clock] != unit:
            mixed = True
        units[clock] = unit
    if mixed:
        return ({
            "backward_time_relation_ids": [],
            "clocks": [],
            "status": "INVALID",
        }, True)
    clocks = []
    any_conflict = False
    for clock in sorted(units):
        selected_clock = [row for row in selected if row["clock_id"] == clock]
        sets = _WeightedSet(nodes, budget)
        loops: list[str] = []
        conflicts: list[str] = []
        for row in selected_clock:
            closed, consistent = sets.add(
                row["source_id"], row["target_id"], row["temporal_offset"]
            )
            if closed:
                loops.append(row["relation_id"])
            if not consistent:
                conflicts.append(row["relation_id"])
        any_conflict |= bool(conflicts)
        clocks.append({
            "clock_id": clock,
            "conflicting_relation_ids": conflicts,
            "loop_closing_relation_ids": loops,
            "relation_ids": [row["relation_id"] for row in selected_clock],
            "status": "CONFLICTED" if conflicts else "CONSISTENT",
            "unit": units[clock],
        })
    return ({
        "backward_time_relation_ids": sorted(
            row["relation_id"] for row in selected if row["temporal_offset"] < 0
        ),
        "clocks": clocks,
        "status": "CONFLICTED" if any_conflict else "CONSISTENT",
    }, False)


def _empty_facets(state: AssessmentState) -> dict[str, Any]:
    return {
        "simultaneous_constraints": {
            "conflicting_relation_ids": [],
            "loop_closing_relation_ids": [],
            "relation_ids": [],
            "status": state.value,
        },
        "support_dependencies": {
            "cycle_groups": [],
            "relation_ids": [],
            "status": state.value,
        },
        "temporal_relations": {
            "backward_time_relation_ids": [],
            "clocks": [],
            "status": state.value,
        },
    }


def _checker_coordinate() -> dict[str, Any]:
    try:
        source_digest = digest_bytes(Path(__file__).read_bytes())
    except OSError:
        source_digest = "UNAVAILABLE"
    return {
        "coordinate_kind": "LOCAL_SOURCE_BYTES_NOT_RUNTIME_ATTESTATION",
        "implementation_ref": CHECKER_IMPLEMENTATION,
        "source_digest": source_digest,
        "version": CHECKER_VERSION,
    }


def assess_global_cycles(
    declaration_bytes: bytes,
    materials: Mapping[str, CycleRelationMaterial],
    *,
    max_work: int = MAX_WORK,
) -> GlobalCycleReceipt:
    """Replay all selected relations and classify only the resulting bound graph.

    ``materials`` is keyed by exact relation-boundary receipt digest.  Every
    kind-specific interpretation is read from a separate exact semantic source
    only after its source-grounding receipt is reproduced.  Missing retained
    evidence is UNKNOWN; digest, receipt, or semantic substitution is INVALID.
    """

    declaration = GlobalCycleDeclaration.from_bytes(declaration_bytes)
    if type(max_work) is not int or not 1 <= max_work <= MAX_WORK:
        raise GlobalCycleError(f"max_work must be an integer in 1..{MAX_WORK}")
    if not isinstance(materials, Mapping):
        raise GlobalCycleError("materials must be a mapping")
    if len(materials) > MAX_MATERIALS:
        raise _Limit("relation material count bound exceeded")
    report: dict[str, Any] = {
        "assessment_complete": False,
        "assessment_state": AssessmentState.UNKNOWN.value,
        "checker_coordinate": _checker_coordinate(),
        "declaration_digest": declaration.canonical_digest(),
        "limits": {
            "max_evidence_bytes": MAX_EVIDENCE_BYTES,
            "max_evidence_entries_per_relation": MAX_EVIDENCE_ENTRIES,
            "max_materials": MAX_MATERIALS,
            "max_propositions": MAX_PROPOSITIONS,
            "max_relations": MAX_RELATIONS,
            "max_total_material_bytes": MAX_TOTAL_MATERIAL_BYTES,
            "max_work": max_work,
        },
        "reason_codes": [],
        "relation_results": [],
        "residual_obligations": list(_RESIDUALS),
        "schema_version": RECEIPT_SCHEMA,
        "semantics": {
            "backward_time": "Declared negative relative offset; physical retrocausation is not established.",
            "simultaneous_constraint": "Undirected parity constraint with no chosen causal direction.",
            "support_dependency": "Directed support/dependency interpretation; causation is not established.",
            "verification_effect": "NONE",
        },
        **_empty_facets(AssessmentState.UNKNOWN),
    }

    def finish(state: AssessmentState, reasons: set[str]) -> GlobalCycleReceipt:
        report["assessment_state"] = state.value
        report["reason_codes"] = sorted(reasons)
        return GlobalCycleReceipt(canonical_bytes(report))

    reasons: set[str] = set()
    rows: list[dict[str, Any]] = []
    nodes: set[str] = set()
    proposition_coordinates: dict[str, str] = {}
    budget = _Budget(max_work)
    selected_bytes = 0
    for row in declaration.to_dict()["relations"]:
        material = materials.get(row["receipt_digest"])
        if isinstance(material, CycleRelationMaterial):
            selected_bytes += sum(len(value) for value in (
                material.relation_declaration_bytes,
                material.relation_receipt_bytes,
                material.semantic_source_bytes,
                material.grounding_declaration_bytes,
                material.grounding_receipt_bytes,
            ))
            selected_bytes += sum(len(value) for _key, value in material.relation_evidence)
            selected_bytes += sum(len(value) for _key, value in material.grounding_evidence)
            if selected_bytes > MAX_TOTAL_MATERIAL_BYTES:
                return finish(
                    AssessmentState.UNKNOWN,
                    {"RELATION_MATERIAL_BYTE_BOUND_EXCEEDED"},
                )
    try:
        relation_module = _relation_boundary_module()
        grounding_module = _source_grounding_module()
    except (ImportError, AttributeError):
        return finish(
            AssessmentState.UNKNOWN,
            {"RELATION_OR_GROUNDING_MECHANISM_UNAVAILABLE"},
        )

    declared = declaration.to_dict()["relations"]
    for row in declared:
        budget.spend()
        receipt_digest = row["receipt_digest"]
        try:
            material = materials[receipt_digest]
        except (KeyError, TypeError):
            reasons.add("RELATION_MATERIAL_MISSING")
            report["relation_results"].append({
                "relation_id": row["relation_id"],
                "result": AssessmentState.UNKNOWN.value,
            })
            continue
        if not isinstance(material, CycleRelationMaterial):
            reasons.add("RELATION_MATERIAL_INVALID")
            return finish(AssessmentState.INVALID, reasons)
        if material.receipt_digest != receipt_digest:
            reasons.add("RELATION_RECEIPT_SUBSTITUTED")
            return finish(AssessmentState.INVALID, reasons)
        if material.declaration_digest != row["relation_declaration_digest"]:
            reasons.add("RELATION_DECLARATION_SUBSTITUTED")
            return finish(AssessmentState.INVALID, reasons)
        if material.semantic_source_digest != row["semantic_source_digest"]:
            reasons.add("SEMANTIC_SOURCE_SUBSTITUTED")
            return finish(AssessmentState.INVALID, reasons)
        if material.grounding_declaration_digest != row["grounding_declaration_digest"]:
            reasons.add("GROUNDING_DECLARATION_SUBSTITUTED")
            return finish(AssessmentState.INVALID, reasons)
        if material.grounding_receipt_digest != row["grounding_receipt_digest"]:
            reasons.add("GROUNDING_RECEIPT_SUBSTITUTED")
            return finish(AssessmentState.INVALID, reasons)
        try:
            recorded = relation_module.decode_relation_boundary_receipt(
                material.relation_receipt_bytes
            )
            retained_coordinates = {key for key, _value in material.relation_evidence}
            required_coordinates = {
                recorded.source_digest,
                recorded.target_digest,
                recorded.evidence_digest,
            }
            if not required_coordinates <= retained_coordinates:
                reasons.add("RELATION_EVIDENCE_INCOMPLETE")
                report["relation_results"].append({
                    "declaration_digest": material.declaration_digest,
                    "receipt_digest": material.receipt_digest,
                    "relation_id": row["relation_id"],
                    "result": AssessmentState.UNKNOWN.value,
                })
                continue
            grounding_recorded = grounding_module.decode_source_grounding_receipt(
                material.grounding_receipt_bytes
            )
            grounding_coordinates = {key for key, _value in material.grounding_evidence}
            grounding_required = {
                grounding_recorded.source_digest,
                grounding_recorded.certificate_digest,
            }
            if not grounding_required <= grounding_coordinates:
                reasons.add("SEMANTIC_GROUNDING_EVIDENCE_INCOMPLETE")
                report["relation_results"].append({
                    "relation_id": row["relation_id"],
                    "result": AssessmentState.UNKNOWN.value,
                })
                continue
            bound_digests = {
                declaration.canonical_digest(),
                material.declaration_digest,
                material.receipt_digest,
                material.semantic_source_digest,
                material.grounding_declaration_digest,
                material.grounding_receipt_digest,
                grounding_recorded.certificate_digest,
            }
            if len(bound_digests) != 7:
                reasons.add("CIRCULAR_OR_ALIASED_SEMANTIC_EVIDENCE")
                return finish(AssessmentState.INVALID, reasons)
            receipt = relation_module.recheck_relation_boundary_receipt(
                material.relation_declaration_bytes,
                material.relation_receipt_bytes,
                dict(material.relation_evidence),
            )
            boundary = relation_module.decode_relation_boundary_declaration(
                material.relation_declaration_bytes
            )
            grounding = grounding_module.recheck_source_grounding_receipt(
                material.grounding_declaration_bytes,
                material.grounding_receipt_bytes,
                dict(material.grounding_evidence),
            )
            grounding_declaration = grounding_module.decode_source_grounding_declaration(
                material.grounding_declaration_bytes
            )
            semantics = _decode_semantic_source(
                material.semantic_source_bytes, grounding_module
            )
        except Exception as error:
            allowed = tuple(
                error_type for error_type in (
                    getattr(relation_module, "RelationBoundaryError", None),
                    getattr(grounding_module, "SourceGroundingError", None),
                    GlobalCycleError,
                ) if isinstance(error_type, type)
            )
            if isinstance(error, allowed):
                reasons.add("RELATION_OR_SEMANTIC_RECHECK_INVALID")
                return finish(AssessmentState.INVALID, reasons)
            raise
        grounding_result = getattr(grounding.result, "value", grounding.result)
        if grounding_result in {"REFUTED", "INVALID"}:
            reasons.add("SEMANTIC_GROUNDING_NOT_ESTABLISHED")
            return finish(AssessmentState.INVALID, reasons)
        if grounding_result != "ESTABLISHED":
            reasons.add("SEMANTIC_GROUNDING_UNKNOWN")
            report["relation_results"].append({
                "relation_id": row["relation_id"],
                "result": AssessmentState.UNKNOWN.value,
            })
            continue
        semantic_body = json.loads(material.semantic_source_bytes)["cycle_relation_semantics"]
        grounding_source = grounding_declaration.source
        ground_proposition = grounding_declaration.ground_proposition
        if (
            grounding.source_digest != material.semantic_source_digest
            or grounding.declaration_digest != material.grounding_declaration_digest
            or grounding_source.digest != material.semantic_source_digest
            or grounding_source.size_bytes != len(material.semantic_source_bytes)
            or ground_proposition.path != ("cycle_relation_semantics",)
            or ground_proposition.predicate != "JSON_POINTER_EQUALS"
            or grounding_module.canonical_bytes(ground_proposition.expected)
            != grounding_module.canonical_bytes(semantic_body)
        ):
            reasons.add("SEMANTIC_GROUNDING_COORDINATE_INVALID")
            return finish(AssessmentState.INVALID, reasons)
        result = getattr(receipt.result, "value", receipt.result)
        if result not in {"ESTABLISHED", "REFUTED", "UNKNOWN", "INVALID"}:
            reasons.add("RELATION_RESULT_UNSUPPORTED")
            return finish(AssessmentState.INVALID, reasons)
        report["relation_results"].append({
            "declaration_digest": material.declaration_digest,
            "grounding_declaration_digest": material.grounding_declaration_digest,
            "grounding_receipt_digest": material.grounding_receipt_digest,
            "receipt_digest": material.receipt_digest,
            "relation_id": row["relation_id"],
            "relation_kind": semantics["relation_kind"],
            "result": result,
            "semantic_source_digest": material.semantic_source_digest,
            "source_digest": receipt.source_digest,
            "target_digest": receipt.target_digest,
        })
        if result == "INVALID" or result == "REFUTED":
            reasons.add("RELATION_NOT_ESTABLISHED")
            return finish(AssessmentState.INVALID, reasons)
        if result == "UNKNOWN":
            reasons.add("RELATION_RESULT_UNKNOWN")
            continue
        source_id = boundary.source.proposition_id
        target_id = boundary.target.proposition_id
        if (
            receipt.source_digest != boundary.source.artifact.digest
            or receipt.target_digest != boundary.target.artifact.digest
            or receipt.declaration_digest != material.declaration_digest
            or semantics["relation_declaration_digest"] != material.declaration_digest
            or semantics["relation_receipt_digest"] != material.receipt_digest
            or semantics["source_endpoint"] != {
                "artifact_digest": receipt.source_digest,
                "proposition_id": source_id,
            }
            or semantics["target_endpoint"] != {
                "artifact_digest": receipt.target_digest,
                "proposition_id": target_id,
            }
        ):
            reasons.add("RELATION_COORDINATE_INVALID")
            return finish(AssessmentState.INVALID, reasons)
        for identifier, coordinate in (
            (source_id, receipt.source_digest),
            (target_id, receipt.target_digest),
        ):
            if identifier in proposition_coordinates and proposition_coordinates[identifier] != coordinate:
                reasons.add("PROPOSITION_ID_COORDINATE_CONFLICT")
                return finish(AssessmentState.INVALID, reasons)
            proposition_coordinates[identifier] = coordinate
            nodes.add(identifier)
            if len(nodes) > MAX_PROPOSITIONS:
                return finish(AssessmentState.UNKNOWN, {"PROPOSITION_COUNT_BOUND_EXCEEDED"})
        rows.append({
            "clock_id": semantics["clock_id"],
            "constraint_polarity": semantics["constraint_polarity"],
            "relation_id": row["relation_id"],
            "relation_kind": semantics["relation_kind"],
            "source_id": source_id,
            "target_id": target_id,
            "temporal_offset": semantics["temporal_offset"],
            "temporal_unit": semantics["temporal_unit"],
        })

    if reasons:
        return finish(AssessmentState.UNKNOWN, reasons)
    try:
        report["support_dependencies"] = _support_facet(rows, nodes, budget)
        report["simultaneous_constraints"] = _constraint_facet(rows, nodes, budget)
        temporal, invalid_units = _temporal_facet(rows, nodes, budget)
        report["temporal_relations"] = temporal
        if invalid_units:
            return finish(AssessmentState.INVALID, {"ONE_CLOCK_MIXES_TEMPORAL_UNITS"})
        conflicted = (
            report["simultaneous_constraints"]["status"] == "CONFLICTED"
            or report["temporal_relations"]["status"] == "CONFLICTED"
        )
        report["assessment_complete"] = True
        return finish(
            AssessmentState.CONFLICTED if conflicted else AssessmentState.ASSESSED,
            {"DECLARED_CONSTRAINTS_CONFLICT"} if conflicted else set(),
        )
    except _Limit as error:
        report.update(_empty_facets(AssessmentState.UNKNOWN))
        return finish(AssessmentState.UNKNOWN, {str(error).upper().replace(" ", "_")})


def build_global_cycle_receipt(
    declaration_bytes: bytes,
    materials: Mapping[str, CycleRelationMaterial],
    *,
    max_work: int = MAX_WORK,
) -> bytes:
    """Return deterministic canonical bytes for the current assessment."""

    return assess_global_cycles(
        declaration_bytes, materials, max_work=max_work
    ).canonical_bytes()


def recheck_global_cycle_receipt(
    declaration_bytes: bytes,
    receipt_bytes: bytes,
    materials: Mapping[str, CycleRelationMaterial],
    *,
    max_work: int = MAX_WORK,
) -> GlobalCycleReceipt:
    """Require exact receipt reproduction under retained relation evidence."""

    expected = build_global_cycle_receipt(
        declaration_bytes, materials, max_work=max_work
    )
    if receipt_bytes != expected:
        raise GlobalCycleError("GLOBAL_CYCLE_RECEIPT_NOT_REPRODUCED")
    return GlobalCycleReceipt(receipt_bytes)


__all__ = [
    "AssessmentState",
    "DECLARATION_SCHEMA",
    "GlobalCycleDeclaration",
    "GlobalCycleError",
    "GlobalCycleReceipt",
    "CycleRelationMaterial",
    "RECEIPT_SCHEMA",
    "SEMANTICS_SCHEMA",
    "assess_global_cycles",
    "build_global_cycle_receipt",
    "canonical_bytes",
    "digest_bytes",
    "recheck_global_cycle_receipt",
]
