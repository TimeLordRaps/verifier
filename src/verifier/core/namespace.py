"""Verifier Standard (VSTD) object identity and finite typed composition.

This foundation uses the maintainer's 26-object hierarchy and eight meta-tiers.
JavaScript Object Notation (JSON) payloads are immutable canonical bytes. A
collection commitment binds both records and references; a local object digest
alone does not bind the objects its operands name. Counts are dimensionless.

PASS establishes only finite typed composition. It grants no numbered-profile
conformance, personhood, consent, ownership, execution, or physical isolation.
Existing receipt wire identifiers are not renamed or accepted as object kinds.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum, IntEnum
import json
import math
import re
from typing import Any, Mapping, Sequence

from .certificate import Verdict, canonical_bytes, canonical_digest


DEFAULT_MAX_OBJECTS = 4096


class ObjectKind(str, Enum):
    HUMAN = "HUMAN"
    ACTOR = "ACTOR"
    COLLECTIVE = "COLLECTIVE"
    ROLE = "ROLE"
    IDENTITY = "IDENTITY"
    OWNER = "OWNER"
    HARDWARE = "HARDWARE"
    RECEIPT = "RECEIPT"
    OBJECT = "OBJECT"
    GRAPH = "GRAPH"
    SPACE = "SPACE"
    TIME = "TIME"
    EVENT = "EVENT"
    ENV = "ENV"
    DATA = "DATA"
    VERIFIER = "VERIFIER"
    BENCH = "BENCH"
    ARCH = "ARCH"
    TRAIN = "TRAIN"
    HYPER = "HYPER"
    MODEL = "MODEL"
    HARNESS = "HARNESS"
    AGENT = "AGENT"
    SIM = "SIM"
    BOT = "BOT"
    TOKEN = "TOKEN"


class MetaTier(IntEnum):
    FACETS = 1
    DYNAMICS = 2
    STATICS = 3
    CLOSURE = 4
    INDEPENDENCE = 5
    PRIVACY = 6
    CONSENT = 7
    GOVERNANCE = 8


@dataclass(frozen=True)
class ObjectCoordinate:
    """An objective's address, not evidence that this objective is implemented."""

    object_kind: ObjectKind
    tier: MetaTier
    objective: int

    def __post_init__(self) -> None:
        if not isinstance(self.object_kind, ObjectKind) or not isinstance(self.tier, MetaTier):
            raise ValueError("coordinate requires an admitted object and meta-tier")
        if type(self.objective) is not int or self.objective < 1:
            raise ValueError("objective index must be a positive integer")

    @classmethod
    def parse(cls, value: str) -> ObjectCoordinate:
        match = re.fullmatch(r"([A-Z]+)-([1-8])\.([1-9][0-9]{0,8})", value)
        if match is None:
            raise ValueError("expected an object, meta-tier and positive objective index")
        return cls(ObjectKind(match[1]), MetaTier(int(match[2])), int(match[3]))

    def __str__(self) -> str:
        return f"{self.object_kind.value}-{self.tier.value}.{self.objective}"


def _name(value: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError("object identifiers and operand roles require bounded nonempty strings")


def _payload_bytes(value: Any) -> bytes:
    if type(value) is not dict:
        raise ValueError("object payload must be a JSON object")
    pending = [(value, 0)]
    used = 0
    characters = 0
    while pending:
        part, depth = pending.pop()
        used += 1
        if used > 10000 or depth > 64:
            raise ValueError("object payload exceeds structural bounds")
        if type(part) is dict:
            if any(type(key) is not str for key in part):
                raise ValueError("JSON object keys must be strings")
            characters += sum(len(key) for key in part)
            if len(part) > 10000:
                raise ValueError("object payload exceeds structural bounds")
            pending.extend((child, depth + 1) for child in part.values())
        elif type(part) is list:
            if len(part) > 10000:
                raise ValueError("object payload exceeds structural bounds")
            pending.extend((child, depth + 1) for child in part)
        elif type(part) is str:
            characters += len(part)
        elif type(part) is int and part.bit_length() > 4096:
            raise ValueError("payload integer exceeds representation bound")
        elif part is not None and type(part) not in (str, bool, int, float):
            raise ValueError("payload includes a non-JSON value")
        elif type(part) is float and not math.isfinite(part):
            raise ValueError("payload numbers must be finite")
        if characters > 1024 * 1024:
            raise ValueError("object payload exceeds character bound")
    encoded = canonical_bytes(value)
    if len(encoded) > 1024 * 1024:
        raise ValueError("object payload exceeds one mebibyte")
    return encoded


@dataclass(frozen=True)
class NamespaceObject:
    """Something a receipt can describe; construction itself issues no receipt."""

    object_id: str
    kind: ObjectKind
    payload_bytes: bytes
    operands: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        _name(self.object_id)
        if not isinstance(self.kind, ObjectKind):
            raise ValueError("object kind must be admitted explicitly")
        if type(self.payload_bytes) is not bytes or len(self.payload_bytes) > 1024 * 1024:
            raise ValueError("payload must be bounded canonical bytes")
        try:
            canonical = _payload_bytes(json.loads(self.payload_bytes))
        except (ValueError, RecursionError) as exc:
            raise ValueError("invalid canonical object payload") from exc
        if canonical != self.payload_bytes:
            raise ValueError("noncanonical or duplicate-key payload")
        if type(self.operands) is not tuple or len(self.operands) > 4096:
            raise ValueError("operands must be a bounded immutable tuple")
        roles: set[str] = set()
        total = 0
        for binding in self.operands:
            if type(binding) is not tuple or len(binding) != 2:
                raise ValueError("operand binding must be a role and immutable targets")
            role, targets = binding
            _name(role)
            if role in roles or type(targets) is not tuple:
                raise ValueError("duplicate role or mutable operand targets")
            roles.add(role)
            for target in targets:
                _name(target)
            if len(set(targets)) != len(targets):
                raise ValueError("duplicate target within one operand role")
            total += len(targets)
        if total > 4096 or tuple(sorted(self.operands)) != self.operands:
            raise ValueError("operand roles must be sorted and within the reference bound")

    @classmethod
    def create(cls, object_id: str, kind: str | ObjectKind, payload: dict[str, Any],
               operands: Mapping[str, Sequence[str]] | None = None) -> NamespaceObject:
        bindings = []
        for role, targets in (operands or {}).items():
            if isinstance(targets, (str, bytes)):
                raise ValueError("operand targets must be a sequence of identifiers")
            bindings.append((role, tuple(targets)))
        return cls(object_id, ObjectKind(kind), _payload_bytes(payload), tuple(sorted(bindings)))

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.payload_bytes)

    def to_dict(self) -> dict[str, Any]:
        return {"object_id": self.object_id, "kind": self.kind.value,
                "payload": self.payload,
                "operands": {role: list(targets) for role, targets in self.operands}}

    @property
    def digest(self) -> str:
        return "sha256:" + canonical_digest(self.to_dict())


# Slot names bind the roles of operands, not just a bag of compatible types.
# Repeated EVENT occurrences in the source MODEL expression use one events slot;
# order and multiplicity of distinct event identifiers remain explicit.
_SLOTS: dict[str, dict[str, tuple[str, ...]]] = {
    "ACTOR": {"representation": ("HUMAN", "AGENT", "BOT"), "root_human": ("HUMAN",)},
    "COLLECTIVE": {"roles": ("ROLE",)},
    "IDENTITY": {"actor": ("ACTOR",), "role": ("ROLE",)},
    "OWNER": {"actor": ("ACTOR",), "object": ("OBJECT",)},
    "RECEIPT": {"subject": ("OBJECT",), "hardware": ("HARDWARE",)},
    "EVENT": {"time": ("TIME",), "space": ("SPACE",), "meaning": ("OBJECT",)},
    "BENCH": {"verifier": ("VERIFIER",), "data": ("DATA",)},
    "TRAIN": {"data": ("DATA",), "events": ("EVENT",), "bench": ("BENCH",), "arch": ("ARCH",)},
    "MODEL": {"train": ("TRAIN",), "data": ("DATA",), "events": ("EVENT",),
              "bench": ("BENCH",), "arch": ("ARCH",), "env": ("ENV",), "hardware": ("HARDWARE",)},
    "AGENT": {"model": ("MODEL",), "harness": ("HARNESS",), "env": ("ENV",)},
    "SIM": {"data": ("DATA",), "verifier": ("VERIFIER",), "objects": ("OBJECT",), "env": ("ENV",)},
    "BOT": {"agent": ("AGENT",), "sim": ("SIM",), "env": ("ENV",)},
}


def composition_digest(objects: Sequence[NamespaceObject]) -> str:
    """Bind every supplied record; record order is not a dependency or event order."""
    return "sha256:" + canonical_digest({"schema_version": "verifier-object-composition-1",
        "objects": [obj.to_dict() for obj in sorted(objects, key=lambda item: item.object_id)]})


@dataclass(frozen=True)
class CompositionAssessment:
    verdict: Verdict
    collection_digest: str | None
    reason: str
    objects_checked: int = 0
    scope: str = "finite typed object composition"
    object_profile_conformance: str = "NOT_ESTABLISHED"


class _BoundExceeded(ValueError):
    pass


def _validate(objects: Sequence[NamespaceObject], max_operations: int) -> int:
    used = 0

    def charge(count: int = 1) -> None:
        nonlocal used
        used += count
        if used > max_operations:
            raise _BoundExceeded("composition operation bound exhausted")

    by_id = {obj.object_id: obj for obj in objects}
    if len(by_id) != len(objects):
        raise ValueError("duplicate object identifier")
    dependencies: dict[str, set[str]] = {}
    dependents: dict[str, set[str]] = {name: set() for name in by_id}
    for item in objects:
        charge()
        charge(sum(len(targets) for _, targets in item.operands))
        refs = {ref for _, targets in item.operands for ref in targets}
        if refs - by_id.keys():
            raise ValueError("operand refers to an unbound object")
        dependencies[item.object_id] = refs
        for ref in refs:
            dependents[ref].add(item.object_id)
    ready = deque(sorted(name for name, refs in dependencies.items() if not refs))
    order = []
    while ready:
        name = ready.popleft()
        order.append(name)
        for parent in sorted(dependents[name]):
            charge()
            dependencies[parent].remove(name)
            if not dependencies[parent]:
                ready.append(parent)
    if len(order) != len(objects):
        raise ValueError("composition dependency cycle")
    leaves: dict[str, frozenset[str]] = {}
    for name in order:
        item = by_id[name]
        slots = dict(item.operands)
        kind = item.kind.value
        if kind == "GRAPH":
            if set(slots) != {"members"} or not slots["members"]:
                raise ValueError("typed graph requires nonempty bound members")
            element = ObjectKind(item.payload.get("element_kind"))
            expanded: set[str] = set()
            for member in slots["members"]:
                child = by_id[member]
                if (element != ObjectKind.OBJECT and child.kind == ObjectKind.GRAPH
                        and child.payload.get("element_kind") != element.value):
                    raise ValueError("nested graph changes its declared element kind")
                values = leaves[member]
                charge(len(values))
                expanded.update(values)
            if element != ObjectKind.OBJECT and any(by_id[ref].kind != element for ref in expanded):
                raise ValueError("typed graph contains a different element kind")
            leaves[name] = frozenset(expanded)
            continue
        leaves[name] = frozenset({name})
        if kind == "HYPER":
            if not slots or any(not refs for refs in slots.values()):
                raise ValueError("relational composition requires named nonempty operands")
            continue
        expected = _SLOTS.get(kind, {})
        if set(slots) != set(expected):
            raise ValueError(f"{kind} operand roles differ from its composition contract")
        for role, allowed in expected.items():
            if not slots[role]:
                raise ValueError("required operand has no objects")
            for ref in slots[role]:
                charge(len(leaves[ref]))
                if ("OBJECT" not in allowed and by_id[ref].kind == ObjectKind.GRAPH
                        and by_id[ref].payload.get("element_kind") not in allowed):
                    raise ValueError(f"{kind} operand {role} requires an explicitly typed graph")
                if "OBJECT" not in allowed and any(by_id[leaf].kind.value not in allowed for leaf in leaves[ref]):
                    raise ValueError(f"{kind} operand {role} has an incompatible type")
        if kind == "ACTOR":
            representations = {leaf for ref in slots["representation"] for leaf in leaves[ref]}
            roots = {leaf for ref in slots["root_human"] for leaf in leaves[ref]}
            if len(representations) != 1 or len(roots) != 1:
                raise ValueError("one actor requires one representation and one responsible human")
            representation = next(iter(representations))
            if by_id[representation].kind == ObjectKind.HUMAN and roots != {representation}:
                raise ValueError("a human actor must be its own responsible human")
    return len(order)


def assess_composition(objects: Sequence[NamespaceObject], *, expected_digest: str | None,
                       max_objects: int = DEFAULT_MAX_OBJECTS, max_operations: int = 100000,
                       max_payload_bytes: int = 8 * 1024 * 1024,
                       max_reference_bytes: int = 8 * 1024 * 1024) -> CompositionAssessment:
    """Recompute a caller-selected complete collection's structural proposition.

An expected commitment selects the claim; it is not an authority credential.
Missing bindings or exceeded bounds are UNKNOWN; refuted structure is FAIL.
"""
    bounds = (max_objects, max_operations, max_payload_bytes, max_reference_bytes)
    if any(type(bound) is not int or bound < 1 for bound in bounds):
        raise ValueError("checker bounds must be positive integers")
    if expected_digest is None:
        return CompositionAssessment(Verdict.UNKNOWN, None, "expected collection commitment absent")
    if not isinstance(objects, (list, tuple)):
        return CompositionAssessment(Verdict.FAIL, None, "expected a finite sequence of namespace objects")
    if len(objects) > max_objects:
        return CompositionAssessment(Verdict.UNKNOWN, None, "composition object bound exhausted")
    # Commit and traverse one immutable collection, even if the caller changes
    # its list after the digest is computed. The records are already immutable.
    objects = tuple(objects)
    if any(not isinstance(obj, NamespaceObject) for obj in objects):
        return CompositionAssessment(Verdict.FAIL, None, "expected a finite sequence of namespace objects")
    if sum(len(obj.payload_bytes) for obj in objects) > max_payload_bytes:
        return CompositionAssessment(Verdict.UNKNOWN, None, "composition payload byte bound exhausted")
    size = len(objects) + sum(len(obj.operands) + sum(len(refs) for _, refs in obj.operands)
                              for obj in objects)
    if size > max_operations:
        return CompositionAssessment(Verdict.UNKNOWN, None, "composition input operation bound exhausted")
    reference_bytes = 0
    for obj in objects:
        reference_bytes += len(canonical_bytes(obj.object_id))
        for role, targets in obj.operands:
            reference_bytes += len(canonical_bytes(role))
            reference_bytes += sum(len(canonical_bytes(target)) for target in targets)
        if reference_bytes > max_reference_bytes:
            return CompositionAssessment(Verdict.UNKNOWN, None, "composition reference byte bound exhausted")
    observed = composition_digest(objects)
    if observed != expected_digest:
        return CompositionAssessment(Verdict.FAIL, observed, "collection commitment differs")
    try:
        if not objects:
            raise ValueError("composition has no objects")
        count = _validate(objects, max_operations - size)
    except _BoundExceeded as exc:
        return CompositionAssessment(Verdict.UNKNOWN, observed, str(exc))
    except ValueError as exc:
        return CompositionAssessment(Verdict.FAIL, observed, str(exc))
    return CompositionAssessment(Verdict.PASS, observed, "all declared operand bindings and kinds checked", count)
