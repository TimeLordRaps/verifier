"""Versioned typed TIME/SPACE context references on unchanged namespace records.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
This separate digest domain preserves namespace version-one operands and EVENT
roles. Structural context identity does not establish a capability's semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Sequence

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, ObjectKind, assess_composition, composition_digest
from verifier.core.receipt import strict_json_loads

OBJECT_VERSION = "verifier-contextual-namespace-object-1"
COLLECTION_VERSION = "verifier-contextual-namespace-composition-1"
ASSESSMENT_VERSION = "verifier-contextual-namespace-assessment-1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
LIMITS = {"max_objects": 256, "max_references": 4096, "max_bytes": 4 * 1024**2, "max_operations": 100000}


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256 or any(ord(char) < 32 for char in value):
        raise ValueError("bounded plain context identifiers required")
    return value


@dataclass(frozen=True)
class ContextReference:
    role: str
    kind: ObjectKind
    object_id: str
    object_digest: str
    domain: str
    profile: str

    def __post_init__(self) -> None:
        for value in (self.role, self.object_id, self.domain, self.profile):
            _text(value)
        if type(self.kind) is not ObjectKind or self.kind not in (ObjectKind.TIME, ObjectKind.SPACE):
            raise ValueError("context reference requires typed TIME or SPACE")
        if type(self.object_digest) is not str or _HASH.fullmatch(self.object_digest) is None:
            raise ValueError("exact contextual target commitment required")

    @property
    def key(self) -> tuple[str, str, str]:
        return self.role, self.kind.value, self.domain

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "kind": self.kind.value, "object_id": self.object_id,
            "object_digest": self.object_digest, "domain": self.domain, "profile": self.profile}

    @classmethod
    def from_dict(cls, value: Any) -> ContextReference:
        if type(value) is not dict or set(value) != {"role", "kind", "object_id", "object_digest", "domain", "profile"}:
            raise ValueError("closed context-reference fields required")
        return cls(value["role"], ObjectKind(value["kind"]), value["object_id"], value["object_digest"], value["domain"], value["profile"])


@dataclass(frozen=True)
class ContextualObject:
    record: NamespaceObject
    contexts: tuple[ContextReference, ...] = ()

    def __post_init__(self) -> None:
        if type(self.record) is not NamespaceObject or type(self.contexts) is not tuple or len(self.contexts) > LIMITS["max_references"]:
            raise ValueError("immutable bounded namespace record/context tuple required")
        if any(type(row) is not ContextReference for row in self.contexts):
            raise ValueError("typed immutable context references required")
        keys = [row.key for row in self.contexts]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("unique sorted role/kind/domain context bindings required")

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": OBJECT_VERSION, "record": self.record.to_dict(),
            "contexts": [row.to_dict() for row in self.contexts]}

    @property
    def digest(self) -> str:
        return "sha256:" + canonical_digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> ContextualObject:
        if type(value) is not dict or set(value) != {"schema_version", "record", "contexts"} or value["schema_version"] != OBJECT_VERSION:
            raise ValueError("explicit contextual object version/closed fields required")
        row = value["record"]
        if type(row) is not dict or set(row) != {"object_id", "kind", "payload", "operands"} or type(row["operands"]) is not dict:
            raise ValueError("unchanged closed namespace record required")
        if type(row["object_id"]) is not str or type(row["kind"]) is not str or len(row["operands"]) > LIMITS["max_references"] or any(type(role) is not str for role in row["operands"]) or any(type(refs) is not list or len(refs) > LIMITS["max_references"] or any(type(name) is not str for name in refs) for refs in row["operands"].values()):
            raise ValueError("closed plain namespace operand lists required")
        if type(value["contexts"]) is not list or len(value["contexts"]) > LIMITS["max_references"]:
            raise ValueError("bounded explicit context list required")
        record = NamespaceObject.create(row["object_id"], row["kind"], row["payload"], row["operands"])
        return cls(record, tuple(ContextReference.from_dict(item) for item in value["contexts"]))


def contextual_digest(objects: Sequence[ContextualObject]) -> str:
    return "sha256:" + canonical_digest({"schema_version": COLLECTION_VERSION,
        "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.record.object_id)]})


def decode_contextual_object(raw: bytes) -> ContextualObject:
    if type(raw) is not bytes or len(raw) > LIMITS["max_bytes"]:
        raise ValueError("bounded immutable contextual object bytes required")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
        result = ContextualObject.from_dict(value)
        if canonical_bytes(result.to_dict()) != raw:
            raise ValueError("canonical contextual object wire required")
        return result
    except RecursionError as exc:
        raise ValueError("contextual object structural bound exhausted") from exc


def decode_contextual_collection(raw: bytes) -> tuple[ContextualObject, ...]:
    if type(raw) is not bytes or len(raw) > LIMITS["max_bytes"]:
        raise ValueError("bounded immutable contextual collection bytes required")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
        if type(value) is not dict or set(value) != {"schema_version", "objects"} or value["schema_version"] != COLLECTION_VERSION:
            raise ValueError("closed contextual collection version required")
        if type(value["objects"]) is not list or len(value["objects"]) > LIMITS["max_objects"]:
            raise ValueError("bounded explicit contextual object list required")
        objects = tuple(ContextualObject.from_dict(row) for row in value["objects"])
        expected = {"schema_version": COLLECTION_VERSION,
            "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.record.object_id)]}
        if canonical_bytes(expected) != raw:
            raise ValueError("canonical sorted contextual collection wire required")
        return objects
    except RecursionError as exc:
        raise ValueError("contextual collection structural bound exhausted") from exc


def assess_contextual_composition(objects: Sequence[ContextualObject], *, expected_digest: str | None,
        required_contexts: tuple[tuple[str, ContextReference], ...] = ()) -> dict[str, Any]:
    report: dict[str, Any] = {"schema_version": ASSESSMENT_VERSION, "status": "UNKNOWN",
        "collection_digest": None, "scope": "FINITE_TYPED_CONTEXT_IDENTITY_AND_ACYCLIC_COMPOSITION",
        "capability_semantics": "NOT_ASSESSED", "legacy_namespace_semantics": "UNCHANGED"}
    if expected_digest is None:
        return {**report, "reason": "independent contextual collection commitment absent"}
    if type(expected_digest) is not str or _HASH.fullmatch(expected_digest) is None:
        return {**report, "status": "REFUSAL", "reason": "canonical contextual commitment required"}
    if type(objects) not in (list, tuple) or any(type(item) is not ContextualObject for item in objects):
        return {**report, "status": "REFUSAL", "reason": "explicit contextual object collection required"}
    objects = tuple(objects)
    if len(objects) > LIMITS["max_objects"] or sum(len(item.contexts) + sum(len(refs) for _, refs in item.record.operands) for item in objects) > LIMITS["max_references"]:
        return {**report, "reason": "contextual collection/reference bound exhausted"}
    if sum(len(canonical_bytes(item.to_dict())) for item in objects) > LIMITS["max_bytes"]:
        return {**report, "reason": "contextual byte bound exhausted"}
    observed = contextual_digest(objects)
    report["collection_digest"] = observed
    if observed != expected_digest:
        return {**report, "status": "FAIL", "reason": "contextual collection commitment differs"}
    by_id = {item.record.object_id: item for item in objects}
    if len(by_id) != len(objects):
        return {**report, "status": "FAIL", "reason": "duplicate contextual object identifier"}
    dependencies = {}
    for item in objects:
        dependencies[item.record.object_id] = {ref for _, refs in item.record.operands for ref in refs} | {row.object_id for row in item.contexts}
        if dependencies[item.record.object_id] - by_id.keys():
            return {**report, "reason": "selected referenced object missing"}
    pending, operations = {name: set(refs) for name, refs in dependencies.items()}, 0
    while pending:
        operations += sum(len(refs)+1 for refs in pending.values())
        if operations > LIMITS["max_operations"]:
            return {**report, "reason": "context composition operation bound exhausted"}
        ready = {name for name, refs in pending.items() if not refs}
        if not ready:
            return {**report, "status": "FAIL", "reason": "operand/context dependency cycle"}
        pending = {name: refs-ready for name, refs in pending.items() if name not in ready}
    legacy = [item.record for item in objects]
    structural = assess_composition(legacy, expected_digest=composition_digest(legacy),
        max_objects=LIMITS["max_objects"], max_operations=LIMITS["max_operations"],
        max_payload_bytes=LIMITS["max_bytes"], max_reference_bytes=LIMITS["max_bytes"])
    if structural.verdict.value != "PASS":
        return {**report, "status": structural.verdict.value, "reason": structural.reason}
    for item in objects:
        for row in item.contexts:
            target = by_id[row.object_id]
            if target.record.kind != row.kind or target.digest != row.object_digest:
                return {**report, "status": "FAIL", "reason": "substituted context record/kind"}
            payload = target.record.payload
            if payload.get("domain") != row.domain or payload.get("profile") != row.profile:
                return {**report, "status": "FAIL", "reason": "context domain/profile binding differs"}
    if type(required_contexts) is not tuple or len(required_contexts) > LIMITS["max_references"]:
        return {**report, "status": "REFUSAL", "reason": "bounded independently selected context policy required"}
    selected_keys = set()
    for entry in required_contexts:
        if type(entry) is not tuple or len(entry) != 2 or type(entry[0]) is not str or not entry[0].strip() or len(entry[0]) > 256 or type(entry[1]) is not ContextReference:
            return {**report, "status": "REFUSAL", "reason": "closed typed context policy required"}
        name, required = entry
        selected_key = (name, required.key)
        if selected_key in selected_keys:
            return {**report, "status": "REFUSAL", "reason": "ambiguous duplicate context policy entry"}
        selected_keys.add(selected_key)
        subject = by_id.get(name)
        rows = {row.key: row for row in subject.contexts} if subject else {}
        if required.key not in rows:
            return {**report, "reason": "required context observation absent"}
        if rows[required.key] != required:
            return {**report, "status": "FAIL", "reason": "independent context selection differs"}
    return {**report, "status": "PASS", "objects_checked": len(objects), "reason": "selected finite context identity and composition replayed"}
