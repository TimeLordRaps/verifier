"""Bind one declared Verifier Standard (VSTD) ACTOR-to-ROLE instance.

The versioned namespace contract accepts HUMAN, AGENT and BOT decision makers
with an explicit HUMAN root, a ROLE contained by a selected COLLECTIVE, and
byte-bound declaration evidence. It checks a finite representation, not a live
occupancy, personhood, role authority, consent, privacy admissibility, or a
numbered-profile certificate. Identifiers and counts have no physical unit.
"""
from __future__ import annotations

import re
from typing import Any, Sequence

from verifier.core.namespace import (
    DEFAULT_MAX_OBJECTS, NamespaceObject, ObjectKind, assess_composition,
)
from verifier.domains.common import Refuted, digest


_EVIDENCE_SCHEMA = "verifier-namespace-identity-evidence-1"
_ASSESSMENT_SCHEMA = "verifier-namespace-identity-assessment-1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EVIDENCE_FIELDS = frozenset({
    "schema_version", "identity_id", "actor_id", "role_id", "collective_id",
    "representation_id", "actor_kind", "root_human_id", "scope", "evidence_ref",
})


def _selected_id(value: str, label: str) -> None:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ValueError(f"selected {label} requires a bounded nonempty identifier")


def _leaves(index: dict[str, NamespaceObject], item: NamespaceObject,
            role: str) -> list[NamespaceObject]:
    """Expand one role after exact finite composition has already passed."""
    pending = list(dict(item.operands)[role])
    seen: set[str] = set()
    leaves: dict[str, NamespaceObject] = {}
    while pending:
        identifier = pending.pop()
        if identifier in seen:
            continue
        seen.add(identifier)
        child = index[identifier]
        if child.kind == ObjectKind.GRAPH:
            pending.extend(dict(child.operands)["members"])
        else:
            leaves[identifier] = child
    return [leaves[key] for key in sorted(leaves)]


def assess_identity_occupancy(objects: Sequence[NamespaceObject], *, identity_id: str,
                              collective_id: str, expected_digest: str | None,
                              expected_evidence_digest: str | None,
                              evidence: dict[str, Any] | None) -> dict[str, Any]:
    """Check an exact declared ACTOR, ROLE, COLLECTIVE and evidence binding.

    A PASS is only a finite declared relation. The caller selects complete
    collection and evidence commitments; neither commitment authenticates the
    source or grants authority. Missing selection or role scope is UNKNOWN.
    Contradictory selected bytes or relations FAIL.
    """
    _selected_id(identity_id, "IDENTITY")
    _selected_id(collective_id, "COLLECTIVE")
    # Use the same immutable collection for composition replay and relation
    # inspection. A caller can mutate its list after one checker call returns.
    if isinstance(objects, (list, tuple)) and len(objects) <= DEFAULT_MAX_OBJECTS:
        objects = tuple(objects)
    composition = assess_composition(objects, expected_digest=expected_digest)

    def result(status: str, reason: str, **facts: str) -> dict[str, Any]:
        record: dict[str, Any] = {
            "schema_version": _ASSESSMENT_SCHEMA,
            "status": status, "reason": reason,
            "scope": "declared_actor_role_binding",
            "identity_id": identity_id, "collective_id": collective_id,
            "collection_digest": composition.collection_digest,
            "selected_evidence_digest": (expected_evidence_digest
                if type(expected_evidence_digest) is str
                and _HASH.fullmatch(expected_evidence_digest) else None),
            "human_authenticity": "NOT_ESTABLISHED",
            "role_authority": "NOT_ESTABLISHED",
            "evidence_ref_resolution": "NOT_ESTABLISHED",
            "occupancy_liveness": "NOT_ESTABLISHED",
            "privacy": "NOT_ESTABLISHED",
            "consent": "NOT_ESTABLISHED",
            "governance": "NOT_ESTABLISHED",
            "object_profile_conformance": "NOT_ESTABLISHED",
            **facts,
        }
        record["assessment_digest"] = digest(record)
        return record

    if composition.verdict.value != "PASS":
        return result(composition.verdict.value, composition.reason)
    if expected_evidence_digest is None or evidence is None:
        return result("UNKNOWN", "checker-selected evidence commitment or bytes absent")
    if type(expected_evidence_digest) is not str or not _HASH.fullmatch(expected_evidence_digest):
        return result("FAIL", "evidence commitment is not a canonical digest")
    if type(evidence) is not dict:
        return result("FAIL", "identity binding evidence fields differ")
    # Copy once before hashing and interpretation. The caller owns its mapping;
    # later edits cannot make checked bytes describe a different relation.
    evidence = evidence.copy()
    if set(evidence) != _EVIDENCE_FIELDS:
        return result("FAIL", "identity binding evidence fields differ")
    if any(type(value) is not str or not value.strip() or len(value) > 256
           for value in evidence.values()):
        return result("FAIL", "identity binding evidence has invalid or oversized text")
    observed = digest(evidence)
    if observed != expected_evidence_digest:
        return result("FAIL", "identity evidence differs from checker-selected bytes")
    if evidence["schema_version"] != _EVIDENCE_SCHEMA:
        return result("UNKNOWN", "identity binding evidence version unsupported")
    if not _HASH.fullmatch(evidence["evidence_ref"]):
        return result("FAIL", "retained evidence reference is not a canonical digest")

    index = {item.object_id: item for item in objects}
    identity = index.get(identity_id)
    collective = index.get(collective_id)
    if identity is None or identity.kind != ObjectKind.IDENTITY:
        return result("FAIL", "selected IDENTITY is absent or has another kind")
    if collective is None or collective.kind != ObjectKind.COLLECTIVE:
        return result("FAIL", "selected COLLECTIVE is absent or has another kind")
    if "binding_evidence_digest" not in identity.payload or "scope" not in identity.payload:
        return result("UNKNOWN", "IDENTITY declaration lacks evidence or scope binding")
    if identity.payload["binding_evidence_digest"] != expected_evidence_digest:
        return result("FAIL", "IDENTITY object binds different evidence bytes")

    actors = _leaves(index, identity, "actor")
    roles = _leaves(index, identity, "role")
    if len(actors) != 1 or len(roles) != 1:
        return result("FAIL", "one IDENTITY instance requires one ACTOR and one ROLE")
    actor, role = actors[0], roles[0]
    if role.object_id not in {item.object_id for item in _leaves(index, collective, "roles")}:
        return result("FAIL", "ROLE is not a member of the selected COLLECTIVE")
    represented = _leaves(index, actor, "representation")[0]
    root = _leaves(index, actor, "root_human")[0]
    required = {
        "identity_id": identity.object_id, "actor_id": actor.object_id,
        "role_id": role.object_id, "collective_id": collective.object_id,
        "representation_id": represented.object_id,
        "actor_kind": represented.kind.value, "root_human_id": root.object_id,
    }
    for field, value in required.items():
        if evidence[field] != value:
            return result("FAIL", f"identity evidence {field} differs from bound object")
    scope = evidence["scope"]
    if identity.payload["scope"] != scope:
        return result("FAIL", "IDENTITY scope differs from bound declaration")
    admitted = role.payload.get("admitted_scopes")
    if admitted is None:
        return result("UNKNOWN", "ROLE has no declared scope admission")
    if type(admitted) is not list or not admitted:
        return result("FAIL", "ROLE scope admission is malformed")
    if len(admitted) > 64:
        return result("UNKNOWN", "ROLE scope admission bound exhausted")
    if any(type(value) is not str or not value.strip() or len(value) > 256 for value in admitted):
        return result("FAIL", "ROLE scope admission is malformed")
    if scope not in admitted:
        return result("FAIL", "IDENTITY scope is outside the declared ROLE scopes")
    if represented.kind == ObjectKind.BOT:
        simulations = _leaves(index, represented, "sim")
        if scope not in {"simulation:" + item.object_id for item in simulations}:
            return result("FAIL", "BOT identity scope is outside its bound SIM")
    return result("PASS", "exact finite actor-role declaration and scope checked",
                  actor_id=actor.object_id, actor_kind=represented.kind.value,
                  representation_id=represented.object_id,
                  root_human_id=root.object_id, role_id=role.object_id,
                  declared_scope=scope)


def recheck_identity_occupancy(assessment: dict[str, Any],
                               objects: Sequence[NamespaceObject], *, identity_id: str,
                               collective_id: str, expected_digest: str | None,
                               expected_evidence_digest: str | None,
                               evidence: dict[str, Any] | None) -> dict[str, Any]:
    """Recompute every field; a self-consistent carried digest is insufficient."""
    reproduced = assess_identity_occupancy(
        objects, identity_id=identity_id, collective_id=collective_id,
        expected_digest=expected_digest,
        expected_evidence_digest=expected_evidence_digest, evidence=evidence)
    if type(assessment) is not dict or len(assessment) != len(reproduced):
        raise Refuted("identity assessment shape differs")
    if set(assessment) != set(reproduced):
        raise Refuted("identity assessment keys differ")
    for key, expected in reproduced.items():
        actual = assessment[key]
        if type(actual) is not type(expected) or (isinstance(actual, str) and len(actual) > 1024):
            raise Refuted("identity assessment field type or bound differs")
        if actual != expected:
            raise Refuted("identity assessment does not replay")
    return reproduced
