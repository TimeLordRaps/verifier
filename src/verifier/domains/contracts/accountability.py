"""Bound hardware-ownership eligibility in the new object hierarchy.

Verifier Standard (VSTD) declaration checks never grant legal title, human
authenticity, control authority, or physical host containment. A HUMAN may be
the declared owner of physical HARDWARE. An AGENT may not own HARDWARE. A BOT
may own only virtual HARDWARE inside its own, replayed finite isolated SIM
(simulation). All counts are dimensionless. This is an accountability-contract
increment, not complete object-profile conformance or runtime authorization.
"""
from __future__ import annotations

from typing import Any, Sequence

from verifier.core.namespace import DEFAULT_MAX_OBJECTS, NamespaceObject, ObjectKind, assess_composition

from ..common import Refuted, Unavailable, digest
from .sim_isolation import assess_sim_isolation


def _targets(index: dict[str, NamespaceObject], item: NamespaceObject, role: str) -> list[NamespaceObject]:
    """Expand already-validated graph substitutions; never resolve external data."""
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


def assess_hardware_ownership(objects: Sequence[NamespaceObject], *, owner_id: str,
                              expected_digest: str | None,
                              isolation_evidence: dict[str, Any] | None = None,
                              isolation_binding: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recheck a bound OWNER relation against the hardware-kind restrictions.

The caller selects the complete collection commitment and any simulation
binding. PASS establishes eligibility of these exact declarations only. No
status supplied by the owner, actor, hardware or simulation is trusted.
"""
    if type(owner_id) is not str or not owner_id.strip() or len(owner_id) > 256:
        raise ValueError("selected OWNER needs a bounded nonempty identifier")
    # Keep replay and ownership resolution on the same immutable collection.
    # Larger or invalid inputs go straight to the composition checker's bound.
    if isinstance(objects, (list, tuple)) and len(objects) <= DEFAULT_MAX_OBJECTS:
        objects = tuple(objects)
    composition = assess_composition(objects, expected_digest=expected_digest)

    def result(status: str, reason: str, **facts: Any) -> dict[str, Any]:
        record = {"schema_version": "verifier-hardware-ownership-assessment-1",
                  "status": status, "reason": reason, "owner_id": owner_id,
                  "collection_digest": composition.collection_digest,
                  "scope": "declared_hardware_ownership_eligibility",
                  "authority": "NOT_ESTABLISHED", "human_authenticity": "NOT_ESTABLISHED",
                  "physical_host_containment": "NOT_ESTABLISHED",
                  "object_profile_conformance": "NOT_ESTABLISHED", **facts}
        record["assessment_digest"] = digest(record)
        return record

    if composition.verdict.value != "PASS":
        return result(composition.verdict.value, composition.reason)
    index = {item.object_id: item for item in objects}
    owner = index.get(owner_id)
    if owner is None or owner.kind != ObjectKind.OWNER:
        return result("FAIL", "selected OWNER does not resolve in the bound collection")
    actors = _targets(index, owner, "actor")
    if len(actors) != 1:
        return result("FAIL", "one ownership relation requires one accountable actor")
    actor = actors[0]
    represented = _targets(index, actor, "representation")[0]
    root = _targets(index, actor, "root_human")[0]
    hardware = _targets(index, owner, "object")
    facts = {"actor_id": actor.object_id, "actor_kind": represented.kind.value,
             "root_human_id": root.object_id, "hardware_ids": [item.object_id for item in hardware]}
    if any(item.kind != ObjectKind.HARDWARE for item in hardware):
        return result("UNKNOWN", "this mechanism applies only to hardware ownership", **facts)
    if represented.kind == ObjectKind.AGENT:
        return result("FAIL", "an AGENT cannot own HARDWARE, including virtual HARDWARE", **facts)
    realms = [item.payload.get("realm") for item in hardware]
    if any(realm not in ("physical", "virtual") for realm in realms):
        return result("UNKNOWN", "hardware physical or virtual realm is not specified", **facts)
    if represented.kind == ObjectKind.HUMAN:
        return result("PASS", "HUMAN declaration satisfies the hardware-kind restriction", **facts)
    if any(realm != "virtual" for realm in realms):
        return result("FAIL", "a BOT cannot own physical HARDWARE", **facts)
    if isolation_evidence is None or isolation_binding is None:
        return result("UNKNOWN", "BOT virtual ownership requires retained finite isolation evidence", **facts)

    # A carried PASS is insufficient: reconstruct the finite reachable transition
    # closure on every call, under the caller-selected expected evidence binding.
    try:
        isolation = assess_sim_isolation(isolation_evidence, expected_binding=isolation_binding)
    except Unavailable as exc:
        return result("UNKNOWN", str(exc), **facts)
    except (Refuted, TypeError, ValueError) as exc:
        return result("FAIL", str(exc), **facts)
    facts["isolation_assessment_digest"] = isolation["assessment_digest"]
    if isolation["status"] != "PASS":
        return result(isolation["status"], isolation["reason"], **facts)
    simulations = {item.object_id: item for item in _targets(index, represented, "sim")}
    sim_id = isolation["sim_id"]
    simulation = simulations.get(sim_id)
    if simulation is None:
        return result("FAIL", "isolation evidence belongs to a different BOT simulation", **facts)
    expected_evidence = simulation.payload.get("isolation_evidence_digest")
    if expected_evidence is None:
        return result("UNKNOWN", "SIM object does not bind retained isolation evidence", **facts)
    if expected_evidence != isolation["evidence_digest"]:
        return result("FAIL", "SIM object and checker-selected isolation commitment differ", **facts)
    # Consume the inventory reconstructed by replay, never reread a caller-owned
    # mutable dictionary after the commitment and transition checks completed.
    resources = {row["id"]: row["kind"] for row in isolation["virtual_hardware"]}
    simulated_objects = {item.object_id for item in _targets(index, simulation, "objects")}
    for item in hardware:
        payload = item.payload
        if item.object_id not in simulated_objects:
            return result("FAIL", "owned virtual hardware is outside the bound SIM object inventory", **facts)
        if payload.get("simulation_id") != sim_id:
            return result("FAIL", "virtual hardware belongs to a different simulation", **facts)
        resource = payload.get("resource_id")
        kind = payload.get("resource_kind")
        if not isinstance(resource, str) or not isinstance(kind, str):
            return result("UNKNOWN", "virtual hardware needs its exact finite resource binding", **facts)
        if resource not in resources or resources[resource] != kind:
            return result("FAIL", "virtual hardware differs from the replayed resource inventory", **facts)
    return result("PASS", "BOT virtual hardware is bound inside its finite isolated model", **facts)


def recheck_hardware_ownership(assessment: dict[str, Any], objects: Sequence[NamespaceObject], *,
                               owner_id: str, expected_digest: str | None,
                               isolation_evidence: dict[str, Any] | None = None,
                               isolation_binding: dict[str, Any] | None = None) -> dict[str, Any]:
    """Reproduce every result field; a recomputed digest alone is insufficient."""
    reproduced = assess_hardware_ownership(objects, owner_id=owner_id,
        expected_digest=expected_digest, isolation_evidence=isolation_evidence,
        isolation_binding=isolation_binding)
    if type(assessment) is not dict or set(assessment) != set(reproduced):
        raise Refuted("hardware ownership assessment shape differs")
    # The result is deliberately flat: strings, null and bounded string lists.
    # Compare its exact types before values without serializing an attacker-sized
    # carried result or allowing Python's boolean/integer equality coercion.
    for key, expected in reproduced.items():
        actual = assessment[key]
        if type(actual) is not type(expected):
            raise Refuted("hardware ownership assessment type differs")
        if isinstance(expected, list) and (len(actual) != len(expected)
                or any(type(item) is not str for item in actual)):
            raise Refuted("hardware ownership assessment list differs")
        if actual != expected:
            raise Refuted("hardware ownership assessment does not replay")
    return reproduced
