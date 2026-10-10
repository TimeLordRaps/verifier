"""Bounded COLLECTIVE role-graph declaration checks.

A graph edge states structure only. It cannot prove authority, seat occupancy,
natural-person separation, legal existence, consent or a collective decision.
"""
from __future__ import annotations

from typing import Any

from .common import Budget, Refuted, Unavailable, digest, need, obj, same, seq, text


RELATIONS = frozenset({"reports-to", "delegates-to", "must-countersign"})


def _names(value: Any, budget: Budget, *, nonempty: bool = False) -> list[str]:
    names = [text(item) for item in seq(value, budget, nonempty=nonempty)]
    if len(set(names)) != len(names):
        raise Refuted("duplicate collective class or facet")
    return names


def _graph(artifact: dict, inputs: dict, budget: Budget) -> dict:
    text(need(artifact, "collective_id"))
    text(need(artifact, "coordinate"))
    roles = _names(need(artifact, "role_classes"), budget, nonempty=True)
    relations = _names(need(artifact, "relation_types"), budget)
    if not set(relations) <= RELATIONS:
        raise Refuted("collective declares an unsupported relation type")
    inside = _names(need(artifact, "inside"), budget)
    outside = _names(need(artifact, "outside"), budget)
    _names(need(artifact, "decision_classes"), budget)
    if set(inside) != set(roles) or set(inside) & set(outside):
        raise Refuted("collective boundary differs from its role set")
    edges = seq(need(inputs, "role_graph"), budget, nonempty=False)
    same(digest(edges), need(artifact, "role_graph_digest"), "collective role graph differs")
    vertices = set(inside) | set(outside)
    seen: set[tuple[str, str, str]] = set()
    for raw in edges:
        edge = obj(raw, {"source", "target", "relation"})
        source, target, relation = (text(edge[k]) for k in ("source", "target", "relation"))
        if source not in vertices or target not in vertices:
            raise Refuted("collective edge references an undeclared role class")
        if relation not in relations:
            raise Refuted("collective edge has an undeclared relation type")
        key = (source, target, relation)
        if key in seen:
            raise Refuted("duplicate collective relation")
        seen.add(key)
    return {"role_classes": len(roles), "boundary_external_classes": len(outside),
            "relations": len(edges), "decision_classes_declared_only": True,
            "occupancy_or_authority_established": False}


def _decisions(artifact: dict, inputs: dict, budget: Budget) -> dict:
    _graph(artifact, inputs, budget)
    roles = set(_names(need(artifact, "role_classes"), budget, nonempty=True))
    decision_classes = set(_names(need(artifact, "decision_classes"), budget))
    policy = obj(need(artifact, "assembly_policy"))
    if set(policy) != decision_classes:
        raise Refuted("collective assembly policy does not cover declared decision classes")
    required: dict[str, set[str]] = {}
    for decision_class, rule in policy.items():
        role_ids = set(_names(need(obj(rule, {"required_roles"}), "required_roles"),
                              budget, nonempty=True))
        if not role_ids <= roles:
            raise Refuted("collective assembly policy names a role outside the graph")
        required[decision_class] = role_ids

    role_decisions = seq(need(inputs, "role_decisions"), budget)
    collective_decisions = seq(need(inputs, "collective_decisions"), budget)
    same(digest(role_decisions), need(artifact, "role_decisions_digest"),
         "collective role decision trace differs")
    same(digest(collective_decisions), need(artifact, "collective_decisions_digest"),
         "collective decision trace differs")
    recorded: dict[str, dict] = {}
    for position, raw in enumerate(role_decisions):
        row = obj(raw, {"position", "decision_id", "role_class_id", "decision_class", "bearer_id"})
        if type(row["position"]) is not int or row["position"] != position:
            raise Refuted("role decisions are not contiguous")
        identifier = text(row["decision_id"])
        if identifier in recorded:
            raise Refuted("duplicate role decision identifier")
        if text(row["role_class_id"]) not in roles:
            raise Refuted("role decision names a class outside the collective")
        if text(row["decision_class"]) not in decision_classes:
            raise Refuted("role decision has an undeclared decision class")
        text(row["bearer_id"])  # Declaration only; no personhood or occupancy inference.
        recorded[identifier] = row

    used: set[str] = set()
    collective_ids: set[str] = set()
    for raw in collective_decisions:
        row = obj(raw, {"decision_id", "decision_class", "component_decision_ids"})
        identifier = text(row["decision_id"])
        decision_class = text(row["decision_class"])
        if identifier in collective_ids:
            raise Refuted("duplicate collective decision identifier")
        collective_ids.add(identifier)
        if decision_class not in required:
            raise Refuted("collective decision has an undeclared decision class")
        components = _names(row["component_decision_ids"], budget, nonempty=True)
        if set(components) & used:
            raise Refuted("role decision reused by split collective decisions")
        used.update(components)
        if any(component not in recorded for component in components):
            raise Refuted("collective decision cites an absent role decision")
        if any(recorded[component]["decision_class"] != decision_class for component in components):
            raise Refuted("collective decision mixes decision classes")
        component_roles = {recorded[component]["role_class_id"] for component in components}
        if len(component_roles) != len(components) or component_roles != required[decision_class]:
            raise Refuted("collective decision violates its declared assembly policy")
    return {"collective_decisions_replayed": len(collective_decisions),
            "role_decisions_referenced": len(used),
            "person_or_authority_established": False}


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, **_: Any) -> dict:
    if check == "graph":
        return _graph(artifact, inputs, budget)
    if check in ("decisions", "quorum"):
        replay = _decisions(artifact, inputs, budget)
        if check == "decisions":
            return replay
        raise Unavailable("independent role occupancy and person authority evidence required for quorum")
    raise Unavailable(f"unsupported COLLECTIVE check: {check}")
