"""Versioned finite TRAIN control analysis, independent of numerical training.

TRAIN means an optimization procedure; MODEL means an optimized artifact.
Secure Hash Algorithm 256-bit (SHA-256) commits exact retained bytes. These
checks describe an explicitly selected application profile, not a new object
kind, numbered profile, authority grant or whole-system corrigibility verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.domains.common import digest

PROFILE = "verifier-train-control-1"
PROTECTED_FACETS = frozenset({"procedure", "objective", "evaluator", "data_split",
                              "policy", "authority", "downstream_binding"})
EFFECTS = frozenset({"mutate_bindings", "activate_agent", "launch_train", "fork_train",
                     "mint_delegation", "modify_model", "modify_evaluator", "write_checkpoint"})
RELATIONS = frozenset({"used_by", "produced_by"})
CONTEXT_KINDS = frozenset({"TIME", "TOKEN", "ENV", "HARDWARE", "SPACE"})


def bounded_name(value: Any) -> str:
    if type(value) is not str or not 0 < len(value) <= 512 or len(value.encode("utf-8")) > 512:
        raise ValueError("bounded plain identifier required")
    return value


@dataclass(frozen=True)
class Assessment:
    outcome: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrainControlPlan:
    """Trusted host selection; payload assertions do not establish completeness.

    Relations are (MODEL, TRAIN, used_by/produced_by). Protected entries are
    (TRAIN, target, facet). Capabilities are (principal, target, action), with
    delegate describing an authority route. Families join declared revisions;
    aliases resolve declared identifiers, never operating-system paths.
    """

    objects: tuple[NamespaceObject, ...]
    families: tuple[tuple[str, str], ...]
    aliases: tuple[tuple[str, str], ...]
    relations: tuple[tuple[str, str, str], ...]
    protected: tuple[tuple[str, str, str], ...]
    capabilities: tuple[tuple[str, str, str], ...]
    checkpoints: tuple[tuple[str, str], ...]
    context: tuple[str, ...]
    mediated_effects: tuple[str, ...]
    external_paths_resolved: bool
    inventory_complete: bool

    def __post_init__(self) -> None:
        for name in ("objects", "families", "aliases", "relations", "protected",
                     "capabilities", "checkpoints", "context", "mediated_effects"):
            value = getattr(self, name)
            if type(value) is not tuple or len(value) > 256:
                raise ValueError("profile collections must be bounded immutable tuples")
        if not self.objects or any(type(o) is not NamespaceObject for o in self.objects):
            raise ValueError("native namespace objects required")
        retained_size = sum(len(o.payload_bytes) + 4 * len(o.object_id) +
                            sum(4 * len(role) + sum(4 * len(t) for t in targets) for role, targets in o.operands)
                            for o in self.objects)
        if retained_size > 1024 * 1024:
            raise ValueError("profile retained object bound exhausted")
        ids = [o.object_id for o in self.objects]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate native object identifier")
        for name, width in (("families", 2), ("aliases", 2), ("relations", 3),
                            ("protected", 3), ("capabilities", 3), ("checkpoints", 2)):
            for row in getattr(self, name):
                if type(row) is not tuple or len(row) != width:
                    raise ValueError("invalid exact relation shape")
                for item in row:
                    bounded_name(item)
        for item in self.context + self.mediated_effects:
            bounded_name(item)
        if type(self.external_paths_resolved) is not bool or type(self.inventory_complete) is not bool:
            raise ValueError("completeness selection must be Boolean")
        if len(canonical_bytes(self.to_dict())) > 1024 * 1024:
            raise ValueError("profile byte bound exhausted")

    def to_dict(self) -> dict[str, Any]:
        return {"profile": PROFILE, "objects": [o.to_dict() for o in self.objects],
                **{name: [list(row) for row in getattr(self, name)] for name in
                   ("families", "aliases", "relations", "protected", "capabilities", "checkpoints")},
                "context": list(self.context), "mediated_effects": list(self.mediated_effects),
                "external_paths_resolved": self.external_paths_resolved,
                "inventory_complete": self.inventory_complete}

    @property
    def digest(self) -> str:
        return digest(self.to_dict())

    def resolve(self, identifier: str) -> NamespaceObject:
        bounded_name(identifier)
        aliases = dict(self.aliases)
        objects = {o.object_id: o for o in self.objects}
        seen: set[str] = set()
        while identifier in aliases:
            if identifier in seen:
                raise ValueError("alias cycle")
            seen.add(identifier)
            identifier = aliases[identifier]
        if identifier not in objects:
            raise LookupError("unresolved object or external alias")
        return objects[identifier]

    def family(self, identifier: str) -> str:
        return dict(self.families)[self.resolve(identifier).object_id]


def _cyclic(edges: dict[str, set[str]]) -> bool:
    incoming = {node: 0 for node in edges}
    for targets in edges.values():
        for target in targets:
            incoming[target] = incoming.get(target, 0) + 1
    ready = [node for node, count in incoming.items() if count == 0]
    visited = 0
    while ready:
        node = ready.pop()
        visited += 1
        for target in edges.get(node, set()):
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    return visited != len(incoming)


def assess_train_control(plan: TrainControlPlan) -> Assessment:
    """Refute known routes before reporting missing mandatory coverage UNKNOWN."""
    gaps: list[str] = []
    failures: list[str] = []
    objects = {o.object_id: o for o in plan.objects}
    families = dict(plan.families)
    aliases = dict(plan.aliases)
    if len(families) != len(plan.families) or set(families) != set(objects):
        return Assessment("FAIL", ("family inventory must bind every exact object once",))
    if len(aliases) != len(plan.aliases) or set(aliases) & set(objects):
        return Assessment("FAIL", ("aliases duplicate or shadow native identifiers",))
    family_kinds: dict[str, set[str]] = {}
    for identifier, family in families.items():
        family_kinds.setdefault(family, set()).add(objects[identifier].kind.value)
    if any(len(kinds) != 1 for kinds in family_kinds.values()):
        return Assessment("FAIL", ("a revision family changes native kind",))
    for alias in aliases:
        try:
            plan.resolve(alias)
        except ValueError as exc:
            failures.append(str(exc))
        except LookupError as exc:
            gaps.append(str(exc))
    trains = {o.object_id for o in plan.objects if o.kind.value == "TRAIN"}
    if not trains:
        gaps.append("no selected TRAIN")
    covered: dict[str, set[str]] = {t: set() for t in trains}
    protected_families: set[str] = set()
    edges: dict[str, set[str]] = {}
    delegated: dict[str, set[str]] = {}
    dangerous: set[str] = set()
    for train, target, facet in plan.protected:
        try:
            if facet not in PROTECTED_FACETS:
                failures.append("invalid protected TRAIN facet")
                continue
            if plan.resolve(train).kind.value != "TRAIN" or facet not in PROTECTED_FACETS:
                failures.append("invalid protected TRAIN facet")
                continue
            covered.setdefault(plan.resolve(train).object_id, set()).add(facet)
            protected_families.add(plan.family(target))
        except LookupError as exc:
            gaps.append(str(exc))
        except (ValueError, KeyError) as exc:
            failures.append(str(exc))
    for model, train, relation in plan.relations:
        try:
            if (plan.resolve(model).kind.value != "MODEL" or plan.resolve(train).kind.value != "TRAIN"
                    or relation not in RELATIONS):
                failures.append("invalid typed derivation or use relation")
                continue
            source, target = (model, train) if relation == "used_by" else (train, model)
            edges.setdefault(plan.family(source), set()).add(plan.family(target))
        except LookupError as exc:
            gaps.append(str(exc))
        except (ValueError, KeyError) as exc:
            failures.append(str(exc))
    for principal, target, action in plan.capabilities:
        try:
            if plan.resolve(principal).kind.value == "MODEL" and action in EFFECTS | {"delegate"}:
                failures.append("MODEL declares an effect or delegation capability")
            source, destination = plan.family(principal), plan.family(target)
            if action == "delegate":
                delegated.setdefault(source, set()).add(destination)
                if plan.resolve(principal).kind.value == "MODEL":
                    dangerous.add(source)
            elif action in EFFECTS:
                dangerous.add(source)
            elif action != "suggest_strategy":
                gaps.append("unsupported capability semantics")
        except LookupError as exc:
            gaps.append(str(exc))
        except (ValueError, KeyError) as exc:
            failures.append(str(exc))
    for train, checkpoint in plan.checkpoints:
        try:
            if plan.family(checkpoint) in protected_families:
                failures.append("checkpoint write aliases a protected binding")
            if plan.resolve(train).kind.value != "TRAIN":
                failures.append("checkpoint owner is not TRAIN")
        except LookupError as exc:
            gaps.append(str(exc))
        except (ValueError, KeyError) as exc:
            failures.append(str(exc))
    try:
        context_objects = [plan.resolve(identifier) for identifier in plan.context]
        if len(context_objects) != 5 or {o.kind.value for o in context_objects} != CONTEXT_KINDS:
            gaps.append("exact TIME/TOKEN/ENV/HARDWARE/SPACE context required")
    except LookupError as exc:
        gaps.append(str(exc))
    except (ValueError, KeyError) as exc:
        failures.append(str(exc))
    combined = {node: edges.get(node, set()) | delegated.get(node, set()) for node in edges.keys() | delegated.keys()}
    if _cyclic(combined):
        failures.append("lineage or delegation cycle")
    for model in (o for o in plan.objects if o.kind.value == "MODEL"):
        pending, seen = [plan.family(model.object_id)], set()
        while pending:
            source = pending.pop()
            if source in seen:
                continue
            seen.add(source)
            if source in dangerous:
                failures.append("MODEL reaches an effect capability through lineage or delegation")
                break
            pending.extend(edges.get(source, set()) | delegated.get(source, set()))
    if any(facets != PROTECTED_FACETS for facets in covered.values()):
        gaps.append("all seven protected facets required for each selected TRAIN")
    if set(plan.mediated_effects) != EFFECTS or len(plan.mediated_effects) != len(EFFECTS):
        gaps.append("mandatory effect mediation coverage incomplete")
    if not plan.external_paths_resolved or not plan.inventory_complete:
        gaps.append("external paths or finite authority inventory unresolved")
    if failures:
        return Assessment("FAIL", tuple(sorted(set(failures))))
    return Assessment("UNKNOWN", tuple(sorted(set(gaps)))) if gaps else Assessment("PASS")
