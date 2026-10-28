# Acronyms: conjunctive normal form (CNF).
"""Strict generic finite-domain route language and deterministic CNF compiler."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations, product
from typing import Any, Mapping, Sequence

from .canonical import canonical_digest


ROUTE_VERSION = "vgsat-route-0.1"
MAX_SLOTS = 128
MAX_DOMAIN_VALUES = 256
MAX_CONSTRAINTS = 20_000
MAX_CLAUSES = 500_000


class RouteError(ValueError):
    """A route is malformed or exceeds a declared experiment bound."""


@dataclass(frozen=True)
class CompiledRoute:
    """A validated route compiled to a deterministic one-hot CNF formula."""

    route: dict[str, Any]
    route_digest: str
    clauses: tuple[tuple[int, ...], ...]
    variable_by_value: dict[tuple[str, int], int]
    value_by_variable: dict[int, tuple[str, int]]
    domains: dict[str, tuple[int, ...]]
    decoder: dict[str, Any]

    @property
    def variable_count(self) -> int:
        return len(self.variable_by_value)

    @property
    def clause_count(self) -> int:
        return len(self.clauses)

    @property
    def formula_digest(self) -> str:
        return canonical_digest(self.formula_payload())

    def formula_payload(self) -> dict[str, Any]:
        return {
            "encoding": "finite-domain-one-hot-v1",
            "route_digest": self.route_digest,
            "variable_count": self.variable_count,
            "clauses": [list(clause) for clause in self.clauses],
            "variables": [
                {"variable": var, "slot": slot, "value": value}
                for (slot, value), var in sorted(
                    self.variable_by_value.items(), key=lambda item: item[1]
                )
            ],
            "decoder": self.decoder,
        }

    def decode_model(self, model: Sequence[int]) -> dict[str, Any]:
        positive = {literal for literal in model if literal > 0}
        assignment: dict[str, int] = {}
        for slot, domain in self.domains.items():
            chosen = [value for value in domain if self.variable_by_value[(slot, value)] in positive]
            if len(chosen) != 1:
                raise RouteError(f"model does not select exactly one value for slot {slot}")
            assignment[slot] = chosen[0]

        if self.decoder["kind"] == "list_field":
            return {
                self.decoder["field"]: [assignment[slot] for slot in self.decoder["slots"]]
            }
        if self.decoder["kind"] == "object_fields":
            return {
                field: assignment[slot]
                for field, slot in self.decoder["fields"].items()
            }
        raise RouteError("unsupported decoder kind")


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RouteError(f"{label} must be an object")
    return value


def _require_exact_keys(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    extras = set(value) - allowed
    if extras:
        raise RouteError(f"{label} has unsupported fields: {sorted(extras)}")


def _slot_name(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 80:
        raise RouteError("slot identifiers must be nonempty strings of at most 80 characters")
    if not all(char.isalnum() or char in "_-" for char in value):
        raise RouteError(f"invalid slot identifier: {value!r}")
    return value


def _int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RouteError(f"{label} must be an integer")
    return value


def _pair(value: Any, label: str) -> tuple[int, int]:
    if not isinstance(value, list) or len(value) != 2:
        raise RouteError(f"{label} must be a two-integer array")
    return (_int(value[0], label), _int(value[1], label))


def _validate_decoder(decoder_raw: Any, slots: set[str]) -> dict[str, Any]:
    decoder = dict(_require_mapping(decoder_raw, "decoder"))
    kind = decoder.get("kind")
    if kind == "list_field":
        _require_exact_keys(decoder, {"kind", "field", "slots"}, "decoder")
        field = decoder.get("field")
        sequence = decoder.get("slots")
        if not isinstance(field, str) or not field:
            raise RouteError("list_field decoder requires a nonempty field")
        if not isinstance(sequence, list) or not sequence:
            raise RouteError("list_field decoder requires a nonempty slots array")
        decoded_slots = [_slot_name(slot) for slot in sequence]
        if len(set(decoded_slots)) != len(decoded_slots):
            raise RouteError("decoder slots must not repeat")
        if set(decoded_slots) != slots:
            raise RouteError("decoder must consume every route slot exactly once")
        return {"kind": kind, "field": field, "slots": decoded_slots}
    if kind == "object_fields":
        _require_exact_keys(decoder, {"kind", "fields"}, "decoder")
        fields = decoder.get("fields")
        if not isinstance(fields, Mapping) or not fields:
            raise RouteError("object_fields decoder requires a nonempty fields object")
        normalized: dict[str, str] = {}
        for field, slot in fields.items():
            if not isinstance(field, str) or not field:
                raise RouteError("decoder field names must be nonempty strings")
            normalized[field] = _slot_name(slot)
        if len(set(normalized.values())) != len(normalized):
            raise RouteError("decoder slots must not repeat")
        if set(normalized.values()) != slots:
            raise RouteError("decoder must consume every route slot exactly once")
        return {"kind": kind, "fields": normalized}
    raise RouteError("decoder kind must be list_field or object_fields")


def compile_route(route_raw: Any) -> CompiledRoute:
    """Validate a generic route and compile it to a one-hot CNF formula.

    The accepted language is intentionally closed. Unknown fields or constraint
    kinds fail rather than being ignored.
    """

    route_obj = _require_mapping(route_raw, "route")
    _require_exact_keys(
        route_obj,
        {"route_version", "slots", "constraints", "decoder", "declared_statement"},
        "route",
    )
    if route_obj.get("route_version") != ROUTE_VERSION:
        raise RouteError(f"route_version must be {ROUTE_VERSION}")
    declared_statement = route_obj.get("declared_statement")
    if not isinstance(declared_statement, str) or not declared_statement.strip():
        raise RouteError("declared_statement must be a nonempty string")

    slots_raw = route_obj.get("slots")
    if not isinstance(slots_raw, list) or not slots_raw:
        raise RouteError("slots must be a nonempty array")
    if len(slots_raw) > MAX_SLOTS:
        raise RouteError(f"slot count exceeds {MAX_SLOTS}")

    domains: dict[str, tuple[int, ...]] = {}
    normalized_slots: list[dict[str, Any]] = []
    for index, slot_raw in enumerate(slots_raw):
        slot = _require_mapping(slot_raw, f"slots[{index}]")
        _require_exact_keys(slot, {"id", "domain"}, f"slots[{index}]")
        name = _slot_name(slot.get("id"))
        if name in domains:
            raise RouteError(f"duplicate slot identifier: {name}")
        domain_raw = slot.get("domain")
        if not isinstance(domain_raw, list) or not domain_raw:
            raise RouteError(f"slot {name} requires a nonempty integer domain")
        values = tuple(sorted({_int(value, f"domain value for {name}") for value in domain_raw}))
        if len(values) != len(domain_raw):
            raise RouteError(f"slot {name} domain must not contain duplicates")
        if len(values) > MAX_DOMAIN_VALUES:
            raise RouteError(f"slot {name} domain exceeds {MAX_DOMAIN_VALUES} values")
        domains[name] = values
        normalized_slots.append({"id": name, "domain": list(values)})

    decoder = _validate_decoder(route_obj.get("decoder"), set(domains))
    constraints_raw = route_obj.get("constraints")
    if not isinstance(constraints_raw, list):
        raise RouteError("constraints must be an array")
    if len(constraints_raw) > MAX_CONSTRAINTS:
        raise RouteError(f"constraint count exceeds {MAX_CONSTRAINTS}")

    variable_by_value: dict[tuple[str, int], int] = {}
    value_by_variable: dict[int, tuple[str, int]] = {}
    next_variable = 1
    for slot, values in domains.items():
        for value in values:
            variable_by_value[(slot, value)] = next_variable
            value_by_variable[next_variable] = (slot, value)
            next_variable += 1

    clauses: list[tuple[int, ...]] = []

    def literal(slot: str, value: int) -> int:
        if slot not in domains:
            raise RouteError(f"constraint references unknown slot: {slot}")
        try:
            return variable_by_value[(slot, value)]
        except KeyError as exc:
            raise RouteError(f"value {value} is outside domain for slot {slot}") from exc

    def append_clause(*values: int) -> None:
        clauses.append(tuple(values))
        if len(clauses) > MAX_CLAUSES:
            raise RouteError(f"compiled formula exceeds {MAX_CLAUSES} clauses")

    # One-hot domain constraints.
    for slot, values in domains.items():
        append_clause(*(literal(slot, value) for value in values))
        for left, right in combinations(values, 2):
            append_clause(-literal(slot, left), -literal(slot, right))

    normalized_constraints: list[dict[str, Any]] = []
    for index, constraint_raw in enumerate(constraints_raw):
        constraint = dict(_require_mapping(constraint_raw, f"constraints[{index}]"))
        kind = constraint.get("kind")
        if kind == "fixed":
            _require_exact_keys(constraint, {"kind", "slot", "value"}, f"constraints[{index}]")
            slot = _slot_name(constraint.get("slot"))
            value = _int(constraint.get("value"), "fixed value")
            append_clause(literal(slot, value))
            normalized_constraints.append({"kind": kind, "slot": slot, "value": value})
        elif kind == "allowed_values":
            _require_exact_keys(constraint, {"kind", "slot", "values"}, f"constraints[{index}]")
            slot = _slot_name(constraint.get("slot"))
            values_raw = constraint.get("values")
            if not isinstance(values_raw, list) or not values_raw:
                raise RouteError("allowed_values requires a nonempty values array")
            values = sorted({_int(value, "allowed value") for value in values_raw})
            if len(values) != len(values_raw):
                raise RouteError("allowed_values must not contain duplicates")
            append_clause(*(literal(slot, value) for value in values))
            normalized_constraints.append({"kind": kind, "slot": slot, "values": values})
        elif kind == "all_different":
            _require_exact_keys(constraint, {"kind", "slots"}, f"constraints[{index}]")
            members_raw = constraint.get("slots")
            if not isinstance(members_raw, list) or len(members_raw) < 2:
                raise RouteError("all_different requires at least two slots")
            members = [_slot_name(slot) for slot in members_raw]
            if len(set(members)) != len(members):
                raise RouteError("all_different slots must not repeat")
            if any(slot not in domains for slot in members):
                raise RouteError("all_different references an unknown slot")
            for left, right in combinations(members, 2):
                for value in sorted(set(domains[left]) & set(domains[right])):
                    append_clause(-literal(left, value), -literal(right, value))
            normalized_constraints.append({"kind": kind, "slots": members})
        elif kind == "forbidden_pair":
            _require_exact_keys(
                constraint,
                {"kind", "left_slot", "left_value", "right_slot", "right_value"},
                f"constraints[{index}]",
            )
            left_slot = _slot_name(constraint.get("left_slot"))
            right_slot = _slot_name(constraint.get("right_slot"))
            left_value = _int(constraint.get("left_value"), "left_value")
            right_value = _int(constraint.get("right_value"), "right_value")
            append_clause(-literal(left_slot, left_value), -literal(right_slot, right_value))
            normalized_constraints.append(
                {
                    "kind": kind,
                    "left_slot": left_slot,
                    "left_value": left_value,
                    "right_slot": right_slot,
                    "right_value": right_value,
                }
            )
        elif kind == "allowed_pairs":
            _require_exact_keys(
                constraint, {"kind", "left_slot", "right_slot", "pairs"}, f"constraints[{index}]"
            )
            left_slot = _slot_name(constraint.get("left_slot"))
            right_slot = _slot_name(constraint.get("right_slot"))
            if left_slot not in domains or right_slot not in domains:
                raise RouteError("allowed_pairs references an unknown slot")
            pairs_raw = constraint.get("pairs")
            if not isinstance(pairs_raw, list) or not pairs_raw:
                raise RouteError("allowed_pairs requires a nonempty pairs array")
            pairs = sorted({_pair(pair, "allowed pair") for pair in pairs_raw})
            if len(pairs) != len(pairs_raw):
                raise RouteError("allowed_pairs must not contain duplicates")
            allowed = set(pairs)
            for left_value, right_value in product(domains[left_slot], domains[right_slot]):
                if (left_value, right_value) not in allowed:
                    append_clause(
                        -literal(left_slot, left_value), -literal(right_slot, right_value)
                    )
            normalized_constraints.append(
                {
                    "kind": kind,
                    "left_slot": left_slot,
                    "right_slot": right_slot,
                    "pairs": [list(pair) for pair in pairs],
                }
            )
        elif kind == "product_equals":
            _require_exact_keys(
                constraint, {"kind", "left_slot", "right_slot", "target"}, f"constraints[{index}]"
            )
            left_slot = _slot_name(constraint.get("left_slot"))
            right_slot = _slot_name(constraint.get("right_slot"))
            target = _int(constraint.get("target"), "product target")
            if left_slot not in domains or right_slot not in domains:
                raise RouteError("product_equals references an unknown slot")
            for left_value, right_value in product(domains[left_slot], domains[right_slot]):
                if left_value * right_value != target:
                    append_clause(
                        -literal(left_slot, left_value), -literal(right_slot, right_value)
                    )
            normalized_constraints.append(
                {
                    "kind": kind,
                    "left_slot": left_slot,
                    "right_slot": right_slot,
                    "target": target,
                }
            )
        else:
            raise RouteError(f"unsupported constraint kind: {kind!r}")

    normalized_route = {
        "route_version": ROUTE_VERSION,
        "declared_statement": declared_statement.strip(),
        "slots": normalized_slots,
        "constraints": normalized_constraints,
        "decoder": decoder,
    }
    return CompiledRoute(
        route=normalized_route,
        route_digest=canonical_digest(normalized_route),
        clauses=tuple(clauses),
        variable_by_value=variable_by_value,
        value_by_variable=value_by_variable,
        domains=domains,
        decoder=decoder,
    )
