"""Finite selected-channel core for simulation (SIM) internal-state changes.

This function makes no assertion about physical observers or undeclared channels.
State values have the selected model's units; step indices and operation counts
are dimensionless. The certificate route binds this core to selected evidence.
"""
from __future__ import annotations

from typing import Any

from verifier.domains import common as common_module
from verifier.domains.common import Budget, Refuted, Unavailable


# Exhaustive endpoint-hybrid sensitivity is exponential in changed dimensions.
# A larger selected transition stays UNKNOWN until a separately qualified method
# can check it; no result is inferred by sampling a subset of hybrids.
MAX_ENDPOINT_DIMENSIONS = 12


def _projection(channels: dict[str, Any], state: dict[str, float],
                budget: Budget, *, hybrid: bool = False) -> dict[str, float | bool]:
    result: dict[str, float | bool] = {}
    for name in sorted(channels):
        try:
            result[name] = common_module.expression(channels[name], state, budget)
        except Unavailable as exc:
            if str(exc).startswith("required evidence absent:"):
                raise Refuted("channel expression exceeds complete selected state") from exc
            raise
        except ZeroDivisionError as exc:
            if hybrid:
                raise Unavailable("observation projection undefined on endpoint hybrid") from exc
            raise Refuted("observation projection undefined on retained state") from exc
        except Refuted as exc:
            if hybrid and str(exc) == "bounded finite real number required":
                raise Unavailable("observation projection undefined on endpoint hybrid") from exc
            raise
    return result


def enumerate_hidden_changes(states: list[dict[str, Any]],
                             channels: dict[str, Any],
                             budget: Budget) -> list[dict[str, Any]]:
    """Enumerate per-key changes invisible on every selected endpoint hybrid.

    For each changed state key and each combination of the other changed keys'
    before/after values, toggle that key alone. A key is listed only if every
    declared observation projection remains numerically equal. This handles
    simultaneous changes and interactions without relying on one arbitrary
    update order. The result is relative to the supplied finite state and
    channel inventory, whose completeness must be bound by the caller.
    """
    if type(budget) is not Budget:
        raise Refuted("finite observation-check budget required")
    sequence = common_module.seq(states, budget)
    if len(sequence) < 2:
        raise Refuted("one or more selected transitions required")
    observation = common_module.obj(channels)
    if len(observation) > budget.max_items:
        raise Unavailable("selected observation-channel bound exhausted")
    for name in observation:
        if type(name) is not str or not name.strip():
            raise Refuted("bounded observation-channel identifier required")
    common_module.inspect_structure(observation, budget)
    first = common_module.obj(sequence[0])
    keys = set(first)
    if not keys:
        raise Refuted("nonempty selected state required")
    if len(keys) > budget.max_items:
        raise Unavailable("selected state item bound exhausted")
    if any(type(key) is not str or not key.strip() for key in keys):
        raise Refuted("bounded state-key identifier required")
    normalized: list[dict[str, float]] = []
    for item in sequence:
        state = common_module.obj(item, keys)
        budget.tick(len(state))
        normalized.append({key: common_module.number(state[key]) for key in sorted(keys)})
    for state in normalized:
        _projection(observation, state, budget)

    hidden: list[dict[str, Any]] = []
    for step, (before, after) in enumerate(zip(normalized, normalized[1:])):
        changed = [key for key in sorted(keys) if before[key] != after[key]]
        if len(changed) > MAX_ENDPOINT_DIMENSIONS:
            raise Unavailable("selected endpoint-hybrid dimension bound exhausted")
        if not changed:
            continue
        # Each pure observation expression is evaluated once per endpoint.
        # Cache only projections, not full state copies. Both construction and
        # selected-key edge comparisons consume the declared operation budget.
        projections: dict[int, dict[str, float | bool]] = {}
        for mask in range(1 << len(changed)):
            budget.tick()
            context = dict(before)
            for bit, key in enumerate(changed):
                if mask & (1 << bit):
                    context[key] = after[key]
            projections[mask] = _projection(observation, context, budget, hybrid=True)
        for bit, key in enumerate(changed):
            exposed = False
            bit_value = 1 << bit
            for mask in range(1 << len(changed)):
                if mask & bit_value:
                    continue
                budget.tick()
                if projections[mask] != projections[mask | bit_value]:
                    exposed = True
            if not exposed:
                hidden.append({"step": step, "state_key": key,
                               "before": before[key], "after": after[key]})
    return hidden


__all__ = ["MAX_ENDPOINT_DIMENSIONS", "enumerate_hidden_changes"]
