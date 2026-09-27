"""HARDWARE: finite retained device records, never physical attestation.

Terminology: central processing unit (CPU); graphics processing unit (GPU);
quantum processing unit (QPU); random-access memory (RAM). Byte capacities are bytes; slot
counts are dimensionless reservations within a named device, not equivalent
performance across devices. Times are integer microseconds on one declared clock.
"""
from __future__ import annotations

from .common import Budget, Refuted, Unavailable, digest, integer, need, obj, same, seq, text, unique

KINDS = {"CPU", "GPU", "QPU", "STORAGE", "RAM", "SENSOR", "OTHER"}
UNITS = {"MEMORY_BYTE", "STORAGE_BYTE", "COMPUTE_SLOT", "SAMPLE_SLOT"}


def _records(name, artifact, inputs, budget, *, nonempty=True):
    records = seq(need(inputs, name), budget, nonempty=nonempty)
    same(digest(records), need(artifact, name + "_digest"), name + " commitment differs")
    return records


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    if need(artifact, "scope") != "retained-hardware-records":
        raise Unavailable("physical hardware claims require a separately qualified observation mechanism")
    devices = unique(_records("devices", artifact, inputs, budget), "id")
    capacities = {}
    for identifier, record in devices.items():
        text(identifier)
        obj(record, {"id", "kind", "capacities"})
        if record["kind"] not in KINDS:
            raise Unavailable("unsupported retained device kind")
        declared = obj(record["capacities"])
        if not declared:
            raise Unavailable("no retained device capacity")
        budget.tick(len(declared))
        for unit, quantity in declared.items():
            if unit not in UNITS:
                raise Unavailable("unsupported hardware capacity unit")
            capacities[identifier, unit] = integer(quantity)
    result = {"devices": len(devices), "scope": "retained-hardware-records",
              "physical_authenticity": "NOT_ESTABLISHED", "live_availability": "NOT_ESTABLISHED",
              "credit_authority": "NOT_ESTABLISHED"}
    if check == "topology":
        edges = _records("topology", artifact, inputs, budget, nonempty=False)
        children = {key: [] for key in devices}
        degree = {key: 0 for key in devices}
        seen = set()
        for edge in edges:
            obj(edge, {"parent", "child"})
            pair = (text(edge["parent"]), text(edge["child"]))
            if pair in seen or pair[0] not in devices or pair[1] not in devices:
                raise Refuted("duplicate or unresolved topology edge")
            seen.add(pair)
            children[pair[0]].append(pair[1])
            degree[pair[1]] += 1
        ready = [key for key, value in degree.items() if value == 0]
        visited = 0
        while ready:
            parent = ready.pop()
            visited += 1
            budget.tick()
            for child in children[parent]:
                budget.tick()
                degree[child] -= 1
                if degree[child] == 0:
                    ready.append(child)
        if visited != len(devices):
            raise Refuted("retained containment topology is cyclic")
        result["edges"] = len(edges)
    elif check in {"allocations", "measurements"}:
        text(need(artifact, "clock"))
        records = unique(_records(check, artifact, inputs, budget), "id")
        events = {}
        for identifier, record in records.items():
            text(identifier)
            fields = {"id", "device", "unit", "quantity"}
            obj(record, fields | ({"start_us", "end_us"} if check == "allocations" else {"at_us"}))
            key = (text(record["device"]), text(record["unit"]))
            if key not in capacities:
                raise Refuted("record names an undeclared device or unit")
            quantity = integer(record["quantity"], 1 if check == "allocations" else 0)
            if quantity > capacities[key]:
                raise Refuted("retained quantity exceeds declared capacity")
            if check == "measurements":
                integer(record["at_us"])
            else:
                start, end = integer(record["start_us"]), integer(record["end_us"])
                if start >= end:
                    raise Refuted("allocation interval must be nonempty")
                events.setdefault(key, []).extend([(start, quantity), (end, -quantity)])
        for key, changes in events.items():
            # Half-open intervals: releases precede acquisitions at an equal instant.
            budget.tick(len(changes) * max(1, len(changes).bit_length()))
            occupancy = 0
            for _, delta in sorted(changes):
                occupancy += delta
                if not 0 <= occupancy <= capacities[key]:
                    raise Refuted("overlapping allocations exceed declared capacity")
            if occupancy != 0:
                raise Refuted("allocation sweep does not close")
        result[check] = len(records)
    elif check != "inventory":
        raise Unavailable("unsupported hardware check")
    return result
