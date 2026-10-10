"""Verifier Standard (VSTD) selected objective inventory application-profile closure.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
PASS establishes exact finite plan coverage and replay of declared applicability
rules. Normative exhaustiveness, authenticated inapplicability, native objective
truth, public proof and polished admission remain NOT_ESTABLISHED. Counts and
reserved operation units are dimensionless; transport and output limits use bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectCoordinate, ObjectKind, assess_composition
from verifier.core.receipt import strict_json_loads


CEILINGS = {"objects": 256, "profile_objectives": 8192, "expanded_objectives": 32768,
            "rule_operations": 1000000, "composition_operations": 1000000,
            "output_bytes": 8 * 1024**2}
TRANSPORT_BYTES = {"profile": 4 * 1024**2, "collection": 32 * 1024**2,
                   "request": 1024**2, "plan": 8 * 1024**2, "assessment": 8 * 1024**2}
BOUNDARY = ("Exact finite plan coverage relative to the selected objective inventory application "
            "profile and retained typed collection, with declared applicability-rule replay only. "
            "Normative inventory completeness, authenticated authority and inapplicability, native "
            "objective truth, public proof and polished admission are NOT_ESTABLISHED.")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MISSING = object()


class InventoryUnavailable(RuntimeError):
    """No complete plan can be produced within the selected admitted capacity."""


@dataclass(frozen=True)
class _Exhausted(Exception):
    resource: str


@dataclass
class _Meter:
    limit: int
    used: int = 0

    def take(self, amount: int = 1) -> None:
        if amount > self.limit - self.used:
            raise _Exhausted("rule_operations")
        self.used += amount


@dataclass(frozen=True)
class _Prepared:
    request: dict[str, Any]
    requirements: tuple[dict[str, Any], ...]
    unprofiled: tuple[str, ...]
    usage: dict[str, int] = field(default_factory=dict)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism_digest() -> str:
    """Bind the installed replay implementation and its executed source dependencies."""
    root = Path(__file__).parents[1]
    names = ("runtime/polish_inventory.py", "core/namespace.py", "core/certificate.py",
             "core/receipt.py", "standard/POLISH_INVENTORY.md", "standard/NAMESPACE_OBJECTS.md",
             "standard/META_TIERS.md", "standard/POLISHED_ARTIFACTS.md")
    return _digest(canonical_bytes({"schema_version": "verifier-polish-inventory-mechanism-1",
        "sources": {name: _digest((root / name).read_bytes()) for name in names}}))


def _keys(value: Any, fields: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(fields.split()):
        raise ValueError("unexpected fields")
    return value


def _text(value: Any, maximum: int = 256) -> str:
    if type(value) is not str or not value.strip() or len(value) > maximum:
        raise ValueError("bounded plain text required")
    return value


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError("canonical digest required")
    return value


def _admit_transport(raw: bytes, transport: str) -> None:
    if type(raw) is not bytes or len(raw) > TRANSPORT_BYTES[transport]:
        raise ValueError("immutable transport bound exceeded")


def _load(raw: bytes, transport: str) -> dict[str, Any]:
    _admit_transport(raw, transport)
    return _keys(strict_json_loads(raw.decode("utf-8")), {
        "profile": "schema_version profile_id revision kinds",
        "collection": "schema_version objects",
        "request": "schema_version root_id profile_digest collection_bytes_digest collection_digest mechanism_digest limits",
        "plan": "schema_version profile_digest collection_digest request_digest requirements",
    }[transport]) if transport != "assessment" else strict_json_loads(raw.decode("utf-8"))


def _limits(value: Any) -> dict[str, int]:
    result = _keys(value, " ".join(CEILINGS))
    for name, maximum in CEILINGS.items():
        if type(result[name]) is not int or not 1 <= result[name] <= maximum:
            raise ValueError("inadmissible resource selection")
    if result["output_bytes"] < 4096:
        raise ValueError("diagnostic output reservation required")
    return result


def _path(value: Any) -> None:
    if type(value) is not list or not 1 <= len(value) <= 16:
        raise ValueError("bounded nonempty path required")
    for segment in value:
        if type(segment) is str:
            _text(segment)
        elif type(segment) is not int or not 0 <= segment < 10000:
            raise ValueError("plain path key or nonnegative array index required")


def _validate_rule(rule: Any, meter: _Meter) -> None:
    pending = [(rule, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 512 or depth > 16 or type(node) is not dict:
            raise ValueError("rule structural ceiling exceeded")
        meter.take()
        op = _text(node.get("op"))
        fields = {"always": "op", "present": "op path", "equals": "op path value",
                  "integer_range": "op path minimum maximum", "not": "op rule",
                  "all": "op rules", "any": "op rules"}
        if op not in fields:
            raise ValueError("unsupported declarative rule")
        _keys(node, fields[op])
        if "path" in node:
            _path(node["path"])
            meter.take(len(node["path"]))
        if op == "equals" and len(canonical_bytes(node["value"])) > 4096:
            raise ValueError("equality literal byte ceiling exceeded")
        if op == "integer_range":
            low, high = node["minimum"], node["maximum"]
            if (type(low) is not int or type(high) is not int or
                    low.bit_length() > 128 or high.bit_length() > 128 or low > high):
                raise ValueError("plain bounded ordered integer interval required")
        if op == "not":
            pending.append((node["rule"], depth + 1))
        elif op in ("all", "any"):
            children = node["rules"]
            if type(children) is not list or not 1 <= len(children) <= 64:
                raise ValueError("bounded nonempty compound rule required")
            pending.extend((child, depth + 1) for child in children)


def _observe(record: dict[str, Any], path: list[Any], meter: _Meter) -> Any:
    current: Any = record
    for segment in path:
        meter.take(1 + (len(segment) if type(segment) is str else 1))
        if type(current) is dict and type(segment) is str:
            current = current.get(segment, _MISSING)
        elif type(current) is list and type(segment) is int and segment < len(current):
            current = current[segment]
        else:
            return _MISSING
        if current is _MISSING:
            return current
    return current


def _typed_equal(left: Any, right: Any, meter: _Meter) -> bool:
    pending = [(left, right)]
    while pending:
        first, second = pending.pop()
        meter.take()
        if type(first) is not type(second):
            return False
        if type(first) is dict:
            meter.take(sum(len(key) for key in first) + sum(len(key) for key in second))
            if first.keys() != second.keys():
                return False
            pending.extend((first[key], second[key]) for key in first)
        elif type(first) is list:
            if len(first) != len(second):
                return False
            pending.extend(zip(first, second))
        elif type(first) is str:
            meter.take(len(first) + len(second))
            if first != second:
                return False
        else:
            if type(first) is int:
                meter.take((first.bit_length() + second.bit_length() + 7) // 8)
            if canonical_bytes(first) != canonical_bytes(second):
                return False
    return True


def _evaluate(rule: dict[str, Any], record: dict[str, Any], meter: _Meter) -> bool | None:
    meter.take()
    op = rule["op"]
    if op == "always":
        return True
    if op == "not":
        result = _evaluate(rule["rule"], record, meter)
        return None if result is None else not result
    if op in ("all", "any"):
        values = [_evaluate(child, record, meter) for child in rule["rules"]]
        if op == "all":
            return False if False in values else (None if None in values else True)
        return True if True in values else (None if None in values else False)
    observed = _observe(record, rule["path"], meter)
    if op == "present":
        return observed is not _MISSING
    if observed is _MISSING:
        return None
    if op == "equals":
        return _typed_equal(observed, rule["value"], meter)
    if type(observed) is not int:
        return None
    meter.take(1 + (observed.bit_length() + 7) // 8)
    return rule["minimum"] <= observed <= rule["maximum"]


def _profile(value: dict[str, Any], meter: _Meter) -> tuple[dict[str, list[dict[str, Any]]], int]:
    if value["schema_version"] != "verifier-polish-objective-profile-1":
        raise ValueError("wrong application profile contract")
    _text(value["profile_id"])
    _text(value["revision"])
    kinds = value["kinds"]
    if type(kinds) is not list or not 1 <= len(kinds) <= len(ObjectKind):
        raise ValueError("finite admitted kind inventory required")
    compiled = {}
    count = 0
    for definition in kinds:
        _keys(definition, "kind tiers")
        kind = ObjectKind(_text(definition["kind"])).value
        if kind in compiled:
            raise ValueError("duplicate kind profile")
        tiers = definition["tiers"]
        if type(tiers) is not list or len(tiers) != 9:
            raise ValueError("all nine general tiers required")
        seen: set[int] = set()
        identities: set[tuple[str, str]] = set()
        entries = []
        for tier_row in tiers:
            _keys(tier_row, "tier objectives")
            tier = tier_row["tier"]
            if type(tier) is not int or not 1 <= tier <= 9 or tier in seen:
                raise ValueError("duplicate or invalid tier")
            seen.add(tier)
            objectives = tier_row["objectives"]
            if type(objectives) is not list or not objectives:
                raise ValueError("nonempty objective inventory required")
            unconditional = False
            for item in objectives:
                _keys(item, "semantic_version coordinate proposition applicability_rule")
                semantic = _text(item["semantic_version"])
                if semantic == "verifier-current-ten-tier-object-obligations-1":
                    raise ValueError("historical nine-tier inventory semantic version differs")
                address = ObjectCoordinate.parse(_text(item["coordinate"]))
                identity = (semantic, str(address))
                if (address.tier.value != tier or address.object_kind.value not in (kind, "OBJECT") or
                        identity in identities):
                    raise ValueError("conflicting objective identity")
                identities.add(identity)
                _text(item["proposition"], 1024)
                _validate_rule(item["applicability_rule"], meter)
                unconditional |= item["applicability_rule"] == {"op": "always"}
                entries.append(item)
                count += 1
            if not unconditional:
                raise ValueError("general tier cannot be wholly conditional")
        compiled[kind] = sorted(entries, key=lambda item: (
            ObjectCoordinate.parse(item["coordinate"]).tier.value,
            ObjectCoordinate.parse(item["coordinate"]).objective, item["semantic_version"]))
    return compiled, count


def _selected_request(raw: bytes, profile_bytes: bytes, collection_bytes: bytes,
                      mechanism: str) -> dict[str, Any]:
    _admit_transport(profile_bytes, "profile")
    _admit_transport(collection_bytes, "collection")
    request = _load(raw, "request")
    if request["schema_version"] != "verifier-polish-inventory-request-1":
        raise ValueError("wrong external selection contract")
    _text(request["root_id"])
    for name in ("profile_digest", "collection_bytes_digest", "collection_digest", "mechanism_digest"):
        _hash(request[name])
    _limits(request["limits"])
    if (request["profile_digest"] != _digest(profile_bytes) or
            request["collection_bytes_digest"] != _digest(collection_bytes) or
            request["mechanism_digest"] != mechanism):
        raise ValueError("selected source or retained bytes substituted")
    return request


def _prepare(profile_bytes: bytes, collection_bytes: bytes, request: dict[str, Any]) -> _Prepared:
    limits = request["limits"]
    meter = _Meter(limits["rule_operations"])
    compiled, profile_count = _profile(_load(profile_bytes, "profile"), meter)
    if profile_count > limits["profile_objectives"]:
        raise _Exhausted("profile_objectives")
    collection = _load(collection_bytes, "collection")
    if collection["schema_version"] != "verifier-polish-object-collection-1":
        raise ValueError("wrong collection contract")
    records = collection["objects"]
    if type(records) is not list or not records:
        raise ValueError("nonempty finite collection required")
    if len(records) > limits["objects"]:
        raise _Exhausted("objects")
    objects: dict[str, NamespaceObject] = {}
    for record in records:
        _keys(record, "object_id kind payload operands")
        object_id = _text(record["object_id"])
        _text(record["kind"])
        if type(record["operands"]) is not dict:
            raise ValueError("operand map required")
        for role, targets in record["operands"].items():
            _text(role)
            if type(targets) is not list:
                raise ValueError("plain operand sequence required")
            for target in targets:
                _text(target)
        item = NamespaceObject.create(object_id, record["kind"], record["payload"], record["operands"])
        if object_id in objects:
            raise ValueError("duplicate object identity")
        objects[object_id] = item
    if request["root_id"] not in objects:
        raise ValueError("selected root is absent")
    composition = assess_composition(tuple(objects.values()), expected_digest=request["collection_digest"],
        max_objects=limits["objects"], max_operations=limits["composition_operations"],
        max_payload_bytes=TRANSPORT_BYTES["collection"], max_reference_bytes=TRANSPORT_BYTES["collection"])
    if composition.verdict.value == "FAIL":
        raise ValueError("selected typed composition refuted")
    if composition.verdict.value != "PASS":
        raise _Exhausted("composition_operations")
    rows = []
    unprofiled: set[str] = set()
    expanded = sum(len(compiled.get(item.kind.value, ())) for item in objects.values())
    if expanded > limits["expanded_objectives"]:
        raise _Exhausted("expanded_objectives")
    for object_id in sorted(objects):
        item = objects[object_id]
        if item.kind.value not in compiled:
            unprofiled.add(item.kind.value)
            continue
        record = item.to_dict()
        for objective in compiled[item.kind.value]:
            result = _evaluate(objective["applicability_rule"], record, meter)
            rows.append({"object_id": object_id, "semantic_version": objective["semantic_version"],
                "coordinate": objective["coordinate"],
                "applicability": "UNKNOWN" if result is None else ("REQUIRED" if result else "NOT_APPLICABLE")})
    usage = {"objects": len(objects), "profile_objectives": profile_count,
        "expanded_objectives": expanded, "rule_operations": meter.used,
        "composition_operations": limits["composition_operations"]}
    return _Prepared(request, tuple(rows), tuple(sorted(unprofiled)), usage)


def _plan(prepared: _Prepared, request_bytes: bytes) -> dict[str, Any]:
    return {"schema_version": "verifier-polish-objective-plan-1",
        "profile_digest": prepared.request["profile_digest"],
        "collection_digest": prepared.request["collection_digest"],
        "request_digest": _digest(request_bytes), "requirements": list(prepared.requirements)}


def build_objective_inventory_plan(*, profile_bytes: bytes, collection_bytes: bytes,
                                  request_bytes: bytes) -> bytes:
    """Produce a finite plan, preserving unresolved rules and refusing partial capacity."""
    request = _selected_request(request_bytes, profile_bytes, collection_bytes, mechanism_digest())
    try:
        prepared = _prepare(profile_bytes, collection_bytes, request)
        if prepared.unprofiled:
            raise InventoryUnavailable("selected application profile does not cover every supplied kind")
        encoded = canonical_bytes(_plan(prepared, request_bytes))
        if len(encoded) + 4096 > request["limits"]["output_bytes"]:
            raise _Exhausted("output_bytes")
        return encoded
    except _Exhausted as error:
        raise InventoryUnavailable(error.resource) from error


def assess_objective_inventory(plan_bytes: bytes, *, profile_bytes: bytes,
                              collection_bytes: bytes, request_bytes: bytes) -> dict[str, Any]:
    """Check every declared objective; a matching plan supplies no native certificate."""
    report: dict[str, Any] = {"schema_version": "verifier-polish-inventory-assessment-1",
        "status": "UNKNOWN", "polished": False, "objective_inventory_closure": "NOT_ESTABLISHED",
        "authority_status": "NOT_ESTABLISHED", "public_checkability": "NOT_ESTABLISHED",
        "profile_plan_coverage": "NOT_ESTABLISHED", "replayable": False, "claim_boundary": BOUNDARY}
    try:
        retained = {"plan": plan_bytes, "profile": profile_bytes,
                    "collection": collection_bytes, "request": request_bytes}
        for name, raw in retained.items():
            _admit_transport(raw, name)
        report["input_digests"] = {name: _digest(raw) for name, raw in retained.items()}
        source = mechanism_digest()
        report["mechanism_digest"] = source
        report["replayable"] = True
        request = _selected_request(request_bytes, profile_bytes, collection_bytes, source)
        supplied = _load(plan_bytes, "plan")
        rows = supplied["requirements"]
        if type(rows) is not list:
            raise ValueError("plain finite plan required")
        if len(rows) > request["limits"]["expanded_objectives"]:
            raise _Exhausted("expanded_objectives")
        for row in rows:
            _keys(row, "object_id semantic_version coordinate applicability")
            _text(row["object_id"])
            _text(row["semantic_version"])
            ObjectCoordinate.parse(_text(row["coordinate"]))
            if type(row["applicability"]) is not str or row["applicability"] not in (
                    "REQUIRED", "NOT_APPLICABLE", "UNKNOWN"):
                raise ValueError("unknown plan classification")
        prepared = _prepare(profile_bytes, collection_bytes, request)
        expected = _plan(prepared, request_bytes)
        if canonical_bytes(supplied) != canonical_bytes(expected):
            raise ValueError("plan differs from selected finite inventory")
        output_reservation = len(canonical_bytes(expected)) + 4096
        if output_reservation > request["limits"]["output_bytes"]:
            raise _Exhausted("output_bytes")
        unresolved = sum(row["applicability"] == "UNKNOWN" for row in prepared.requirements)
        report.update(status="UNKNOWN" if unresolved or prepared.unprofiled else "PASS",
            profile_plan_coverage="UNKNOWN" if prepared.unprofiled else "PASS",
            declared_applicability_status="UNKNOWN" if unresolved else "PASS",
            unresolved_applicability=unresolved, unprofiled_kinds=list(prepared.unprofiled),
            root_id=request["root_id"], profile_digest=request["profile_digest"],
            collection_digest=request["collection_digest"],
            collection_bytes_digest=request["collection_bytes_digest"],
            request_digest=_digest(request_bytes), plan_digest=_digest(plan_bytes),
            resource_usage={**prepared.usage, "output_bytes": output_reservation})
    except _Exhausted as error:
        report.update(status="UNKNOWN", reason="RESOURCE_LIMIT_EXCEEDED", exhausted_resource=error.resource)
    except OSError:
        report.update(status="UNKNOWN", reason="MECHANISM_UNAVAILABLE", replayable=False)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        report.update(status="FAIL", reason="INVALID_OR_SUBSTITUTED_INPUT")
    report["assessment_digest"] = _digest(canonical_bytes(report))
    return report


def recheck_objective_inventory(assessment_bytes: bytes, *, plan_bytes: bytes,
                               profile_bytes: bytes, collection_bytes: bytes,
                               request_bytes: bytes) -> dict[str, Any]:
    """Recompute exact scoped results rather than trusting a carried digest or PASS."""
    result = {"schema_version": "verifier-polish-inventory-replay-1", "status": "FAIL",
              "replay_status": "REJECTED", "polished": False, "claim_boundary": BOUNDARY}
    try:
        stored = _load(assessment_bytes, "assessment")
        expected = assess_objective_inventory(plan_bytes, profile_bytes=profile_bytes,
            collection_bytes=collection_bytes, request_bytes=request_bytes)
        if expected["replayable"] is True and canonical_bytes(stored) == canonical_bytes(expected):
            result.update(status=expected["status"], replay_status="REPRODUCED",
                          assessment_digest=expected["assessment_digest"])
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        pass
    return result
