"""Declared bounded TIME/SPACE capabilities, separate from existing objectives.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Exact rational coordinates describe selected domains. They do not authenticate
physical clocks, synchronize domains, or impose a universal spatial metric.
"""
from __future__ import annotations

from fractions import Fraction
import math
from typing import Any, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from verifier.core.contextual_namespace import ContextReference, ContextualObject

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.receipt import strict_json_loads

TIME_VERSION = "verifier-declared-time-capabilities-1"
SPACE_VERSION = "verifier-declared-space-capabilities-1"
ASSESSMENT_VERSION = "verifier-spacetime-capability-assessment-1"
LIMITS = {"max_bytes": 4 * 1024**2, "max_items": 4096, "max_integer_bits": 128,
    "max_operations": 100000, "max_depth": 16}
TIME_PROFILES = {"logical-strict/1", "logical-partial/1", "physical-clock/1"}
SPACE_PROFILES = {"directed-adjacency/1", "finite-metric/1"}


class Unsupported(ValueError):
    """Selected capability is not implemented; its proposition remains UNKNOWN."""


class Exhausted(ValueError):
    """A declared representation or checking bound is exhausted."""


def text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256 or any(ord(char) < 32 for char in value):
        raise ValueError("bounded plain domain identifiers required")
    return value


def keys(value: Any, fields: str) -> dict:
    if type(value) is not dict or set(value) != set(fields.split()):
        raise ValueError("closed versioned fields required")
    return value


def rational(numerator: int, denominator: int = 1) -> dict[str, int]:
    if type(numerator) is not int or type(denominator) is not int or denominator == 0:
        raise ValueError("exact integer rational components required")
    if max(numerator.bit_length(), denominator.bit_length()) > LIMITS["max_integer_bits"]:
        raise Exhausted("rational integer representation bound exhausted")
    value = Fraction(numerator, denominator)
    return {"numerator": value.numerator, "denominator": value.denominator}


def checked_fraction(value: Fraction) -> Fraction:
    """Bound each normalized exact arithmetic result before relying on it."""
    if max(value.numerator.bit_length(), value.denominator.bit_length()) > LIMITS["max_integer_bits"]:
        raise Exhausted("accumulated exact rational representation bound exhausted")
    return value


def fraction(value: Any) -> Fraction:
    keys(value, "numerator denominator")
    numerator, denominator = value["numerator"], value["denominator"]
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise ValueError("canonical exact rational components required")
    if max(numerator.bit_length(), denominator.bit_length()) > LIMITS["max_integer_bits"]:
        raise Exhausted("rational integer representation bound exhausted")
    if math.gcd(numerator, denominator) != 1:
        raise ValueError("rational is not normalized")
    return Fraction(numerator, denominator)


def capture(raw: bytes) -> dict:
    if raw is None:
        raise Unsupported("retained evidence observation absent")
    if type(raw) is not bytes:
        raise ValueError("immutable evidence bytes required")
    if len(raw) > LIMITS["max_bytes"]:
        raise Exhausted("evidence byte bound exhausted")
    value = strict_json_loads(raw.decode("utf-8"))
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > LIMITS["max_operations"] or depth > LIMITS["max_depth"]:
            raise Exhausted("evidence structural bound exhausted")
        if type(item) is dict:
            if len(item) > LIMITS["max_items"]:
                raise Exhausted("evidence field bound exhausted")
            pending.extend((part, depth+1) for part in item.values())
        elif type(item) is list:
            if len(item) > LIMITS["max_items"]:
                raise Exhausted("evidence item bound exhausted")
            pending.extend((part, depth+1) for part in item)
        elif type(item) is int and item.bit_length() > LIMITS["max_integer_bits"]:
            raise Exhausted("evidence integer bound exhausted")
    if type(value) is not dict:
        raise ValueError("evidence object required")
    if canonical_bytes(value) != raw:
        raise ValueError("canonical immutable evidence required")
    return value


def _list(value: Any, *, nonempty: bool = False) -> list:
    if type(value) is not list or len(value) > LIMITS["max_items"]:
        raise Exhausted("finite item bound exhausted")
    if nonempty and not value:
        raise Unsupported("retained observations absent")
    return value


def acyclic(names: set[str], edges: list, *, operations: int = 100000) -> dict[str, set[str]]:
    graph = {name: set() for name in names}
    indegree = {name: 0 for name in names}
    used, seen = 0, set()
    for pair in _list(edges):
        if type(pair) is not list or len(pair) != 2 or any(type(item) is not str for item in pair):
            raise ValueError("closed ordered pair required")
        left, right = pair
        if left not in names or right not in names or left == right or (left, right) in seen:
            raise ValueError("missing, reflexive or duplicate relation endpoint")
        seen.add((left, right)); graph[left].add(right); indegree[right] += 1
    ready = sorted(name for name in names if indegree[name] == 0)
    visited = 0
    while ready:
        name = ready.pop()
        visited += 1
        for target in graph[name]:
            used += 1
            if used > operations:
                raise Exhausted("order replay operation bound exhausted")
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    if visited != len(names):
        raise ValueError("declared order cycle")
    return graph


def time_profile(value: Any) -> dict:
    keys(value, "schema_version profile domain unit epoch resolution uncertainty run_id branch_id points order")
    if value["schema_version"] != TIME_VERSION:
        raise ValueError("separate TIME capability version required")
    profile = text(value["profile"])
    if profile not in TIME_PROFILES:
        raise Unsupported("TIME capability profile is unimplemented")
    text(value["domain"])
    for field in ("run_id", "branch_id"):
        if value[field] is not None:
            text(value[field])
    points = {}
    for row in _list(value["points"], nonempty=True):
        keys(row, "id value")
        name = text(row["id"])
        if name in points:
            raise ValueError("duplicate TIME point")
        points[name] = None if row["value"] is None else fraction(row["value"])
    if profile == "logical-partial/1":
        if any(value[field] is not None for field in ("unit", "epoch", "resolution", "uncertainty")) or any(point is not None for point in points.values()):
            raise ValueError("partial-order TIME has no implicit scalar clock")
        graph = acyclic(set(points), value["order"])
    else:
        text(value["unit"])
        resolution, uncertainty = fraction(value["resolution"]), fraction(value["uncertainty"])
        if resolution <= 0 or uncertainty < 0 or any(point is None for point in points.values()):
            raise ValueError("scalar TIME resolution/uncertainty/point differs")
        if value["order"] != []:
            raise ValueError("scalar TIME uses its explicit retained sequence")
        if profile == "logical-strict/1":
            if value["epoch"] is not None or uncertainty != 0:
                raise ValueError("logical TIME does not fabricate epoch or physical uncertainty")
            if any(right <= left for left, right in zip(list(points.values()), list(points.values())[1:])):
                raise ValueError("logical trajectory is not strictly increasing")
        else:
            text(value["epoch"])
        graph = {}
    return {"descriptor": value, "points": points, "graph": graph}


def space_profile(value: Any) -> dict:
    keys(value, "schema_version profile domain unit frame nodes relations")
    if value["schema_version"] != SPACE_VERSION:
        raise ValueError("separate SPACE capability version required")
    profile = text(value["profile"])
    if profile not in SPACE_PROFILES:
        raise Unsupported("SPACE capability profile is unimplemented")
    text(value["domain"]); text(value["frame"])
    nodes = [text(name) for name in _list(value["nodes"], nonempty=True)]
    if len(set(nodes)) != len(nodes):
        raise ValueError("duplicate SPACE point")
    node_set = set(nodes)
    relations, seen = {}, set()
    for row in _list(value["relations"]):
        keys(row, "source target" if profile == "directed-adjacency/1" else "source target distance")
        left, right = text(row["source"]), text(row["target"])
        if left not in node_set or right not in node_set or (left, right) in seen:
            raise ValueError("missing or duplicate spatial relation endpoint")
        seen.add((left, right))
        relations[left, right] = True if profile == "directed-adjacency/1" else fraction(row["distance"])
    if profile == "directed-adjacency/1":
        if value["unit"] is not None:
            raise ValueError("adjacency has no implicit metric unit")
    else:
        text(value["unit"])
        if len(nodes)**2 != len(relations):
            raise Unsupported("complete selected finite metric table absent")
        used = 0
        for left in nodes:
            for right in nodes:
                distance = relations[left, right]
                if distance < 0 or ((left == right) != (distance == 0)) or distance != relations[right, left]:
                    raise ValueError("finite metric identity/symmetry/positivity refuted")
                for via in nodes:
                    used += 1
                    if used > LIMITS["max_operations"]:
                        raise Exhausted("finite metric checking operation bound exhausted")
                    if distance > checked_fraction(relations[left, via] + relations[via, right]):
                        raise ValueError("finite metric triangle inequality refuted")
    return {"descriptor": value, "nodes": nodes, "relations": relations}


def assess_profile(raw: bytes, *, expected_digest: str | None, kind: str) -> dict:
    report = {"schema_version": ASSESSMENT_VERSION, "status": "UNKNOWN",
        "scope": "SELECTED_DECLARED_FINITE_CAPABILITY", "physical_authenticity": "UNKNOWN"}
    if expected_digest is None:
        return {**report, "reason": "independent capability commitment absent"}
    try:
        value = capture(raw)
        observed = "sha256:" + canonical_digest(value)
        report["evidence_digest"] = observed
        if observed != expected_digest:
            return {**report, "status": "FAIL", "reason": "selected capability bytes differ"}
        if kind not in ("TIME", "SPACE"):
            return {**report, "status": "REFUSAL", "reason": "typed TIME/SPACE capability selection required"}
        (time_profile if kind == "TIME" else space_profile)(value)
        return {**report, "status": "PASS", "profile": value["profile"], "domain": value["domain"]}
    except (Unsupported, Exhausted) as exc:
        return {**report, "reason": str(exc)[:256]}
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        return {**report, "status": "FAIL", "reason": str(exc)[:256]}


def compare_time(left: dict, left_point: str, right: dict, right_point: str) -> dict:
    try:
        return compare_parsed_time(time_profile(left), left_point, time_profile(right), right_point)
    except (Unsupported, Exhausted) as exc:
        return {"status": "UNKNOWN", "relation": None, "reason": str(exc)[:256]}
    except (ValueError, TypeError) as exc:
        return {"status": "FAIL", "relation": None, "reason": str(exc)[:256]}


def compare_parsed_time(first: dict, left_point: str, second: dict, right_point: str) -> dict:
    """Internal replay helper for already validated, privately captured profiles."""
    report = {"status": "UNKNOWN", "relation": None, "scope": "DECLARED_DOMAIN_POINT_RELATION", "physical_causality": "UNKNOWN"}
    try:
        left, right = first["descriptor"], second["descriptor"]
        fields = ("profile", "domain", "unit", "epoch", "resolution", "uncertainty", "run_id", "branch_id")
        if any(left[field] != right[field] for field in fields):
            return {**report, "reason": "different TIME domains/profiles; explicit mapping required"}
        if left_point not in first["points"] or right_point not in second["points"]:
            return {**report, "reason": "selected TIME point absent"}
        if left["profile"] == "logical-partial/1":
            if canonical_bytes(left) != canonical_bytes(right):
                return {**report, "reason": "different declared partial-order evidence"}
            def reaches(start: str, target: str) -> bool:
                pending, seen = [start], set()
                while pending:
                    name = pending.pop()
                    if name == target:
                        return True
                    if name not in seen:
                        seen.add(name); pending.extend(first["graph"][name])
                return False
            relation = "EQUAL" if left_point == right_point else "BEFORE" if reaches(left_point, right_point) else "AFTER" if reaches(right_point, left_point) else "INCOMPARABLE"
        else:
            a, b = first["points"][left_point], second["points"][right_point]
            uncertainty = fraction(left["uncertainty"])
            if a == b and uncertainty == 0:
                relation = "EQUAL"
            elif checked_fraction(a + uncertainty) < checked_fraction(b - uncertainty):
                relation = "BEFORE"
            elif checked_fraction(b + uncertainty) < checked_fraction(a - uncertainty):
                relation = "AFTER"
            else:
                return {**report, "reason": "declared uncertainty intervals overlap"}
        return {**report, "status": "PASS", "relation": relation}
    except (Unsupported, Exhausted) as exc:
        return {**report, "reason": str(exc)}
    except (ValueError, TypeError) as exc:
        return {**report, "status": "FAIL", "reason": str(exc)}


def query_space(value: dict, *, capability: str, source: str, target: str) -> dict:
    report = {"status": "UNKNOWN", "scope": "SELECTED_DECLARED_SPATIAL_RELATION", "physical_geometry": "UNKNOWN"}
    try:
        parsed = space_profile(value)
        if source not in parsed["nodes"] or target not in parsed["nodes"]:
            return {**report, "reason": "selected spatial endpoint absent"}
        if capability == "adjacency" and value["profile"] == "directed-adjacency/1":
            return {**report, "status": "PASS", "adjacent": (source, target) in parsed["relations"]}
        if capability == "distance" and value["profile"] == "finite-metric/1":
            distance = parsed["relations"][source, target]
            return {**report, "status": "PASS", "distance": rational(distance.numerator, distance.denominator)}
        return {**report, "reason": "UNSUPPORTED capability; profile supplies no direction/frame transform meaning"}
    except (Unsupported, Exhausted) as exc:
        return {**report, "reason": str(exc)}
    except (ValueError, TypeError) as exc:
        return {**report, "status": "FAIL", "reason": str(exc)}


def assess_context_capabilities(objects: Sequence[ContextualObject], *, expected_digest: str | None,
        required_contexts: tuple[tuple[str, ContextReference], ...] = ()) -> dict:
    """Compose separately scoped context identity and supported capability shape."""
    from verifier.core.contextual_namespace import assess_contextual_composition
    report = assess_contextual_composition(objects, expected_digest=expected_digest, required_contexts=required_contexts)
    if report["status"] != "PASS":
        return report
    by_id = {item.record.object_id: item for item in objects}
    targets = sorted({row.object_id for item in objects for row in item.contexts})
    rows = []
    for name in targets:
        target = by_id[name].record
        raw = target.payload_bytes
        rows.append({"object_id": name, "assessment": assess_profile(raw,
            expected_digest="sha256:" + canonical_digest(target.payload), kind=target.kind.value)})
    statuses = [row["assessment"]["status"] for row in rows]
    status = "FAIL" if any(value in ("FAIL", "REFUSAL") for value in statuses) else "UNKNOWN" if "UNKNOWN" in statuses else "PASS"
    return {**report, "status": status, "scope": "SELECTED_TYPED_CONTEXT_IDENTITY_AND_SUPPORTED_CAPABILITIES",
        "capability_semantics": "SELECTED_FINITE_PROFILE_CHECKS", "capability_rows": rows,
        "selected_context_targets": len(targets), "physical_authenticity": "UNKNOWN"}
