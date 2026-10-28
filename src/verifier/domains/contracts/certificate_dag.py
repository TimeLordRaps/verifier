"""Exact certificate dependency closure under independently selected application profiles.

directed acyclic graph (DAG); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Nodes are claims, never tier labels. This bounded
validator establishes only the selected claim set and preserves native scope.
Subject bindings use each installed native schema's exact fields, without aliases.
No complete nine-tier profiles, physical or statistical claims are supplied.
"""
from __future__ import annotations

from asyncio import CancelledError
from collections import deque
import hashlib
import re
from typing import Any, Callable

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectKind, composition_digest
from verifier.core.receipt import strict_json_loads

PROFILE = "verifier-certificate-dag-profile-1"
POLICY = "verifier-certificate-dag-policy-1"
BUNDLE = "verifier-certificate-dag-bundle-1"
ASSESSMENT = "verifier-certificate-dag-assessment-1"
FAULT_ASSESSMENT = "verifier-certificate-dag-assessment-2"
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 512
MAX_EDGES = 4096
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


class _Exhausted(ValueError):
    pass


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def artifact_files_digest(files: dict[str, bytes]) -> str:
    """Commit the entire retained file set, including names and exact bytes."""
    return _digest(canonical_bytes([{"path": p, "digest": _digest(raw), "size_bytes": len(raw)}
                                    for p, raw in sorted(files.items())]))


def _record(value: Any, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ValueError("exact dependency record fields required")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ValueError("bounded dependency identifier required")
    return value


def _hash(value: Any) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        raise ValueError("exact SHA-256 dependency commitment required")
    return value


def _path(value: Any) -> str:
    _text(value)
    if ("\\" in value or ":" in value or value.startswith("/") or
            any(ord(c) < 32 for c in value) or any(p in {"", ".", ".."} for p in value.split("/"))):
        raise ValueError("snapshot-relative dependency path required")
    return value


def _list(value: Any, maximum: int = MAX_NODES) -> list[Any]:
    if type(value) is not list:
        raise ValueError("plain dependency list required")
    if len(value) > maximum:
        raise _Exhausted("dependency item bound exhausted")
    return value


def _parse(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes:
        raise ValueError("exact dependency bytes required")
    if len(raw) > MAX_BYTES:
        raise _Exhausted("dependency byte bound exhausted")
    # Preflight before the decoder can recurse. Brackets inside strings do not count.
    depth = 0
    quoted = escaped = False
    number_digits = 0
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif 48 <= byte <= 57:
            number_digits += 1
            if number_digits > 1234:
                raise _Exhausted("dependency numeric bound exhausted")
        elif byte == 34:
            number_digits = 0
            quoted = True
        elif byte in (91, 123):
            number_digits = 0
            depth += 1
            if depth > 48:
                raise _Exhausted("dependency nesting bound exhausted")
        elif byte in (93, 125):
            number_digits = 0
            depth -= 1
        else:
            number_digits = 0
    value = strict_json_loads(raw.decode("utf-8"))
    pending = [(value, 0)]
    count = 0
    while pending:
        item, nesting = pending.pop()
        count += 1
        if count > 100000 or nesting > 48:
            raise _Exhausted("dependency structural bound exhausted")
        if type(item) in (dict, list):
            pending.extend((child, nesting + 1) for child in
                           (list(item.values()) + list(item) if type(item) is dict else item))
        elif type(item) is int and item.bit_length() > 4096:
            raise _Exhausted("dependency integer bound exhausted")
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise ValueError("canonical dependency object required")
    return value


def _assess(bundle: dict[str, Any], policy: dict[str, Any], files: dict[str, bytes],
            observe: Callable[[dict[str, Any]], None] | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    _record(policy, {"schema_version", "approved_profiles", "required_objects", "required_roots",
                     "nodes", "artifact_files_digest"})
    _record(bundle, {"schema_version", "profiles", "objects", "nodes", "edges"})
    if policy["schema_version"] != POLICY or bundle["schema_version"] != BUNDLE:
        raise ValueError("unsupported dependency contract")
    if _hash(policy["artifact_files_digest"]) != artifact_files_digest(files):
        raise ValueError("dependency artifact file set changed")
    approved = [_hash(p) for p in _list(policy["approved_profiles"])]
    if len(set(approved)) != len(approved):
        raise ValueError("duplicate approved dependency profile")
    blockers: list[str] = []
    profiles = {}
    obligations = {}
    for profile in _list(bundle["profiles"]):
        _record(profile, {"schema_version", "profile_id", "profile_version", "object_kind", "obligations"})
        if profile["schema_version"] != PROFILE:
            raise ValueError("unsupported dependency profile")
        _text(profile["profile_id"])
        _text(profile["profile_version"])
        ObjectKind(profile["object_kind"])
        pin = _digest(canonical_bytes(profile))
        if pin in profiles:
            raise ValueError("duplicate dependency profile")
        profiles[pin] = profile
        claims = {}
        for claim in _list(profile["obligations"]):
            _record(claim, {"claim_id", "semantic_version", "objective", "proposition_digest",
                            "scope", "assumptions", "dependencies"})
            identity = _text(claim["claim_id"])
            if identity in claims:
                raise ValueError("duplicate profile claim")
            for field in ("semantic_version", "objective", "scope"):
                _text(claim[field])
            _hash(claim["proposition_digest"])
            assumptions = [_hash(v) for v in _list(claim["assumptions"])]
            if len(set(assumptions)) != len(assumptions):
                raise ValueError("duplicate selected assumption")
            for dependency in _list(claim["dependencies"], MAX_EDGES):
                _record(dependency, {"claim_id", "operand_role", "object_kind", "profile_digest"})
                _text(dependency["claim_id"])
                ObjectKind(dependency["object_kind"])
                if dependency["operand_role"] is None:
                    if dependency["object_kind"] != profile["object_kind"] or dependency["profile_digest"] is not None:
                        raise ValueError("local prerequisite changes object profile")
                else:
                    _text(dependency["operand_role"])
                    _hash(dependency["profile_digest"])
            if len({canonical_bytes(d) for d in claim["dependencies"]}) != len(claim["dependencies"]):
                raise ValueError("duplicate profile prerequisite")
            claims[identity] = claim
        if not claims:
            blockers.append("EMPTY_PROFILE:" + pin)
        obligations[pin] = claims
    objects = {}
    for record in _list(bundle["objects"]):
        _record(record, {"object_id", "kind", "payload", "operands"})
        item = NamespaceObject.create(record["object_id"], record["kind"], record["payload"], record["operands"])
        if item.to_dict() != record or item.object_id in objects:
            raise ValueError("duplicate or noncanonical dependency object")
        objects[item.object_id] = item
    selected_objects = {}
    for selected in _list(policy["required_objects"]):
        _record(selected, {"object_id", "object_kind", "record_digest", "profile_digest"})
        oid = _text(selected["object_id"])
        ObjectKind(selected["object_kind"])
        _hash(selected["record_digest"])
        pin = _hash(selected["profile_digest"])
        if oid in selected_objects:
            raise ValueError("duplicate selected dependency object")
        selected_objects[oid] = selected
        if oid not in objects:
            blockers.append("OBJECT_MISSING:" + oid)
        elif objects[oid].kind.value != selected["object_kind"] or objects[oid].digest != selected["record_digest"]:
            raise ValueError("dependency object kind or record changed")
        if pin not in approved:
            blockers.append("PROFILE_UNAPPROVED:" + oid)
        if pin not in profiles:
            blockers.append("PROFILE_MISSING:" + oid)
        elif profiles[pin]["object_kind"] != selected["object_kind"]:
            raise ValueError("dependency profile kind differs")
    if set(objects) - set(selected_objects):
        raise ValueError("carried object is outside independently selected scope")
    if not selected_objects:
        blockers.append("NO_SELECTED_OBJECT_PROFILE")
    expected_nodes = _list(policy["nodes"])
    if bundle["nodes"] != expected_nodes:
        raise ValueError("dependency nodes differ from independently selected certificates or intent")
    nodes = {}
    by_claim = {}
    for node in _list(bundle["nodes"]):
        _record(node, {"node_id", "object_id", "claim_id", "certificate_path", "certificate_digest",
                       "request", "checker_policy", "contract_version", "artifact_bindings", "facet_bindings"})
        nid, oid, cid = (_text(node[k]) for k in ("node_id", "object_id", "claim_id"))
        _path(node["certificate_path"])
        _hash(node["certificate_digest"])
        if type(node["request"]) is not dict or type(node["checker_policy"]) is not dict:
            raise ValueError("external native request and policy required")
        if node["contract_version"] not in ("1", "2"):
            raise ValueError("selected native replay version unsupported")
        if node["checker_policy"].get("witness_keys"):
            raise ValueError("secret witness keys cannot enter public dependency records")
        if nid in nodes or (oid, cid) in by_claim or oid not in selected_objects:
            raise ValueError("duplicate or unselected dependency claim")
        pin = selected_objects[oid]["profile_digest"]
        if pin in obligations and cid not in obligations[pin]:
            raise ValueError("claim absent from selected profile")
        _record(node["facet_bindings"], {"payload_digest", "operands_digest"})
        for field in node["facet_bindings"].values():
            _hash(field)
        if oid in objects:
            item = objects[oid]
            facets = {"payload_digest": _digest(item.payload_bytes),
                      "operands_digest": _digest(canonical_bytes(item.to_dict()["operands"]))}
            if node["facet_bindings"] != facets:
                raise ValueError("dependency facet changed")
        bindings = _list(node["artifact_bindings"], 1024)
        if not bindings:
            raise ValueError("claim requires selected artifact bindings")
        paths = []
        for binding in bindings:
            _record(binding, {"path", "digest"})
            path = _path(binding["path"])
            pin_bytes = _hash(binding["digest"])
            paths.append(path)
            if path not in files:
                blockers.append("ARTIFACT_MISSING:" + path)
            elif _digest(files[path]) != pin_bytes:
                raise ValueError("dependency artifact binding changed")
        if len(set(paths)) != len(paths):
            raise ValueError("duplicate claim artifact binding")
        nodes[nid], by_claim[(oid, cid)] = node, nid
    for oid, selected in selected_objects.items():
        for cid in obligations.get(selected["profile_digest"], {}):
            if (oid, cid) not in by_claim:
                blockers.append("CLAIM_MISSING:" + oid + ":" + cid)
    edges = set()
    dependencies = {nid: set() for nid in nodes}
    dependents = {nid: set() for nid in nodes}
    for edge in _list(bundle["edges"], MAX_EDGES):
        _record(edge, {"node_id", "prerequisite_id", "operand_role"})
        nid, prerequisite = _text(edge["node_id"]), _text(edge["prerequisite_id"])
        role = edge["operand_role"]
        if role is not None:
            _text(role)
        key = nid, prerequisite, role
        if key in edges or nid not in nodes or prerequisite not in nodes:
            raise ValueError("duplicate or dangling certificate dependency")
        edges.add(key)
        dependencies[nid].add(prerequisite)
        dependents[prerequisite].add(nid)
    expected_edges = set()
    incomplete = set()
    dependency_work = 0
    for nid, node in nodes.items():
        oid = node["object_id"]
        profile_pin = selected_objects[oid]["profile_digest"]
        claim = obligations.get(profile_pin, {}).get(node["claim_id"])
        if claim is None or oid not in objects:
            incomplete.add(nid)
            continue
        for dependency in claim["dependencies"]:
            dependency_work += 1
            if dependency_work > MAX_EDGES:
                raise _Exhausted("profile dependency work bound exhausted")
            role = dependency["operand_role"]
            if role is None:
                targets = [oid]
            else:
                targets = list(dict(objects[oid].operands).get(role, ()))
                if not targets:
                    incomplete.add(nid)
                    blockers.append("OPERAND_PREREQUISITE_MISSING:" + nid)
            for target in targets:
                if target not in selected_objects:
                    incomplete.add(nid)
                    blockers.append("DEPENDENCY_OBJECT_MISSING:" + target)
                    continue
                target_selection = selected_objects[target]
                if (target_selection["object_kind"] != dependency["object_kind"] or
                        role is not None and target_selection["profile_digest"] != dependency["profile_digest"]):
                    raise ValueError("typed prerequisite kind or exact profile changed")
                parent = by_claim.get((target, dependency["claim_id"]))
                if parent is None:
                    incomplete.add(nid)
                    blockers.append("DEPENDENCY_CLAIM_MISSING:" + nid)
                else:
                    expected_edges.add((nid, parent, role))
                    if len(expected_edges) > MAX_EDGES:
                        raise _Exhausted("expanded dependency edge bound exhausted")
    known_sources = {nid for nid, node in nodes.items() if node["object_id"] in objects
        and node["claim_id"] in obligations.get(selected_objects[node["object_id"]]["profile_digest"], {})}
    if {edge for edge in edges if edge[0] in known_sources} != expected_edges:
        raise ValueError("certificate dependency edges differ from selected profiles and operands")
    pending = {nid: set(values) for nid, values in dependencies.items()}
    ready = deque(sorted(nid for nid, values in pending.items() if not values))
    order = []
    while ready:
        nid = ready.popleft()
        order.append(nid)
        for descendant in sorted(dependents[nid]):
            pending[descendant].remove(nid)
            if not pending[descendant]:
                ready.append(descendant)
    if len(order) != len(nodes):
        raise ValueError("certificate dependency cycle")
    roots = [_text(n) for n in _list(policy["required_roots"])]
    if len(set(roots)) != len(roots):
        raise ValueError("duplicate required claim root")
    if not roots:
        blockers.append("NO_REQUIRED_CLAIM_ROOT")
    visited = set()
    traversal = list(roots)
    while traversal:
        nid = traversal.pop()
        if nid not in nodes:
            blockers.append("ROOT_CLAIM_MISSING:" + nid)
        elif nid not in visited:
            visited.add(nid)
            traversal.extend(dependencies[nid])
    if set(nodes) - visited:
        raise ValueError("selected claims are outside required dependency closure")
    from verifier.domains.contracts.current_object_routes import (
        CurrentObjectRouteRefusal, CurrentObjectRouteUnavailable,
        current_object_route_catalog, current_ten_tier_route_catalog, replay_current_object_certificate)
    catalog = {(r["semantic_version"], r["objective"]): r for r in current_object_route_catalog()}
    results = {}
    collection = composition_digest(list(objects.values()))
    replay_bytes = 0
    replay_exhausted = False
    for nid in order:
        node, direct, reason, replay_digest = nodes[nid], "UNKNOWN", "NATIVE_INPUT_UNAVAILABLE", None
        oid = node["object_id"]
        selected = selected_objects[oid]
        profile_pin = selected["profile_digest"]
        claim = obligations.get(profile_pin, {}).get(node["claim_id"])
        certificate = files.get(node["certificate_path"])
        if certificate is not None and _digest(certificate) != node["certificate_digest"]:
            raise ValueError("selected certificate bytes changed")
        if claim is not None and oid in objects:
            if claim["semantic_version"] == "verifier-current-ten-tier-object-obligations-1":
                try:
                    catalog.update({(r["semantic_version"], r["objective"]): r
                                    for r in current_ten_tier_route_catalog()})
                except (ImportError, OSError, MemoryError, CurrentObjectRouteUnavailable):
                    # Unavailable opt-in support never blocks historical replay.
                    pass
            route = catalog.get((claim["semantic_version"], claim["objective"]))
            request, native_policy = node["request"], node["checker_policy"]
            subject_field, record_field = "subject_id", "object_digest"
            if (claim["objective"] == "OBJECT-1.1" or route is not None
                    and route["certificate_schema_version"] == "verifier-current-object-governance-certificate-1"):
                subject_field, record_field = "object_id", "record_digest"
            elif claim["objective"] == "VERIFIER-2.1":
                subject_field = "object_id"
            elif claim["objective"] in ("RECEIPT-9.1", "RECEIPT-9.2"):
                subject_field, record_field = "receipt_object_id", "receipt_object_digest"
            if (request.get(subject_field) != oid or request.get(record_field) != selected["record_digest"]
                    or ("object_kind" in request and request["object_kind"] != selected["object_kind"])
                    or ("object_kind" not in request and route is not None
                        and route["represented_kind_rule"] != selected["object_kind"])
                    or request.get("proposition_digest") != claim["proposition_digest"]):
                raise ValueError("native claim differs from exact selected object or proposition")
            if "collection_digest" in request and request["collection_digest"] != collection:
                raise ValueError("native claim collection differs from dependency collection")
            if route is None or route["scope"] != claim["scope"] or route["proposition_digest"] != claim["proposition_digest"]:
                reason = "REGISTERED_PROPOSITION_OR_SCOPE_UNAVAILABLE"
            elif certificate is not None:
                if replay_exhausted or replay_bytes + len(certificate) > 64 * 1024 * 1024:
                    replay_exhausted = True
                    reason = "DEPENDENCY_RESOURCE_BOUND_EXHAUSTED"
                    blockers.append(reason)
                else:
                    replay_bytes += len(certificate)
                    try:
                        replay = replay_current_object_certificate(certificate,
                            semantic_version=claim["semantic_version"], objective=claim["objective"],
                            represented_kind=selected["object_kind"], expected_request=request, policy=native_policy)
                        if replay["schema_version"] != "verifier-current-object-route-replay-" + node["contract_version"]:
                            raise ValueError("selected replay contract version differs")
                        replay_digest = _digest(canonical_bytes(replay))
                        direct = replay["computational_status"] if replay["replay_status"] == "REPRODUCED" else "UNKNOWN"
                        reason = "NATIVE_REPLAY"
                    except (CurrentObjectRouteUnavailable, ImportError, OSError):
                        reason = "CHECKER_UNAVAILABLE"
                    except CurrentObjectRouteRefusal:
                        direct, reason = "FAIL", "NATIVE_REPLAY_REJECTED"
        child_selection_mismatch = False
        if claim is not None and claim["semantic_version"] == "verifier-current-object-obligations-1":
            for parent in dependencies[nid]:
                child_node = nodes[parent]
                child_claim = obligations.get(selected_objects[child_node["object_id"]]["profile_digest"], {}).get(child_node["claim_id"])
                if ((nid, parent, None) in expected_edges and child_claim is not None
                        and child_claim["semantic_version"] == claim["semantic_version"]
                        and child_claim["objective"] == "GRAPH-3.1"
                        and claim["objective"] in ("GRAPH-4.1", "GRAPH-9.2")
                        and not _selected_graph_child_matches(claim["objective"], node["request"], child_node)):
                    child_selection_mismatch = True
        if child_selection_mismatch:
            reason = "CHILD_CERTIFICATE_SELECTION_MISMATCH"
        prerequisites = [results[parent]["qualified_status"] for parent in sorted(dependencies[nid])]
        qualified = ("FAIL" if direct == "FAIL" or child_selection_mismatch or "FAIL" in prerequisites else
                     "PASS" if direct == "PASS" and all(s == "PASS" for s in prerequisites)
                     and nid not in incomplete and profile_pin in approved else "UNKNOWN")
        results[nid] = {"node_id": nid, "direct_status": direct, "qualified_status": qualified,
            "reason": reason, "prerequisites": sorted(dependencies[nid]), "replay_digest": replay_digest,
            "certificate_digest": node["certificate_digest"], "request_digest": _digest(canonical_bytes(node["request"])),
            "checker_policy_digest": _digest(canonical_bytes(node["checker_policy"])),
            "profile_digest": profile_pin, "scope": claim["scope"] if claim else None,
            "assumptions": claim["assumptions"] if claim else [], "facet_bindings": node["facet_bindings"],
            "artifact_bindings": node["artifact_bindings"]}
        if observe is not None:
            observe(results[nid])
    return [results[nid] for nid in sorted(results)], sorted(set(blockers))


def _selected_graph_child_matches(objective: str, request: dict[str, Any], child: dict[str, Any]) -> bool:
    """Correlate selected local GRAPH edges with the parent's exact native child.

    This supplies no extra dependency to profiles without such a selected edge.
    Native replay still independently checks the retained embedded child bytes.
    """
    if request.get("child_certificate_digest") != child["certificate_digest"]:
        return False
    if objective == "GRAPH-4.1":
        return (request.get("child_request_digest") == _digest(canonical_bytes(child["request"]))
                and request.get("child_policy_digest") == _digest(canonical_bytes(child["checker_policy"])))
    return (canonical_bytes(request.get("child_request")) == canonical_bytes(child["request"])
            and canonical_bytes(request.get("child_policy")) == canonical_bytes(child["checker_policy"]))


def assess_certificate_dependencies(bundle_bytes: bytes, *, expected_policy_bytes: bytes | None,
                                    artifact_files: dict[str, bytes]) -> dict[str, Any]:
    """Replay native observations and exact prerequisites; never adopt carried approval."""
    result: dict[str, Any] = {"schema_version": ASSESSMENT, "status": "UNKNOWN", "nodes": [],
        "blockers": [], "bundle_digest": _digest(bundle_bytes) if type(bundle_bytes) is bytes else None,
        "policy_digest": _digest(expected_policy_bytes) if type(expected_policy_bytes) is bytes else None,
        "object_profile_conformance": "NOT_ESTABLISHED", "whole_tier_conformance": "NOT_ESTABLISHED",
        "claim_boundary": "Exact independently selected finite claim dependency closure only; native scopes and assumptions remain unchanged. No full nine-tier, physical-world, statistical, model-correctness, safety, authority or publication conclusion."}
    if expected_policy_bytes is None or bundle_bytes is None:
        result["blockers"] = ["INDEPENDENT_PROFILE_POLICY_MISSING" if expected_policy_bytes is None else "DEPENDENCY_BUNDLE_MISSING"]
        result["assessment_digest"] = _digest(canonical_bytes(result))
        return result
    try:
        if (type(artifact_files) is not dict or len(artifact_files) > 1024 or
                any(type(p) is not str or type(raw) is not bytes for p, raw in artifact_files.items())):
            raise ValueError("plain exact artifact snapshot required")
        if sum(len(raw) for raw in artifact_files.values()) > 64 * 1024 * 1024:
            raise _Exhausted("artifact byte bound exhausted")
        for path in artifact_files:
            _path(path)
        files = dict(artifact_files)
        result["nodes"], result["blockers"] = _assess(_parse(bundle_bytes), _parse(expected_policy_bytes), files)
        statuses = [node["qualified_status"] for node in result["nodes"]]
        result["status"] = ("FAIL" if "FAIL" in statuses else
                            "PASS" if statuses and not result["blockers"] and all(s == "PASS" for s in statuses) else "UNKNOWN")
    except (_Exhausted, RecursionError, OverflowError):
        result["blockers"] = ["DEPENDENCY_RESOURCE_BOUND_EXHAUSTED"]
    except (ValueError, TypeError, KeyError, UnicodeError):
        result["status"], result["blockers"] = "FAIL", ["DEPENDENCY_CONTRACT_REJECTED"]
    except (ImportError, OSError):
        result["blockers"] = ["DEPENDENCY_CHECKER_UNAVAILABLE"]
    result["assessment_digest"] = _digest(canonical_bytes(result))
    return result



def assess_certificate_dependencies_preserving_faults(bundle_bytes: bytes, *,
        expected_policy_bytes: bytes | None, artifact_files: dict[str, bytes]) -> dict[str, Any]:
    """Opt-in version 2 report retains observations across later replay interruption.

    Historical version 1 callers and receipts retain their own contract. This
    function invokes the same native validator and cannot select a carried verdict.
    """
    result: dict[str, Any] = {"schema_version": FAULT_ASSESSMENT, "status": "UNKNOWN", "nodes": [],
        "blockers": [], "bundle_digest": None, "policy_digest": None,
        "object_profile_conformance": "NOT_ESTABLISHED", "whole_tier_conformance": "NOT_ESTABLISHED",
        "claim_boundary": "Exact selected finite native claim closure; interrupted replay retains observed refutations. No complete application, authority, model correctness, safety or publication."}
    observed: list[dict[str, Any]] = []
    try:
        if expected_policy_bytes is None or bundle_bytes is None:
            result["blockers"] = ["INDEPENDENT_PROFILE_POLICY_MISSING"]
        else:
            bundle, policy = _parse(bundle_bytes), _parse(expected_policy_bytes)
            result.update(bundle_digest=_digest(bundle_bytes), policy_digest=_digest(expected_policy_bytes))
            if type(artifact_files) is not dict:
                raise ValueError("plain artifact snapshot required")
            if len(artifact_files) > 1024:
                raise _Exhausted()
            files = dict(artifact_files)
            for path, value in files.items():
                if type(path) is not str or len(path) > 256:
                    raise ValueError("bounded artifact name required")
                _path(path)
                if type(value) is not bytes:
                    raise ValueError("immutable artifact bytes required")
            if sum(len(value) for value in files.values()) > 64 * 1024 * 1024:
                raise _Exhausted()
            result["nodes"], result["blockers"] = _assess(bundle, policy, files, observed.append)
            statuses = [row["qualified_status"] for row in result["nodes"]]
            result["status"] = ("FAIL" if "FAIL" in statuses else "PASS" if statuses
                and not result["blockers"] and all(s == "PASS" for s in statuses) else "UNKNOWN")
    except (_Exhausted, RecursionError, OverflowError):
        result["blockers"] = ["DEPENDENCY_RESOURCE_BOUND_EXHAUSTED"]
    except (CancelledError, ImportError, OSError):
        result["blockers"] = ["DEPENDENCY_REPLAY_INTERRUPTED"]
    except (ValueError, TypeError, KeyError, UnicodeError):
        result["status"], result["blockers"] = "FAIL", ["DEPENDENCY_CONTRACT_REJECTED"]
    if observed:
        result["nodes"] = sorted(observed, key=lambda row: row["node_id"])
        if any(row["qualified_status"] == "FAIL" for row in observed):
            result["status"] = "FAIL"
    result["assessment_digest"] = _digest(canonical_bytes(result))
    return result


__all__ = ["assess_certificate_dependencies", "assess_certificate_dependencies_preserving_faults", "artifact_files_digest"]
