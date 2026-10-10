"""Strict cumulative progression for a separately selected nine-core-tier profile.

Verifier Standard (VSTD); directed acyclic graph (DAG); JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256); mebibytes (MiB).
This gate binds a rank overlay to exact native certificate instances. A selected
finite progression result is not complete application or whole-tier conformance.
Explicit core names preserve namespace meanings; historical ten-tier modules remain unchanged.
No authority, signature, receipt, model-correctness or publication is produced.
"""
from __future__ import annotations

from asyncio import CancelledError
from collections import deque
from enum import IntEnum
import hashlib
from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.domains.contracts import certificate_dag as dag, current_object_routes
from verifier.domains.contracts.application_requirements import (
    SEMANTIC as OBJECT_SEMANTIC,
    STRUCTURAL as STRUCTURAL_PROFILE,
    installed_families,
)
from verifier.domains.inventory import build_234_inventory

PROFILE = "verifier-current-nine-core-tier-progression-1"
SELECTION = "verifier-nine-core-tier-progression-selection-1"
ASSESSMENT = "verifier-nine-core-tier-progression-assessment-1"
INSTALLED_ROUTE_INVENTORY = "verifier-current-nine-core-installed-route-inventory-1"
TIER1_SELF_APPLICATION = "verifier-tier1-self-application-obligations-1"
MAX_SELECTION_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_BINDING_HASH_BYTES = 128 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_NODES = 512
MAX_EDGES = 4096


class CoreTier(IntEnum):
    """Ranks in this profile only; never cast historical coordinates into them."""

    FACETS = 1
    DYNAMICS = 2
    STATICS = 3
    CLOSURE = 4
    INDEPENDENCE = 5
    PRIVACY = 6
    CONSENT = 7
    GOVERNANCE = 8
    SECURITY = 9


class _Exhausted(ValueError):
    pass


class _Refused(ValueError):
    """A fixed public code, never input values or exception details."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism_digest() -> str:
    """Bind this gate, its executed dependency helpers and both contracts."""
    root = Path(__file__).parents[1]
    names = ("runtime/core_tier_progression.py", "domains/inventory.py",
             "domains/contracts/application_requirements.py",
             "domains/contracts/certificate_dag.py",
             "domains/contracts/current_object_routes.py", "core/certificate.py",
             "core/receipt.py", "core/namespace.py", "standard/CERTIFICATE_DAG.md",
             "standard/CORE_NINE_TIER_RELEASE.md", "standard/CORE_SECURITY9_REQUIREMENTS.md")
    shared = Path(dag.__file__).resolve().parents[2]
    return digest(canonical_bytes({name: digest(((root if name.startswith(("runtime/core_", "standard/CORE_")) else shared) / name).read_bytes()) for name in names}))


def installed_core_route_inventory() -> dict[str, Any]:
    """Enumerate the installed route registry without claiming normative closure."""
    rows = [slot.to_dict() for slot in build_234_inventory()]
    expected_cells = {(kind.value, tier.value) for kind in ObjectKind for tier in CoreTier}
    observed_cells: set[tuple[str, int]] = set()
    route_identities: set[tuple[str, str]] = set()
    by_tier = {tier.value: 0 for tier in CoreTier}
    cells = []
    for row in rows:
        kind = ObjectKind(row["object_kind"]).value
        tier = named_core_tier(row["tier"], row["tier_name"])
        key = kind, tier
        if key in observed_cells:
            raise RuntimeError("duplicate installed core route family cell")
        observed_cells.add(key)
        memberships = []
        for registered in row["registered_objectives"]:
            semantic = registered["semantic_version"]
            coordinate = registered["coordinate"]
            identity = semantic, coordinate
            if identity in route_identities:
                raise RuntimeError("installed core route belongs to more than one family cell")
            try:
                native = current_object_routes.select_current_object_route(
                    semantic_version=semantic, objective=coordinate,
                    represented_kind=kind)
            except current_object_routes.CurrentObjectRouteRefusal as exc:
                raise RuntimeError("inventory names an unregistered core route") from exc
            except current_object_routes.CurrentObjectRouteUnavailable as exc:
                raise OSError("installed core route registry is unavailable") from exc
            binding = registered["binding"]
            if (binding["artifact_coordinate"] != coordinate
                    or native.module.PROPOSITION_DIGEST is None):
                raise RuntimeError("installed core route binding differs")
            route_identities.add(identity)
            by_tier[tier] += 1
            memberships.append({
                "semantic_version": semantic,
                "coordinate": coordinate,
                "proposition_digest": native.module.PROPOSITION_DIGEST,
                "certificate_schema_version": native.module.CERTIFICATE_VERSION,
                "checking_mechanism": binding["checking_mechanism"],
                "scope": native.scope,
            })
        if (not memberships or row["status"] != "REPLAYABLE"
                or not row["mechanized"]):
            raise RuntimeError("installed core route family cell is not replayable")
        cells.append({
            "object_kind": kind,
            "tier": tier,
            "tier_name": CoreTier(tier).name,
            "denominator_status": "ESTABLISHED_FOR_INSTALLED_ROUTE_REGISTRY",
            "registered_route_memberships": memberships,
            "registered_route_membership_count": len(memberships),
            "normative_full_family_closure": "NOT_ESTABLISHED",
            "concrete_instance_status": "NOT_INSTANTIATED",
        })
    if observed_cells != expected_cells:
        raise RuntimeError("installed core route family grid differs")
    cells.sort(key=lambda row: (row["object_kind"], row["tier"]))
    return {
        "schema_version": INSTALLED_ROUTE_INVENTORY,
        "semantic_version": OBJECT_SEMANTIC,
        "status": "PASS",
        "object_kind_count": len(ObjectKind),
        "tier_count": len(CoreTier),
        "family_cell_count": len(cells),
        "registered_route_membership_count": len(route_identities),
        "registered_route_membership_count_by_tier": {
            str(tier): by_tier[tier] for tier in sorted(by_tier)},
        "family_cells": cells,
        "normative_full_family_closure": "NOT_ESTABLISHED",
        "concrete_required_certificate_instances": "NOT_INSTANTIATED",
        "claim_boundary": (
            "PASS closes enumeration of installed replay routes only. It does not "
            "establish exhaustive normative meaning, application applicability, "
            "certificate instances, native outcomes, or release authority."),
    }


def verifier_tier1_self_application_obligations(
        *, object_id: str | None = None) -> dict[str, Any]:
    """Derive the retained structural obligations for one concrete VERIFIER root."""
    family = installed_families([ObjectKind.VERIFIER.value])[0]
    if (family["represented_kind"] != ObjectKind.VERIFIER.value
            or family["semantic_version"] != OBJECT_SEMANTIC
            or family["scope"] != STRUCTURAL_PROFILE
            or [row["coordinate"] for row in family["members"]]
            != ["OBJECT-1.1", "VERIFIER-1.1"]):
        raise RuntimeError("installed VERIFIER tier-1 family differs")
    if object_id is not None:
        _text(object_id)
    definitions = [dict(row) for row in family["members"]]
    instances = None if object_id is None else [
        {"object_id": object_id, "semantic_version": family["semantic_version"],
         "coordinate": row["coordinate"],
         "instance_identity_digest": digest(canonical_bytes({
             "object_id": object_id,
             "semantic_version": family["semantic_version"],
             "coordinate": row["coordinate"],
         }))}
        for row in definitions
    ]
    return {
        "schema_version": TIER1_SELF_APPLICATION,
        "profile_id": STRUCTURAL_PROFILE,
        "semantic_version": family["semantic_version"],
        "family_id": family["family_id"],
        "object_kind": ObjectKind.VERIFIER.value,
        "tier": CoreTier.FACETS.value,
        "tier_name": CoreTier.FACETS.name,
        "definition_denominator_status": "PASS",
        "definition_count": len(definitions),
        "definitions": definitions,
        "instantiated_obligation_count": None if instances is None else len(instances),
        "instantiated_obligations": instances,
        "native_instance_binding_status": (
            "REQUIRES_EXACT_COLLECTION_REQUEST_POLICY_AND_CERTIFICATE"),
        "claim_boundary": (
            "The two obligation identities are exact for one selected VERIFIER root. "
            "Native PASS still requires the exact collection, request, checker policy, "
            "certificate and retained evidence for each identity."),
    }


def core_tier_profile() -> dict[str, Any]:
    """Describe the fixed order and exact installed-route denominator."""
    inventory = installed_core_route_inventory()
    return {"semantic_version": PROFILE,
            "tiers": [{"tier": t.value, "name": t.name} for t in CoreTier],
            "family_membership": "INSTALLED_ROUTE_REGISTRY_ENUMERATED",
            "family_cell_count": inventory["family_cell_count"],
            "registered_route_membership_count": inventory["registered_route_membership_count"],
            "installed_route_inventory_digest": digest(canonical_bytes(inventory)),
            "normative_full_family_closure": "NOT_ESTABLISHED",
            "full_required_certificate_instances": "REQUIRES_CONCRETE_SELECTION"}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise _Refused(code)


def _record(value: Any, fields: set[str]) -> None:
    _require(type(value) is dict and set(value) == fields, "PROGRESSION_RECORD_FIELDS")


def _text(value: Any) -> str:
    _require(type(value) is str and len(value) <= 256 and bool(value.strip()), "PROGRESSION_IDENTIFIER")
    return value


def _hash(value: Any) -> str:
    _require(type(value) is str and dag._HASH.fullmatch(value) is not None, "PROGRESSION_DIGEST")
    return value


def _tier(value: Any) -> int:
    _require(type(value) is int and 1 <= value <= 9, "PROGRESSION_TIER")
    return value


def named_core_tier(tier: Any, name: Any) -> int:
    """Bind an integer to its explicit current nine-tier name; no ordinal casts."""
    rank = _tier(tier)
    _require(type(name) is str and name in CoreTier.__members__ and CoreTier[name].value == rank,
             "CORE_NAMED_TIER_DIFFERS")
    return rank


def _list(value: Any, maximum: int) -> list[Any]:
    _require(type(value) is list, "PROGRESSION_LIST")
    if len(value) > maximum:
        raise _Exhausted()
    return value


def _parse(raw: bytes, maximum: int) -> dict[str, Any]:
    _require(type(raw) is bytes, "PROGRESSION_IMMUTABLE_BYTES")
    if len(raw) > maximum:
        raise _Exhausted()
    return dag._parse(raw)


def _selection(value: dict[str, Any]) -> tuple[dict[str, int], dict[int, dict[str, Any]]]:
    _record(value, {"schema_version", "semantic_version", "profile_id", "subject", "target_tier", "target_tier_name",
                    "bundle_digest", "policy_digest", "artifact_files_digest", "ranks", "tiers"})
    _require(value["schema_version"] == SELECTION and value["semantic_version"] == PROFILE,
             "PROGRESSION_VERSION")
    _text(value["profile_id"])
    _record(value["subject"], {"object_id", "object_kind", "record_digest"})
    _text(value["subject"]["object_id"])
    ObjectKind(value["subject"]["object_kind"])
    _hash(value["subject"]["record_digest"])
    named_core_tier(value["target_tier"], value["target_tier_name"])
    for key in ("bundle_digest", "policy_digest", "artifact_files_digest"):
        _hash(value[key])
    ranks: dict[str, int] = {}
    for row in _list(value["ranks"], MAX_NODES):
        _record(row, {"node_id", "tier", "tier_name"})
        name, rank = _text(row["node_id"]), named_core_tier(row["tier"], row["tier_name"])
        _require(name not in ranks, "PROGRESSION_DUPLICATE_INSTANCE")
        ranks[name] = rank
    _require(bool(ranks), "PROGRESSION_EMPTY_INSTANCE_SELECTION")
    tiers: dict[int, dict[str, Any]] = {}
    selected: set[str] = set()
    for row in _list(value["tiers"], 9):
        _record(row, {"tier", "tier_name", "census", "required_nodes"})
        rank = named_core_tier(row["tier"], row["tier_name"])
        _require(rank not in tiers and row["census"] in ("COMPLETE", "UNKNOWN"), "PROGRESSION_CENSUS")
        names = [_text(n) for n in _list(row["required_nodes"], MAX_NODES)]
        _require(len(names) == len(set(names)), "PROGRESSION_DUPLICATE_REQUIREMENT")
        _require(row["census"] != "COMPLETE" or bool(names), "PROGRESSION_EMPTY_COMPLETE_CENSUS")
        _require(all(n in ranks and ranks[n] == rank and n not in selected for n in names),
                 "PROGRESSION_REQUIRED_RANK_DIFFERS")
        selected.update(names)
        tiers[rank] = row
    _require(set(tiers) == set(range(1, 10)) and selected == set(ranks), "PROGRESSION_CENSUS_COVERAGE")
    return ranks, tiers


def _graph(bundle: dict[str, Any], policy: dict[str, Any], ranks: dict[str, int],
           subject: dict[str, str]) -> list[dict[str, Any]]:
    _record(bundle, {"schema_version", "profiles", "objects", "nodes", "edges"})
    _record(policy, {"schema_version", "approved_profiles", "required_objects", "required_roots", "nodes", "artifact_files_digest"})
    _require(bundle["schema_version"] == dag.BUNDLE and policy["schema_version"] == dag.POLICY,
             "PROGRESSION_NATIVE_VERSION")
    roots = [row for row in _list(policy["required_objects"], MAX_NODES)
             if type(row) is dict and row.get("object_id") == subject["object_id"]]
    _require(len(roots) == 1 and all(roots[0].get(k) == v for k, v in subject.items()),
             "PROGRESSION_SUBJECT_DIFFERS")
    # Inspect available record/facet contradictions without running a checker.
    # Cancellation may stop replay, but cannot erase a contradiction in these bytes.
    objects = {}
    for row in _list(bundle["objects"], MAX_NODES):
        _record(row, {"object_id", "kind", "payload", "operands"})
        item = NamespaceObject.create(**row)
        _require(item.object_id not in objects and item.to_dict() == row,
                 "CORE_NATIVE_OBJECT_RECORD_DIFFERS")
        objects[item.object_id] = item
    required_kinds: dict[str, str] = {}
    for row in _list(policy["required_objects"], MAX_NODES):
        _record(row, {"object_id", "object_kind", "record_digest", "profile_digest"})
        oid = _text(row["object_id"])
        kind = ObjectKind(row["object_kind"]).value
        _require(oid not in required_kinds, "PROGRESSION_DUPLICATE_OBJECT_SELECTION")
        required_kinds[oid] = kind
        item = objects.get(row["object_id"])
        _require(item is None or (item.kind.value == row["object_kind"]
                 and item.digest == row["record_digest"]), "CORE_NATIVE_OBJECT_BINDING_DIFFERS")
    nodes = _list(bundle["nodes"], MAX_NODES)
    names, identities = set(), set()
    for node in nodes:
        _record(node, {"node_id", "object_id", "claim_id", "certificate_path", "certificate_digest",
                       "request", "checker_policy", "contract_version", "artifact_bindings", "facet_bindings"})
        name = _text(node["node_id"])
        _record(node["facet_bindings"], {"payload_digest", "operands_digest"})
        for pin in node["facet_bindings"].values():
            _hash(pin)
        item = objects.get(node["object_id"])
        _require(item is None or node["facet_bindings"] == {
            "payload_digest": digest(item.payload_bytes),
            "operands_digest": digest(canonical_bytes(item.to_dict()["operands"]))},
            "CORE_NATIVE_FACET_BINDING_DIFFERS")
        native_request = node["request"]
        _require(type(native_request) is dict, "CORE_NATIVE_REQUEST")
        _require(native_request.get("semantic_version") == "verifier-current-object-obligations-1",
                 "CORE_NATIVE_SEMANTIC_VERSION_DIFFERS")
        coordinate = native_request.get("coordinate")
        import re
        match = re.fullmatch(r"[A-Z]+-([1-9])\.([1-9][0-9]*)", coordinate) if type(coordinate) is str else None
        _require(match is not None and ranks.get(name) == int(match.group(1)),
                 "CORE_NATIVE_COORDINATE_TIER_DIFFERS")
        represented_kind = item.kind.value if item is not None else required_kinds.get(node["object_id"])
        _require(represented_kind is not None, "CORE_NATIVE_OBJECT_BINDING_DIFFERS")
        try:
            current_object_routes.select_current_object_route(
                semantic_version=native_request["semantic_version"],
                objective=coordinate, represented_kind=represented_kind)
        except current_object_routes.CurrentObjectRouteRefusal as exc:
            raise _Refused("CORE_NATIVE_OBJECTIVE_UNREGISTERED") from exc
        except current_object_routes.CurrentObjectRouteUnavailable as exc:
            raise OSError("installed core route registry is unavailable") from exc
        identity = canonical_bytes({k: node[k] for k in ("object_id", "request", "checker_policy")})
        _require(name not in names and identity not in identities, "PROGRESSION_DUPLICATE_NATIVE_INSTANCE")
        names.add(name)
        identities.add(identity)
    _require(names == set(ranks) and policy["nodes"] == nodes, "PROGRESSION_INSTANCE_SELECTION_DIFFERS")
    dependents = {name: set() for name in names}
    prerequisites = {name: set() for name in names}
    edges: set[tuple[str, str, str | None]] = set()
    for edge in _list(bundle["edges"], MAX_EDGES):
        _record(edge, {"node_id", "prerequisite_id", "operand_role"})
        parent, child = _text(edge["node_id"]), _text(edge["prerequisite_id"])
        role = edge["operand_role"]
        _require(role is None or type(role) is str and bool(_text(role)), "PROGRESSION_OPERAND_ROLE")
        key = parent, child, role
        _require(parent in names and child in names and key not in edges, "PROGRESSION_EDGE_SELECTION")
        _require(ranks[child] <= ranks[parent], "PROGRESSION_UPWARD_PREREQUISITE")
        edges.add(key)
        prerequisites[parent].add(child)
        dependents[child].add(parent)
    pending = deque(sorted(name for name in names if not prerequisites[name]))
    remaining = {name: len(prerequisites[name]) for name in names}
    visited = 0
    while pending:
        visited += 1
        for name in sorted(dependents[pending.popleft()]):
            remaining[name] -= 1
            if remaining[name] == 0:
                pending.append(name)
    _require(visited == len(names), "PROGRESSION_DEPENDENCY_CYCLE")
    root_names = [_text(name) for name in _list(policy["required_roots"], MAX_NODES)]
    _require(bool(root_names) and len(root_names) == len(set(root_names)), "PROGRESSION_ROOT_SELECTION")
    subject_root = any(node["node_id"] in root_names and node["object_id"] == subject["object_id"]
                       for node in nodes)
    # An absent root remains unavailable native evidence, never root clearance.
    # A complete selected root set belonging to other objects is a contradiction.
    _require(subject_root or any(name not in names for name in root_names),
             "PROGRESSION_SUBJECT_ROOT_DIFFERS")
    return nodes


def assess_tier_progression(selection_bytes: bytes, *, bundle_bytes: bytes | None,
                            expected_policy_bytes: bytes | None, artifact_files: dict[str, bytes],
                            expected_selection_digest: str | None,
                            expected_mechanism_digest: str | None, cancelled: bool = False) -> dict[str, Any]:
    """Replay exact selected native instances and gate their cumulative finite ranks."""
    report: dict[str, Any] = {"schema_version": ASSESSMENT, "semantic_version": PROFILE, "status": "UNKNOWN",
        "selected_depth": 0, "selected_target_status": "UNKNOWN", "can_advance_to": None, "tiers": [],
        "native_replay": "NOT_RUN", "native_assessment": None, "blockers": [], "report_complete": True,
        "installed_route_inventory_status": "UNKNOWN", "installed_route_inventory_digest": None,
        "installed_route_family_cell_count": None, "installed_route_membership_count": None,
        "polished": False, "full_application_status": "UNKNOWN", "whole_tier_conformance": "NOT_ESTABLISHED",
        "inventory_authority": "NOT_ESTABLISHED", "full_required_certificate_instances": "UNKNOWN",
        "claim_boundary": "Exact externally selected finite rank overlay and native instances only. Census labels and hashes do not authenticate complete application requirements. No historical coordinate reinterpretation, authority, model correctness, safety or publication."}
    report.update(selection_digest=None, expected_selection_digest=None, expected_mechanism_digest=None, subject=None)
    try:
        try:
            installed = installed_core_route_inventory()
        except RuntimeError as exc:
            raise _Refused("CORE_INSTALLED_ROUTE_INVENTORY_DIFFERS") from exc
        report.update(
            installed_route_inventory_status="PASS",
            installed_route_inventory_digest=digest(canonical_bytes(installed)),
            installed_route_family_cell_count=installed["family_cell_count"],
            installed_route_membership_count=installed["registered_route_membership_count"],
        )
        _require(type(cancelled) is bool, "PROGRESSION_CANCEL_FLAG")
        for label, value in (("expected_selection_digest", expected_selection_digest), ("expected_mechanism_digest", expected_mechanism_digest)):
            if value is not None:
                report[label] = _hash(value)
        value = _parse(selection_bytes, MAX_SELECTION_BYTES)
        report["selection_digest"] = digest(selection_bytes)
        ranks, tiers = _selection(value)
        report["subject"] = dict(value["subject"])
        if expected_selection_digest is not None:
            _require(_hash(expected_selection_digest) == digest(selection_bytes), "PROGRESSION_EXTERNAL_PIN_DIFFERS")
        if bundle_bytes is None or expected_policy_bytes is None:
            report["blockers"].append("PROGRESSION_NATIVE_SELECTION_MISSING")
            return _finish(report)
        bundle, policy = _parse(bundle_bytes, MAX_RECORD_BYTES), _parse(expected_policy_bytes, MAX_RECORD_BYTES)
        nodes = _graph(bundle, policy, ranks, value["subject"])
        _require(digest(bundle_bytes) == value["bundle_digest"] and digest(expected_policy_bytes) == value["policy_digest"],
                 "PROGRESSION_NATIVE_BYTES_DIFFER")
        _require(type(artifact_files) is dict, "PROGRESSION_ARTIFACT_SNAPSHOT")
        if len(artifact_files) > 1024:
            raise _Exhausted()
        files = dict(artifact_files)
        for path, raw in files.items():
            _require(type(path) is str and len(path) <= 256, "PROGRESSION_ARTIFACT_NAME")
            dag._path(path)
            _require(type(raw) is bytes, "PROGRESSION_ARTIFACT_SNAPSHOT")
        if sum(len(raw) for raw in files.values()) > MAX_ARTIFACT_BYTES:
            raise _Exhausted()
        _require(dag.artifact_files_digest(files) == value["artifact_files_digest"] == policy["artifact_files_digest"],
                 "PROGRESSION_ARTIFACT_BYTES_DIFFER")
        hashes = {path: digest(raw) for path, raw in files.items()}
        work = 0
        for node in nodes:
            path, pin = dag._path(node["certificate_path"]), _hash(node["certificate_digest"])
            if path in files:
                _require(hashes[path] == pin, "PROGRESSION_CERTIFICATE_BYTES_DIFFER")
            work += len(files.get(path, b""))
            if work > MAX_BINDING_HASH_BYTES:
                raise _Exhausted()
            for reference in _list(node["artifact_bindings"], 1024):
                _record(reference, {"path", "digest"})
                path = dag._path(reference["path"])
                _hash(reference["digest"])
                work += len(files.get(path, b""))
                if work > MAX_BINDING_HASH_BYTES:
                    raise _Exhausted()
        objects: dict[str, NamespaceObject] = {}
        for row in _list(bundle["objects"], MAX_NODES):
            _record(row, {"object_id", "kind", "payload", "operands"})
            item = NamespaceObject.create(**row)
            _require(item.object_id not in objects and item.to_dict() == row, "PROGRESSION_OBJECT_RECORD_DIFFERS")
            objects[item.object_id] = item
        selected_objects: set[str] = set()
        for row in policy["required_objects"]:
            _record(row, {"object_id", "object_kind", "record_digest", "profile_digest"})
            oid = _text(row["object_id"])
            _hash(row["record_digest"])
            _hash(row["profile_digest"])
            ObjectKind(row["object_kind"])
            _require(oid not in selected_objects, "PROGRESSION_DUPLICATE_OBJECT_SELECTION")
            selected_objects.add(oid)
            if oid in objects:
                _require(objects[oid].kind.value == row["object_kind"] and objects[oid].digest == row["record_digest"],
                         "PROGRESSION_SELECTED_OBJECT_DIFFERS")
        _require(not set(objects) - selected_objects, "PROGRESSION_UNSELECTED_OBJECT")
        for node in nodes:
            for reference in node["artifact_bindings"]:
                if reference["path"] in hashes:
                    _require(hashes[reference["path"]] == reference["digest"], "PROGRESSION_ARTIFACT_BINDING_DIFFERS")
            item = objects.get(node["object_id"])
            _record(node["facet_bindings"], {"payload_digest", "operands_digest"})
            if item is not None:
                _require(node["facet_bindings"] == {"payload_digest": digest(item.payload_bytes),
                    "operands_digest": digest(canonical_bytes(item.to_dict()["operands"]))}, "PROGRESSION_FACET_BINDING_DIFFERS")
        if expected_selection_digest is None or expected_mechanism_digest is None:
            report["blockers"].append("PROGRESSION_EXTERNAL_PIN_MISSING")
        if expected_mechanism_digest is not None:
            _require(_hash(expected_mechanism_digest) == mechanism_digest(), "PROGRESSION_EXTERNAL_PIN_DIFFERS")
        if cancelled:
            report["blockers"].append("PROGRESSION_CANCELLED")
        if report["blockers"]:
            return _finish(report)
        report["native_replay"] = "ATTEMPTED"
        native = dag.assess_certificate_dependencies_preserving_faults(bundle_bytes,
            expected_policy_bytes=expected_policy_bytes, artifact_files=files)
        report["native_replay"], report["native_assessment"] = "EXECUTED", native
        _require(native["schema_version"] == dag.FAULT_ASSESSMENT and native["status"] in ("PASS", "FAIL", "UNKNOWN"),
                 "PROGRESSION_NATIVE_REPORT_DIFFERS")
        results = {row["node_id"]: row["qualified_status"] for row in native["nodes"]}
        _require(all(name in ranks and status in ("PASS", "FAIL", "UNKNOWN") for name, status in results.items()),
                 "PROGRESSION_NATIVE_REPORT_DIFFERS")
        failed = native["status"] == "FAIL" or any(s == "FAIL" for s in results.values())
        if failed:
            report["status"] = "FAIL"
        cumulative = "PASS"
        for rank in range(1, 10):
            row = tiers[rank]
            observed = [results.get(name, "UNKNOWN") for name in row["required_nodes"]]
            direct = ("FAIL" if "FAIL" in observed else "PASS" if row["census"] == "COMPLETE" and observed
                      and all(s == "PASS" for s in observed) else "UNKNOWN")
            cumulative = ("FAIL" if "FAIL" in (direct, cumulative) else
                          "PASS" if direct == cumulative == "PASS" else "UNKNOWN")
            report["tiers"].append({"tier": rank, "tier_name": CoreTier(rank).name, "name": CoreTier(rank).name, "census": row["census"],
                "required_nodes": row["required_nodes"], "direct_status": direct, "cumulative_status": cumulative})
            if cumulative == "PASS":
                report["selected_depth"] = rank
        target = value["target_tier"]
        report["selected_target_status"] = report["tiers"][target - 1]["cumulative_status"]
        if native["status"] != "PASS" or native["blockers"]:
            report["selected_depth"] = 0
            if report["selected_target_status"] == "PASS":
                report["selected_target_status"] = "UNKNOWN"
        report["status"] = "FAIL" if failed else report["selected_target_status"]
        if report["status"] == "PASS" and target < 9 and report["tiers"][target]["cumulative_status"] == "PASS":
            report["can_advance_to"] = target + 1
        report["blockers"] = list(native["blockers"])
        if report["selected_target_status"] != "PASS":
            report["blockers"].append("PROGRESSION_REQUIRED_TIER_NOT_CLEAR")
        if target < 9 and tiers[target + 1]["census"] == "UNKNOWN":
            report["blockers"].append("PROGRESSION_NEXT_CENSUS_UNKNOWN")
    except (_Exhausted, dag._Exhausted, RecursionError, OverflowError):
        report["blockers"].append("PROGRESSION_CAPACITY_EXHAUSTED")
    except (CancelledError, ImportError, OSError):
        if report["native_replay"] == "ATTEMPTED":
            report["native_replay"] = "UNAVAILABLE"
        report["blockers"].append("PROGRESSION_REPLAY_UNAVAILABLE")
    except _Refused as exc:
        report["status"] = "FAIL"
        report["blockers"].append(exc.code)
    except (ValueError, TypeError, KeyError, UnicodeError):
        report["status"] = "FAIL"
        report["blockers"].append("PROGRESSION_CONTRACT_REJECTED")
    return _finish(report)


def _finish(report: dict[str, Any]) -> dict[str, Any]:
    # Include the digest field's fixed width in the capacity decision.
    reserved = {**report, "assessment_digest": "sha256:" + "0" * 64}
    if len(canonical_bytes(reserved)) > MAX_REPORT_BYTES:
        report.update(status="FAIL" if report["status"] == "FAIL" else "UNKNOWN", report_complete=False,
                      selected_depth=0, selected_target_status="UNKNOWN", can_advance_to=None, tiers=[],
                      native_assessment=None, blockers=["PROGRESSION_REPORT_CAPACITY_EXHAUSTED"])
    report["assessment_digest"] = digest(canonical_bytes(report))
    return report


__all__ = [
    "CoreTier", "assess_tier_progression", "core_tier_profile",
    "installed_core_route_inventory", "mechanism_digest",
    "verifier_tier1_self_application_obligations",
]
