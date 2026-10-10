"""Strict cumulative progression for a separately selected ten-tier profile.

Verifier Standard (VSTD); directed acyclic graph (DAG); JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256); mebibytes (MiB).
This gate binds a rank overlay to exact native certificate instances. A selected
finite progression result is not complete application or whole-tier conformance.
Existing nine-tier and legacy certificate propositions keep their own meanings.
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
from verifier.domains.contracts import certificate_dag as dag

PROFILE = "verifier-current-ten-tier-progression-1"
SELECTION = "verifier-ten-tier-progression-selection-1"
ASSESSMENT = "verifier-ten-tier-progression-assessment-2"
MAX_SELECTION_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_BINDING_HASH_BYTES = 128 * 1024 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_NODES = 512
MAX_EDGES = 4096


class ProgressionTier(IntEnum):
    """Ranks in this profile only; never cast historical coordinates into them."""

    FACETS = 1
    DYNAMICS = 2
    STATICS = 3
    CLOSURE = 4
    INDEPENDENCE = 5
    SECURITY = 6
    PRIVACY = 7
    CONSENT = 8
    GOVERNANCE = 9
    CORRIGIBILITY = 10


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
    names = ("runtime/tier_progression.py", "domains/contracts/certificate_dag.py",
             "domains/contracts/current_object_routes.py", "core/certificate.py",
             "core/receipt.py", "core/namespace.py", "standard/CERTIFICATE_DAG.md",
             "standard/CURRENT_TEN_TIER_PROGRESSION.md")
    return digest(canonical_bytes({name: digest((root / name).read_bytes()) for name in names}))


def ten_tier_profile() -> dict[str, Any]:
    """Describe the fixed order, without inventing required family members."""
    return {"semantic_version": PROFILE,
            "tiers": [{"tier": t.value, "name": t.name} for t in ProgressionTier],
            "family_membership": "INDEPENDENT_SELECTION_REQUIRED",
            "full_required_certificate_instances": "UNKNOWN"}


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
    _require(type(value) is int and 1 <= value <= 10, "PROGRESSION_TIER")
    return value


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
    _record(value, {"schema_version", "semantic_version", "profile_id", "subject", "target_tier",
                    "bundle_digest", "policy_digest", "artifact_files_digest", "ranks", "tiers"})
    _require(value["schema_version"] == SELECTION and value["semantic_version"] == PROFILE,
             "PROGRESSION_VERSION")
    _text(value["profile_id"])
    _record(value["subject"], {"object_id", "object_kind", "record_digest"})
    _text(value["subject"]["object_id"])
    ObjectKind(value["subject"]["object_kind"])
    _hash(value["subject"]["record_digest"])
    _tier(value["target_tier"])
    for key in ("bundle_digest", "policy_digest", "artifact_files_digest"):
        _hash(value[key])
    ranks: dict[str, int] = {}
    for row in _list(value["ranks"], MAX_NODES):
        _record(row, {"node_id", "tier"})
        name, rank = _text(row["node_id"]), _tier(row["tier"])
        _require(name not in ranks, "PROGRESSION_DUPLICATE_INSTANCE")
        ranks[name] = rank
    _require(bool(ranks), "PROGRESSION_EMPTY_INSTANCE_SELECTION")
    tiers: dict[int, dict[str, Any]] = {}
    selected: set[str] = set()
    for row in _list(value["tiers"], 10):
        _record(row, {"tier", "census", "required_nodes"})
        rank = _tier(row["tier"])
        _require(rank not in tiers and row["census"] in ("COMPLETE", "UNKNOWN"), "PROGRESSION_CENSUS")
        names = [_text(n) for n in _list(row["required_nodes"], MAX_NODES)]
        _require(len(names) == len(set(names)), "PROGRESSION_DUPLICATE_REQUIREMENT")
        _require(row["census"] != "COMPLETE" or bool(names), "PROGRESSION_EMPTY_COMPLETE_CENSUS")
        _require(all(n in ranks and ranks[n] == rank and n not in selected for n in names),
                 "PROGRESSION_REQUIRED_RANK_DIFFERS")
        selected.update(names)
        tiers[rank] = row
    _require(set(tiers) == set(range(1, 11)) and selected == set(ranks), "PROGRESSION_CENSUS_COVERAGE")
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
    nodes = _list(bundle["nodes"], MAX_NODES)
    names, identities = set(), set()
    for node in nodes:
        _record(node, {"node_id", "object_id", "claim_id", "certificate_path", "certificate_digest",
                       "request", "checker_policy", "contract_version", "artifact_bindings", "facet_bindings"})
        name = _text(node["node_id"])
        native_request = node["request"]
        if type(native_request) is dict and native_request.get("semantic_version") ==                 "verifier-current-ten-tier-object-obligations-1":
            native_rank = {"VERIFIER-6.1": ProgressionTier.SECURITY.value,
                           "VERIFIER-10.1": ProgressionTier.CORRIGIBILITY.value}.get(native_request.get("coordinate"))
            _require(native_rank is not None and ranks.get(name) == native_rank,
                     "PROGRESSION_NATIVE_TEN_TIER_RANK_DIFFERS")
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
        "polished": False, "full_application_status": "UNKNOWN", "whole_tier_conformance": "NOT_ESTABLISHED",
        "inventory_authority": "NOT_ESTABLISHED", "full_required_certificate_instances": "UNKNOWN",
        "claim_boundary": "Exact externally selected finite rank overlay and native instances only. Census labels and hashes do not authenticate complete application requirements. No historical coordinate reinterpretation, authority, model correctness, safety or publication."}
    report.update(selection_digest=None, expected_selection_digest=None, expected_mechanism_digest=None, subject=None)
    try:
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
        for rank in range(1, 11):
            row = tiers[rank]
            observed = [results.get(name, "UNKNOWN") for name in row["required_nodes"]]
            direct = ("FAIL" if "FAIL" in observed else "PASS" if row["census"] == "COMPLETE" and observed
                      and all(s == "PASS" for s in observed) else "UNKNOWN")
            cumulative = ("FAIL" if "FAIL" in (direct, cumulative) else
                          "PASS" if direct == cumulative == "PASS" else "UNKNOWN")
            report["tiers"].append({"tier": rank, "name": ProgressionTier(rank).name, "census": row["census"],
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
        if report["status"] == "PASS" and target < 10 and report["tiers"][target]["cumulative_status"] == "PASS":
            report["can_advance_to"] = target + 1
        report["blockers"] = list(native["blockers"])
        if report["selected_target_status"] != "PASS":
            report["blockers"].append("PROGRESSION_REQUIRED_TIER_NOT_CLEAR")
        if target < 10 and tiers[target + 1]["census"] == "UNKNOWN":
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


__all__ = ["ProgressionTier", "ten_tier_profile", "assess_tier_progression", "mechanism_digest"]
