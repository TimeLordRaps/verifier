"""Verifier Standard (VSTD) application release-consumer binding and native replay.

application programming interface (API); command-line interface (CLI); JavaScript
Object Notation (JSON); directed acyclic graph (DAG); Secure Hash Algorithm 256-bit
(SHA-256); mebibytes (MiB). This version evaluates exact finite artifact/member and
selected native-instance bindings. Mandatory full self-polish gates remain separate
and unavailable in this version; a finite PASS never authorizes release.
"""
from __future__ import annotations

import argparse
from asyncio import CancelledError
from io import BytesIO
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
from typing import Any
import zipfile
import zlib

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, assess_composition, composition_digest
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import certificate_dag as dag
from verifier.runtime import tier_progression as progression

SELECTION = "verifier-application-release-selection-1"
ASSESSMENT = "verifier-application-release-assessment-2"
REQUIREMENTS = "verifier-application-required-instances-1"
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_FILES = 1024
MAX_SOURCE_FILES = 8192
MAX_SHARDS = 32
MAX_INSTANCES = 16384
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
FULL_GATES = ("APPLICATION_CENSUS", "PUBLIC_CHECKABILITY", "COMPOSED_SECURITY",
              "COMPLETE_CORRIGIBILITY", "ACCEPTANCE")


class _Refuted(ValueError):
    pass


class _Unavailable(ValueError):
    pass


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism_digest() -> str:
    root = Path(__file__).parents[1]
    names = ("runtime/application_release.py", "runtime/tier_progression.py",
             "runtime/artifact_snapshot.py", "core/namespace.py", "core/certificate.py",
             "core/receipt.py", "domains/contracts/certificate_dag.py",
             "standard/APPLICATION_RELEASE_CONSUMER.md")
    return digest(canonical_bytes({"direct_sources": {name: digest((root / name).read_bytes()) for name in names},
                                   "progression_mechanism": progression.mechanism_digest()}))


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise _Refuted(code)


def _keys(value: Any, fields: set[str]) -> None:
    _require(type(value) is dict and set(value) == fields, "APPLICATION_RECORD_FIELDS")


def _text(value: Any) -> str:
    _require(type(value) is str and len(value) <= 256 and bool(value.strip())
             and not any(ord(c) < 32 for c in value), "APPLICATION_IDENTIFIER")
    return value


def _hash(value: Any) -> str:
    _require(type(value) is str and _HASH.fullmatch(value) is not None, "APPLICATION_DIGEST")
    return value


def _path(value: Any) -> str:
    path = _text(value)
    _require("\\" not in path and ":" not in path
             and all(part not in ("", ".", "..") for part in path.split("/")), "APPLICATION_PATH")
    return path


def _list(value: Any, maximum: int) -> list[Any]:
    _require(type(value) is list, "APPLICATION_LIST")
    if len(value) > maximum:
        raise _Unavailable("APPLICATION_CAPACITY_EXHAUSTED")
    return value


def _parse(raw: bytes, record: bool = True) -> Any:
    _require(type(raw) is bytes, "APPLICATION_IMMUTABLE_BYTES")
    if len(raw) > MAX_RECORD_BYTES:
        raise _Unavailable("APPLICATION_CAPACITY_EXHAUSTED")
    result = strict_json_loads(raw.decode("utf-8"))
    _require(not record or type(result) is dict, "APPLICATION_RECORD_FIELDS")
    return result


def _source_rows(rows: list[dict[str, Any]]) -> dict:
    expected = {}
    total = 0
    for row in _list(rows, MAX_SOURCE_FILES):
        _keys(row, {"path", "bytes", "digest"})
        name = _path(row["path"])
        _hash(row["digest"])
        _require(name not in expected and type(row["bytes"]) is int and row["bytes"] >= 0,
                 "APPLICATION_SOURCE_INVENTORY")
        expected[name] = row
        total += row["bytes"]
    _require(bool(expected), "APPLICATION_SOURCE_INVENTORY")
    if total > MAX_SOURCE_BYTES:
        raise _Unavailable("APPLICATION_SOURCE_CAPACITY_EXHAUSTED")
    return expected


def _source_archive(raw: bytes, rows: list[dict[str, Any]]) -> None:
    expected = _source_rows(rows)
    # Bound actual central-directory records before ZipFile allocates entries.
    marker = raw.rfind(b"PK\x05\x06", max(0, len(raw)-65557))
    _require(marker >= 0 and marker+22 <= len(raw), "APPLICATION_SOURCE_ARCHIVE")
    end = struct.unpack_from("<4s4H2LH", raw, marker)
    _require(marker+22+end[-1] == len(raw) and end[1:3] == (0, 0)
             and end[3] == end[4], "APPLICATION_SOURCE_ARCHIVE")
    if 65535 in end[3:5] or 4294967295 in end[5:7]:
        raise _Unavailable("APPLICATION_SOURCE_ARCHIVE_FORMAT_UNSUPPORTED")
    directory_size, offset = end[5:7]
    _require(offset+directory_size == marker, "APPLICATION_SOURCE_ARCHIVE")
    if directory_size > MAX_RECORD_BYTES:
        raise _Unavailable("APPLICATION_SOURCE_CAPACITY_EXHAUSTED")
    position, count, unsupported = offset, 0, False
    while position < marker:
        _require(position+46 <= marker and raw[position:position+4] == b"PK\x01\x02",
                 "APPLICATION_SOURCE_ARCHIVE")
        header = struct.unpack_from("<4s6H3L5H2L", raw, position)
        size = 46 + header[10] + header[11] + header[12]
        _require(position+size <= marker and header[13] == 0, "APPLICATION_SOURCE_ARCHIVE")
        if 4294967295 in (header[8], header[9], header[16]):
            raise _Unavailable("APPLICATION_SOURCE_ARCHIVE_FORMAT_UNSUPPORTED")
        extra_start = position+46+header[10]
        extra_end = extra_start+header[11]
        while extra_start < extra_end:
            _require(extra_start+4 <= extra_end, "APPLICATION_SOURCE_ARCHIVE")
            tag, length = struct.unpack_from("<HH", raw, extra_start)
            _require(extra_start+4+length <= extra_end, "APPLICATION_SOURCE_ARCHIVE")
            if tag == 1:
                raise _Unavailable("APPLICATION_SOURCE_ARCHIVE_FORMAT_UNSUPPORTED")
            extra_start += 4+length
        unsupported |= header[4] not in (0, 8)
        count += 1
        if count > MAX_SOURCE_FILES:
            raise _Unavailable("APPLICATION_SOURCE_CAPACITY_EXHAUSTED")
        position += size
    _require(position == marker and count == end[4], "APPLICATION_SOURCE_ARCHIVE")
    if unsupported:
        raise _Unavailable("APPLICATION_SOURCE_ARCHIVE_COMPRESSION_UNSUPPORTED")
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        entries = archive.infolist()
        _require(len(entries) == len(expected) and len({row.filename for row in entries}) == len(entries),
                 "APPLICATION_SOURCE_SET_DIFFERS")
        _require({row.filename for row in entries} == set(expected), "APPLICATION_SOURCE_SET_DIFFERS")
        for entry in entries:
            selected = expected[_path(entry.filename)]
            _require(not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16)
                     and not entry.flag_bits & 1 and entry.file_size == selected["bytes"],
                     "APPLICATION_SOURCE_ARCHIVE")
            with archive.open(entry) as stream:
                content = stream.read(selected["bytes"]+1)
            _require(len(content) == selected["bytes"] and digest(content) == selected["digest"],
                     "APPLICATION_SOURCE_BYTES_DIFFER")


def _membership(selection: dict, membership: dict, source: dict, operations: list,
                contexts: list, files: dict[str, bytes]) -> tuple[dict[str, NamespaceObject], dict]:
    _require(membership.get("schema_version") == "verifier-own-application-membership-manifest-1",
             "APPLICATION_MEMBERSHIP_VERSION")
    objects = {}
    for row in _list(membership["objects"], 4096):
        _keys(row, {"object_id", "kind", "payload", "operands"})
        item = NamespaceObject.create(**row)
        _require(item.object_id not in objects and item.to_dict() == row, "APPLICATION_MEMBER_RECORD_DIFFERS")
        objects[item.object_id] = item
    root = objects.get(selection["root"]["object_id"])
    _require(root is not None and root.kind.value == "VERIFIER" and not root.operands,
             "APPLICATION_ROOT_DIFFERS")
    _require(root.digest == selection["root"]["record_digest"]
             and canonical_bytes(membership["application_root"]) == canonical_bytes(root.to_dict())
             and membership["application_root_digest"] == root.digest, "APPLICATION_ROOT_DIFFERS")
    envelope = objects.get(membership["membership_envelope_id"])
    _require(envelope is not None and envelope.kind.value == "HYPER"
             and envelope.digest == membership["membership_envelope_digest"], "APPLICATION_MEMBERSHIP_DIFFERS")
    roles = dict(envelope.operands)
    _require(roles.get("application") == (root.object_id,), "APPLICATION_ROOT_DIFFERS")
    members = {oid: item.digest for oid, item in sorted(objects.items())
               if oid not in (root.object_id, envelope.object_id)}
    _require({name for role, names in roles.items() if role != "application" for name in names} == set(members),
             "APPLICATION_MEMBER_SET_DIFFERS")
    _require(root.payload.get("exact_member_records_digest") == digest(canonical_bytes(members)),
             "APPLICATION_MEMBER_BODY_DIFFERS")
    collection = composition_digest(list(objects.values()))
    _require(collection == membership["collection_digest"], "APPLICATION_COLLECTION_DIFFERS")
    _require(source.get("schema_version") == "verifier-actual-source-manifest-1", "APPLICATION_SOURCE_VERSION")
    _source_rows(source["source_files"])
    source_item = objects.get(selection["source_member_id"])
    _require(source_item is not None and source_item.kind.value == "DATA"
             and source_item.payload.get("manifest_digest") == digest(canonical_bytes(source)),
             "APPLICATION_SOURCE_MEMBER_DIFFERS")
    sources = {row["path"]: row["digest"] for row in source["source_files"]}
    for item in objects.values():
        if "module_path" in item.payload:
            _require(sources.get(item.payload["module_path"]) == item.payload.get("module_digest"),
                     "APPLICATION_MODULE_BYTES_DIFFER")
    _require(root.payload.get("operation_definition_digest") == digest(canonical_bytes(operations))
             and root.payload.get("actual_operation_context_digest") == digest(canonical_bytes(contexts)),
             "APPLICATION_OPERATION_CONTEXT_DIFFERS")
    declared = {}
    for row in _list(operations, MAX_INSTANCES):
        oid = _text(row["operation_id"])
        _require(oid not in declared, "APPLICATION_DUPLICATE_OPERATION")
        declared[oid] = row
    observed = {}
    for row in _list(contexts, MAX_INSTANCES):
        oid = _text(row["operation_id"])
        pin = _hash(row["context_revision_digest"])
        _require(pin not in observed and digest(canonical_bytes({k: v for k, v in row.items()
                 if k != "context_revision_digest"})) == pin, "APPLICATION_CONTEXT_DIFFERS")
        _require(digest(canonical_bytes(row["instruction"])) == row["instruction_revision_digest"],
                 "APPLICATION_INSTRUCTION_DIFFERS")
        observed[pin] = row
    for oid in roles.get("artifacts", ()):
        item = objects[oid]
        path = _path(item.payload["name"])
        _require(item.kind.value == "DATA", "APPLICATION_ARTIFACT_MEMBER_DIFFERS")
        _require(type(item.payload["bytes"]) is int and item.payload["bytes"] >= 0,
                 "APPLICATION_ARTIFACT_MEMBER_DIFFERS")
        _hash(item.payload["digest"])
        if path not in files:
            continue
        _require(item.kind.value == "DATA" and len(files[path]) == item.payload["bytes"]
                 and digest(files[path]) == item.payload["digest"], "APPLICATION_ARTIFACT_BYTES_DIFFER")
    return objects, {"operations": declared, "contexts": observed}


def _available_members(selection: dict, membership: dict, source: dict,
                       objects: dict, files: dict, blockers: list[str]) -> None:
    """Decode only after all available structural/global bindings are inspected."""
    typed = assess_composition(list(objects.values()), expected_digest=membership["collection_digest"])
    _require(typed.verdict.value != "FAIL", "APPLICATION_TYPED_COMPOSITION_DIFFERS")
    if typed.verdict.value != "PASS":
        blockers.append("APPLICATION_TYPED_COMPOSITION_UNAVAILABLE")
    root = objects[selection["source_member_id"]]
    archive_path = _path(selection["source_archive_path"])
    if archive_path not in files:
        blockers.append("APPLICATION_SOURCE_ARCHIVE_MISSING")
    else:
        _require(digest(files[archive_path]) == root.payload.get("source_archive_digest")
                 == source["preserved_source_archive"]["digest"], "APPLICATION_SOURCE_ARCHIVE_DIFFERS")
        try:
            _source_archive(files[archive_path], source["source_files"])
        except _Unavailable as exc:
            blockers.append(str(exc))
    envelope = objects[membership["membership_envelope_id"]]
    for oid in dict(envelope.operands).get("artifacts", ()):
        if objects[oid].payload["name"] not in files:
            blockers.append("APPLICATION_ARTIFACT_MISSING")



def assess_application_release(selection_bytes: bytes, *, membership_bytes: bytes,
        source_manifest_bytes: bytes, operation_definitions_bytes: bytes, contexts_bytes: bytes,
        requirements_bytes: bytes, artifact_files: dict[str, bytes], shard_inputs: dict[str, dict],
        expected_selection_digest: str | None, expected_mechanism_digest: str | None,
        cancelled: bool = False) -> dict[str, Any]:
    report = {"schema_version": ASSESSMENT, "status": "UNKNOWN", "binding_status": "UNKNOWN",
        "native_status": "UNKNOWN", "shards": [], "blockers": [], "polished": False,
        "release_authorized": False, "full_application_status": "UNKNOWN",
        "required_operational_certificate_instances": "UNKNOWN",
        "full_gates": {name: "UNKNOWN" for name in FULL_GATES},
        "claim_boundary": "Finite declared bindings and actual selected native replay. Mandatory full self-polish, applicability authority, execution attestation, whole corrigibility and acceptance are not established."}
    report.update(selection_digest=None, expected_selection_digest=None, expected_mechanism_digest=None, root=None)
    structural_done = False
    try:
        _require(type(cancelled) is bool, "APPLICATION_CANCEL_FLAG")
        for label, value in (("expected_selection_digest", expected_selection_digest), ("expected_mechanism_digest", expected_mechanism_digest)):
            if value is not None:
                report[label] = _hash(value)
        selection = _parse(selection_bytes)
        report["selection_digest"] = digest(selection_bytes)
        _keys(selection, {"schema_version", "root", "membership_digest", "source_manifest_digest",
            "source_member_id", "source_archive_path", "operation_definitions_digest", "contexts_digest",
            "requirements_digest", "artifact_files_digest", "shards"})
        _require(selection["schema_version"] == SELECTION, "APPLICATION_SELECTION_VERSION")
        _keys(selection["root"], {"object_id", "object_kind", "record_digest"})
        _text(selection["root"]["object_id"])
        _require(selection["root"]["object_kind"] == "VERIFIER", "APPLICATION_ROOT_DIFFERS")
        _hash(selection["root"]["record_digest"])
        report["root"] = dict(selection["root"])
        unavailable = []
        records = {}
        for key, raw in (("membership_digest", membership_bytes), ("source_manifest_digest", source_manifest_bytes),
            ("operation_definitions_digest", operation_definitions_bytes), ("contexts_digest", contexts_bytes),
            ("requirements_digest", requirements_bytes)):
            _hash(selection[key])
            _require(type(raw) is bytes, "APPLICATION_IMMUTABLE_BYTES")
            if len(raw) > MAX_RECORD_BYTES:
                unavailable.append("APPLICATION_CAPACITY_EXHAUSTED")
                continue
            _require(digest(raw) == selection[key], "APPLICATION_SELECTED_BYTES_DIFFER")
            records[key] = _parse(raw, key not in ("operation_definitions_digest", "contexts_digest"))
        if expected_selection_digest is not None:
            _require(digest(selection_bytes) == _hash(expected_selection_digest), "APPLICATION_EXTERNAL_PIN_DIFFERS")
        if unavailable:
            raise _Unavailable(unavailable[0])
        _require(type(artifact_files) is dict and type(shard_inputs) is dict, "APPLICATION_INPUT_MAP")
        if len(artifact_files) > MAX_FILES or len(shard_inputs) > MAX_SHARDS:
            raise _Unavailable("APPLICATION_CAPACITY_EXHAUSTED")
        files, captured = dict(artifact_files), {}
        for name, raw in files.items():
            _path(name)
            _require(type(raw) is bytes, "APPLICATION_IMMUTABLE_BYTES")
        if sum(map(len, files.values())) > MAX_INPUT_BYTES:
            raise _Unavailable("APPLICATION_CAPACITY_EXHAUSTED")
        _require(dag.artifact_files_digest(files) == _hash(selection["artifact_files_digest"]),
                 "APPLICATION_ARTIFACT_SNAPSHOT_DIFFERS")
        for sid, inputs in dict(shard_inputs).items():
            _text(sid)
            _keys(inputs, {"selection_bytes", "bundle_bytes", "policy_bytes", "artifact_paths"})
            captured[sid] = {field: inputs[field] for field in ("selection_bytes", "bundle_bytes", "policy_bytes")}
            captured[sid]["artifact_paths"] = list(_list(inputs["artifact_paths"], MAX_FILES))
        membership, source = records["membership_digest"], records["source_manifest_digest"]
        objects, contexts = _membership(selection, membership, source,
            records["operation_definitions_digest"], records["contexts_digest"], files)
        requirements = records["requirements_digest"]
        _keys(requirements, {"schema_version", "root", "tiers", "instances"})
        _require(requirements["schema_version"] == REQUIREMENTS and requirements["root"] == selection["root"],
                 "APPLICATION_REQUIREMENTS_DIFFER")
        selected_shards = {}
        for row in _list(selection["shards"], MAX_SHARDS):
            _keys(row, {"shard_id", "selection_digest", "bundle_digest", "policy_digest", "artifact_files_digest"})
            sid = _text(row["shard_id"])
            _require(sid not in selected_shards, "APPLICATION_DUPLICATE_SHARD")
            for field in ("selection_digest", "bundle_digest", "policy_digest", "artifact_files_digest"):
                _hash(row[field])
            selected_shards[sid] = row
        _require(not set(captured)-set(selected_shards), "APPLICATION_UNSELECTED_SHARD")
        instances, node_keys, by_node = {}, set(), {}
        for row in _list(requirements["instances"], MAX_INSTANCES):
            _keys(row, {"instance_id", "object_id", "operation_id", "context_digest", "instruction_digest",
                "generation", "shard_id", "node_id", "tier", "semantic_version", "objective",
                "proposition_digest", "request_digest", "checker_policy_digest"})
            iid, oid, operation = _text(row["instance_id"]), _text(row["object_id"]), _text(row["operation_id"])
            key = (_text(row["shard_id"]), _text(row["node_id"]))
            for field in ("context_digest", "instruction_digest", "proposition_digest", "request_digest", "checker_policy_digest"):
                _hash(row[field])
            _text(row["semantic_version"])
            _text(row["objective"])
            _require(iid not in instances and key not in node_keys and oid in objects
                     and key[0] in selected_shards, "APPLICATION_INSTANCE_SELECTION_DIFFERS")
            _require(type(row["tier"]) is int and 1 <= row["tier"] <= 10
                     and type(row["generation"]) is int and row["generation"] >= 0,
                     "APPLICATION_INSTANCE_SELECTION_DIFFERS")
            if operation not in contexts["operations"]:
                report["blockers"].append("APPLICATION_OPERATION_DECLARATION_MISSING")
            observed = contexts["contexts"].get(row["context_digest"])
            if observed is None:
                report["blockers"].append("APPLICATION_CONTEXT_EVIDENCE_MISSING")
            else:
                _require(observed["operation_id"] == operation
                         and observed["instruction_revision_digest"] == row["instruction_digest"],
                         "APPLICATION_INSTANCE_CONTEXT_DIFFERS")
                if "generation" not in observed:
                    report["blockers"].append("APPLICATION_GENERATION_EVIDENCE_MISSING")
                else:
                    _require(type(observed["generation"]) is int and observed["generation"] == row["generation"],
                             "APPLICATION_INSTANCE_CONTEXT_DIFFERS")
            instances[iid], by_node[key] = row, row
            node_keys.add(key)
        tiers, covered = {}, set()
        for row in _list(requirements["tiers"], 10):
            _keys(row, {"tier", "census", "required_instances"})
            tier = row["tier"]
            _require(type(tier) is int and 1 <= tier <= 10 and tier not in tiers
                     and row["census"] in ("COMPLETE", "UNKNOWN"), "APPLICATION_TIER_CENSUS")
            names = [_text(name) for name in _list(row["required_instances"], MAX_INSTANCES)]
            _require(len(names) == len(set(names)) and not set(names)&covered
                     and all(name in instances and instances[name]["tier"] == tier for name in names),
                     "APPLICATION_REQUIREMENT_CONSERVATION_DIFFERS")
            _require(row["census"] != "COMPLETE" or bool(names), "APPLICATION_EMPTY_COMPLETE_CENSUS")
            tiers[tier] = row
            covered.update(names)
        _require(set(tiers) == set(range(1, 11)) and covered == set(instances),
                 "APPLICATION_REQUIREMENT_CONSERVATION_DIFFERS")
        # Inspect every available shard before decoder, source I/O or native replay.
        prepared, native_seen, work = {}, set(), 0
        for sid, selected in selected_shards.items():
            inputs = captured.get(sid)
            if inputs is None:
                report["blockers"].append("APPLICATION_REQUIRED_SHARD_MISSING")
                continue
            bounded = True
            for field, pin in (("selection_bytes", "selection_digest"), ("bundle_bytes", "bundle_digest"),
                               ("policy_bytes", "policy_digest")):
                raw = inputs[field]
                _require(type(raw) is bytes, "APPLICATION_IMMUTABLE_BYTES")
                if len(raw) > progression.MAX_RECORD_BYTES:
                    unavailable.append("APPLICATION_CAPACITY_EXHAUSTED")
                    bounded = False
                    continue
                _require(digest(raw) == selected[pin], "APPLICATION_SHARD_BYTES_DIFFER")
                work += len(raw)
            paths = [_path(path) for path in inputs["artifact_paths"]]
            _require(len(paths) == len(set(paths)), "APPLICATION_SHARD_ARTIFACT_SELECTION")
            shard_files = {path: files[path] for path in paths if path in files}
            work += sum(map(len, shard_files.values()))
            if work > MAX_INPUT_BYTES:
                raise _Unavailable("APPLICATION_CAPACITY_EXHAUSTED")
            _require(dag.artifact_files_digest(shard_files) == selected["artifact_files_digest"],
                     "APPLICATION_SHARD_ARTIFACT_BYTES_DIFFER")
            if not bounded:
                continue
            bundle, policy, native_selection = (_parse(inputs[field]) for field in
                                               ("bundle_bytes", "policy_bytes", "selection_bytes"))
            _require(all(native_selection[field] == selected[field] for field in
                         ("bundle_digest", "policy_digest", "artifact_files_digest"))
                     and policy["artifact_files_digest"] == selected["artifact_files_digest"],
                     "APPLICATION_NATIVE_SELECTION_DIFFERS")
            try:
                ranks, _ = progression._selection(native_selection)
                progression._graph(bundle, policy, ranks, native_selection["subject"])
            except progression._Exhausted:
                unavailable.append("APPLICATION_CAPACITY_EXHAUSTED")
                continue
            _require(canonical_bytes(policy["nodes"]) == canonical_bytes(bundle["nodes"]),
                     "APPLICATION_NATIVE_SELECTION_DIFFERS")
            subject = native_selection["subject"]
            item = objects.get(subject["object_id"])
            _require(item is not None and subject["object_kind"] == item.kind.value
                     and subject["record_digest"] == item.digest, "APPLICATION_NATIVE_SUBJECT_DIFFERS")
            seen_objects = set()
            for row in _list(bundle["objects"], 4096):
                item = objects.get(row["object_id"])
                _require(item is not None and row["object_id"] not in seen_objects
                         and canonical_bytes(row) == canonical_bytes(item.to_dict()), "APPLICATION_NATIVE_MEMBER_DIFFERS")
                seen_objects.add(row["object_id"])
            seen_required = set()
            for row in _list(policy["required_objects"], 4096):
                item = objects.get(row["object_id"])
                _require(item is not None and row["object_id"] not in seen_required
                         and row["object_kind"] == item.kind.value and row["record_digest"] == item.digest,
                         "APPLICATION_NATIVE_REQUIRED_MEMBER_DIFFERS")
                seen_required.add(row["object_id"])
            profiles = {digest(canonical_bytes(row)): row for row in _list(bundle["profiles"], 4096)}
            chosen_profiles = {row["object_id"]: profiles.get(row["profile_digest"])
                               for row in policy["required_objects"]}
            hashes = {path: digest(raw) for path, raw in shard_files.items()}
            seen_nodes = set()
            for node in _list(bundle["nodes"], progression.MAX_NODES):
                path, pin = _path(node["certificate_path"]), _hash(node["certificate_digest"])
                _require(path not in hashes or hashes[path] == pin, "APPLICATION_NATIVE_CERTIFICATE_BYTES_DIFFER")
                for binding in _list(node["artifact_bindings"], MAX_FILES):
                    _keys(binding, {"path", "digest"})
                    path, pin = _path(binding["path"]), _hash(binding["digest"])
                    _require(path not in hashes or hashes[path] == pin, "APPLICATION_NATIVE_ARTIFACT_BYTES_DIFFER")
                key = sid, node["node_id"]
                _require(key in node_keys and key not in seen_nodes, "APPLICATION_UNSELECTED_NATIVE_INSTANCE")
                requirement = by_node[key]
                profile = chosen_profiles.get(node["object_id"])
                claims = [row for row in profile["obligations"] if row["claim_id"] == node["claim_id"]] if profile else []
                _require(len(claims) == 1, "APPLICATION_NATIVE_CLAIM_DIFFERS")
                claim = claims[0]
                _require(node["object_id"] == requirement["object_id"] and ranks.get(node["node_id"]) == requirement["tier"]
                         and digest(canonical_bytes(node["request"])) == requirement["request_digest"]
                         and digest(canonical_bytes(node["checker_policy"])) == requirement["checker_policy_digest"]
                         and all(claim[field] == requirement[field] for field in
                                 ("semantic_version", "objective", "proposition_digest")), "APPLICATION_NATIVE_INSTANCE_DIFFERS")
                native_seen.add(key)
                seen_nodes.add(key)
            prepared[sid] = inputs, shard_files
        if native_seen != node_keys:
            report["blockers"].append("APPLICATION_REQUIRED_NATIVE_INSTANCE_MISSING")
        structural_done = True
        report["blockers"].extend(unavailable)
        _available_members(selection, membership, source, objects, files, report["blockers"])
        if not report["blockers"]:
            report["binding_status"] = "PASS"
        if expected_selection_digest is None or expected_mechanism_digest is None:
            report["blockers"].append("APPLICATION_EXTERNAL_PIN_MISSING")
        if expected_mechanism_digest is not None:
            _require(_hash(expected_mechanism_digest) == mechanism_digest(), "APPLICATION_EXTERNAL_PIN_DIFFERS")
        if cancelled:
            report["blockers"].append("APPLICATION_CANCELLED")
        for sid, (inputs, shard_files) in prepared.items():
            if cancelled:
                break
            try:
                result = progression.assess_tier_progression(inputs["selection_bytes"],
                    bundle_bytes=inputs["bundle_bytes"], expected_policy_bytes=inputs["policy_bytes"],
                    artifact_files=shard_files, expected_selection_digest=selected_shards[sid]["selection_digest"]
                        if expected_selection_digest is not None else None,
                    expected_mechanism_digest=progression.mechanism_digest()
                        if expected_mechanism_digest is not None else None)
                row = {"shard_id": sid, "status": result["status"], "assessment_digest": result["assessment_digest"],
                    "selected_depth": result["selected_depth"], "selected_target_status": result["selected_target_status"],
                    "native_status": result["native_assessment"]["status"] if result["native_assessment"] else "UNKNOWN",
                    "blocker_count": len(result["blockers"]), "blockers": result["blockers"][:32]}
                if result["status"] == "FAIL":
                    report["status"] = report["native_status"] = "FAIL"
            except (CancelledError, ImportError, OSError, RuntimeError, RecursionError, OverflowError, MemoryError):
                row = {"shard_id": sid, "status": "UNKNOWN", "blockers": ["APPLICATION_REPLAY_UNAVAILABLE"]}
            report["shards"].append(row)
        if native_seen != node_keys:
            report["blockers"].append("APPLICATION_REQUIRED_NATIVE_INSTANCE_MISSING")
        if (report["native_status"] != "FAIL" and not cancelled and report["shards"]
                and len(report["shards"]) == len(selected_shards) and native_seen == node_keys
                and all(row["status"] == "PASS" for row in report["shards"])):
            report["native_status"] = "PASS"
    except _Unavailable as exc:
        report["blockers"].append(str(exc))
    except (CancelledError, ImportError, OSError, NotImplementedError, RuntimeError, RecursionError, OverflowError, MemoryError):
        report["blockers"].append("APPLICATION_REPLAY_UNAVAILABLE")
    except (_Refuted, ValueError, TypeError, KeyError, UnicodeError, zipfile.BadZipFile, struct.error, zlib.error) as exc:
        report["status"] = "FAIL"
        report["binding_status"] = "FAIL"
        report["blockers"].append(str(exc) if isinstance(exc, _Refuted) else "APPLICATION_CONTRACT_REJECTED")
    report["blockers"] = sorted(set(report["blockers"]) | {"APPLICATION_"+name+"_NOT_ESTABLISHED" for name in FULL_GATES})
    # Retained native details are bounded summaries; full proof remains its own input.
    if len(canonical_bytes(report)) > MAX_RECORD_BYTES:
        report["shards"] = [{"shard_id": row["shard_id"], "status": row["status"]} for row in report["shards"]]
        report["blockers"].append("APPLICATION_REPORT_CAPACITY_EXHAUSTED")
    report["assessment_digest"] = digest(canonical_bytes(report))
    return report


def recheck_application_release(assessment_bytes: bytes, selection_bytes: bytes, **inputs: Any) -> dict[str, Any]:
    """Recompute exact selected inputs; carried PASS is never current evidence."""
    expected = assess_application_release(selection_bytes, **inputs)
    try:
        stored = _parse(assessment_bytes)
        body = {key: value for key, value in stored.items() if key != "assessment_digest"}
        _require(stored.get("assessment_digest") == digest(canonical_bytes(body)), "APPLICATION_ASSESSMENT_DIFFERS")
        _require(canonical_bytes(stored) == canonical_bytes(expected), "APPLICATION_ASSESSMENT_DIFFERS")
    except (_Unavailable, RecursionError, OverflowError, CancelledError, MemoryError):
        return {"schema_version": ASSESSMENT, "status": "FAIL" if expected["status"] == "FAIL" else "UNKNOWN",
                "polished": False, "release_authorized": False, "reason": "APPLICATION_CAPACITY_EXHAUSTED",
                **{key: expected[key] for key in ("selection_digest", "expected_selection_digest", "expected_mechanism_digest", "root")}}
    except (ValueError, TypeError, UnicodeError):
        return {"schema_version": ASSESSMENT, "status": "FAIL", "polished": False,
                "release_authorized": False, "reason": "APPLICATION_ASSESSMENT_DIFFERS",
                **{key: expected[key] for key in ("selection_digest", "expected_selection_digest", "expected_mechanism_digest", "root")}}
    return expected


def add_application_parser(commands: Any) -> None:
    parser = commands.add_parser(
        "application",
        help=(
            "Replay the separately versioned historical ten-tier application "
            "contract; use core-application for the current nine-tier core."
        ),
    )
    modes = parser.add_subparsers(dest="application_command", required=True)
    for mode in ("assess", "check"):
        action = modes.add_parser(mode, help="Evaluate exact application release inputs." if mode == "assess" else "Recompute an application release assessment.")
        action.add_argument("selection")
        if mode == "check":
            action.add_argument("--assessment", required=True)
        for name in ("membership", "source-manifest", "operation-definitions", "contexts", "requirements", "artifacts", "shards", "selection-digest", "mechanism-digest"):
            action.add_argument("--"+name, required=True)
        action.add_argument("--json", action="store_true")


def handle_application_command(args: argparse.Namespace) -> int:
    from verifier.runtime.artifact_snapshot import capture, read_bytes
    capacity_reasons = {"artifact inventory or byte limit exceeded", "artifact traversal limit exceeded",
                        "selected input byte limit exceeded"}
    def bounded_read(path: str, bound: int) -> bytes:
        try:
            return read_bytes(path, bound)
        except ValueError as exc:
            if str(exc) in capacity_reasons:
                raise _Unavailable("APPLICATION_CAPACITY_EXHAUSTED") from exc
            raise
    try:
        try:
            files = capture(args.artifacts).files
        except ValueError as exc:
            if str(exc) in capacity_reasons:
                raise _Unavailable("APPLICATION_CAPACITY_EXHAUSTED") from exc
            raise
        shards = _parse(bounded_read(args.shards, MAX_RECORD_BYTES))
        _keys(shards, {"schema_version", "shards"})
        _require(shards["schema_version"] == "verifier-application-shard-locators-1", "APPLICATION_SHARD_LOCATORS_VERSION")
        inputs, locators = {}, {}
        for row in _list(shards["shards"], MAX_SHARDS):
            _keys(row, {"shard_id", "selection_path", "bundle_path", "policy_path", "artifact_paths"})
            sid = _text(row["shard_id"])
            _require(sid not in locators, "APPLICATION_DUPLICATE_SHARD")
            names = {field: _path(row[path]) for field, path in
                (("selection_bytes", "selection_path"), ("bundle_bytes", "bundle_path"), ("policy_bytes", "policy_path"))}
            paths = [_path(path) for path in _list(row["artifact_paths"], MAX_FILES)]
            _require(len(paths) == len(set(paths)), "APPLICATION_SHARD_ARTIFACT_SELECTION")
            locators[sid] = names, paths
        if any(name not in files for names, _ in locators.values() for name in names.values()):
            raise _Unavailable("APPLICATION_REQUIRED_SHARD_MISSING")
        for sid, (names, paths) in locators.items():
            inputs[sid] = {field: files[name] for field, name in names.items()}
            inputs[sid]["artifact_paths"] = paths
        options = {name+"_bytes": bounded_read(getattr(args, name), MAX_RECORD_BYTES)
            for name in ("membership", "source_manifest", "operation_definitions", "contexts", "requirements")}
        options.update(artifact_files=files, shard_inputs=inputs,
            expected_selection_digest=args.selection_digest, expected_mechanism_digest=args.mechanism_digest)
        selection = bounded_read(args.selection, MAX_RECORD_BYTES)
        result = (recheck_application_release(bounded_read(args.assessment, MAX_RECORD_BYTES), selection, **options)
                  if args.application_command == "check" else assess_application_release(selection, **options))
    except (_Unavailable, OSError, NotImplementedError, RuntimeError, RecursionError, MemoryError):
        result = {"schema_version": ASSESSMENT, "status": "UNKNOWN", "polished": False,
                  "release_authorized": False, "reason": "APPLICATION_INPUTS_UNAVAILABLE"}
    except (ValueError, TypeError, UnicodeError):
        result = {"schema_version": ASSESSMENT, "status": "FAIL", "polished": False,
                  "release_authorized": False, "reason": "APPLICATION_CONTRACT_REJECTED"}
    except KeyError:
        result = {"schema_version": ASSESSMENT, "status": "UNKNOWN", "polished": False,
                  "release_authorized": False, "reason": "APPLICATION_INPUTS_UNAVAILABLE"}
    print(json.dumps(result, sort_keys=True) if args.json else
          "["+result["status"]+"] Application release authorization remains unavailable.")
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}.get(result["status"], 2)
