"""Separately selected native context identity assessment; no native replay.

Terminology: directed acyclic graph (DAG); Secure Hash Algorithm 256-bit
(SHA-256); identifier (ID).

Retained certificate DAG v1's global collection requirement is unchanged. A PASS
here binds one selected context, not DAG v1 replay or full application closure.
"""
from __future__ import annotations

from asyncio import CancelledError

from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectKind, composition_digest
from verifier.domains.contracts import application_requirements as app, certificate_dag as dag

POLICY = "verifier-selected-native-context-policy-1"
SCHEMA = "verifier-selected-native-context-assessment-1"
_MAX_ASSESSMENT_BYTES = dag.MAX_BYTES
_PINS = {**app._PINS,
    "domains/contracts/hyper_closure.py": "90dd531363322e219ca087998c6dac75a5f9793ed87902b66fa2719fba023053",
    "standard/CURRENT_HYPER_CLOSURE.md": "7f5d987c2fa38ab67d9ad394169e21b50977382f7cc771174edd3ecaf751dcf9"}


def source_bindings() -> dict[str, str]:
    root = Path(__file__).parents[2]
    names = {*_PINS, "domains/contracts/selected_native_contexts.py",
        "domains/contracts/application_requirements.py", "domains/contracts/certificate_dag.py",
        "core/certificate.py", "core/receipt.py", "core/evidence.py", "domains/common.py",
        "standard/CURRENT_SELECTED_NATIVE_CONTEXTS.md"}
    return {name: app._digest((root / name).read_bytes()) for name in sorted(names)}


def mechanism_digest() -> str:
    return app._value_digest({"schema_version": "verifier-selected-native-context-mechanism-1",
        "source_bindings": source_bindings()})


def _capture_files(files: Any) -> dict[str, bytes]:
    if type(files) is not dict:
        raise ValueError("plain artifact inventory required")
    if len(files) > 1024:
        raise dag._Exhausted("artifact_count")
    captured, used = {}, 0
    for name, raw in list(files.items()):
        if type(name) is not str or type(raw) is not bytes:
            raise ValueError("plain names/immutable bytes required")
        dag._path(name)
        used += len(raw)
        if used > 64 * 1024**2:
            raise dag._Exhausted("artifact_bytes")
        captured[name] = raw
    return captured


def _context(row: dict[str, Any], node: dict[str, Any], objects: dict[str, NamespaceObject]) -> None:
    app._keys(row, "node_id adapter_id subject_id object_kind object_digest member_ids collection_digest")
    app._keys(node, "node_id object_id claim_id certificate_path certificate_digest request checker_policy contract_version artifact_bindings facet_bindings")
    subject = objects.get(row["subject_id"])
    if (subject is None or subject.object_id != node["object_id"]
            or row["object_kind"] != subject.kind.value or row["object_digest"] != subject.digest):
        raise ValueError("exact subject record/kind differs")
    if node["facet_bindings"] != {"payload_digest": app._digest(subject.payload_bytes),
            "operands_digest": app._value_digest(subject.to_dict()["operands"])}:
        raise ValueError("node facet bindings differ from exact native subject")
    names = row["member_ids"]
    if type(names) is not list or names != sorted(set(names)) or any(type(name) is not str for name in names):
        raise ValueError("sorted exact member IDs required")
    if set(names) - objects.keys():
        raise ValueError("native context has unbound records")
    request = node["request"]
    if type(request) is not dict or type(node["checker_policy"]) is not dict:
        raise ValueError("exact native request/policy required")
    for field in ("schema_version", "semantic_version", "coordinate", "proposition_digest", "policy_digest"):
        if field not in request or type(request[field]) is not str:
            raise ValueError("mandatory native request field absent or malformed")
    if request["policy_digest"] != app._value_digest(node["checker_policy"]):
        raise ValueError("selected native request/policy commitment differs")
    if request.get("semantic_version") != app.SEMANTIC:
        raise dag._Exhausted("unsupported_semantic_version")
    adapter = row["adapter_id"]
    if adapter == "object-record/1":
        if request.get("coordinate") != "OBJECT-1.1":
            raise ValueError("generic adapter objective differs")
        if (names != [subject.object_id] or row["collection_digest"] is not None
                or request.get("object_id") != subject.object_id
                or request.get("object_kind") != subject.kind.value
                or request.get("record_digest") != subject.digest):
            raise ValueError("generic record adapter differs")
        app._native_intent({"object_id": subject.object_id, "coordinate": "OBJECT-1.1",
            "request": request, "checker_policy": node["checker_policy"]}, subject, "OBJECT-1.1", "")
    elif adapter == "typed-collection/1":
        coordinate = "OBJECT-1.2" if subject.kind is ObjectKind.OBJECT else subject.kind.value + "-1.1"
        if request.get("coordinate") != coordinate or request.get("object_kind") != subject.kind.value:
            raise ValueError("typed adapter objective/kind differs")
        if names != sorted(objects):
            raise ValueError("typed full selected collection was replaced by subset")
        app._native_intent({"object_id": subject.object_id, "coordinate": coordinate,
            "request": request, "checker_policy": node["checker_policy"]}, subject, coordinate,
            composition_digest(list(objects.values())))
    elif adapter == "hyper-operand-cone/1":
        if subject.kind is not ObjectKind.HYPER or request.get("coordinate") != "HYPER-4.1":
            raise ValueError("HYPER adapter subject/objective differs")
        from verifier.domains.contracts import hyper_closure
        hyper_closure._request(request); hyper_closure._policy(node["checker_policy"])
        visited, pending = set(), [subject.object_id]
        operations = 0
        while pending:
            operations += 1
            if operations > 100000:
                raise dag._Exhausted("native_cone_operations")
            name = pending.pop()
            if name in visited:
                continue
            item = objects.get(name)
            if item is None:
                raise ValueError("native cone reference absent")
            visited.add(name)
            for _, targets in item.operands:
                operations += len(targets)
                if operations > 100000:
                    raise dag._Exhausted("native_cone_operations")
                pending.extend(targets)
        if names != sorted(visited):
            raise ValueError("exact native cone members differ")
        cone = app._value_digest({"schema_version": "verifier-current-hyper-closure-members-1",
            "subject_id": subject.object_id, "members": [{"object_id": name,
                "object_digest": objects[name].digest} for name in sorted(visited)]})
        if request.get("cone_digest") != cone:
            raise ValueError("native cone commitment differs")
    else:
        raise dag._Exhausted("unsupported_context_adapter")
    if adapter != "object-record/1":
        digest = composition_digest([objects[name] for name in names])
        if (row["collection_digest"] != digest or request.get("collection_digest") != digest
                or request.get("subject_id") != subject.object_id or request.get("object_digest") != subject.digest):
            raise ValueError("native subject/collection commitment differs")


def _finish_assessment(report: dict[str, Any]) -> dict[str, Any]:
    """Bound every diagnostic before hashing; discarded observations cannot replay."""
    digest_reservation = len(canonical_bytes({"assessment_digest": "sha256:" + "0" * 64})) - 1
    if len(canonical_bytes(report)) + digest_reservation > _MAX_ASSESSMENT_BYTES:
        known_fail = report["status"] == "FAIL" or any(row["status"] == "FAIL" for row in report["rows"])
        report.update(status="FAIL" if known_fail else "UNKNOWN", replayable=False,
            rows=[], uncovered_nodes=[], complete_context_identity=False,
            context_observations_status="DISCARDED_OUTPUT_BOUND",
            reason="REFUTED_CONTEXT_OUTPUT_COMPACTED" if known_fail else "CONTEXT_OUTPUT_BOUND_UNAVAILABLE",
            exhausted_resource="assessment_output_bytes")
    # Retained metadata contains only fixed fields, fixed source names and bounded
    # SHA-256 commitments. After discarding rows and uncovered identifiers it fits
    # the installed 8-mebibyte ceiling; no carried arbitrary metadata is retained.
    report["assessment_digest"] = app._value_digest(report)
    return report


def assess_selected_native_contexts(bundle_bytes: bytes, *, expected_dependency_policy_bytes: bytes,
        expected_context_policy_bytes: bytes, artifact_files: dict[str, bytes]) -> dict[str, Any]:
    report: dict[str, Any] = {"schema_version": SCHEMA, "status": "UNKNOWN", "replayable": False,
        "rows": [], "native_replay_status": "NOT_EVALUATED", "compiler_closure_status": "NOT_EVALUATED",
        "legacy_dag_contract": "UNCHANGED", "object_profile_conformance": "NOT_ESTABLISHED"}
    try:
        files = _capture_files(artifact_files)  # Before source work, comparison or callbacks.
        inputs = {"bundle": bundle_bytes, "dependency_policy": expected_dependency_policy_bytes,
            "context_policy": expected_context_policy_bytes}
        for raw in inputs.values():
            if type(raw) is not bytes or len(raw) > dag.MAX_BYTES:
                raise dag._Exhausted("immutable_transport")
        report["input_digests"] = {name: app._digest(raw) for name, raw in inputs.items()}
        report["input_digests"]["artifact_files"] = dag.artifact_files_digest(files)
        bindings = source_bindings()
        report.update(source_bindings=bindings, mechanism_digest=mechanism_digest(), replayable=True)
        if any(bindings[path] != "sha256:" + pin for path, pin in _PINS.items()):
            raise dag._Exhausted("authored_context_source_drift")
        bundle, dependency, policy = (dag._parse(raw) for raw in inputs.values())
        app._keys(bundle, "schema_version profiles objects nodes edges")
        app._keys(dependency, "schema_version approved_profiles required_objects required_roots nodes artifact_files_digest")
        app._keys(policy, "schema_version mechanism_digest compiler_manifest_digest contexts")
        if bundle["schema_version"] != dag.BUNDLE or dependency["schema_version"] != dag.POLICY or policy["schema_version"] != POLICY:
            raise ValueError("selected contract differs")
        if policy["mechanism_digest"] != report["mechanism_digest"]:
            raise ValueError("selected context mechanism differs")
        app._hash(policy["compiler_manifest_digest"])
        report["compiler_manifest_digest"] = policy["compiler_manifest_digest"]
        if (bundle["nodes"] != dependency["nodes"]
                or dependency["artifact_files_digest"] != report["input_digests"]["artifact_files"]):
            raise ValueError("independent node/file selection differs")
        rows = dag._list(policy["contexts"])
        nodes = {}
        for node in dag._list(bundle["nodes"]):
            app._keys(node, "node_id object_id claim_id certificate_path certificate_digest request checker_policy contract_version artifact_bindings facet_bindings")
            node_id = app._text(node["node_id"])
            if node_id in nodes:
                raise ValueError("duplicate node")
            nodes[node_id] = node
        objects = {}
        for row in dag._list(bundle["objects"]):
            app._keys(row, "object_id kind payload operands")
            item = NamespaceObject.create(**row)
            if item.object_id in objects or canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise ValueError("duplicate/substituted namespace record")
            objects[item.object_id] = item
        seen = set()
        for row in rows:
            app._keys(row, "node_id adapter_id subject_id object_kind object_digest member_ids collection_digest")
            node_id = app._text(row["node_id"])
            adapter_id = app._text(row["adapter_id"])
            if node_id in seen or node_id not in nodes:
                raise ValueError("duplicate/unbound context node")
            seen.add(node_id)
            node = nodes[node_id]
            outcome, reason = "PASS", "EXACT_CONTEXT_IDENTITY"
            try:
                _context(row, node, objects)
            except (OSError, ImportError):
                outcome, reason = "UNKNOWN", "NATIVE_CONTEXT_CHECKER_UNAVAILABLE"
                report["replayable"] = False
            except dag._Exhausted:
                outcome, reason = "UNKNOWN", "CONTEXT_ADAPTER_UNAVAILABLE"
            except (RecursionError, OverflowError, CancelledError):
                outcome, reason = "UNKNOWN", "NATIVE_CONTEXT_RESOURCE_OR_CANCELLED_UNAVAILABLE"
                report["replayable"] = False
            except (ValueError, TypeError, KeyError, UnicodeError):
                outcome, reason = "FAIL", "CONTEXT_BINDING_DIFFERS"
            report["rows"].append({"node_id": node_id, "adapter_id": adapter_id,
                "status": outcome, "reason": reason, "context_digest": app._value_digest(row),
                "request_digest": app._value_digest(node["request"]),
                "policy_digest": app._value_digest(node["checker_policy"])})
        report["uncovered_nodes"] = sorted(set(nodes) - seen)
        statuses = [row["status"] for row in report["rows"]]
        report["status"] = ("FAIL" if "FAIL" in statuses else "UNKNOWN" if "UNKNOWN" in statuses
            or report["uncovered_nodes"] or not nodes else "PASS")
    except (OSError, ImportError):
        report.update(status="FAIL" if any(row["status"] == "FAIL" for row in report["rows"]) else "UNKNOWN",
            replayable=False, reason="MECHANISM_UNAVAILABLE")
    except dag._Exhausted:
        report.update(status="FAIL" if any(row["status"] == "FAIL" for row in report["rows"]) else "UNKNOWN",
            reason="CONTEXT_RESOURCE_OR_SUPPORT_UNAVAILABLE")
    except (RecursionError, OverflowError, CancelledError):
        report.update(status="FAIL" if any(row["status"] == "FAIL" for row in report["rows"]) else "UNKNOWN",
            replayable=False, reason="CONTEXT_RESOURCE_OR_CANCELLED_UNAVAILABLE")
    except (ValueError, TypeError, KeyError, UnicodeError):
        report.update(status="FAIL", reason="INVALID_OR_SUBSTITUTED_INPUT")
    return _finish_assessment(report)


def recheck_selected_native_contexts_assessment(assessment_bytes: bytes, *, expected_mechanism_digest: str,
        expected_assessment_digest: str, bundle_bytes: bytes, expected_dependency_policy_bytes: bytes,
        expected_context_policy_bytes: bytes, artifact_files: dict[str, bytes]) -> dict[str, Any]:
    result = {"schema_version": "verifier-selected-native-context-replay-1", "status": "FAIL", "replay_status": "REJECTED"}
    try:
        files = _capture_files(artifact_files)
        inputs = {"bundle": bundle_bytes, "dependency_policy": expected_dependency_policy_bytes,
            "context_policy": expected_context_policy_bytes}
        for raw in inputs.values():
            if type(raw) is not bytes or len(raw) > dag.MAX_BYTES:
                raise dag._Exhausted("immutable_transport")
        # Check the carried assessment and independently selected commitments before
        # installed-source reconstruction. Unavailability cannot reproduce a claim.
        stored = dag._parse(assessment_bytes)
        app._hash(expected_mechanism_digest); app._hash(expected_assessment_digest)
        if (stored.get("schema_version") != SCHEMA or stored.get("status") not in ("PASS", "FAIL", "UNKNOWN")
                or type(stored.get("replayable")) is not bool
                or stored.get("assessment_digest") != expected_assessment_digest
                or app._value_digest({k: v for k, v in stored.items() if k != "assessment_digest"}) != expected_assessment_digest
                or stored.get("mechanism_digest") is not None and stored["mechanism_digest"] != expected_mechanism_digest):
            return result
        if (stored.get("context_observations_status") == "DISCARDED_OUTPUT_BOUND"
                and (stored["status"] == "PASS" or stored["replayable"] is not False
                     or stored.get("complete_context_identity") is not False)):
            return result
        input_digests = {name: app._digest(raw) for name, raw in inputs.items()}
        input_digests["artifact_files"] = dag.artifact_files_digest(files)
        if "input_digests" not in stored:
            if stored["status"] != "PASS":
                result.update(status="UNKNOWN", replay_status="UNAVAILABLE", reason="CONTEXT_INPUT_BINDINGS_UNAVAILABLE")
            return result
        if stored["input_digests"] != input_digests:
            return result
        current = assess_selected_native_contexts(bundle_bytes,
            expected_dependency_policy_bytes=expected_dependency_policy_bytes,
            expected_context_policy_bytes=expected_context_policy_bytes, artifact_files=files)
        if current.get("mechanism_digest") is not None and current["mechanism_digest"] != expected_mechanism_digest:
            return result
        if current["replayable"] is not True:
            result.update(status="FAIL" if current["status"] == "FAIL" else "UNKNOWN", replay_status="UNAVAILABLE",
                reason=current.get("reason", "CONTEXT_RECONSTRUCTION_UNAVAILABLE"),
                expected_assessment_digest=expected_assessment_digest, observed_assessment_digest=current["assessment_digest"])
            for name in ("input_digests", "source_bindings", "mechanism_digest", "compiler_manifest_digest",
                         "complete_context_identity", "context_observations_status", "exhausted_resource"):
                if name in current:
                    result[name] = current[name]
            return result
        if (current.get("mechanism_digest") == expected_mechanism_digest
                and current["assessment_digest"] == expected_assessment_digest and canonical_bytes(current) == assessment_bytes):
            result.update(status=current["status"], replay_status="REPRODUCED", assessment_digest=expected_assessment_digest)
    except dag._Exhausted:
        result.update(status="UNKNOWN", replay_status="UNAVAILABLE", reason="CONTEXT_REPLAY_RESOURCE_UNAVAILABLE")
    except (RecursionError, OverflowError, CancelledError):
        known_fail = "current" in locals() and current.get("status") == "FAIL"
        result.update(status="FAIL" if known_fail else "UNKNOWN", replay_status="UNAVAILABLE",
            reason="CONTEXT_REPLAY_RESOURCE_OR_CANCELLED_UNAVAILABLE")
    except (ValueError, TypeError, KeyError, UnicodeError):
        pass
    return result
