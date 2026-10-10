"""Separately selected native child identity links; no native replay or clearance.

directed acyclic graph (DAG); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). This additive contract leaves certificate DAG v1
unchanged. PASS means exact selected consumed-child identity only. Unsupported
selectors/contexts and absent retained inputs remain UNKNOWN; demonstrated
certificate/request/policy substitution fails. No complete application profile.
"""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import certificate_dag as dag

POLICY = "verifier-native-child-link-policy-1"
ASSESSMENT = "verifier-native-child-link-assessment-1"
RULES = "verifier-native-child-link-rules-1"
SELECTOR = "sim-response/trajectory/1"
SEMANTIC = "verifier-current-object-obligations-1"
SOURCE_PINS = {
    "domains/contracts/sim_response.py": "0d9afe7a445286a7a2fe116cdbaeb59ccf7a957c14e5ecb168e521e4c998a4cf",
    "domains/contracts/sim_dynamics.py": "72c786f691d39658c464c59da94b6f6e1e2d601543340d4bdb0e53c99c9c256e",
    "standard/CURRENT_SIM_RESPONSE.md": "536096af5a7cb7d9b7214874d2c2442efffbae242bba79daae675022bd6878d2",
    "standard/CURRENT_SIM_DYNAMICS.md": "32f5d3576cab0559f08293f1dbf678a476b35decc4eebe4fceca7d90b244f3fa",
}


class _Unavailable(ValueError):
    pass


def mechanism_source_bindings() -> list[dict[str, str]]:
    """Exact installed bytes; a source digest is not runtime attestation."""
    root = Path(__file__).parents[2]
    paths = {"domains/contracts/native_child_links.py": Path(__file__)}
    for relative in (*SOURCE_PINS, "domains/contracts/certificate_dag.py",
                     "core/namespace.py", "core/certificate.py", "core/receipt.py",
                     "standard/NATIVE_CHILD_LINKS.md"):
        paths[relative] = root / relative
    return [{"path": relative, "digest": dag._digest(path.read_bytes())}
            for relative, path in sorted(paths.items())]


def mechanism_digest() -> str:
    return dag._digest(canonical_bytes({"assessment_version": ASSESSMENT,
        "policy_version": POLICY, "rules_version": RULES, "sources": mechanism_source_bindings()}))


def installed_native_child_link_rules() -> dict[str, Any]:
    """Authored fixed native paths; never execute a submitted extractor or callback."""
    root = Path(__file__).parents[2]
    for relative, pin in SOURCE_PINS.items():
        if dag._digest((root / relative).read_bytes()) != "sha256:" + pin:
            raise _Unavailable("AUTHORED_NATIVE_SOURCE_CHANGED")
    return {"schema_version": RULES, "checker_source_digest": dag._digest(Path(__file__).read_bytes()),
        "rules": [{"selector": SELECTOR, "rule_version": "1", "semantic_version": SEMANTIC,
            "parent_objective": "SIM-2.2", "child_objective": "SIM-2.1", "kind": "SIM",
            "operand_role": None, "subject_mode": "DIRECT_SAME_OBJECT",
            "request_fields": ["trajectory_request", "trajectory_policy", "trajectory_certificate_digest"],
            "evidence_child_field": "trajectory_certificate", "sources": SOURCE_PINS}],
        "scope": "exact_selected_native_child_identity_only", "production_profile_approval": "NOT_ESTABLISHED"}


def _certificate(node: dict[str, Any], files: dict[str, bytes]) -> tuple[bytes, dict[str, Any]]:
    path = dag._path(node["certificate_path"])
    if path not in files:
        raise _Unavailable("SELECTED_CERTIFICATE_ABSENT")
    raw = files[path]
    if dag._digest(raw) != dag._hash(node["certificate_digest"]):
        raise ValueError("SELECTED_CERTIFICATE_CHANGED")
    value = dag._parse(raw)
    if canonical_bytes(value.get("request")) != canonical_bytes(node["request"]):
        raise ValueError("CERTIFICATE_REQUEST_CHANGED")
    return raw, value


def _decode(encoded: Any) -> bytes:
    if type(encoded) is not str:
        raise ValueError("RETAINED_CHILD_ENCODING_INVALID")
    if len(encoded) > dag.MAX_BYTES:
        raise dag._Exhausted("native link encoding bound exhausted")
    raw = base64.b64decode(encoded, validate=True)
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise ValueError("RETAINED_CHILD_ENCODING_NONCANONICAL")
    return raw


def _capture_files(artifact_files: dict[str, bytes]) -> dict[str, bytes]:
    if type(artifact_files) is not dict:
        raise ValueError("EXACT_NATIVE_LINK_ARTIFACT_FILES_REQUIRED")
    items = list(artifact_files.items())
    if len(items) > 1024:
        raise dag._Exhausted("native link file count bound exhausted")
    if any(type(path) is not str or type(raw) is not bytes for path, raw in items):
        raise ValueError("EXACT_NATIVE_LINK_ARTIFACT_FILES_REQUIRED")
    if sum(len(raw) for _, raw in items) > 64 * 1024 * 1024:
        raise dag._Exhausted("native link snapshot bound exhausted")
    return dict(items)


def _selection(node: dict[str, Any], coordinate: str, bundle: dict[str, Any], dependency: dict[str, Any]) -> None:
    subjects = [row for row in dependency["required_objects"] if row["object_id"] == node["object_id"]]
    if len(subjects) != 1:
        raise _Unavailable("EXACT_NATIVE_SUBJECT_SELECTION_ABSENT")
    subject = subjects[0]
    if subject["object_kind"] != "SIM":
        raise _Unavailable("TYPED_GRAPH_SUBJECT_SELECTOR_UNSUPPORTED")
    if subject["record_digest"] != node["request"]["object_digest"]:
        raise ValueError("SELECTED_NATIVE_SUBJECT_RECORD_CHANGED")
    profiles = [row for row in bundle["profiles"] if dag._digest(canonical_bytes(row)) == subject["profile_digest"]]
    if len(profiles) != 1:
        raise _Unavailable("SELECTED_NATIVE_PROFILE_ABSENT")
    claims = [row for row in profiles[0]["obligations"] if row["claim_id"] == node["claim_id"]]
    if len(claims) != 1:
        raise _Unavailable("SELECTED_NATIVE_CLAIM_ABSENT")
    claim = claims[0]
    expected_scope = "finite_model_relative_action_response" if coordinate == "SIM-2.2" else "finite_selected_native_transition_replay"
    if (profiles[0]["object_kind"] != "SIM" or claim["semantic_version"] != SEMANTIC
            or claim["objective"] != coordinate or claim["scope"] != expected_scope
            or claim["proposition_digest"] != node["request"]["proposition_digest"]):
        raise ValueError("SELECTED_NATIVE_CLAIM_CHANGED")


def _context(node: dict[str, Any], selected: dict[str, Any] | None) -> None:
    if selected is None:
        raise _Unavailable("FULL_NATIVE_CONTEXT_ABSENT")
    dag._record(selected, {"node_id", "scope", "subject_mode", "objects"})
    if selected["scope"] != "FULL_NATIVE_COLLECTION" or selected["subject_mode"] != "DIRECT_SAME_OBJECT":
        raise _Unavailable("NATIVE_CONTEXT_SELECTOR_UNSUPPORTED")
    objects = []
    for record in dag._list(selected["objects"]):
        dag._record(record, {"object_id", "kind", "payload", "operands"})
        item = NamespaceObject.create(record["object_id"], record["kind"], record["payload"], record["operands"])
        if item.to_dict() != record:
            raise ValueError("NATIVE_CONTEXT_RECORD_CHANGED")
        objects.append(item)
    if len({item.object_id for item in objects}) != len(objects):
        raise ValueError("NATIVE_CONTEXT_IDENTIFIERS_DUPLICATED")
    request = node["request"]
    if composition_digest(objects) != request["collection_digest"]:
        raise _Unavailable("NATIVE_CONTEXT_SUBSET_OR_DIFFERENT_COLLECTION")
    subjects = [item for item in objects if item.object_id == node["object_id"]]
    if len(subjects) != 1:
        raise _Unavailable("DIRECT_NATIVE_SUBJECT_NOT_RECONSTRUCTED")
    if subjects[0].kind.value != "SIM":
        raise _Unavailable("TYPED_GRAPH_SUBJECT_SELECTOR_UNSUPPORTED")
    if request["subject_id"] != subjects[0].object_id or request["object_digest"] != subjects[0].digest:
        raise ValueError("NATIVE_SUBJECT_RECORD_CHANGED")


def _link(parent: dict[str, Any], child: dict[str, Any], files: dict[str, bytes]) -> None:
    request = parent["request"]
    child_request, child_policy = child["request"], child["checker_policy"]
    for node, coordinate, schema in ((parent, "SIM-2.2", "verifier-current-sim-response-request-1"),
                                    (child, "SIM-2.1", "verifier-current-sim-dynamics-request-1")):
        selected = node["request"]
        if (selected.get("schema_version") != schema or selected.get("semantic_version") != SEMANTIC
                or selected.get("coordinate") != coordinate or selected.get("object_kind") != "SIM"):
            raise ValueError("NATIVE_OBJECTIVE_SELECTOR_CHANGED")
        if selected.get("policy_digest") != dag._digest(canonical_bytes(node["checker_policy"])):
            raise ValueError("NATIVE_REQUEST_POLICY_CHANGED")
    if parent["object_id"] != child["object_id"]:
        raise ValueError("SAME_OBJECT_CHILD_CHANGED")
    for key in ("subject_id", "object_digest", "collection_digest"):
        if request[key] != child_request[key]:
            raise ValueError("NATIVE_SUBJECT_OR_COLLECTION_CHANGED")
    if (canonical_bytes(request["trajectory_request"]) != canonical_bytes(child_request)
            or canonical_bytes(request["trajectory_policy"]) != canonical_bytes(child_policy)
            or request["trajectory_certificate_digest"] != child["certificate_digest"]):
        raise ValueError("CONSUMED_CHILD_TUPLE_CHANGED")
    # Inspect independently retained tuple fields before requesting bytes.
    # Missing one certificate cannot hide a contradiction in its available sibling.
    certificates = []
    missing = []
    for node, schema in ((parent, "verifier-current-sim-response-certificate-1"),
                         (child, "verifier-current-sim-dynamics-certificate-1")):
        try:
            raw, value = _certificate(node, files)
        except _Unavailable as exc:
            missing.append(str(exc))
            certificates.append(None)
            continue
        if value.get("schema_version") != schema:
            raise ValueError("NATIVE_CERTIFICATE_SCHEMA_CHANGED")
        certificates.append((raw, value))
    if certificates[0] is not None:
        parent_value = certificates[0][1]
        payloads = parent_value.get("evidence_payloads")
        if type(payloads) is not dict or request["evidence_ref"] not in payloads:
            missing.append("PARENT_NATIVE_EVIDENCE_ABSENT")
        else:
            evidence_raw = _decode(payloads[request["evidence_ref"]])
            if dag._digest(evidence_raw) != request["evidence_ref"]:
                raise ValueError("PARENT_NATIVE_EVIDENCE_CHANGED")
            evidence = dag._parse(evidence_raw)
            if evidence.get("schema_version") != "verifier-current-sim-response-evidence-1":
                raise ValueError("PARENT_NATIVE_EVIDENCE_SCHEMA_CHANGED")
            encoded = evidence.get("trajectory_certificate")
            if encoded is None:
                missing.append("CONSUMED_CHILD_BYTES_ABSENT")
            else:
                consumed = _decode(encoded)
                if (dag._digest(consumed) != dag._hash(child["certificate_digest"])
                        or (certificates[1] is not None and consumed != certificates[1][0])):
                    raise ValueError("CONSUMED_CHILD_BYTES_CHANGED")
    if missing:
        raise _Unavailable(missing[0])


def _input_digest(raw: Any) -> str | None:
    # Refuse foreign/over-capacity transport before hashing its input bytes.
    return dag._digest(raw) if type(raw) is bytes and len(raw) <= dag.MAX_BYTES else None


def assess_native_child_links(bundle_bytes: bytes, *, expected_dependency_policy_bytes: bytes,
                              expected_link_policy_bytes: bytes | None,
                              artifact_files: dict[str, bytes]) -> dict[str, Any]:
    """Link identity only; native replay and consumer-census admission stay separate."""
    result = {"schema_version": ASSESSMENT, "status": "UNKNOWN", "links": [], "blockers": [],
        "mechanism_digest": None, "source_bindings": [],
        "input_bindings": {
            "bundle_digest": _input_digest(bundle_bytes),
            "dependency_policy_digest": _input_digest(expected_dependency_policy_bytes),
            "link_policy_digest": _input_digest(expected_link_policy_bytes),
            "artifact_files_digest": None},
        "native_replay_status": "NOT_ESTABLISHED", "consumer_census_completeness": "NOT_ESTABLISHED",
        "claim_boundary": "Exact selected consumed-child identity only; no native PASS, application completeness, authority or publication clearance."}
    try:
        # Capture the exact plain dictionary once before comparison or source work.
        # Every retained value is immutable bytes; all later reads use this copy.
        files = _capture_files(artifact_files)
        result["input_bindings"]["artifact_files_digest"] = dag.artifact_files_digest(files)
        result["source_bindings"] = mechanism_source_bindings()
        result["mechanism_digest"] = dag._digest(canonical_bytes({"assessment_version": ASSESSMENT,
            "policy_version": POLICY, "rules_version": RULES, "sources": result["source_bindings"]}))
        if bundle_bytes is None or expected_dependency_policy_bytes is None:
            raise _Unavailable("INDEPENDENT_NATIVE_DEPENDENCY_SELECTION_MISSING")
        if expected_link_policy_bytes is None:
            raise _Unavailable("INDEPENDENT_NATIVE_LINK_POLICY_MISSING")
        bundle, dependency, policy = (dag._parse(raw) for raw in
            (bundle_bytes, expected_dependency_policy_bytes, expected_link_policy_bytes))
        dag._record(bundle, {"schema_version", "profiles", "objects", "nodes", "edges"})
        dag._record(dependency, {"schema_version", "approved_profiles", "required_objects", "required_roots", "nodes", "artifact_files_digest"})
        dag._record(policy, {"schema_version", "rules_digest", "coverage_mode", "consumer_nodes", "links", "native_contexts"})
        if policy["schema_version"] != POLICY or bundle["schema_version"] != dag.BUNDLE or dependency["schema_version"] != dag.POLICY:
            raise ValueError("NATIVE_LINK_CONTRACT_VERSION_CHANGED")
        if policy["rules_digest"] != dag._digest(canonical_bytes(installed_native_child_link_rules())):
            raise _Unavailable("INDEPENDENT_NATIVE_LINK_RULES_DIFFER")
        if canonical_bytes(bundle["nodes"]) != canonical_bytes(dependency["nodes"]):
            raise ValueError("INDEPENDENT_NATIVE_NODES_CHANGED")
        if dependency["artifact_files_digest"] != result["input_bindings"]["artifact_files_digest"]:
            raise ValueError("INDEPENDENT_NATIVE_FILE_SET_CHANGED")
        for selected_object in dag._list(dependency["required_objects"]):
            dag._record(selected_object, {"object_id", "object_kind", "record_digest", "profile_digest"})
        for profile in dag._list(bundle["profiles"]):
            dag._record(profile, {"schema_version", "profile_id", "profile_version", "object_kind", "obligations"})
            for claim in dag._list(profile["obligations"]):
                dag._record(claim, {"claim_id", "semantic_version", "objective", "proposition_digest", "scope", "assumptions", "dependencies"})
        nodes = {}
        for node in dag._list(bundle["nodes"]):
            dag._record(node, {"node_id", "object_id", "claim_id", "certificate_path", "certificate_digest",
                "request", "checker_policy", "contract_version", "artifact_bindings", "facet_bindings"})
            if type(node["request"]) is not dict or type(node["checker_policy"]) is not dict:
                raise ValueError("EXACT_NATIVE_REQUEST_AND_POLICY_RECORDS_REQUIRED")
            dag._text(node["contract_version"])
            identity = dag._text(node["node_id"])
            if identity in nodes:
                raise ValueError("DUPLICATE_NATIVE_NODE")
            nodes[identity] = node
        contexts = {}
        for context in dag._list(policy["native_contexts"]):
            identity = dag._text(context["node_id"])
            if identity in contexts or identity not in nodes:
                raise ValueError("DUPLICATE_OR_UNSELECTED_NATIVE_CONTEXT")
            contexts[identity] = context
        consumers = [dag._text(identity) for identity in dag._list(policy["consumer_nodes"])]
        if len(set(consumers)) != len(consumers) or any(identity not in nodes for identity in consumers):
            raise ValueError("NATIVE_CONSUMER_CENSUS_INVALID")
        selected = set()
        for link in dag._list(policy["links"], dag.MAX_EDGES):
            dag._record(link, {"parent_node_id", "prerequisite_node_id", "selector"})
            parent_id, child_id = dag._text(link["parent_node_id"]), dag._text(link["prerequisite_node_id"])
            selector = dag._text(link["selector"])
            identity = parent_id, selector, child_id
            if identity in selected or parent_id not in consumers or child_id not in nodes:
                raise ValueError("NATIVE_LINK_ENDPOINT_INVALID")
            selected.add(identity)
            status, code = "PASS", "EXACT_CONSUMED_CHILD_TUPLE"
            try:
                if not any(type(edge) is dict and edge.get("node_id") == parent_id
                           and edge.get("prerequisite_id") == child_id
                           for edge in dag._list(bundle["edges"], dag.MAX_EDGES)):
                    raise ValueError("SELECTED_LOCAL_CHILD_EDGE_ABSENT")
                if selector != SELECTOR:
                    raise _Unavailable("NATIVE_CHILD_SELECTOR_UNSUPPORTED")
                edge = {"node_id": parent_id, "prerequisite_id": child_id, "operand_role": None}
                if edge not in bundle["edges"]:
                    raise ValueError("SELECTED_LOCAL_CHILD_EDGE_ABSENT")
                if nodes[parent_id]["contract_version"] != "1" or nodes[child_id]["contract_version"] != "1":
                    raise _Unavailable("NATIVE_CHILD_REPLAY_CONTRACT_UNSUPPORTED")
                _link(nodes[parent_id], nodes[child_id], files)
                _selection(nodes[parent_id], "SIM-2.2", bundle, dependency)
                _selection(nodes[child_id], "SIM-2.1", bundle, dependency)
                _context(nodes[parent_id], contexts.get(parent_id))
                _context(nodes[child_id], contexts.get(child_id))
            except (_Unavailable, dag._Exhausted) as exc:
                status, code = "UNKNOWN", str(exc)
            except (ValueError, TypeError, KeyError, UnicodeError):
                status, code = "FAIL", "EXACT_NATIVE_CHILD_LINK_REJECTED"
            result["links"].append({"parent_node_id": parent_id, "prerequisite_node_id": child_id,
                "selector": selector, "status": status, "code": code})
        if policy["coverage_mode"] != "FULL_SELECTED_CONSUMER_SET":
            result["blockers"].append("NATIVE_LINK_SUBSET_SELECTOR_UNQUALIFIED")
        if not consumers or {parent for parent, _, _ in selected} != set(consumers):
            result["blockers"].append("SELECTED_NATIVE_CONSUMER_LINKS_INCOMPLETE")
        statuses = [row["status"] for row in result["links"]]
        result["status"] = ("FAIL" if "FAIL" in statuses else
            "PASS" if statuses and all(status == "PASS" for status in statuses) and not result["blockers"] else "UNKNOWN")
    except (_Unavailable, ImportError, OSError) as exc:
        result["blockers"] = [str(exc) if isinstance(exc, _Unavailable) else "NATIVE_LINK_SOURCE_UNAVAILABLE"]
    except (dag._Exhausted, RecursionError, OverflowError):
        result["blockers"] = ["NATIVE_LINK_RESOURCE_BOUND_EXHAUSTED"]
    except (ValueError, TypeError, KeyError, UnicodeError):
        result["status"], result["blockers"] = "FAIL", ["NATIVE_LINK_CONTRACT_REJECTED"]
    if any(row["status"] == "FAIL" for row in result["links"]):
        result["status"] = "FAIL"
    result["binding_status"] = "PASS" if result["mechanism_digest"] is not None and all(
        value is not None for value in result["input_bindings"].values()) else "UNKNOWN"
    result["assessment_digest"] = dag._digest(canonical_bytes(result))
    return result


def recheck_native_child_links_assessment(assessment_bytes: bytes, *, expected_mechanism_digest: str,
                                         expected_assessment_digest: str, bundle_bytes: bytes,
                                         expected_dependency_policy_bytes: bytes,
                                         expected_link_policy_bytes: bytes | None,
                                         artifact_files: dict[str, bytes]) -> dict[str, Any]:
    """Exact external-input reproduction; carried link status grants no approval."""
    files = _capture_files(artifact_files)
    value = dag._parse(assessment_bytes)
    selected_mechanism = dag._hash(expected_mechanism_digest)
    if mechanism_digest() != selected_mechanism or value.get("mechanism_digest") != selected_mechanism:
        raise _Unavailable("SELECTED_NATIVE_LINK_MECHANISM_UNAVAILABLE")
    selected_assessment = dag._hash(expected_assessment_digest)
    if value.get("schema_version") != ASSESSMENT or value.get("assessment_digest") != selected_assessment:
        raise ValueError("SELECTED_NATIVE_LINK_ASSESSMENT_CHANGED")
    body = {key: item for key, item in value.items() if key != "assessment_digest"}
    if dag._digest(canonical_bytes(body)) != selected_assessment:
        raise ValueError("NATIVE_LINK_ASSESSMENT_DIGEST_CHANGED")
    rebuilt = assess_native_child_links(bundle_bytes,
        expected_dependency_policy_bytes=expected_dependency_policy_bytes,
        expected_link_policy_bytes=expected_link_policy_bytes, artifact_files=files)
    if canonical_bytes(rebuilt) != assessment_bytes:
        raise ValueError("NATIVE_LINK_ASSESSMENT_DOES_NOT_REPRODUCE")
    return rebuilt


__all__ = ["POLICY", "ASSESSMENT", "SELECTOR", "mechanism_digest", "mechanism_source_bindings",
    "installed_native_child_link_rules", "assess_native_child_links", "recheck_native_child_links_assessment"]
