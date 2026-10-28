"""Native consumed-child identity and substitution regression tests.

simulation (SIM); directed acyclic graph (DAG). Native PASS below must be obtained
by the real registered replay functions, separately from link identity.
The link gate proves identity only and does not certify a complete application.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import native_child_links as links
from verifier.domains.contracts import sim_dynamics, sim_response
from test_current_sim_response import fixture


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _case(*, select_b: bool = False) -> tuple[dict, dict, dict, dict, tuple]:
    parent_request, parent_policy, parent_evidence, *_ = fixture(responsive=True)
    a_raw = base64.b64decode(json.loads(parent_evidence)["trajectory_certificate"], validate=True)
    a_request = parent_request["trajectory_request"]
    a_policy = parent_request["trajectory_policy"]
    a_envelope = json.loads(a_raw)
    child_evidence = base64.b64decode(a_envelope["evidence_payloads"][a_request["evidence_ref"]], validate=True)
    b_policy = sim_dynamics.sim_dynamics_policy(trust_roots=["second-external-policy", "selected-response-fixture"])
    b_request = sim_dynamics.sim_dynamics_request(subject_id=a_request["subject_id"],
        object_digest=a_request["object_digest"], collection_digest=a_request["collection_digest"],
        artifact_digest=a_request["artifact_digest"], inputs_digest=a_request["inputs_digest"],
        expected_counts=a_request["expected_counts"], evidence_ref=a_request["evidence_ref"],
        policy=b_policy, limits=a_request["limits"])
    b_raw = sim_dynamics.build_sim_dynamics_certificate(b_request, child_evidence, policy=b_policy)
    parent_raw = sim_response.build_sim_response_certificate(parent_request, parent_evidence, policy=parent_policy)
    records = json.loads(child_evidence)["objects"]
    subject_record = next(row for row in records if row["object_id"] == "sim")
    subject = NamespaceObject.create(**subject_record)
    profile = {"schema_version": dag.PROFILE, "profile_id": "selected-response-identity", "profile_version": "1",
        "object_kind": "SIM", "obligations": [
            {"claim_id": "trajectory", "semantic_version": sim_dynamics.SEMANTIC_VERSION,
             "objective": "SIM-2.1", "proposition_digest": a_request["proposition_digest"],
             "scope": sim_dynamics.SCOPE, "assumptions": [], "dependencies": []},
            {"claim_id": "response", "semantic_version": sim_response.SEMANTIC_VERSION,
             "objective": "SIM-2.2", "proposition_digest": parent_request["proposition_digest"],
             "scope": sim_response.SCOPE, "assumptions": [], "dependencies": [
                {"claim_id": "trajectory", "operand_role": None, "object_kind": "SIM", "profile_digest": None}]}]}
    profile_digest = _digest(canonical_bytes(profile))
    selected_raw, selected_request, selected_policy = (b_raw, b_request, b_policy) if select_b else (a_raw, a_request, a_policy)
    files = {"native/response.json": parent_raw, "native/trajectory.json": selected_raw}
    facets = {"payload_digest": _digest(subject.payload_bytes),
              "operands_digest": _digest(canonical_bytes(subject_record["operands"]))}
    nodes = [
        {"node_id": "response-node", "object_id": "sim", "claim_id": "response",
         "certificate_path": "native/response.json", "certificate_digest": _digest(parent_raw),
         "request": parent_request, "checker_policy": parent_policy, "contract_version": "1",
         "artifact_bindings": [{"path": "native/response.json", "digest": _digest(parent_raw)}], "facet_bindings": facets},
        {"node_id": "trajectory-node", "object_id": "sim", "claim_id": "trajectory",
         "certificate_path": "native/trajectory.json", "certificate_digest": _digest(selected_raw),
         "request": selected_request, "checker_policy": selected_policy, "contract_version": "1",
         "artifact_bindings": [{"path": "native/trajectory.json", "digest": _digest(selected_raw)}], "facet_bindings": facets}]
    bundle = {"schema_version": dag.BUNDLE, "profiles": [profile], "objects": records, "nodes": nodes,
        "edges": [{"node_id": "response-node", "prerequisite_id": "trajectory-node", "operand_role": None}]}
    dependency = {"schema_version": dag.POLICY, "approved_profiles": [profile_digest],
        "required_objects": [{"object_id": "sim", "object_kind": "SIM", "record_digest": subject.digest, "profile_digest": profile_digest}],
        "required_roots": ["response-node"], "nodes": nodes, "artifact_files_digest": dag.artifact_files_digest(files)}
    # The link test's native context is the exact native collection; the DAG's
    # required subject scope is deliberately separate. No DAG v1 PASS is claimed.
    policy = {"schema_version": links.POLICY,
        "rules_digest": _digest(canonical_bytes(links.installed_native_child_link_rules())),
        "coverage_mode": "FULL_SELECTED_CONSUMER_SET", "consumer_nodes": ["response-node"],
        "links": [{"parent_node_id": "response-node", "prerequisite_node_id": "trajectory-node", "selector": links.SELECTOR}],
        "native_contexts": [{"node_id": node["node_id"], "scope": "FULL_NATIVE_COLLECTION",
            "subject_mode": "DIRECT_SAME_OBJECT", "objects": records} for node in nodes]}
    native = (parent_raw, parent_request, parent_policy, a_raw, a_request, a_policy, b_raw, b_request, b_policy)
    return bundle, dependency, policy, files, native


def _assess(case: tuple[dict, dict, dict, dict, tuple]) -> dict:
    bundle, dependency, policy, files, _ = case
    return links.assess_native_child_links(canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency),
        expected_link_policy_bytes=canonical_bytes(policy), artifact_files=files)


def _assert_native_pass(native: tuple) -> None:
    parent_raw, parent_request, parent_policy, a_raw, a_request, a_policy, b_raw, b_request, b_policy = native
    assert sim_response.recheck_sim_response_certificate(parent_raw, expected_request=parent_request, policy=parent_policy)["status"] == "PASS"
    assert sim_dynamics.recheck_sim_dynamics_certificate(a_raw, expected_request=a_request, policy=a_policy)["status"] == "PASS"
    assert sim_dynamics.recheck_sim_dynamics_certificate(b_raw, expected_request=b_request, policy=b_policy)["status"] == "PASS"
    assert a_request["subject_id"] == b_request["subject_id"]
    assert a_request["object_digest"] == b_request["object_digest"]
    assert a_request != b_request and a_policy != b_policy and a_raw != b_raw


def test_exact_consumed_a_tuple_links_without_upgrading_native_or_census_status() -> None:
    case = _case()
    _assert_native_pass(case[-1])
    result = _assess(case)
    assert result["status"] == "PASS"
    assert result["native_replay_status"] == "NOT_ESTABLISHED"
    assert result["consumer_census_completeness"] == "NOT_ESTABLISHED"


def test_two_native_pass_children_same_subject_do_not_allow_parent_a_to_link_b() -> None:
    case = _case(select_b=True)
    _assert_native_pass(case[-1])
    result = _assess(case)
    assert result["status"] == "FAIL"
    assert result["links"][0]["status"] == "FAIL"


@pytest.mark.parametrize("variant", ["subset-context", "typed-graph-context", "unknown-selector", "subset-selection", "missing-context", "missing-consumer-link"])
def test_unresolved_context_or_selector_cannot_establish_linkage(variant: str) -> None:
    case = _case()
    policy = case[2]
    if variant == "subset-context":
        policy["native_contexts"][0]["objects"] = policy["native_contexts"][0]["objects"][-1:]
    elif variant == "typed-graph-context":
        policy["native_contexts"][0]["subject_mode"] = "TYPED_GRAPH_OPERAND"
    elif variant == "unknown-selector":
        policy["links"][0]["selector"] = "sim-response/trajectory/not-admitted"
    elif variant == "subset-selection":
        policy["coverage_mode"] = "SUBSET"
    elif variant == "missing-context":
        policy["native_contexts"] = []
    else:
        policy["consumer_nodes"].append("trajectory-node")
    assert _assess(case)["status"] == "UNKNOWN"


def test_known_child_substitution_is_not_softened_by_missing_native_context() -> None:
    case = _case(select_b=True)
    case[2]["native_contexts"] = []
    assert _assess(case)["status"] == "FAIL"


def test_no_selected_link_policy_is_unknown() -> None:
    bundle, dependency, _, files, _ = _case()
    result = links.assess_native_child_links(canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency),
        expected_link_policy_bytes=None, artifact_files=files)
    assert result["status"] == "UNKNOWN"


def test_exact_assessment_recheck_binds_all_external_inputs() -> None:
    case = _case()
    bundle, dependency, policy, files, _ = case
    result = _assess(case)
    raw = canonical_bytes(result)
    reproduced = links.recheck_native_child_links_assessment(raw,
        expected_mechanism_digest=links.mechanism_digest(),
        expected_assessment_digest=result["assessment_digest"], bundle_bytes=canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency),
        expected_link_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert canonical_bytes(reproduced) == raw
    assert result["input_bindings"] == {"bundle_digest": _digest(canonical_bytes(bundle)),
        "dependency_policy_digest": _digest(canonical_bytes(dependency)),
        "link_policy_digest": _digest(canonical_bytes(policy)),
        "artifact_files_digest": dag.artifact_files_digest(files)}
    changed = dict(policy, coverage_mode="SUBSET")
    with pytest.raises(ValueError):
        links.recheck_native_child_links_assessment(raw,
            expected_mechanism_digest=links.mechanism_digest(), expected_assessment_digest=result["assessment_digest"],
            bundle_bytes=canonical_bytes(bundle), expected_dependency_policy_bytes=canonical_bytes(dependency),
            expected_link_policy_bytes=canonical_bytes(changed), artifact_files=files)


def test_same_unknown_diagnostic_for_different_bundle_bytes_has_distinct_bound_digest() -> None:
    case = _case()
    case[2]["native_contexts"] = []
    first = _assess(case)
    case[0]["objects"] = list(reversed(case[0]["objects"]))
    second = _assess(case)
    assert first["status"] == second["status"] == "UNKNOWN"
    assert first["links"] == second["links"]
    assert first["input_bindings"]["bundle_digest"] != second["input_bindings"]["bundle_digest"]
    assert first["assessment_digest"] != second["assessment_digest"]


def test_caller_file_map_mutation_after_capture_cannot_substitute_child(monkeypatch) -> None:
    case = _case()
    files = case[3]
    original = links.installed_native_child_link_rules
    b_raw = case[-1][6]

    def change_caller_map():
        files["native/trajectory.json"] = b_raw
        return original()

    monkeypatch.setattr(links, "installed_native_child_link_rules", change_caller_map)
    result = _assess(case)
    assert files["native/trajectory.json"] == b_raw
    assert result["status"] == "PASS"
    assert result["input_bindings"]["artifact_files_digest"] == case[1]["artifact_files_digest"]


def test_base64_nonzero_padding_bits_are_rejected_even_when_stdlib_decodes() -> None:
    assert base64.b64decode("Zh==", validate=True) == b"f"
    with pytest.raises(ValueError):
        links._decode("Zh==")


def test_distinct_selectors_can_share_parent_without_parent_only_identity() -> None:
    case = _case()
    case[2]["links"].append({"parent_node_id": "response-node",
        "prerequisite_node_id": "trajectory-node", "selector": "future-child/not-admitted"})
    result = _assess(case)
    assert result["status"] == "UNKNOWN"
    assert [row["status"] for row in result["links"]] == ["PASS", "UNKNOWN"]


def test_missing_native_node_field_is_refused_not_treated_as_unavailable() -> None:
    case = _case()
    del case[0]["nodes"][0]["checker_policy"]
    assert _assess(case)["status"] == "FAIL"


@pytest.mark.parametrize("field", ["bundle_bytes", "expected_dependency_policy_bytes", "expected_link_policy_bytes"])
def test_over_capacity_transport_is_not_hashed_or_promoted(field):
    bundle, dependency, policy, files, _ = _case()
    call = {"bundle_bytes": canonical_bytes(bundle),
            "expected_dependency_policy_bytes": canonical_bytes(dependency),
            "expected_link_policy_bytes": canonical_bytes(policy), "artifact_files": files}
    call[field] = b" " * (dag.MAX_BYTES + 1)
    result = links.assess_native_child_links(**call)
    key = {"bundle_bytes": "bundle_digest", "expected_dependency_policy_bytes": "dependency_policy_digest",
           "expected_link_policy_bytes": "link_policy_digest"}[field]
    assert result["status"] == "UNKNOWN"
    assert result["input_bindings"][key] is None
    assert result["binding_status"] == "UNKNOWN"
