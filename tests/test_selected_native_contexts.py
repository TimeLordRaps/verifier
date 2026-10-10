"""Context identity PASS never means native replay PASS."""
from copy import deepcopy
from hashlib import sha256

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import certificate_dag as dag, hyper_closure, typed_facets
from verifier.domains.contracts import selected_native_contexts as contexts


def pin(value):
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


def fixture():
    leaf = NamespaceObject.create("h", "HUMAN", {})
    root = NamespaceObject.create("root", "HYPER", {}, {"related": ["h"]})
    unrelated = NamespaceObject.create("x", "DATA", {})
    policy = hyper_closure.hyper_closure_policy(trust_roots=["fixture"])
    request = hyper_closure.hyper_closure_request([leaf, root], hyper_id="root", policy=policy)
    node = {"node_id": "n", "object_id": "root", "claim_id": "c", "certificate_path": "missing.json",
        "certificate_digest": "sha256:" + "0" * 64, "request": request, "checker_policy": policy,
        "contract_version": "1", "artifact_bindings": [], "facet_bindings": {
            "payload_digest": pin(root.payload), "operands_digest": pin(root.to_dict()["operands"])}}
    bundle = {"schema_version": dag.BUNDLE, "profiles": [],
        "objects": [item.to_dict() for item in [leaf, root, unrelated]], "nodes": [node], "edges": []}
    dependency = {"schema_version": dag.POLICY, "approved_profiles": [], "required_objects": [],
        "required_roots": ["n"], "nodes": [node], "artifact_files_digest": dag.artifact_files_digest({})}
    context = {"schema_version": contexts.POLICY, "mechanism_digest": contexts.mechanism_digest(),
        "compiler_manifest_digest": "sha256:" + "1" * 64, "contexts": [{"node_id": "n",
            "adapter_id": "hyper-operand-cone/1", "subject_id": "root", "object_kind": "HYPER",
            "object_digest": root.digest, "member_ids": ["h", "root"],
            "collection_digest": composition_digest([leaf, root])}]}
    return bundle, dependency, context


def assess(bundle, dependency, policy):
    return contexts.assess_selected_native_contexts(canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency),
        expected_context_policy_bytes=canonical_bytes(policy), artifact_files={})


def test_hyper_exact_cone_is_distinct_from_larger_application_context():
    args = fixture()
    result = assess(*args)
    assert result["status"] == "PASS"
    assert result["native_replay_status"] == result["compiler_closure_status"] == "NOT_EVALUATED"
    assert result["legacy_dag_contract"] == "UNCHANGED"
    replay = contexts.recheck_selected_native_contexts_assessment(canonical_bytes(result),
        expected_mechanism_digest=result["mechanism_digest"], expected_assessment_digest=result["assessment_digest"],
        bundle_bytes=canonical_bytes(args[0]), expected_dependency_policy_bytes=canonical_bytes(args[1]),
        expected_context_policy_bytes=canonical_bytes(args[2]), artifact_files={})
    assert replay["replay_status"] == "REPRODUCED"


def test_wrong_subset_or_extra_member_refutes_context_identity():
    for members in (["root"], ["h", "root", "x"]):
        bundle, dependency, policy = fixture()
        policy["contexts"][0]["member_ids"] = members
        assert assess(bundle, dependency, policy)["status"] == "FAIL"


def test_unknown_adapter_stays_local_unknown():
    bundle, dependency, policy = fixture()
    policy["contexts"][0]["adapter_id"] = "future-subset/1"
    result = assess(bundle, dependency, policy)
    assert result["status"] == "UNKNOWN" and result["rows"][0]["status"] == "UNKNOWN"


def test_missing_context_and_known_missing_request_field_do_not_pass():
    bundle, dependency, policy = fixture()
    policy["contexts"] = []
    assert assess(bundle, dependency, policy)["status"] == "UNKNOWN"
    bundle, dependency, policy = fixture()
    del bundle["nodes"][0]["request"]["policy_digest"]
    dependency["nodes"] = deepcopy(bundle["nodes"])
    assert assess(bundle, dependency, policy)["status"] == "FAIL"


def test_typed_graph_cannot_be_retyped_as_element_kind():
    member = NamespaceObject.create("e", "ENV", {})
    graph = NamespaceObject.create("g", "GRAPH", {"element_kind": "ENV"}, {"members": ["e"]})
    objects = [member, graph]
    native_policy = typed_facets.typed_facets_policy(trust_roots=["fixture"])
    evidence = canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION,
        "objects": [item.to_dict() for item in objects]})
    req = typed_facets.typed_facets_request(object_kind="GRAPH", subject_id="g", object_digest=graph.digest,
        collection_digest=composition_digest(objects), evidence_ref="sha256:" + sha256(evidence).hexdigest(), policy=native_policy)
    bundle, dependency, policy = fixture()
    bundle["objects"] = [item.to_dict() for item in objects]
    node = bundle["nodes"][0]
    node.update(object_id="g", request=req, checker_policy=native_policy)
    node["facet_bindings"] = {"payload_digest": pin(graph.payload), "operands_digest": pin(graph.to_dict()["operands"])}
    dependency["nodes"] = deepcopy(bundle["nodes"])
    policy["contexts"] = [{"node_id": "n", "adapter_id": "typed-collection/1", "subject_id": "g",
        "object_kind": "GRAPH", "object_digest": graph.digest, "member_ids": ["e", "g"],
        "collection_digest": composition_digest(objects)}]
    assert assess(bundle, dependency, policy)["status"] == "PASS"
    policy["contexts"][0]["object_kind"] = "ENV"
    assert assess(bundle, dependency, policy)["status"] == "FAIL"


@pytest.mark.parametrize("adapter", [None, [], {}, False, 1, "", " ", "x" * 257])
def test_malformed_adapter_refused_before_native_context_callback(adapter, monkeypatch):
    bundle, dependency, policy = fixture()
    policy["contexts"][0]["adapter_id"] = adapter
    def unexpected(*args):
        raise AssertionError("malformed adapter reached native context callback")
    monkeypatch.setattr(contexts, "_context", unexpected)
    result = assess(bundle, dependency, policy)
    assert result["status"] == "FAIL" and result["rows"] == []
    assert len(canonical_bytes(result)) <= dag.MAX_BYTES


def test_near_transport_ceiling_adapter_is_not_copied_or_hashed_as_context(monkeypatch):
    bundle, dependency, policy = fixture()
    policy["contexts"][0]["adapter_id"] = "x" * (dag.MAX_BYTES - len(canonical_bytes(policy)) - 64)
    assert len(canonical_bytes(policy)) <= dag.MAX_BYTES
    def unexpected(*args):
        raise AssertionError("overlong adapter reached native context callback")
    monkeypatch.setattr(contexts, "_context", unexpected)
    result = assess(bundle, dependency, policy)
    assert result["status"] == "FAIL" and result["rows"] == []
    assert len(canonical_bytes(result)) <= dag.MAX_BYTES


def test_near_transport_ceiling_uncovered_node_id_is_refused_before_output():
    bundle, dependency, policy = fixture()
    available = dag.MAX_BYTES - max(len(canonical_bytes(bundle)), len(canonical_bytes(dependency))) - 64
    bundle["nodes"][0]["node_id"] = "x" * available
    dependency["nodes"] = deepcopy(bundle["nodes"])
    policy["contexts"] = []
    assert max(len(canonical_bytes(bundle)), len(canonical_bytes(dependency))) <= dag.MAX_BYTES
    result = assess(bundle, dependency, policy)
    assert result["status"] == "FAIL" and not result.get("uncovered_nodes")
    assert len(canonical_bytes(result)) <= dag.MAX_BYTES


def diagnostic_fixture(*, known_fail):
    bundle, dependency, policy = fixture()
    original_node, original_context = bundle["nodes"][0], policy["contexts"][0]
    nodes, rows = [], []
    for index in range(4):
        node, row = deepcopy(original_node), deepcopy(original_context)
        node["node_id"] = row["node_id"] = "n" + str(index)
        node["claim_id"] = "c" + str(index)
        # Each identifier respects the plain256-character bound, but its canonical
        # non-ASCII encoding exercises aggregate diagnostic byte growth.
        row["adapter_id"] = "\uffff" * 256
        if known_fail and index == 0:
            row["adapter_id"] = "hyper-operand-cone/1"
            row["member_ids"] = ["root"]
        nodes.append(node); rows.append(row)
    bundle["nodes"] = nodes
    dependency["nodes"] = deepcopy(nodes)
    dependency["required_roots"] = ["n0"]
    policy["contexts"] = rows
    return bundle, dependency, policy


def recheck(result, bundle, dependency, policy, *, mechanism_digest=None):
    return contexts.recheck_selected_native_contexts_assessment(canonical_bytes(result),
        expected_mechanism_digest=mechanism_digest or result["mechanism_digest"],
        expected_assessment_digest=result["assessment_digest"], bundle_bytes=canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency),
        expected_context_policy_bytes=canonical_bytes(policy), artifact_files={})


@pytest.mark.parametrize("known_fail", [False, True])
def test_final_output_guard_compacts_observations_and_preserves_known_fail(known_fail, monkeypatch):
    args = diagnostic_fixture(known_fail=known_fail)
    # Scale the fixed installed output guard for an adverse path; no runtime policy
    # or caller-selectable output limit is introduced by this instrumentation.
    monkeypatch.setattr(contexts, "_MAX_ASSESSMENT_BYTES", 8192)
    result = assess(*args)
    assert result["status"] == ("FAIL" if known_fail else "UNKNOWN")
    assert result["replayable"] is False and result["complete_context_identity"] is False
    assert result["rows"] == result["uncovered_nodes"] == []
    assert result["context_observations_status"] == "DISCARDED_OUTPUT_BOUND"
    assert result["exhausted_resource"] == "assessment_output_bytes"
    assert len(canonical_bytes(result)) <= 8192
    assert result["input_digests"] and result["source_bindings"] and result["compiler_manifest_digest"]
    replay = recheck(result, *args)
    assert replay["replay_status"] == "UNAVAILABLE" and replay["status"] == result["status"]
    assert replay["input_digests"] == result["input_digests"]


def test_rehashed_compacted_pass_claim_cannot_reproduce(monkeypatch):
    args = diagnostic_fixture(known_fail=False)
    monkeypatch.setattr(contexts, "_MAX_ASSESSMENT_BYTES", 8192)
    result = assess(*args)
    assert result["replayable"] is False
    result.update(status="PASS", replayable=True)
    result["assessment_digest"] = pin({key: value for key, value in result.items() if key != "assessment_digest"})
    replay = recheck(result, *args)
    assert replay["status"] == "FAIL" and replay["replay_status"] == "REJECTED"


def test_rechecker_bounds_carried_assessment_before_installed_source_callback(monkeypatch):
    bundle, dependency, policy = fixture()
    def unexpected():
        raise AssertionError("over-bound replay reached installed-source callback")
    monkeypatch.setattr(contexts, "source_bindings", unexpected)
    replay = contexts.recheck_selected_native_contexts_assessment(b" " * (dag.MAX_BYTES + 1),
        expected_mechanism_digest="sha256:" + "0" * 64,
        expected_assessment_digest="sha256:" + "0" * 64, bundle_bytes=canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency),
        expected_context_policy_bytes=canonical_bytes(policy), artifact_files={})
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"


def test_source_outage_is_unavailable_diagnostic_replay_with_captured_inputs(monkeypatch):
    args = fixture()
    selected_mechanism = contexts.mechanism_digest()
    def unavailable():
        raise OSError("private detail must not escape")
    monkeypatch.setattr(contexts, "source_bindings", unavailable)
    result = assess(*args)
    assert result["status"] == "UNKNOWN" and result["replayable"] is False
    assert "mechanism_digest" not in result and "source_bindings" not in result
    replay = recheck(result, *args, mechanism_digest=selected_mechanism)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"
    assert replay["input_digests"] == result["input_digests"]
    assert "private detail" not in canonical_bytes(replay).decode()


def test_previously_passing_assessment_does_not_carry_pass_through_source_outage(monkeypatch):
    args = fixture()
    result = assess(*args)
    assert result["status"] == "PASS"
    def unavailable():
        raise OSError("source unavailable")
    monkeypatch.setattr(contexts, "source_bindings", unavailable)
    replay = recheck(result, *args)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"
    assert replay["input_digests"] == result["input_digests"]
    assert replay["expected_assessment_digest"] == result["assessment_digest"]
    assert replay["observed_assessment_digest"] != result["assessment_digest"]


@pytest.mark.parametrize("changed", ["bundle", "dependency_policy", "context_policy", "artifact_files"])
def test_changed_original_inputs_refuted_before_context_source_outage(changed, monkeypatch):
    bundle, dependency, policy = fixture()
    result = assess(bundle, dependency, policy)
    files = {}
    if changed == "bundle":
        bundle["edges"] = [{"changed": True}]
    elif changed == "dependency_policy":
        dependency["required_roots"] = ["changed"]
    elif changed == "context_policy":
        policy["compiler_manifest_digest"] = "sha256:" + "2" * 64
    else:
        files = {"changed.json": b"{}"}
    def unexpected():
        raise AssertionError("changed original inputs reached installed-source callback")
    monkeypatch.setattr(contexts, "source_bindings", unexpected)
    replay = contexts.recheck_selected_native_contexts_assessment(canonical_bytes(result),
        expected_mechanism_digest=result["mechanism_digest"], expected_assessment_digest=result["assessment_digest"],
        bundle_bytes=canonical_bytes(bundle), expected_dependency_policy_bytes=canonical_bytes(dependency),
        expected_context_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert replay["status"] == "FAIL" and replay["replay_status"] == "REJECTED"


def test_distinct_compacted_unknown_inputs_keep_distinct_diagnostic_commitments(monkeypatch):
    bundle, dependency, policy = diagnostic_fixture(known_fail=False)
    monkeypatch.setattr(contexts, "_MAX_ASSESSMENT_BYTES", 8192)
    first = assess(bundle, dependency, policy)
    policy["contexts"][0]["adapter_id"] = "\ufffe" * 256
    second = assess(bundle, dependency, policy)
    assert first["status"] == second["status"] == "UNKNOWN"
    assert first["rows"] == second["rows"] == []
    assert first["input_digests"] != second["input_digests"]
    assert first["assessment_digest"] != second["assessment_digest"]
