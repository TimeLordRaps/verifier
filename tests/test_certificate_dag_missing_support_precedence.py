"""Missing-support and structural precedence tests for a directed acyclic graph (DAG).
JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Tests missing/unsupported inputs, structural
violations, and failure precedence under independently selected profiles.
"""
from __future__ import annotations
from copy import deepcopy
import hashlib
from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import certificate_dag as dag
from test_certificate_dag_native_subjects import _fixture


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _assessment(bundle: dict, policy: dict, files: dict[str, bytes]) -> dict:
    return dag.assess_certificate_dependencies(
        canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=files
    )


def _passing_fixture(case: str) -> tuple[dict, dict, dict[str, bytes]]:
    bundle, policy, files = _fixture(case)
    baseline = _assessment(bundle, policy, files)
    assert baseline["status"] == "PASS"
    assert baseline["blockers"] == []
    assert baseline["nodes"]
    assert all(row["direct_status"] == row["qualified_status"] == "PASS"
               for row in baseline["nodes"])
    return bundle, policy, files

def test_unknown_control_unapproved_profile_retains_direct_pass() -> None:
    bundle, policy, files = _passing_fixture("governance")
    policy["approved_profiles"] = []
    result = dag.assess_certificate_dependencies(
        canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=files
    )
    oid = bundle["objects"][0]["object_id"]
    assert result["status"] == "UNKNOWN"
    assert result["blockers"] == [f"PROFILE_UNAPPROVED:{oid}"]
    assert result["nodes"][0]["direct_status"] == "PASS"
    assert result["nodes"][0]["qualified_status"] == "UNKNOWN"
def test_unknown_control_missing_artifact_file_retains_unknown() -> None:
    bundle, policy, files = _passing_fixture("verifier")
    empty_files: dict[str, bytes] = {}
    policy["artifact_files_digest"] = dag.artifact_files_digest(empty_files)
    result = dag.assess_certificate_dependencies(
        canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=empty_files
    )
    assert result["status"] == "UNKNOWN"
    assert result["blockers"] == ["ARTIFACT_MISSING:native.json"]
    assert result["nodes"][0]["direct_status"] == "UNKNOWN"
    assert result["nodes"][0]["qualified_status"] == "UNKNOWN"
def test_unknown_control_unregistered_scope_fences_native_replay() -> None:
    bundle, policy, files = _passing_fixture("governance")
    bundle["profiles"][0]["obligations"][0]["scope"] = "unsupported-scope"
    pin = _digest(canonical_bytes(bundle["profiles"][0]))
    policy["approved_profiles"] = [pin]
    policy["required_objects"][0]["profile_digest"] = pin
    result = dag.assess_certificate_dependencies(
        canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=files
    )
    assert result["status"] == "UNKNOWN"
    assert result["nodes"][0]["reason"] == "REGISTERED_PROPOSITION_OR_SCOPE_UNAVAILABLE"
    assert result["nodes"][0]["direct_status"] == "UNKNOWN"
    assert result["nodes"][0]["qualified_status"] == "UNKNOWN"
def test_precedence_native_refusal_overrides_unapproved_profile() -> None:
    bundle, policy, files = _passing_fixture("governance")
    policy["approved_profiles"] = []
    bundle["nodes"][0]["request"]["scope"] = "wrong-scope"
    policy["nodes"] = deepcopy(bundle["nodes"])
    result = dag.assess_certificate_dependencies(
        canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=files
    )
    assert result["status"] == "FAIL"
    assert result["nodes"][0]["direct_status"] == "FAIL"
    assert result["nodes"][0]["qualified_status"] == "FAIL"
    assert result["nodes"][0]["reason"] == "NATIVE_REPLAY_REJECTED"
def test_precedence_unconnected_node_fails_despite_unapproved_profile() -> None:
    bundle, policy, files = _passing_fixture("governance")
    extra_claim = deepcopy(bundle["profiles"][0]["obligations"][0])
    extra_claim["claim_id"] = "extra-claim"
    bundle["profiles"][0]["obligations"].append(extra_claim)
    pin = _digest(canonical_bytes(bundle["profiles"][0]))
    policy["approved_profiles"] = [pin]
    policy["required_objects"][0]["profile_digest"] = pin
    extra_node = deepcopy(bundle["nodes"][0])
    extra_node["node_id"] = "extra-node"
    extra_node["claim_id"] = "extra-claim"
    bundle["nodes"].append(extra_node)
    policy["nodes"] = deepcopy(bundle["nodes"])
    policy["required_roots"] = ["native", "extra-node"]
    complete = _assessment(bundle, policy, files)
    assert complete["status"] == "PASS"
    assert complete["blockers"] == []
    assert {row["node_id"] for row in complete["nodes"]} == {"native", "extra-node"}
    assert all(row["direct_status"] == row["qualified_status"] == "PASS"
               for row in complete["nodes"])
    policy["approved_profiles"] = []
    unavailable = _assessment(bundle, policy, files)
    assert unavailable["status"] == "UNKNOWN"
    assert unavailable["blockers"] == [f"PROFILE_UNAPPROVED:{bundle['objects'][0]['object_id']}"]
    assert len(unavailable["nodes"]) == 2
    assert all(row["direct_status"] == "PASS" and row["qualified_status"] == "UNKNOWN"
               for row in unavailable["nodes"])
    # Only root reachability changes from the admitted UNKNOWN control.
    policy["required_roots"] = ["native"]
    result = _assessment(bundle, policy, files)
    assert result["status"] == "FAIL"
    assert result["nodes"] == []
    assert result["blockers"] == ["DEPENDENCY_CONTRACT_REJECTED"]
def test_precedence_policy_node_mismatch_fails_before_missing_artifact() -> None:
    bundle, policy, files = _passing_fixture("verifier")
    empty_files: dict[str, bytes] = {}
    policy["artifact_files_digest"] = dag.artifact_files_digest(empty_files)
    policy["nodes"][0]["checker_policy"] = {"tampered_policy": True}
    result = dag.assess_certificate_dependencies(
        canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=empty_files
    )
    assert result["status"] == "FAIL"
    assert result["blockers"] == ["DEPENDENCY_CONTRACT_REJECTED"]
def test_precedence_required_object_record_digest_mismatch_fails_before_missing_artifact() -> None:
    bundle, policy, files = _passing_fixture("receipt-chain")
    empty_files: dict[str, bytes] = {}
    policy["artifact_files_digest"] = dag.artifact_files_digest(empty_files)
    policy["required_objects"][0]["record_digest"] = "sha256:" + "0" * 64
    result = dag.assess_certificate_dependencies(
        canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=empty_files
    )
    assert result["status"] == "FAIL"
    assert result["blockers"] == ["DEPENDENCY_CONTRACT_REJECTED"]
def test_precedence_dangling_edge_fails_despite_unapproved_profile() -> None:
    bundle, policy, files = _passing_fixture("receipt-authenticity")
    policy["approved_profiles"] = []
    bundle["edges"].append({"node_id": "native", "prerequisite_id": "dangling-node", "operand_role": None})
    result = dag.assess_certificate_dependencies(
        canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=files
    )
    assert result["status"] == "FAIL"
    assert result["blockers"] == ["DEPENDENCY_CONTRACT_REJECTED"]
def test_precedence_native_subject_id_mismatch_fails_before_replay() -> None:
    bundle, policy, files = _passing_fixture("governance")
    bundle["nodes"][0]["request"]["object_id"] = "alien-subject"
    policy["nodes"] = deepcopy(bundle["nodes"])
    result = dag.assess_certificate_dependencies(
        canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=files
    )
    assert result["status"] == "FAIL"
    assert result["blockers"] == ["DEPENDENCY_CONTRACT_REJECTED"]
