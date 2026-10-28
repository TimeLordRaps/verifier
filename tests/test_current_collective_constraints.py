"""Adversarial current COLLECTIVE static-constraint replay cases.

Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256).
These fixtures establish declared role counts, not an actual collective vote.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import collective_constraints as contract


def digest(value: Any) -> str:
    return "sha256:" + canonical_digest(value)


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def specimen(*, charter: bytes = b"Research charter: record decisions.",
             quorum: int = 2, limits: dict[str, int] | None = None
             ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    roles = [NamespaceObject.create(name, "ROLE", {"purpose": name})
             for name in ("role-a", "role-b")]
    members = [{"role_id": role.object_id, "role_digest": role.digest} for role in roles]
    payload = {"static_constraints": {
        "schema_version": contract.CONSTRAINTS_VERSION,
        "charter_digest": bytes_digest(charter),
        "membership_digest": digest(members), "quorum": quorum,
    }}
    collective = NamespaceObject.create("collective", "COLLECTIVE", payload,
                                         {"roles": [row["role_id"] for row in members]})
    objects = [collective, *roles]
    policy = contract.collective_constraints_policy(
        trust_roots=["selected-retained-declarations"], selected_members=members,
        charter_digest=bytes_digest(charter), quorum=quorum)
    evidence = canonical_bytes({"schema_version": contract.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects], "inputs": {
            "membership": members, "quorum": quorum,
            "charter": {"sha256": bytes_digest(charter),
                        "base64": base64.b64encode(charter).decode("ascii")},
        }})
    request = contract.collective_constraints_request(subject_id=collective.object_id,
        object_digest=collective.digest, collection_digest=composition_digest(objects),
        evidence_ref=bytes_digest(evidence), policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict[str, Any], policy: dict[str, Any], evidence: bytes | None
           ) -> dict[str, Any]:
    certificate = contract.build_collective_constraints_certificate(request, evidence, policy=policy)
    return contract.recheck_collective_constraints_certificate(
        certificate, expected_request=request, policy=policy)


def rebound(request: dict[str, Any], value: dict[str, Any], *, select_objects: bool = False
            ) -> tuple[dict[str, Any], bytes]:
    selected = deepcopy(request)
    evidence = canonical_bytes(value)
    selected["evidence_ref"] = bytes_digest(evidence)
    if select_objects:
        objects = [NamespaceObject.create(**row) for row in value["objects"]]
        selected["collection_digest"] = composition_digest(objects)
        selected["object_digest"] = next(obj.digest for obj in objects
                                         if obj.object_id == selected["subject_id"])
    return selected, evidence


def test_selected_static_constraints_replay_without_authority_or_tier_promotion() -> None:
    request, policy, evidence = specimen()
    result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["coordinate"] == "COLLECTIVE-3.1"
    facts = result["evaluation"]["observations"]
    assert facts["selected_roles"] == 2 and facts["quorum"] == 2
    assert facts["charter_bytes"] == len(b"Research charter: record decisions.")
    for field in ("object_profile_conformance", "membership_completeness",
                  "role_occupancy", "charter_authority", "actual_quorum_decision"):
        assert result[field] == "NOT_ESTABLISHED"
    assert contract.registration()["subject_kind"] == "COLLECTIVE"
    assert contract.CollectiveConstraintsDescriptor.CERTIFICATE_VERSION == contract.CERTIFICATE_VERSION


@pytest.mark.parametrize("quorum", [1, 2])
def test_quorum_feasibility_includes_both_cardinality_boundaries(quorum: int) -> None:
    assert replay(*specimen(quorum=quorum))["status"] == "PASS"


@pytest.mark.parametrize("quorum", [-1, 0, 3])
def test_fully_selected_infeasible_quorum_is_refuted(quorum: int) -> None:
    result = replay(*specimen(quorum=quorum))
    assert result["status"] == "FAIL"
    assert "quorum" in result["evaluation"]["details"]


@pytest.mark.parametrize("charter", [b"", b" \r\n\t", b"\xff"])
def test_rebound_empty_blank_or_non_utf8_charter_is_refuted(charter: bytes) -> None:
    assert replay(*specimen(charter=charter))["status"] == "FAIL"


def test_absent_retained_bundle_remains_unknown() -> None:
    request, policy, _ = specimen()
    assert replay(request, policy, None)["status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["inputs", "membership", "quorum", "charter"])
@pytest.mark.parametrize("omit", [True, False])
def test_required_retained_input_omission_remains_unknown(field: str, omit: bool) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    parent = value if field == "inputs" else value["inputs"]
    if omit:
        del parent[field]
    else:
        parent[field] = None
    request, evidence = rebound(request, value)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


def test_missing_charter_does_not_mask_present_membership_contradiction() -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    value["inputs"]["charter"] = None
    value["inputs"]["membership"][0]["role_digest"] = "sha256:" + "0" * 64
    request, evidence = rebound(request, value)
    assert replay(request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("case", ["duplicate", "reorder", "wrong-digest", "wrong-id", "extra-field"])
def test_rebound_retained_membership_contradictions_are_refuted(case: str) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    members = value["inputs"]["membership"]
    if case == "duplicate":
        members.append(deepcopy(members[0]))
    elif case == "reorder":
        members.reverse()
    elif case == "wrong-digest":
        members[0]["role_digest"] = "sha256:" + "0" * 64
    elif case == "wrong-id":
        members[0]["role_id"] = "outside"
    else:
        members[0]["kind"] = "ACTOR"
    request, evidence = rebound(request, value)
    assert replay(request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("case", ["role-record", "role-kind", "selected-roles", "payload-quorum", "payload-charter", "payload-members"])
def test_rebound_collection_and_payload_cannot_substitute_external_policy(case: str) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    collective = value["objects"][0]
    if case == "role-record":
        value["objects"][1]["payload"]["purpose"] = "substituted"
    elif case == "role-kind":
        value["objects"][1]["kind"] = "HUMAN"
    elif case == "selected-roles":
        collective["operands"]["roles"] = ["role-a"]
    elif case == "payload-quorum":
        collective["payload"]["static_constraints"]["quorum"] = 1
    else:
        key = "charter_digest" if case == "payload-charter" else "membership_digest"
        collective["payload"]["static_constraints"][key] = "sha256:" + "0" * 64
    request, evidence = rebound(request, value, select_objects=True)
    assert replay(request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("field", ["static_constraints", "schema_version"])
def test_unsupported_subject_constraint_semantics_are_unknown(field: str) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    if field == "static_constraints":
        del value["objects"][0]["payload"][field]
    else:
        value["objects"][0]["payload"]["static_constraints"][field] = "unsupported-2"
    request, evidence = rebound(request, value, select_objects=True)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("case", ["bytes", "digest", "encoding", "quorum-bool", "quorum-false", "extra-input"])
def test_retained_charter_and_quorum_contradictions_are_refuted(case: str) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    retained = value["inputs"]
    if case == "bytes":
        retained["charter"]["base64"] = base64.b64encode(b"substitution").decode("ascii")
    elif case == "digest":
        retained["charter"]["sha256"] = "sha256:" + "0" * 64
    elif case == "encoding":
        retained["charter"]["base64"] = "!!"
    elif case == "quorum-bool":
        retained["quorum"] = True
    elif case == "quorum-false":
        retained["quorum"] = 1
    else:
        retained["authority"] = True
    request, evidence = rebound(request, value)
    assert replay(request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("bound", ["max_objects", "max_operations", "max_composition_operations",
    "max_items", "max_evidence_bytes", "max_reference_bytes", "max_payload_bytes",
    "max_depth", "max_charter_bytes"])
def test_each_finite_selected_limit_exhaustion_remains_unknown(bound: str) -> None:
    assert replay(*specimen(limits={bound: 1}))["status"] == "UNKNOWN"


def test_exact_operation_byte_depth_and_charter_boundaries_are_inclusive() -> None:
    request, policy, evidence = specimen()
    operations = replay(request, policy, evidence)["evaluation"]["observations"]["operations"]
    for bound, threshold in (("max_operations", operations), ("max_evidence_bytes", len(evidence)),
                             ("max_objects", 3), ("max_depth", 5),
                             ("max_charter_bytes", len(b"Research charter: record decisions."))):
        assert replay(*specimen(limits={bound: threshold}))["status"] == "PASS"
        assert replay(*specimen(limits={bound: threshold - 1}))["status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest"])
def test_certificate_cannot_be_rechecked_under_substituted_external_selection(field: str) -> None:
    request, policy, evidence = specimen()
    certificate = contract.build_collective_constraints_certificate(request, evidence, policy=policy)
    selected = deepcopy(request)
    selected[field] = "other" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(contract.CollectiveConstraintsError):
        contract.recheck_collective_constraints_certificate(certificate,
            expected_request=selected, policy=policy)


@pytest.mark.parametrize("field", ["status", "object_profile_conformance", "actual_quorum_decision"])
def test_rehashed_certificate_cannot_promote_or_replace_result(field: str) -> None:
    request, policy, evidence = specimen()
    value = json.loads(contract.build_collective_constraints_certificate(request, evidence, policy=policy))
    value["result"][field] = "FAIL" if field == "status" else "PASS"
    value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
    with pytest.raises(contract.CollectiveConstraintsError):
        contract.recheck_collective_constraints_certificate(canonical_bytes(value),
            expected_request=request, policy=policy)


def test_certificate_cannot_shed_exact_retained_charter_bytes() -> None:
    request, policy, evidence = specimen()
    value = json.loads(contract.build_collective_constraints_certificate(request, evidence, policy=policy))
    value["evidence_payloads"] = {}
    value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
    with pytest.raises(contract.CollectiveConstraintsError):
        contract.recheck_collective_constraints_certificate(canonical_bytes(value),
            expected_request=request, policy=policy)


@pytest.mark.parametrize("raw", [b"{", b'{"schema_version":"x","schema_version":"y"}', b"{}\n"])
def test_malformed_duplicate_key_and_noncanonical_evidence_are_refuted(raw: bytes) -> None:
    request, policy, _ = specimen()
    request["evidence_ref"] = bytes_digest(raw)
    assert replay(request, policy, raw)["status"] == "FAIL"


def test_parser_depth_exhaustion_is_unknown_before_recursive_loading() -> None:
    request, policy, _ = specimen()
    evidence = b"[" * 2000 + b"0" + b"]" * 2000
    request["evidence_ref"] = bytes_digest(evidence)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("coordinate", "VSTD-3.1"), ("object_kind", "ACTOR"),
    ("semantic_version", "legacy"), ("proposition_digest", "sha256:" + "0" * 64)])
def test_retired_or_different_object_selection_is_refused(field: str, value: str) -> None:
    request, policy, evidence = specimen()
    request[field] = value
    with pytest.raises(contract.CollectiveConstraintsError):
        contract.build_collective_constraints_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("relative", ["core/namespace.py", "domains/contracts/collective_constraints.py",
    "standard/NAMESPACE_OBJECTS.md", "standard/CURRENT_COLLECTIVE_CONSTRAINTS.md"])
def test_changed_native_dependencies_invalidate_selected_mechanism(relative: str,
                                                                  monkeypatch: Any) -> None:
    request, policy, evidence = specimen()
    original = Path.read_bytes
    target = Path(contract.namespace_module.__file__).parents[1] / relative
    if relative == "domains/contracts/collective_constraints.py":
        target = Path(contract.__file__)
    elif relative.endswith("CURRENT_COLLECTIVE_CONSTRAINTS.md"):
        target = Path(contract.__file__).parents[2] / "standard" / Path(relative).name
    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged dependency\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(contract.CollectiveConstraintsError):
        contract.build_collective_constraints_certificate(request, evidence, policy=policy)


def test_policy_owns_its_external_membership_selection() -> None:
    request, policy, evidence = specimen()
    members = deepcopy(policy["selected_members"])
    selected = contract.collective_constraints_policy(trust_roots=list(policy["trust_roots"]),
        selected_members=members, charter_digest=policy["charter_digest"], quorum=policy["quorum"])
    members[0]["role_id"] = "mutated"
    assert selected == policy
    assert replay(request, selected, evidence)["status"] == "PASS"


@pytest.mark.parametrize("nested", [False, True])
def test_typed_role_graph_expands_exact_selected_membership(nested: bool) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    graphs = []
    members = ["role-a", "role-b"]
    if nested:
        graphs.append(NamespaceObject.create("role-inner", "GRAPH", {"element_kind": "ROLE"},
                                            {"members": ["role-b"]}).to_dict())
        members = ["role-a", "role-inner"]
    graphs.append(NamespaceObject.create("role-set", "GRAPH", {"element_kind": "ROLE"},
                                        {"members": members}).to_dict())
    value["objects"][0]["operands"]["roles"] = ["role-set"]
    value["objects"].extend(graphs)
    request, evidence = rebound(request, value, select_objects=True)
    result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["selected_roles"] == 2
    assert result["actual_quorum_decision"] == "NOT_ESTABLISHED"


def test_typed_role_graph_cannot_hide_unselected_member() -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    extra = NamespaceObject.create("role-extra", "ROLE", {})
    graph = NamespaceObject.create("role-set", "GRAPH", {"element_kind": "ROLE"},
                                   {"members": ["role-a", "role-b", "role-extra"]})
    value["objects"].extend([extra.to_dict(), graph.to_dict()])
    value["objects"][0]["operands"]["roles"] = ["role-set"]
    request, evidence = rebound(request, value, select_objects=True)
    assert replay(request, policy, evidence)["status"] == "FAIL"
