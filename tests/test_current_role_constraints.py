"""Current finite ROLE matrix replay and refutation tests.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). These declarations do not establish authority.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import role_constraints as role


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, mutate_objects=None, mutate_matrix=None, mutate_inputs=None,
             graph_roles: bool = False, **limits: int):
    matrix = {
        "schema_version": role.MATRIX_VERSION, "collective_id": "team",
        "roles": [
            {"role_id": "author", "allowed_permissions": ["write"],
             "allowed_scopes": ["project"], "min_occupants": 1, "max_occupants": 1},
            {"role_id": "reviewer", "allowed_permissions": ["approve", "read"],
             "allowed_scopes": ["project"], "min_occupants": 1, "max_occupants": 1},
        ],
        "actors": [
            {"actor_id": "actor-a", "allowed_roles": ["author"]},
            {"actor_id": "actor-b", "allowed_roles": ["reviewer"]},
        ],
        "occupancies": [
            {"identity_id": "identity-a", "actor_id": "actor-a",
             "role_id": "author", "scope": "project"},
            {"identity_id": "identity-b", "actor_id": "actor-b",
             "role_id": "reviewer", "scope": "project"},
        ],
        "exclusive_role_sets": [["author", "reviewer"]],
    }
    rows = [
        NamespaceObject.create("human-a", "HUMAN", {}).to_dict(),
        NamespaceObject.create("human-b", "HUMAN", {}).to_dict(),
        NamespaceObject.create("actor-a", "ACTOR", {},
            {"representation": ["human-a"], "root_human": ["human-a"]}).to_dict(),
        NamespaceObject.create("actor-b", "ACTOR", {},
            {"representation": ["human-b"], "root_human": ["human-b"]}).to_dict(),
        NamespaceObject.create("author", "ROLE", {
            "permissions": ["write"], "admitted_scopes": ["project"]}).to_dict(),
        NamespaceObject.create("reviewer", "ROLE", {
            "permissions": ["approve", "read"], "admitted_scopes": ["project"]}).to_dict(),
        NamespaceObject.create("team", "COLLECTIVE", {},
            {"roles": ["author", "reviewer"]}).to_dict(),
        NamespaceObject.create("identity-a", "IDENTITY", {"scope": "project"},
            {"actor": ["actor-a"], "role": ["author"]}).to_dict(),
        NamespaceObject.create("identity-b", "IDENTITY", {"scope": "project"},
            {"actor": ["actor-b"], "role": ["reviewer"]}).to_dict(),
    ]
    if graph_roles:
        rows.append(NamespaceObject.create("role-graph", "GRAPH",
            {"element_kind": "ROLE"}, {"members": ["author", "reviewer"]}).to_dict())
        next(row for row in rows if row["object_id"] == "team")["operands"]["roles"] = ["role-graph"]
    if mutate_objects:
        mutate_objects(rows)
    if mutate_matrix:
        mutate_matrix(matrix)
    objects = [NamespaceObject.create(**row) for row in rows]
    subject = next(obj for obj in objects if obj.object_id == "author")
    inputs = {"matrix": matrix}
    if mutate_inputs:
        inputs = mutate_inputs(inputs)
    evidence = canonical_bytes({"schema_version": role.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects], "inputs": inputs})
    policy = role.role_constraints_policy(trust_roots=["selected-role-matrix"])
    request = role.role_constraints_request(subject_id=subject.object_id,
        object_digest=subject.digest, collection_digest=composition_digest(objects),
        matrix_digest=digest(matrix), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = role.build_role_constraints_certificate(request, evidence, policy=policy)
    result = role.recheck_role_constraints_certificate(certificate,
        expected_request=request, policy=policy)
    return certificate, result


def row(rows: list[dict], name: str) -> dict:
    return next(item for item in rows if item["object_id"] == name)


def test_exact_finite_matrix_replays_without_authority_promotion():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["object_kind"] == "ROLE"
    assert result["coordinate"] == "ROLE-3.1"
    for field in ("object_profile_conformance", "statics_tier_conformance", "whole_tier_conformance",
                  "authority", "actual_execution", "actual_occupancy", "enforcement", "human_authenticity"):
        assert result[field] == "NOT_ESTABLISHED"
    assert result["evaluation"]["observations"]["identities"] == 2
    assert certificate == role.build_role_constraints_certificate(request, evidence, policy=policy)


def test_typed_role_graph_replays_same_declared_constraints():
    assert replay(*selected(graph_roles=True))[1]["status"] == "PASS"


@pytest.mark.parametrize("mutation", [
    lambda rows: row(rows, "author")["payload"].update(permissions=["admin", "write"]),
    lambda rows: row(rows, "author")["payload"].update(admitted_scopes=["other", "project"]),
    lambda rows: row(rows, "identity-a")["payload"].update(scope="other"),
    lambda rows: row(rows, "identity-a")["operands"].update(actor=["actor-b"]),
    lambda rows: row(rows, "identity-a")["operands"].update(role=["reviewer"]),
])
def test_reselected_false_permission_or_occupancy_claim_fails(mutation):
    assert replay(*selected(mutate_objects=mutation))[1]["status"] == "FAIL"


def test_same_responsible_human_does_not_satisfy_selected_separation():
    def mutation(rows):
        row(rows, "actor-b")["operands"].update(
            representation=["human-a"], root_human=["human-a"])
    assert replay(*selected(mutate_objects=mutation))[1]["status"] == "FAIL"


@pytest.mark.parametrize("mutation", [
    lambda matrix: matrix["roles"][0].update(max_occupants=0, min_occupants=0),
    lambda matrix: matrix["roles"][0].update(min_occupants=2, max_occupants=2),
    lambda matrix: matrix["actors"][0].update(allowed_roles=[]),
    lambda matrix: matrix["occupancies"].pop(),
    lambda matrix: matrix["roles"].pop(),
    lambda matrix: matrix["actors"].pop(),
    lambda matrix: matrix["occupancies"][0].update(scope="other"),
])
def test_reselected_false_matrix_or_omission_fails(mutation):
    assert replay(*selected(mutate_matrix=mutation))[1]["status"] == "FAIL"


def test_duplicate_identity_does_not_inflate_or_hide_occupancy():
    def mutation(rows):
        extra = deepcopy(row(rows, "identity-a"))
        extra["object_id"] = "identity-c"
        rows.append(extra)
    assert replay(*selected(mutate_objects=mutation))[1]["status"] == "FAIL"


def test_missing_declarations_and_retained_matrix_are_unknown():
    for mutation in (
        lambda rows: row(rows, "author")["payload"].pop("permissions"),
        lambda rows: row(rows, "author")["payload"].pop("admitted_scopes"),
        lambda rows: row(rows, "identity-a")["payload"].pop("scope"),
    ):
        assert replay(*selected(mutate_objects=mutation))[1]["status"] == "UNKNOWN"
    for inputs in (None, {"matrix": None}):
        assert replay(*selected(mutate_inputs=lambda _: inputs))[1]["status"] == "UNKNOWN"
    request, policy, _ = selected()
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", [
    lambda matrix: matrix["roles"][0].update(min_occupants=True),
    lambda matrix: matrix["roles"][0].update(min_occupants=2, max_occupants=1),
    lambda matrix: matrix["roles"][0].update(allowed_permissions=["write", "write"]),
    lambda matrix: matrix["exclusive_role_sets"].append(["author", "missing"]),
    lambda matrix: matrix["exclusive_role_sets"].append(["author", "reviewer"]),
    lambda matrix: matrix.update(extra="unexpected"),
])
def test_malformed_selected_matrix_is_fail(mutation):
    assert replay(*selected(mutate_matrix=mutation))[1]["status"] == "FAIL"


@pytest.mark.parametrize("bound", list(role._CEILINGS))
def test_exhausted_selected_limits_are_unknown(bound):
    assert replay(*selected(**{bound: 1}))[1]["status"] == "UNKNOWN"


def test_exact_selected_evidence_byte_boundary():
    request, policy, evidence = selected()
    request["limits"]["max_evidence_bytes"] = len(evidence)
    assert replay(request, policy, evidence)[1]["status"] == "PASS"
    request["limits"]["max_evidence_bytes"] -= 1
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_exact_operation_and_relation_boundaries():
    request, policy, evidence = selected()
    facts = replay(request, policy, evidence)[1]["evaluation"]["observations"]
    for key, fact in (("max_operations", "operations"), ("max_relation_steps", "relation_steps")):
        selected_request = deepcopy(request)
        selected_request["limits"][key] = facts[fact]
        assert replay(selected_request, policy, evidence)[1]["status"] == "PASS"
        selected_request["limits"][key] -= 1
        assert replay(selected_request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_pinned_matrix_subject_and_collection_cannot_be_substituted():
    request, policy, evidence = selected()
    for field in ("matrix_digest", "object_digest", "collection_digest"):
        changed = deepcopy(request)
        changed[field] = "sha256:" + "f" * 64
        assert replay(changed, policy, evidence)[1]["status"] == "FAIL"
    changed = deepcopy(request)
    changed["subject_id"] = "reviewer"
    assert replay(changed, policy, evidence)[1]["status"] == "FAIL"


def test_external_request_policy_and_rehashed_certificate_tamper_refuse():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed_request = deepcopy(request)
    changed_request["matrix_digest"] = "sha256:" + "e" * 64
    with pytest.raises(role.RoleConstraintsError):
        role.recheck_role_constraints_certificate(certificate,
            expected_request=changed_request, policy=policy)
    changed_policy = deepcopy(policy)
    changed_policy["trust_roots"] = ["other-root"]
    with pytest.raises(role.RoleConstraintsError):
        role.recheck_role_constraints_certificate(certificate,
            expected_request=request, policy=changed_policy)
    for field, value in (("status", "FAIL"), ("authority", "PASS")):
        forged = json.loads(certificate)
        forged["result"][field] = value
        forged.pop("digest")
        forged["digest"] = digest(forged)
        with pytest.raises(role.RoleConstraintsError):
            role.recheck_role_constraints_certificate(canonical_bytes(forged),
                expected_request=request, policy=policy)


def test_retained_bytes_cannot_be_omitted_from_rehashed_pass():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    forged = json.loads(certificate)
    forged["evidence_payloads"] = {}
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(role.RoleConstraintsError):
        role.recheck_role_constraints_certificate(canonical_bytes(forged),
            expected_request=request, policy=policy)


def test_unsupported_matrix_version_is_unknown():
    assert replay(*selected(mutate_matrix=lambda matrix: matrix.update(
        schema_version="unsupported")))[1]["status"] == "UNKNOWN"


def test_excessively_deep_retained_json_is_unknown_before_recursive_parse():
    request, policy, _ = selected()
    evidence = b'{"deep":' + b'[' * 1000 + b'0' + b']' * 1000 + b'}'
    request["evidence_ref"] = "sha256:" + hashlib.sha256(evidence).hexdigest()
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_foreign_request_comparison_is_not_invoked():
    class HostileText(str):
        def __eq__(self, other):
            raise AssertionError("foreign equality callback invoked")

        def __ne__(self, other):
            raise AssertionError("foreign inequality callback invoked")

        __hash__ = str.__hash__

    request, policy, evidence = selected()
    request["object_kind"] = HostileText("ROLE")
    with pytest.raises(role.RoleConstraintsError):
        role.build_role_constraints_certificate(request, evidence, policy=policy)


def test_full_collection_and_namespace_type_binding_are_checked():
    request, policy, evidence = selected()
    changed = json.loads(evidence)
    changed["objects"] = [item for item in changed["objects"] if item["object_id"] != "identity-b"]
    altered = canonical_bytes(changed)
    request["evidence_ref"] = "sha256:" + hashlib.sha256(altered).hexdigest()
    assert replay(request, policy, altered)[1]["status"] == "FAIL"
    def wrong_kind(rows):
        row(rows, "author")["kind"] = "OBJECT"
    assert replay(*selected(mutate_objects=wrong_kind))[1]["status"] == "FAIL"
