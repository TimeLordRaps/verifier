"""Exact native subject binding in the certificate directed acyclic graph (DAG).

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Fixtures establish selected finite native claims, not complete production profiles.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import current_object_routes as routes


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _selected(case: str) -> tuple[NamespaceObject, str, bytes, dict, dict]:
    if case == "governance":
        from test_current_object_governance import selected
        from verifier.domains.contracts import object_governance
        request, policy, evidence, _, _ = selected()
        item = NamespaceObject.create(**json.loads(evidence)["record"])
        raw = object_governance.build_governance_certificate(request, evidence, policy=policy)
        return item, "OBJECT-8.1", raw, request, policy
    if case == "receipt-authenticity":
        from test_current_receipt_authenticity import selected
        from verifier.domains.contracts import receipt_authenticity
        request, policy, evidence = selected()
        child = json.loads(json.loads(evidence)["chain_certificate"])
        import base64
        retained = base64.b64decode(next(iter(child["evidence_payloads"].values())))
        item = NamespaceObject.create(**json.loads(retained)["receipt_object"])
        raw = receipt_authenticity.build_receipt_authenticity_certificate(request, evidence, policy=policy)
        return item, "RECEIPT-9.2", raw, request, policy
    if case == "receipt-chain":
        from test_current_receipt_chain import _evidence, _selection
        from verifier.domains.contracts import receipt_chain
        policy = receipt_chain.receipt_chain_policy(trust_roots=["test:independent-tip"])
        evidence, tip = _evidence((b"first", b"second"))
        request = _selection(evidence, tip, policy=policy)
        item = NamespaceObject.create(**json.loads(evidence)["receipt_object"])
        raw = receipt_chain.build_receipt_chain_certificate(request, evidence, policy=policy)
        return item, "RECEIPT-9.1", raw, request, policy
    from test_current_sim_checker import inputs
    from verifier.domains.contracts import sim_checker
    request, policy, evidence = inputs(sim_checker)
    item = NamespaceObject.create(**json.loads(evidence)["checker_object"])
    raw = sim_checker.build_sim_checker_certificate(request, evidence, policy=policy)
    return item, "VERIFIER-2.1", raw, request, policy


def _fixture(case: str) -> tuple[dict, dict, dict[str, bytes]]:
    item, coordinate, raw, request, checker_policy = _selected(case)
    route = next(row for row in routes.current_object_route_catalog() if row["objective"] == coordinate)
    native = routes.replay_current_object_certificate(raw, semantic_version=route["semantic_version"], objective=coordinate, represented_kind=item.kind.value, expected_request=request, policy=checker_policy)
    assert native["computational_status"] == "PASS"
    profile = {"schema_version": dag.PROFILE, "profile_id": "test-native-subject", "profile_version": "1", "object_kind": item.kind.value, "obligations": [{"claim_id": "native", "semantic_version": route["semantic_version"], "objective": coordinate, "proposition_digest": route["proposition_digest"], "scope": route["scope"], "assumptions": [], "dependencies": []}]}
    node = {"node_id": "native", "object_id": item.object_id, "claim_id": "native", "certificate_path": "native.json", "certificate_digest": _digest(raw), "request": request, "checker_policy": checker_policy, "contract_version": native["schema_version"].rsplit("-", 1)[1], "artifact_bindings": [{"path": "native.json", "digest": _digest(raw)}], "facet_bindings": {"payload_digest": _digest(item.payload_bytes), "operands_digest": _digest(canonical_bytes(item.to_dict()["operands"]))}}
    files = {"native.json": raw}
    pin = _digest(canonical_bytes(profile))
    bundle = {"schema_version": dag.BUNDLE, "profiles": [profile], "objects": [item.to_dict()], "nodes": [node], "edges": []}
    policy = {"schema_version": dag.POLICY, "approved_profiles": [pin], "required_objects": [{"object_id": item.object_id, "object_kind": item.kind.value, "record_digest": item.digest, "profile_digest": pin}], "required_roots": ["native"], "nodes": deepcopy(bundle["nodes"]), "artifact_files_digest": dag.artifact_files_digest(files)}
    return bundle, policy, files


@pytest.mark.parametrize("case", ["governance", "receipt-chain", "receipt-authenticity", "verifier"])
def test_native_subject_schema_replays_without_added_aliases(case: str) -> None:
    bundle, policy, files = _fixture(case)
    result = dag.assess_certificate_dependencies(canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert result["status"] == "PASS"
    assert result["nodes"][0]["direct_status"] == result["nodes"][0]["qualified_status"] == "PASS"
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("case", ["governance", "receipt-chain", "receipt-authenticity", "verifier"])
@pytest.mark.parametrize("change", ["identifier", "digest", "added-alias"])
def test_native_subject_substitution_or_alias_is_refused(case: str, change: str) -> None:
    bundle, policy, files = _fixture(case)
    request = bundle["nodes"][0]["request"]
    if case == "governance":
        identifier, commitment = "object_id", "record_digest"
    elif case.startswith("receipt"):
        identifier, commitment = "receipt_object_id", "receipt_object_digest"
    else:
        identifier, commitment = "object_id", "object_digest"
    if change == "identifier":
        request[identifier] = "different-subject"
    elif change == "digest":
        request[commitment] = "sha256:" + "0" * 64
    else:
        request["subject_id"] = request[identifier]
    policy["nodes"] = deepcopy(bundle["nodes"])
    result = dag.assess_certificate_dependencies(canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=files)
    assert result["status"] == "FAIL"
