"""Exact-kind namespace admission with independent signed evidence.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Ed25519 is the Edwards-curve digital signature
algorithm with a 255-bit field. Time is integer Coordinated Universal Time
(UTC) Unix seconds. Counts are dimensionless. Keys are ephemeral in memory.
These tests do not use the candidate signing-bytes helper as their oracle.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import sys
from typing import Any

import pytest

pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: exact-kind governance evidence is Ed25519-signed and needs the seal extra (cryptography); the platform-python-contracts workflow job installs it")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.domains.contracts import object_governance as governance


KINDS = tuple("HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split())


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(encoded(value)).hexdigest()


def signed(secret: Ed25519PrivateKey, role: str, key_id: str,
           payload: dict[str, Any]) -> dict[str, Any]:
    version = "verifier-current-object-governance-envelope-1"
    message = b"vstd-object-governance-ed25519-1\0" + encoded({
        "schema_version": version, "role": role, "key_id": key_id,
        "payload": payload})
    return {"schema_version": version, "key_id": key_id, "payload": payload,
            "signature": secret.sign(message).hex()}


def specimen(kind: str, *, votes: tuple[str, ...] = ("APPROVE", "APPROVE"),
             status_age: int = 5, revoked: bool = False,
             missing_status: bool = False) -> tuple[dict, dict, bytes]:
    # Intentionally a namespace record only. Operand validity, personhood and
    # payload truth are separate objectives, even when this signed rule passes.
    item = NamespaceObject.create("selected-subject", kind, {"declared": "value"})
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    public = [key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
              for key in keys]
    policy = governance.governance_policy(
        namespace_id="selected-namespace", policy_id="selected-policy", revision=4,
        decision_keys=[{"actor_id": "actor-" + str(i), "key_id": "vote-" + str(i),
                        "public_key": public[i]} for i in range(2)],
        status_key={"key_id": "status", "public_key": public[2]},
        quorum=2, valid_from=100, valid_until=300, max_status_age_seconds=20)
    decisions = [signed(keys[i], "decision", "vote-" + str(i), {
        "schema_version": "verifier-current-object-governance-decision-1",
        "decision_id": "decision-" + str(i), "actor_id": "actor-" + str(i),
        "policy_digest": digest(policy), "record_digest": digest(item.to_dict()),
        "namespace_id": "selected-namespace", "action": "NAMESPACE_ADMIT",
        "vote": vote, "issued_at": 180, "expires_at": 220})
        for i, vote in enumerate(votes)]
    status = None if missing_status else signed(keys[2], "status", "status", {
        "schema_version": "verifier-current-object-governance-status-1",
        "policy_digest": digest(policy), "as_of": 200 - status_age,
        "expires_at": 220, "revoked_decision_ids": ["decision-0"] if revoked else []})
    evidence = {"schema_version": "verifier-current-object-governance-evidence-1",
                "record": item.to_dict(), "decisions": decisions, "status": status}
    request = governance.governance_request(
        item, namespace_id="selected-namespace", evidence_ref=digest(evidence),
        evaluation_time=200, policy=policy)
    return request, policy, encoded(evidence)


def replay(request: dict, policy: dict, evidence: bytes | None) -> tuple[bytes, dict]:
    certificate = governance.build_governance_certificate(request, evidence, policy=policy)
    result = governance.recheck_governance_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


@pytest.mark.parametrize("kind", KINDS)
def test_each_exact_kind_retains_its_own_signed_admission_proposition(kind: str) -> None:
    request, policy, evidence = specimen(kind)
    certificate, result = replay(request, policy, evidence)
    assert request["object_kind"] == result["object_kind"] == kind
    assert request["coordinate"] == result["coordinate"] == kind + "-8.1"
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"] == {
        "approvals": 2, "quorum": 2, "status_as_of": 195, "policy_revision": 4}
    assert result["record_digest"] == digest(json.loads(evidence)["record"])
    assert result["evaluation"]["details"].endswith("selected " + kind)
    for field in ("legal_compliance", "human_consent", "enforcement", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    assert certificate == governance.build_governance_certificate(request, evidence, policy=policy)


def test_kind_registration_is_exact_and_default_object_remains_compatible() -> None:
    assert tuple(kind.value for kind in ObjectKind) == KINDS
    assert governance.registration() == governance.registration("OBJECT")
    assert governance.coordinate("OBJECT") == governance.COORDINATE == "OBJECT-8.1"
    assert governance.GovernanceDescriptor().PROPOSITION_DIGEST == governance.PROPOSITION_DIGEST
    registrations = [governance.registration(kind) for kind in KINDS]
    assert len({digest(row) for row in registrations}) == 26
    for kind, row in zip(KINDS, registrations):
        assert row["subject_kind"] == kind
        assert row["coordinate"] == kind + "-8.1"
        assert governance.KindGovernanceDescriptor(kind).PROPOSITION_DIGEST == digest(row)
    for invalid in ("human", "", "SIM-8.1", "ALIEN", 8, True, ObjectKind.HUMAN):
        with pytest.raises(governance.ObjectGovernanceError):
            governance.registration(invalid)


@pytest.mark.parametrize("kind", [kind for kind in KINDS if kind != "OBJECT"])
def test_generic_object_approvals_cannot_be_relabelled_as_another_kind(kind: str) -> None:
    _, policy, evidence = specimen("OBJECT")
    changed = json.loads(evidence)
    changed["record"]["kind"] = kind
    item = NamespaceObject.create(**{
        "object_id": changed["record"]["object_id"], "kind": kind,
        "payload": changed["record"]["payload"], "operands": changed["record"]["operands"]})
    request = governance.governance_request(item, namespace_id="selected-namespace",
        evidence_ref=digest(changed), evaluation_time=200, policy=policy)
    _, result = replay(request, policy, encoded(changed))
    assert result["status"] == "FAIL"
    assert "differs from selected action" in result["evaluation"]["details"]


@pytest.mark.parametrize("case,expected", [
    ("quorum", "FAIL"), ("veto", "FAIL"), ("revoked", "FAIL"),
    ("stale", "UNKNOWN"), ("missing-status", "UNKNOWN"),
    ("missing-evidence", "UNKNOWN"), ("signature", "FAIL"),
    ("duplicate", "FAIL"), ("foreign-record", "FAIL")])
def test_typed_governance_preserves_existing_negative_and_unknown_rules(case: str, expected: str) -> None:
    request, policy, evidence = specimen("SIM",
        votes=("APPROVE",) if case == "quorum" else ("APPROVE", "VETO") if case == "veto" else ("APPROVE", "APPROVE"),
        status_age=30 if case == "stale" else 5, revoked=case == "revoked",
        missing_status=case == "missing-status")
    if case in {"signature", "duplicate", "foreign-record"}:
        changed = json.loads(evidence)
        if case == "signature":
            changed["decisions"][0]["signature"] = "00" * 64
        elif case == "duplicate":
            changed["decisions"][1] = deepcopy(changed["decisions"][0])
        else:
            changed["record"]["kind"] = "MODEL"
        evidence = encoded(changed)
        request["evidence_ref"] = digest(changed)
    _, result = replay(request, policy, None if case == "missing-evidence" else evidence)
    assert result["status"] == expected


@pytest.mark.parametrize("field,value", [
    ("coordinate", "MODEL-8.1"), ("object_kind", "MODEL"),
    ("proposition_digest", "sha256:" + "0" * 64),
    ("semantic_version", "legacy-unversioned")])
def test_selected_kind_coordinate_and_proposition_cannot_be_mixed(field: str, value: str) -> None:
    request, policy, evidence = specimen("SIM")
    request[field] = value
    with pytest.raises(governance.ObjectGovernanceError):
        governance.build_governance_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("field,value", [
    ("object_kind", "MODEL"), ("coordinate", "MODEL-8.1"),
    ("proposition_digest", "sha256:" + "0" * 64)])
def test_rehashed_carried_kind_relabel_is_rejected(field: str, value: str) -> None:
    request, policy, evidence = specimen("HUMAN")
    certificate, _ = replay(request, policy, evidence)
    changed = json.loads(certificate)
    changed["result"][field] = value
    changed["certificate_digest"] = digest({key: value for key, value in changed.items()
                                            if key != "certificate_digest"})
    with pytest.raises(governance.ObjectGovernanceError):
        governance.recheck_governance_certificate(encoded(changed), expected_request=request, policy=policy)


def test_typed_backend_unavailability_preserves_kind_and_rejects_carried_relabel(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = specimen("HUMAN")
    certificate, _ = replay(request, policy, evidence)
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)
    result = governance.recheck_governance_certificate(certificate, expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN"
    assert result["replay_status"] == "UNAVAILABLE"
    assert result["coordinate"] == "HUMAN-8.1"
    assert result["object_kind"] == "HUMAN"
    changed = json.loads(certificate)
    changed["result"]["evaluation"]["details"] = "configured signed quorum and fresh status admit selected OBJECT"
    changed["certificate_digest"] = digest({key: value for key, value in changed.items()
                                            if key != "certificate_digest"})
    with pytest.raises(governance.ObjectGovernanceError):
        governance.recheck_governance_certificate(encoded(changed), expected_request=request, policy=policy)


def test_same_kind_subject_substitution_and_external_policy_change_remain_rejected() -> None:
    request, policy, evidence = specimen("MODEL")
    certificate, _ = replay(request, policy, evidence)
    foreign = deepcopy(request)
    foreign["object_id"] = "another-subject"
    with pytest.raises(governance.ObjectGovernanceError):
        governance.recheck_governance_certificate(certificate, expected_request=foreign, policy=policy)
    foreign_policy = deepcopy(policy)
    foreign_policy["revision"] += 1
    with pytest.raises(governance.ObjectGovernanceError):
        governance.recheck_governance_certificate(certificate, expected_request=request, policy=foreign_policy)
