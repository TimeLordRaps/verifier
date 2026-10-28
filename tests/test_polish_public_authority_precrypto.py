"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

policy/input contradiction tests without cryptographic execution.

Edwards-curve digital signature algorithm with a 255-bit field (Ed25519);
Secure Hash Algorithm 256-bit (SHA-256). Public encodings below exercise only
the installed encoding screen; no private keys, valid signatures, actor authority,
positive native qualification or human acceptance are supplied by these tests.
The fake backend is used only to deny authentication, never to establish a vote.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.runtime import polish_public_authority as admission


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def envelope(payload: dict[str, Any], key_id: str) -> dict[str, Any]:
    return {"schema_version": admission.ENVELOPE, "algorithm": "Ed25519",
        "key_id": key_id, "payload": payload,
        "payload_digest": digest(canonical_bytes(payload)), "signature": "0" * 128}


@pytest.fixture
def selected_without_crypto() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    source = admission.mechanism_digest()
    scope = {"operation": admission.OPERATION, "application_id": "test:finite-app",
        "profile_digest": "sha256:" + "1" * 64,
        "source_scope_digest": "sha256:" + "2" * 64,
        "collection_digest": "sha256:" + "3" * 64,
        "jurisdiction": "test-only", "ledger_id": "test:ledger",
        "policy_domain": "test:domain", "policy_epoch": 1}
    # Distinct canonical public-data encodings only. No signature is claimed valid.
    policy = {"schema_version": admission.POLICY, "mechanism_digest": source,
        "policy_id": "test:operator-policy", "revision": 1,
        "keys": [{"key_id": name, "actor_id": "actor:" + name,
                  "public_key": encoding * 32}
                 for name, encoding in (("a", "22"), ("b", "33"), ("status", "44"))],
        "voting_key_ids": ["a", "b"], "status_key_id": "status", "quorum": 2,
        "veto_actor_ids": ["actor:a"], "scopes": [scope],
        "effective_from": 100, "effective_until": 300, "max_status_age_seconds": 20}
    policy_bytes = canonical_bytes(policy)
    subject_bytes = canonical_bytes({"schema_version": "test:scope-only-subject", **scope})
    context = {"schema_version": admission.CONTEXT, "mechanism_digest": source,
        "subject_digest": digest(subject_bytes), "policy_digest": digest(policy_bytes),
        **scope, "actor_id": "submitter", "observer_id": "test:observer",
        "purpose": "test exact finite authority", "timestamp": 200,
        "invocation_id": "test:invocation"}
    context_bytes = canonical_bytes(context)
    decisions = [envelope({"schema_version": admission.DECISION,
        "decision_id": "decision:" + name, "actor_id": "actor:" + name,
        "context_digest": digest(context_bytes), "policy_digest": digest(policy_bytes),
        "issued_at": 190, "expires_at": 220, "decision": "APPROVE"}, name)
        for name in ("a", "b")]
    status = envelope({"schema_version": admission.STATUS,
        "policy_digest": digest(policy_bytes), "ledger_id": scope["ledger_id"],
        "policy_domain": scope["policy_domain"], "policy_epoch": scope["policy_epoch"],
        "observed_at": 195, "expires_at": 220, "revoked_decisions": [],
        "revoked_actors": [], "consumed_invocations": []}, "status")
    evidence = {"decisions": decisions, "status": status}
    call = {"subject_bytes": subject_bytes, "context_bytes": context_bytes,
        "evidence_bytes": canonical_bytes(evidence), "trusted_policy_bytes": policy_bytes,
        "expected_trusted_policy_digest": digest(policy_bytes), "evaluation_time": 200}
    return call, evidence, context


def unavailable_backend(monkeypatch: Any) -> list[str]:
    calls: list[str] = []

    def unavailable(item: Any, keys: Any) -> Any:
        calls.append(item["key_id"])
        raise admission.AuthorityUnavailable("negative-only unavailable test backend")

    monkeypatch.setattr(admission, "_authenticate", unavailable)
    return calls


@pytest.mark.parametrize("mutation,reason", [
    ("nonvoting_key", "DEMONSTRATED_POLICY_DECISION_ROLE_MISMATCH"),
    ("key_actor", "DEMONSTRATED_POLICY_DECISION_ROLE_MISMATCH"),
    ("self_decision", "DEMONSTRATED_POLICY_DECISION_ROLE_MISMATCH"),
    ("veto_role", "DEMONSTRATED_UNCONFIGURED_VETO_ROLE"),
    ("status_role", "DEMONSTRATED_POLICY_STATUS_ROLE_MISMATCH"),
])
def test_selected_policy_contradiction_survives_missing_backend(
        selected_without_crypto: Any, monkeypatch: Any, mutation: str, reason: str) -> None:
    call, evidence, context = selected_without_crypto
    call, evidence = dict(call), deepcopy(evidence)
    row = dict(evidence["decisions"][0]["payload"])
    if mutation == "nonvoting_key":
        row["actor_id"] = "actor:status"
        evidence["decisions"][0] = envelope(row, "status")
    elif mutation == "key_actor":
        row["actor_id"] = "unconfigured:actor"
        evidence["decisions"][0] = envelope(row, "a")
    elif mutation == "self_decision":
        context_bytes = canonical_bytes({**context, "actor_id": "actor:a"})
        call["context_bytes"] = context_bytes
        evidence["decisions"] = [envelope(
            {**item["payload"], "context_digest": digest(context_bytes)}, item["key_id"])
            for item in evidence["decisions"]]
    elif mutation == "veto_role":
        evidence["decisions"][1] = envelope(
            {**evidence["decisions"][1]["payload"], "decision": "VETO"}, "b")
    else:
        evidence["status"] = envelope(evidence["status"]["payload"], "a")
    calls = unavailable_backend(monkeypatch)
    result = admission.assess_polish_authority(
        **{**call, "evidence_bytes": canonical_bytes(evidence)})
    assert calls and result["status"] == "FAIL"
    assert reason in result["checks"]
    assert "PUBLIC_SIGNATURE_BACKEND_UNAVAILABLE" in result["checks"]
    assert result["approving_actors"] == [] and result["polished"] is False


@pytest.mark.parametrize("policy_present", [True, False])
@pytest.mark.parametrize("interval", [(100, 150), (210, 220)])
def test_present_ineffective_decision_refuses_without_authentication(
        selected_without_crypto: Any, monkeypatch: Any,
        policy_present: bool, interval: tuple[int, int]) -> None:
    call, evidence, _ = selected_without_crypto
    call, evidence = dict(call), deepcopy(evidence)
    evidence["decisions"][0] = envelope({**evidence["decisions"][0]["payload"],
        "issued_at": interval[0], "expires_at": interval[1]}, "a")
    if not policy_present:
        call["trusted_policy_bytes"] = None
    unavailable_backend(monkeypatch)
    result = admission.assess_polish_authority(
        **{**call, "evidence_bytes": canonical_bytes(evidence)})
    assert result["status"] == "FAIL"
    assert "DEMONSTRATED_DECISION_TIME_MISMATCH" in result["checks"]
    assert result["approving_actors"] == []


@pytest.mark.parametrize("unsigned_claim", ["APPROVE", "DENY", "VETO", "REVOKED", "CONSUMED"])
def test_well_shaped_unauthenticated_claim_has_no_authority_force(
        selected_without_crypto: Any, monkeypatch: Any, unsigned_claim: str) -> None:
    call, evidence, _ = selected_without_crypto
    evidence = deepcopy(evidence)
    if unsigned_claim in ("APPROVE", "DENY", "VETO"):
        evidence["decisions"][0] = envelope(
            {**evidence["decisions"][0]["payload"], "decision": unsigned_claim}, "a")
    else:
        row = dict(evidence["status"]["payload"])
        row["revoked_actors" if unsigned_claim == "REVOKED" else "consumed_invocations"] = [
            "actor:a" if unsigned_claim == "REVOKED" else "test:invocation"]
        evidence["status"] = envelope(row, "status")
    unavailable_backend(monkeypatch)
    result = admission.assess_polish_authority(
        **{**call, "evidence_bytes": canonical_bytes(evidence)})
    assert result["status"] == "UNKNOWN"
    assert result["approving_actors"] == [] and result["polished"] is False
    assert not {"EXPLICIT_DENIAL_OR_VETO", "REVOKED_DECISION_OR_ACTOR",
                "KNOWN_INVOCATION_REPLAY"}.intersection(result["checks"])


def test_missing_action_clock_does_not_prove_decision_expired(
        selected_without_crypto: Any, monkeypatch: Any) -> None:
    call, evidence, _ = selected_without_crypto
    evidence = deepcopy(evidence)
    evidence["decisions"][0] = envelope({**evidence["decisions"][0]["payload"],
        "issued_at": 100, "expires_at": 150}, "a")
    unavailable_backend(monkeypatch)
    result = admission.assess_polish_authority(
        **{**call, "evaluation_time": None, "evidence_bytes": canonical_bytes(evidence)})
    assert result["status"] == "UNKNOWN"
    assert "DEMONSTRATED_DECISION_TIME_MISMATCH" not in result["checks"]


def test_key_actor_claim_without_selected_policy_is_not_authority(
        selected_without_crypto: Any, monkeypatch: Any) -> None:
    call, evidence, _ = selected_without_crypto
    evidence = deepcopy(evidence)
    evidence["decisions"][0] = envelope({**evidence["decisions"][0]["payload"],
        "actor_id": "unconfigured:actor"}, "a")
    calls = unavailable_backend(monkeypatch)
    result = admission.assess_polish_authority(**{**call, "trusted_policy_bytes": None,
        "evidence_bytes": canonical_bytes(evidence)})
    assert result["status"] == "UNKNOWN" and not calls
    assert "DEMONSTRATED_POLICY_DECISION_ROLE_MISMATCH" not in result["checks"]


def test_policy_contradiction_survives_later_checker_capacity(
        selected_without_crypto: Any, monkeypatch: Any) -> None:
    call, evidence, _ = selected_without_crypto
    evidence = deepcopy(evidence)
    evidence["status"] = envelope(evidence["status"]["payload"], "a")

    def exhausted(item: Any, keys: Any) -> Any:
        raise admission.codec._Exhausted("negative-only later resource exhaustion")

    monkeypatch.setattr(admission, "_authenticate", exhausted)
    result = admission.assess_polish_authority(
        **{**call, "evidence_bytes": canonical_bytes(evidence)})
    assert result["status"] == "FAIL"
    assert "DEMONSTRATED_POLICY_STATUS_ROLE_MISMATCH" in result["checks"]
    assert result["reason"] == "AUTHORITY_RESOURCE_BOUND_EXHAUSTED"


@pytest.mark.parametrize("field", ["subject_bytes", "context_bytes", "evidence_bytes", "trusted_policy_bytes"])
def test_transport_refusal_precedes_submitted_hash_and_optional_backend(
        selected_without_crypto: Any, monkeypatch: Any, field: str) -> None:
    call, _, _ = selected_without_crypto
    hashes: list[bool] = []
    original = admission.hashlib.sha256

    def observed(raw: bytes = b"", *args: Any, **kwargs: Any) -> Any:
        hashes.append(True)
        return original(raw, *args, **kwargs)

    class Foreign(bytes):
        def __len__(self) -> int:
            pytest.fail("foreign caller length must never run")

    backend_calls = unavailable_backend(monkeypatch)
    monkeypatch.setattr(admission.hashlib, "sha256", observed)
    for invalid in (Foreign(call[field]), b" " * (admission.MAX_BYTES + 1)):
        hashes.clear()
        backend_calls.clear()
        result = admission.assess_polish_authority(**{**call, field: invalid})
        assert result["status"] == "FAIL" and not hashes and not backend_calls
