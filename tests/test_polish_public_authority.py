"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

Configured-public-key adversarial admission tests.

Edwards-curve digital signature algorithm with a 255-bit field (Ed25519).
Fresh synthetic Ed25519 keys authenticate test statements only; these tests supply
no human authority, complete application profile, public predicate proof or release
acceptance. No private key or protected witness enters an assessment.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.runtime import polish_public_authority as admission


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@pytest.fixture
def selected():
    crypto = pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: signature fixtures require the seal extra (cryptography); the platform-python-contracts workflow job installs it")
    if crypto.__version__ != "50.0.0":
        pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: exact cryptography==50.0.0 public authority signature backend unavailable")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    keys = {name: Ed25519PrivateKey.generate() for name in ("a", "b", "veto", "status")}
    source = admission.mechanism_digest()
    scope = {"operation": admission.OPERATION, "application_id": "app:finite-test",
        "profile_digest": "sha256:" + "1" * 64, "source_scope_digest": "sha256:" + "2" * 64,
        "collection_digest": "sha256:" + "3" * 64, "jurisdiction": "test-only", "ledger_id": "local-test-ledger",
        "policy_domain": "test:operator-policy", "policy_epoch": 1}
    policy = {"schema_version": admission.POLICY, "mechanism_digest": source,
        "policy_id": "operator:test-only", "revision": 1,
        "keys": [{"key_id": name, "actor_id": "actor:" + name,
                  "public_key": key.public_key().public_bytes_raw().hex()} for name, key in keys.items()],
        "voting_key_ids": ["a", "b", "veto"], "status_key_id": "status", "quorum": 2,
        "veto_actor_ids": ["actor:veto"], "scopes": [scope],
        "effective_from": 100, "effective_until": 300, "max_status_age_seconds": 20}
    policy_bytes = canonical_bytes(policy)
    # The generic authority checker attests this statement; it cannot establish
    # the complete native/public predicates that a real issuer must reconstruct.
    subject = {"schema_version": "test:exact-subject", **scope}
    context = {"schema_version": admission.CONTEXT, "mechanism_digest": source,
        "subject_digest": digest(canonical_bytes(subject)), "policy_digest": digest(policy_bytes),
        **scope, "actor_id": "submitter", "observer_id": "observer:test-only",
        "purpose": "test exact finite issuance authority", "timestamp": 200, "invocation_id": "test:one"}
    context_bytes = canonical_bytes(context)

    def envelope(payload, key_id):
        raw = canonical_bytes(payload)
        body = {"schema_version": admission.ENVELOPE, "algorithm": "Ed25519", "key_id": key_id,
                "payload": payload, "payload_digest": digest(raw)}
        return {**body, "signature": keys[key_id].sign(admission.authority_signing_bytes(raw, key_id=key_id)).hex()}

    def decision(name, vote="APPROVE"):
        return envelope({"schema_version": admission.DECISION, "decision_id": "decision:" + name,
            "actor_id": "actor:" + name, "context_digest": digest(context_bytes),
            "policy_digest": digest(policy_bytes), "issued_at": 190, "expires_at": 220,
            "decision": vote}, name)

    status = {"schema_version": admission.STATUS, "policy_digest": digest(policy_bytes),
        "ledger_id": scope["ledger_id"], "policy_domain": scope["policy_domain"],
        "policy_epoch": scope["policy_epoch"], "observed_at": 195, "expires_at": 220,
        "revoked_decisions": [], "revoked_actors": [], "consumed_invocations": []}
    evidence = {"decisions": [decision("a"), decision("b")], "status": envelope(status, "status")}
    call = {"subject_bytes": canonical_bytes(subject), "context_bytes": context_bytes,
        "evidence_bytes": canonical_bytes(evidence), "trusted_policy_bytes": policy_bytes,
        "expected_trusted_policy_digest": digest(policy_bytes), "evaluation_time": 200}
    return call, evidence, context, policy, envelope, decision


def test_real_configured_signature_quorum_replays_without_positive_polish(selected):
    call, *_ = selected
    report = admission.assess_polish_authority(**call)
    assert report["status"] == "PASS"
    assert report["polished"] is False and report["invocation_consumption"] == "NOT_PERFORMED"
    replay = admission.recheck_polish_authority(canonical_bytes(report), **call)
    assert replay["replay_status"] == "REPRODUCED" and replay["status"] == "PASS"


@pytest.mark.parametrize("field,value", [("operation", "NAMESPACE_ADMIT"), ("purpose", "publish"),
    ("observer_id", "other"), ("invocation_id", "other"), ("ledger_id", "other"),
    ("timestamp", 201), ("timestamp", True), ("profile_digest", "sha256:" + "0" * 64)])
def test_changed_action_cannot_reuse_even_valid_signatures(selected, field, value):
    call, _, context, *_ = selected
    changed = {**context, field: value}
    assert admission.assess_polish_authority(**{**call, "context_bytes": canonical_bytes(changed)})["status"] == "FAIL"


@pytest.mark.parametrize("change", ["signature", "duplicate", "deny", "veto", "revoke", "consumed"])
def test_authenticated_or_demonstrated_refutations_dominate(selected, change):
    call, evidence, _, _, envelope, decision = selected
    evidence = deepcopy(evidence)
    if change == "signature":
        evidence["decisions"][0]["signature"] = "0" * 128
    elif change == "duplicate":
        evidence["decisions"][1] = evidence["decisions"][0]
    elif change == "deny":
        evidence["decisions"][0] = decision("a", "DENY")
    elif change == "veto":
        evidence["decisions"].append(decision("veto", "VETO"))
    else:
        status = dict(evidence["status"]["payload"])
        status["revoked_actors" if change == "revoke" else "consumed_invocations"] = ["actor:a" if change == "revoke" else "test:one"]
        evidence["status"] = envelope(status, "status")
    assert admission.assess_polish_authority(**{**call, "evidence_bytes": canonical_bytes(evidence)})["status"] == "FAIL"


@pytest.mark.parametrize("missing", ["clock", "policy", "evidence", "quorum", "status", "freshness"])
def test_unavailable_trust_inputs_stay_unknown(selected, missing):
    call, evidence, _, _, envelope, _ = selected
    call, evidence = dict(call), deepcopy(evidence)
    if missing == "clock":
        call["evaluation_time"] = None
    elif missing == "policy":
        call["trusted_policy_bytes"] = None
    elif missing == "evidence":
        call["evidence_bytes"] = None
    else:
        if missing == "quorum":
            evidence["decisions"] = evidence["decisions"][:1]
        elif missing == "status":
            evidence["status"] = None
        else:
            status = {**evidence["status"]["payload"], "observed_at": 150}
            evidence["status"] = envelope(status, "status")
        call["evidence_bytes"] = canonical_bytes(evidence)
    result = admission.assess_polish_authority(**call)
    assert result["status"] == "UNKNOWN" and result["polished"] is False


def test_denial_dominates_missing_clock(selected):
    call, evidence, _, _, _, decision = selected
    evidence = {**evidence, "decisions": [decision("a", "DENY")]}
    result = admission.assess_polish_authority(**{**call, "evaluation_time": None,
        "evidence_bytes": canonical_bytes(evidence)})
    assert result["status"] == "FAIL"


def test_demonstrated_payload_substitution_fails_even_without_trusted_policy(selected):
    call, evidence, *_ = selected
    evidence = deepcopy(evidence)
    evidence["decisions"][0]["payload"]["actor_id"] = "forged:actor"
    result = admission.assess_polish_authority(**{**call, "trusted_policy_bytes": None,
        "evidence_bytes": canonical_bytes(evidence)})
    assert result["status"] == "FAIL" and result["polished"] is False


def test_finite_checker_capacity_is_unknown(selected, monkeypatch):
    call, *_ = selected
    def exhausted(*args, **kwargs):
        raise admission.codec._Exhausted("test bounded decoder capacity")
    monkeypatch.setattr(admission.codec, "_parse", exhausted)
    report = admission.assess_polish_authority(**call)
    assert report["status"] == "UNKNOWN" and report["reason"] == "AUTHORITY_RESOURCE_BOUND_EXHAUSTED"


def test_authenticated_denial_survives_later_checker_capacity(selected, monkeypatch):
    call, evidence, _, _, _, decision = selected
    evidence = {**evidence, "decisions": [decision("a", "DENY"), evidence["decisions"][1]]}
    original = admission._authenticate
    def exhausted_second(envelope, keys):
        if envelope.get("key_id") == "b":
            raise admission.codec._Exhausted("later bounded checker capacity")
        return original(envelope, keys)
    monkeypatch.setattr(admission, "_authenticate", exhausted_second)
    report = admission.assess_polish_authority(**{**call, "evidence_bytes": canonical_bytes(evidence)})
    assert report["status"] == "FAIL" and "EXPLICIT_DENIAL_OR_VETO" in report["checks"]
    assert report["reason"] == "AUTHORITY_RESOURCE_BOUND_EXHAUSTED"


def test_rotated_public_key_cannot_reproduce_old_signed_action(selected):
    call, _, _, policy, *_ = selected
    pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: signature fixtures require the seal extra (cryptography); the platform-python-contracts workflow job installs it")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    changed = deepcopy(policy)
    changed["keys"][0]["public_key"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    changed["revision"] += 1
    # Even replacing both caller policy pins cannot repair the old context and votes.
    raw = canonical_bytes(changed)
    result = admission.assess_polish_authority(**{**call, "trusted_policy_bytes": raw,
        "expected_trusted_policy_digest": digest(raw)})
    assert result["status"] == "FAIL"


def test_rehashed_forged_positive_assessment_cannot_replay(selected):
    call, *_ = selected
    report = admission.assess_polish_authority(**call)
    report["polished"] = True
    report.pop("assessment_digest")
    report["assessment_digest"] = digest(canonical_bytes(report))
    assert admission.recheck_polish_authority(canonical_bytes(report), **call)["replay_status"] == "REJECTED"


@pytest.mark.parametrize("field", ["subject_bytes", "context_bytes", "evidence_bytes", "trusted_policy_bytes"])
def test_foreign_or_overbound_bytes_refuse_before_hash(selected, monkeypatch, field):
    call, *_ = selected
    calls = []
    original = admission.hashlib.sha256
    def observed(raw=b"", *args, **kwargs):
        calls.append(1)
        return original(raw, *args, **kwargs)
    monkeypatch.setattr(admission.hashlib, "sha256", observed)
    class Foreign(bytes):
        def __len__(self):
            pytest.fail("foreign length called")
    for invalid in (Foreign(call[field]), b" " * (admission.MAX_BYTES + 1)):
        calls.clear()
        result = admission.assess_polish_authority(**{**call, field: invalid})
        assert result["status"] == "FAIL" and calls == []


@pytest.mark.parametrize("clock", [object(), True, -1, 2**63, 2**4097, float("nan"), "200"])
def test_invalid_clock_has_bounded_result_without_crypto_fixture(clock):
    result = admission.assess_polish_authority(b"{}", context_bytes=b"{}",
        evidence_bytes=None, trusted_policy_bytes=None,
        expected_trusted_policy_digest=None, evaluation_time=clock)
    assert result["status"] == "FAIL" and result["evaluation_time"] is None
    assert result["replayable"] is False and result["polished"] is False
    canonical_bytes(result)  # Invalid caller object never escapes into output.


@pytest.mark.parametrize("mutation", ["duplicate_id", "duplicate_actor", "context", "policy", "epoch", "domain"])
def test_local_contradictions_fail_without_selected_policy(selected, mutation):
    call, evidence, _, _, envelope, _ = selected
    evidence = deepcopy(evidence)
    if mutation in ("epoch", "domain"):
        status = dict(evidence["status"]["payload"])
        status["policy_epoch" if mutation == "epoch" else "policy_domain"] = 2 if mutation == "epoch" else "foreign:domain"
        evidence["status"] = envelope(status, "status")
    else:
        row = dict(evidence["decisions"][1]["payload"])
        if mutation == "duplicate_id":
            row["decision_id"] = evidence["decisions"][0]["payload"]["decision_id"]
        elif mutation == "duplicate_actor":
            row["actor_id"] = evidence["decisions"][0]["payload"]["actor_id"]
        else:
            row[mutation + "_digest"] = "sha256:" + "0" * 64
        evidence["decisions"][1] = envelope(row, "b")
    result = admission.assess_polish_authority(**{**call, "trusted_policy_bytes": None,
        "evidence_bytes": canonical_bytes(evidence)})
    assert result["status"] == "FAIL" and result["polished"] is False


def test_earlier_local_contradiction_survives_later_decoder_exhaustion(selected, monkeypatch):
    call, evidence, _, _, envelope, _ = selected
    evidence = deepcopy(evidence)
    changed = {**evidence["decisions"][0]["payload"], "context_digest": "sha256:" + "0" * 64}
    evidence["decisions"][0] = envelope(changed, "a")
    original = admission._envelope
    def exhausted_second(record):
        if record.get("key_id") == "b":
            raise admission.codec._Exhausted("later finite decoding work")
        return original(record)
    monkeypatch.setattr(admission, "_envelope", exhausted_second)
    result = admission.assess_polish_authority(**{**call, "trusted_policy_bytes": None,
        "evidence_bytes": canonical_bytes(evidence)})
    assert result["status"] == "FAIL"
    assert "DEMONSTRATED_ACTION_BINDING_MISMATCH" in result["checks"]
    assert result["reason"] == "AUTHORITY_RESOURCE_BOUND_EXHAUSTED"
