"""Adversarial typed-subject receipt association, built with an independent byte oracle.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Byte limits count octets; sequence indices are
dimensionless. These tests do not prove full security tiers or real-world safety.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.domains.contracts import receipt_chain
from verifier.domains.contracts import subject_security as security

KINDS = "HUMAN ACTOR COLLECTIVE ROLE IDENTITY OWNER HARDWARE RECEIPT OBJECT GRAPH SPACE TIME EVENT ENV DATA VERIFIER BENCH ARCH TRAIN HYPER MODEL HARNESS AGENT SIM BOT TOKEN".split()


def encoded(value: Any) -> bytes:
    """An independent literal implementation of the published byte contract."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fixture(kind: str = "MODEL", *, subject_changes: dict[str, Any] | None = None,
        message_changes: dict[str, Any] | None = None, chain_subjects: list[str] | None = None,
        selected_sequence: int = 8, include_chain: bool = True,
        child_status: str = "PASS", noncanonical_message: bool = False,
        max_evidence_bytes: int = 4 * 1024 * 1024
        ) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    subject = {"object_id": "selected-subject", "kind": kind,
               "payload": {"declared": "finite retained record"}, "operands": {}}
    subject_digest = digest(encoded(subject))
    chain_policy = receipt_chain.receipt_chain_policy(trust_roots=["external-anchor"])
    policy = security.subject_security_policy(object_kind=kind,
        chain_policy=chain_policy, trust_roots=["external-selected-context"])
    # The producer helper is intentionally not called to create the entry.
    message = {"schema_version": "verifier-current-subject-security-message-1",
        "semantic_version": "verifier-current-object-obligations-1",
        "coordinate": kind + ("-9.3" if kind == "RECEIPT" else "-9.1"),
        "proposition_digest": security.SubjectSecurityDescriptor(kind).PROPOSITION_DIGEST,
        "object_kind": kind, "subject_id": "selected-subject", "object_digest": subject_digest,
        "receipt_object_id": "selected-chain", "chain_domain": "test-association",
        "chain_genesis_digest": "sha256:" + "a" * 64, "chain_first_sequence": 7,
        "chain_sequence": 8, "context_digest": "sha256:" + "b" * 64,
        "policy_digest": digest(encoded(policy))}
    message.update(message_changes or {})
    raw_message = json.dumps(message, indent=2).encode() if noncanonical_message else encoded(message)
    entries = [b"uninterpreted neighboring receipt", raw_message]
    previous = "sha256:" + "a" * 64
    for offset, raw in enumerate(entries):
        previous = digest(encoded({"schema_version": "verifier-receipt-chain-link-1",
            "domain": "test-association", "sequence": 7 + offset,
            "previous": previous, "receipt_digest": digest(raw)}))
    tip = previous
    if child_status == "FAIL":
        entries[0] = b"changed after external tip was selected"
    receipt = {"object_id": "selected-chain", "kind": "RECEIPT",
        "payload": {"chain_domain": "test-association", "chain_genesis_digest": "sha256:" + "a" * 64,
                    "chain_first_sequence": 7, "chain_tip_digest": tip},
        "operands": {"subject": ["selected-subject"] if chain_subjects is None else chain_subjects,
                     "hardware": ["retained-device"]}}
    data = encoded({"schema_version": "verifier-receipt-chain-evidence-1", "domain": "test-association",
        "receipt_object": receipt, "entries": [{"sequence": 7 + index,
            "receipt_base64": base64.b64encode(raw).decode("ascii")} for index, raw in enumerate(entries)]})
    child_request = receipt_chain.receipt_chain_request(receipt_object_id="selected-chain",
        receipt_object_digest=digest(encoded(receipt)), domain="test-association",
        genesis_digest="sha256:" + "a" * 64, first_sequence=7, tip_digest=tip,
        evidence_ref=digest(data), policy=chain_policy)
    child = receipt_chain.build_receipt_chain_certificate(child_request,
        None if child_status == "UNKNOWN" else data, policy=chain_policy)
    subject.update(subject_changes or {})
    evidence = encoded({"schema_version": "verifier-current-subject-security-evidence-1",
        "subject": subject, "chain_certificate": child.decode() if include_chain else None})
    request = security.subject_security_request(object_kind=kind, subject_id="selected-subject",
        object_digest=subject_digest, context_digest="sha256:" + "b" * 64,
        chain_request=child_request, chain_certificate_digest=digest(child),
        chain_sequence=selected_sequence, evidence_ref=digest(evidence), policy=policy,
        max_evidence_bytes=max_evidence_bytes)
    return request, policy, evidence, child


def replay(request: dict[str, Any], policy: dict[str, Any], evidence: bytes | None
        ) -> tuple[bytes, dict[str, Any]]:
    certificate = security.build_subject_security_certificate(request, evidence, policy=policy)
    return certificate, security.recheck_subject_security_certificate(
        certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("kind", KINDS)
def test_every_exact_kind_replays_selected_entry_with_bounded_claim(kind: str) -> None:
    request, policy, evidence, child = fixture(kind)
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS" and result["object_kind"] == kind
    assert result["coordinate"] == kind + ("-9.3" if kind == "RECEIPT" else "-9.1")
    assert certificate == security.build_subject_security_certificate(request, evidence, policy=policy)
    native = receipt_chain.recheck_receipt_chain_certificate(child,
        expected_request=request["chain_request"], policy=policy["chain_policy"])
    assert native["status"] == "PASS"
    for name in ("security_tier_conformance", "object_profile_conformance", "issuer_authenticity",
                 "signature_validity", "typed_composition_conformance", "hardware_authenticity",
                 "context_consumption", "public_disclosure_authority"):
        assert result[name] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("subjects", [[], ["another-subject"], ["selected-subject", "another-subject"]])
def test_native_chain_pass_does_not_hide_transplanted_subjects(subjects: list[str]) -> None:
    request, policy, evidence, child = fixture(chain_subjects=subjects)
    assert receipt_chain.recheck_receipt_chain_certificate(child,
        expected_request=request["chain_request"], policy=policy["chain_policy"])["status"] == "PASS"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [("object_id", "transplanted"), ("kind", "ENV"),
    ("payload", {"declared": "changed"}), ("operands", {"changed": []}), ("operands", []),
    ("operands", ["nonempty invalid map"])])
def test_full_selected_record_cannot_be_normalized_or_transplanted(field: str, value: Any) -> None:
    request, policy, evidence, _ = fixture(subject_changes={field: value})
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [
    ("schema_version", "other-message"), ("semantic_version", "legacy"),
    ("coordinate", "ENV-9.1"), ("proposition_digest", "sha256:" + "1" * 64),
    ("object_kind", "ENV"), ("subject_id", "another-subject"),
    ("object_digest", "sha256:" + "2" * 64), ("receipt_object_id", "another-receipt"),
    ("chain_domain", "other-domain"), ("chain_genesis_digest", "sha256:" + "3" * 64),
    ("chain_first_sequence", 6), ("chain_sequence", 7),
    ("context_digest", "sha256:" + "4" * 64), ("policy_digest", "sha256:" + "5" * 64),
    ("extra_scope", "unadmitted"),
])
def test_reanchored_wrong_intent_still_refutes_exact_association(field: str, value: Any) -> None:
    request, policy, evidence, child = fixture(message_changes={field: value})
    assert receipt_chain.recheck_receipt_chain_certificate(child,
        expected_request=request["chain_request"], policy=policy["chain_policy"])["status"] == "PASS"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_semantically_equivalent_noncanonical_entry_is_not_exact_message() -> None:
    request, policy, evidence, _ = fixture(noncanonical_message=True)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("changes,status", [({"include_chain": False}, "UNKNOWN"),
    ({"child_status": "UNKNOWN"}, "UNKNOWN"), ({"child_status": "FAIL"}, "FAIL"),
    ({"selected_sequence": 7}, "FAIL"), ({"selected_sequence": 9}, "FAIL"),
    ({"max_evidence_bytes": 1}, "UNKNOWN")])
def test_missing_refuted_wrong_position_and_bounded_inputs_are_distinct(changes: dict[str, Any], status: str) -> None:
    request, policy, evidence, _ = fixture(**changes)
    assert replay(request, policy, evidence)[1]["status"] == status


def test_missing_outer_evidence_remains_unknown() -> None:
    request, policy, _, _ = fixture()
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_changed_external_context_rejects_old_certificate_and_old_message() -> None:
    request, policy, evidence, _ = fixture()
    certificate, _ = replay(request, policy, evidence)
    changed = {**request, "context_digest": "sha256:" + "7" * 64}
    with pytest.raises(security.SubjectSecurityError):
        security.recheck_subject_security_certificate(certificate, expected_request=changed, policy=policy)
    assert replay(changed, policy, evidence)[1]["status"] == "FAIL"


def test_same_external_selection_can_replay_without_fabricating_consumption() -> None:
    request, policy, evidence, _ = fixture()
    certificate, result = replay(request, policy, evidence)
    again = security.recheck_subject_security_certificate(certificate, expected_request=request, policy=policy)
    assert again == result and again["context_consumption"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("kind", ["ENV", "HUMAN", "RECEIPT"])
def test_policy_and_mechanism_digest_are_kind_specific(kind: str) -> None:
    request, policy, evidence, _ = fixture()
    other = security.subject_security_policy(object_kind=kind,
        chain_policy=policy["chain_policy"], trust_roots=policy["trust_roots"])
    assert other["mechanism_digest"] != policy["mechanism_digest"]
    with pytest.raises(security.SubjectSecurityError):
        security.build_subject_security_certificate({**request, "policy_digest": digest(encoded(other))}, evidence, policy=other)


@pytest.mark.parametrize("field,value", [("semantic_version", "legacy"),
    ("coordinate", "MODEL-9.2"), ("proposition_digest", "sha256:" + "6" * 64),
    ("chain_sequence", True), ("chain_sequence", -1), ("chain_sequence", 2**63),
    ("object_kind", "NONOBJECT"), ("max_evidence_bytes", True)])
def test_malformed_external_selection_never_builds_a_certificate(field: str, value: Any) -> None:
    request, policy, evidence, _ = fixture()
    with pytest.raises(ValueError):
        security.build_subject_security_certificate({**request, field: value}, evidence, policy=policy)


@pytest.mark.parametrize("field,value", [("schema_version", "other-certificate"),
    ("proposition_digest", "sha256:" + "8" * 64), ("mechanism_digest", "sha256:" + "9" * 64)])
def test_rehashed_outer_envelope_does_not_admit_substituted_contract(field: str, value: Any) -> None:
    request, policy, evidence, _ = fixture()
    certificate, _ = replay(request, policy, evidence)
    envelope = json.loads(certificate)
    envelope[field] = value
    envelope["digest"] = digest(encoded({key: value for key, value in envelope.items() if key != "digest"}))
    with pytest.raises(security.SubjectSecurityError):
        security.recheck_subject_security_certificate(encoded(envelope), expected_request=request, policy=policy)


def test_rehashed_carried_pass_cannot_replace_native_refutation() -> None:
    request, policy, evidence, _ = fixture(message_changes={"object_kind": "ENV"})
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    envelope = json.loads(certificate)
    envelope["result"]["status"] = "PASS"
    envelope["result"]["evaluation"]["outcome"] = "PASS"
    envelope["digest"] = digest(encoded({key: value for key, value in envelope.items() if key != "digest"}))
    with pytest.raises(security.SubjectSecurityError):
        security.recheck_subject_security_certificate(encoded(envelope), expected_request=request, policy=policy)


def test_single_bit_subject_change_requires_external_selection_not_outer_rehash() -> None:
    request, policy, evidence, _ = fixture()
    changed = bytearray(evidence)
    position = evidence.index(b"finite retained record")
    changed[position] ^= 1
    with pytest.raises(security.SubjectSecurityError):
        security.build_subject_security_certificate(request, bytes(changed), policy=policy)
    selected = {**request, "evidence_ref": digest(bytes(changed))}
    assert replay(selected, policy, bytes(changed))[1]["status"] == "FAIL"


def test_duplicate_keys_and_noncanonical_outer_evidence_fail() -> None:
    request, policy, evidence, _ = fixture()
    duplicate = evidence[:-1] + b',"schema_version":"verifier-current-subject-security-evidence-1"}'
    selected = {**request, "evidence_ref": digest(duplicate)}
    assert replay(selected, policy, duplicate)[1]["status"] == "FAIL"
    spaced = json.dumps(json.loads(evidence), indent=2).encode()
    selected = {**request, "evidence_ref": digest(spaced)}
    assert replay(selected, policy, spaced)[1]["status"] == "FAIL"


def test_entry_message_has_no_circular_final_chain_commitment() -> None:
    request, policy, _, _ = fixture()
    child = request["chain_request"]
    message = security.subject_security_message(object_kind=request["object_kind"],
        subject_id=request["subject_id"], object_digest=request["object_digest"],
        receipt_object_id=child["receipt_object_id"], domain=child["domain"],
        genesis_digest=child["genesis_digest"], first_sequence=child["first_sequence"],
        sequence=request["chain_sequence"], context_digest=request["context_digest"], policy=policy)
    assert {"tip_digest", "receipt_object_digest", "chain_certificate_digest", "evidence_ref"}.isdisjoint(message)
    assert message["policy_digest"] == digest(encoded(policy))


@pytest.mark.parametrize("relative", ["subject_security.py", "CURRENT_SUBJECT_SECURITY.md"])
def test_selected_policy_invalidates_after_checker_or_specification_change(relative: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, _ = fixture()
    original = Path.read_bytes
    target = Path(security.__file__) if relative.endswith(".py") else Path(security.__file__).parents[2] / "standard" / relative
    def changed(path: Path) -> bytes:
        raw = original(path)
        return raw + b"\nchanged selected dependency\n" if path == target else raw
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(security.SubjectSecurityError):
        security.build_subject_security_certificate(request, evidence, policy=policy)
