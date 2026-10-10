"""Adversarial selected ten-tier composed-security fixtures; no production admission.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); application programming interface (API). Byte
commitments use an independent literal oracle.
Signing keys are generated in memory for each fixture and never retained.
"""
from __future__ import annotations

from asyncio import CancelledError
import base64
import builtins
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.domains.contracts import (
    receipt_authenticity as authenticity, receipt_chain,
    subject_security as association, verifier_composed_security as composed,
)


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def context() -> dict[str, Any]:
    subject = {"object_id": "selected-verifier", "kind": "VERIFIER",
               "payload": {"retained": "test checker declaration"}, "operands": {}}
    return {
        "schema_version": composed.CONTEXT_VERSION, "subject_id": subject["object_id"],
        "object_digest": digest(encoded(subject)),
        "artifact_digests": [digest(b"selected-artifact")],
        "instruction_digest": digest(b"selected-instruction"),
        "context_revision_digest": digest(b"selected-context-revision"),
        "generation": 7, "operation_id": "operation-7", "session_id": "session-7",
        "process_id": "declared-process-7",
        "authority_policy_digest": digest(b"selected-authority-policy"),
    }


def fixture(*, chain_name: str = "chain-a", wrong_signature: bool = False,
        message_changes: dict[str, Any] | None = None) -> dict[str, Any]:
    crypto = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        reason="OPTIONAL_DEPENDENCY_ABSENT: native issuer-key fixture needs cryptography",
    )
    serialization = pytest.importorskip(
        "cryptography.hazmat.primitives.serialization",
        reason="OPTIONAL_DEPENDENCY_ABSENT: native issuer-key fixture needs cryptography",
    )
    key = crypto.Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    binding = context()
    subject = {"object_id": binding["subject_id"], "kind": "VERIFIER",
               "payload": {"retained": "test checker declaration"}, "operands": {}}
    cp = receipt_chain.receipt_chain_policy(trust_roots=["externally-selected-chain-anchor"])
    ap = association.subject_security_policy(object_kind="VERIFIER", chain_policy=cp,
        trust_roots=["externally-selected-context"])
    first, genesis, domain = 7, digest(b"retained-genesis"), "test/" + chain_name
    # Independent literal typed-subject intent; no producer message helper is used.
    message = {
        "schema_version": association.MESSAGE_VERSION,
        "semantic_version": "verifier-current-object-obligations-1",
        "coordinate": "VERIFIER-9.1",
        "proposition_digest": association.SubjectSecurityDescriptor("VERIFIER").PROPOSITION_DIGEST,
        "object_kind": "VERIFIER", "subject_id": binding["subject_id"],
        "object_digest": binding["object_digest"], "receipt_object_id": chain_name,
        "chain_domain": domain, "chain_genesis_digest": genesis,
        "chain_first_sequence": first, "chain_sequence": first,
        "context_digest": digest(encoded(binding)), "policy_digest": digest(encoded(ap)),
    }
    message.update(message_changes or {})
    message_bytes = encoded(message)
    tip = digest(encoded({
        "schema_version": "verifier-receipt-chain-link-1", "domain": domain,
        "sequence": first, "previous": genesis, "receipt_digest": digest(message_bytes),
    }))
    receipt = {
        "object_id": chain_name, "kind": "RECEIPT",
        "payload": {"chain_domain": domain, "chain_genesis_digest": genesis,
                    "chain_first_sequence": first, "chain_tip_digest": tip},
        "operands": {"subject": [binding["subject_id"]], "hardware": ["declared-test-device"]},
    }
    chain_evidence = encoded({
        "schema_version": receipt_chain.EVIDENCE_VERSION, "domain": domain,
        "receipt_object": receipt,
        "entries": [{"sequence": first, "receipt_base64": b64(message_bytes)}],
    })
    cr = receipt_chain.receipt_chain_request(
        domain=domain, genesis_digest=genesis, first_sequence=first, tip_digest=tip,
        receipt_object_id=chain_name, receipt_object_digest=digest(encoded(receipt)),
        evidence_ref=digest(chain_evidence), policy=cp,
    )
    chain_certificate = receipt_chain.build_receipt_chain_certificate(cr, chain_evidence, policy=cp)
    ae = encoded({"schema_version": association.EVIDENCE_VERSION, "subject": subject,
                  "chain_certificate": chain_certificate.decode("utf-8")})
    ar = association.subject_security_request(
        object_kind="VERIFIER", subject_id=binding["subject_id"], object_digest=binding["object_digest"],
        context_digest=digest(encoded(binding)), chain_request=cr,
        chain_certificate_digest=digest(chain_certificate), chain_sequence=first,
        evidence_ref=digest(ae), policy=ap,
    )
    ac = association.build_subject_security_certificate(ar, ae, policy=ap)
    ip = authenticity.receipt_authenticity_policy(
        issuer_key_id="externally-selected-test-key", issuer_public_key=public,
        chain_policy=cp, trust_roots=["externally-selected-issuer-key"],
        max_validity_seconds=100,
    )
    ir = authenticity.receipt_authenticity_request(
        chain_request=cr, chain_certificate_digest=digest(chain_certificate),
        challenge="12" * 32, evaluation_time=100,
        evidence_ref=digest(b"temporary unselected placeholder"), policy=ip,
    )
    # Independent literal issuer intent and domain prefix from the native specification.
    signed = {
        "schema_version": authenticity.MESSAGE_VERSION,
        "semantic_version": "verifier-current-object-obligations-1", "coordinate": "RECEIPT-9.2",
        "proposition_digest": authenticity.PROPOSITION_DIGEST,
        "issuer_key_id": ip["issuer_key_id"], "receipt_object_id": chain_name,
        "receipt_object_digest": cr["receipt_object_digest"],
        "chain_certificate_digest": digest(chain_certificate),
        "chain_request_digest": digest(encoded(cr)), "challenge": ir["challenge"],
        "evaluation_time": 100, "policy_digest": digest(encoded(ip)),
        "issued_at": 100, "expires_at": 200,
    }
    signer = crypto.Ed25519PrivateKey.generate() if wrong_signature else key
    signature = signer.sign(b"verifier-current-receipt-issuer-attestation-1\x00" + encoded(signed))
    ie = encoded({
        "schema_version": authenticity.EVIDENCE_VERSION,
        "chain_certificate": chain_certificate.decode("utf-8"),
        "attestation": {"schema_version": authenticity.ATTESTATION_VERSION,
            "key_id": ip["issuer_key_id"], "payload": signed, "signature": signature.hex()},
    })
    ir["evidence_ref"] = digest(ie)
    ic = authenticity.build_receipt_authenticity_certificate(ir, ie, policy=ip)
    return {
        "context": binding, "association_request": ar, "association_policy": ap,
        "association_certificate": ac, "association_evidence": ae,
        "authenticity_request": ir, "authenticity_policy": ip,
        "authenticity_certificate": ic, "authenticity_evidence": ie,
        "chain_request": cr, "chain_policy": cp, "chain_certificate": chain_certificate,
    }


def selection(left: dict[str, Any], right: dict[str, Any] | None = None
        ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    right = left if right is None else right
    binding = deepcopy(left["context"])
    policy = composed.verifier_composed_security_policy(
        association_policy=left["association_policy"],
        authenticity_policy=right["authenticity_policy"], trust_roots=["selected-composition"],
    )
    evidence = encoded({
        "schema_version": composed.EVIDENCE_VERSION, "context_binding": binding,
        "association_certificate": b64(left["association_certificate"]),
        "authenticity_certificate": b64(right["authenticity_certificate"]),
    })
    request = composed.verifier_composed_security_request(
        subject_id=binding["subject_id"], object_digest=binding["object_digest"],
        context_binding=binding, association_request=left["association_request"],
        authenticity_request=right["authenticity_request"],
        association_certificate_digest=digest(left["association_certificate"]),
        authenticity_certificate_digest=digest(right["authenticity_certificate"]),
        evidence_ref=digest(evidence), policy=policy,
    )
    return request, policy, evidence


def selected(native: dict[str, Any], peer: dict[str, Any] | None = None
        ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Stable integration fixture API: independently selected request/policy/bytes."""
    return selection(native, peer)


def replay(request: dict[str, Any], policy: dict[str, Any], evidence: bytes | None
        ) -> tuple[bytes, dict[str, Any]]:
    certificate = composed.build_verifier_composed_security_certificate(request, evidence, policy=policy)
    result = composed.recheck_verifier_composed_security_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def rebound(request: dict[str, Any], evidence: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    raw = encoded(evidence)
    return {**request, "evidence_ref": digest(raw)}, raw


def unavailable_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    original = builtins.__import__

    def blocked(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("cryptography"):
            raise ImportError("test signature backend unavailable")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)


def test_exact_same_chain_native_pair_passes_only_finite_proposition() -> None:
    native = fixture()
    assert association.recheck_subject_security_certificate(native["association_certificate"],
        expected_request=native["association_request"], policy=native["association_policy"])["status"] == "PASS"
    assert authenticity.recheck_receipt_authenticity_certificate(native["authenticity_certificate"],
        expected_request=native["authenticity_request"], policy=native["authenticity_policy"])["status"] == "PASS"
    request, policy, evidence = selection(native)
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == result["selected_signed_association"] == "PASS"
    assert result["semantic_version"] == "verifier-current-ten-tier-object-obligations-1"
    assert result["coordinate"] == "VERIFIER-6.1"
    assert result["composed_security_admission"] == "UNKNOWN"
    for field in ("whole_security_admission", "authority", "key_custody", "trusted_time",
                  "live_revocation", "challenge_consumption", "actual_execution",
                  "human_acceptance", "production_admission", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    assert certificate == composed.build_verifier_composed_security_certificate(request, evidence, policy=policy)
    retained = json.loads(certificate)
    assert len(retained["evidence_refs"]) == 2
    selector = json.loads(base64.b64decode(retained["evidence_payloads"][retained["evidence_refs"][0]]))
    assert selector == {"schema_version": composed.SELECTOR_VERSION, "independently_selected_request": request}


def test_independently_valid_different_chain_certificates_cannot_compose() -> None:
    left, right = fixture(chain_name="chain-a"), fixture(chain_name="chain-b")
    assert association.recheck_subject_security_certificate(left["association_certificate"],
        expected_request=left["association_request"], policy=left["association_policy"])["status"] == "PASS"
    assert authenticity.recheck_receipt_authenticity_certificate(right["authenticity_certificate"],
        expected_request=right["authenticity_request"], policy=right["authenticity_policy"])["status"] == "PASS"
    request, policy, evidence = selection(left, right)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"
    request["cancelled"] = True
    assert replay(request, policy, None)[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [
    ("semantic_version", "other-family"), ("coordinate", "MODEL-9.1"),
    ("proposition_digest", digest(b"other proposition")), ("object_kind", "MODEL"),
    ("subject_id", "other-verifier"), ("object_digest", digest(b"other subject")),
    ("context_digest", digest(b"other context")), ("chain_sequence", 6),
])
def test_known_selected_native_binding_fail_precedes_missing_or_cancel(
        field: str, value: Any) -> None:
    request, policy, _ = selection(fixture())
    request["association_request"][field] = value
    request["cancelled"] = True
    assert replay(request, policy, None)[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [
    ("generation", 8), ("instruction_digest", digest(b"another instruction")),
    ("artifact_digests", [digest(b"another artifact")]),
    ("context_revision_digest", digest(b"another revision")),
    ("operation_id", "another-operation"), ("session_id", "another-session"),
    ("process_id", "another-process"), ("authority_policy_digest", digest(b"another policy")),
])
def test_every_external_context_component_is_bound_before_missing_or_cancel(
        field: str, value: Any) -> None:
    request, policy, _ = selection(fixture())
    request["context_binding"][field] = value
    request["cancelled"] = True
    assert replay(request, policy, None)[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [
    ("generation", 8), ("instruction_digest", digest(b"other instruction")),
    ("artifact_digests", [digest(b"other artifact")]),
    ("subject_id", "another-verifier"), ("object_digest", digest(b"other subject")),
])
def test_rebound_retained_context_cannot_substitute_external_binding(field: str, value: Any) -> None:
    request, policy, evidence = selection(fixture())
    changed = json.loads(evidence)
    changed["context_binding"][field] = value
    changed["authenticity_certificate"] = None
    request["cancelled"] = True
    request, raw = rebound(request, changed)
    assert replay(request, policy, raw)[1]["status"] == "FAIL"


def test_known_retained_association_fail_survives_missing_peer_and_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selection(fixture(message_changes={"context_digest": digest(b"wrong context")}))
    changed = json.loads(evidence)
    changed["authenticity_certificate"] = None
    request, raw = rebound(request, changed)
    request["cancelled"] = True
    unavailable_backend(monkeypatch)
    assert replay(request, policy, raw)[1]["status"] == "FAIL"


def test_wrong_signature_replays_fail_and_never_earns_full_admission() -> None:
    request, policy, evidence = selection(fixture(wrong_signature=True))
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL" and result["composed_security_admission"] == "UNKNOWN"


def test_actual_wrong_signature_cannot_hide_behind_missing_association() -> None:
    native = fixture(wrong_signature=True)
    assert authenticity.recheck_receipt_authenticity_certificate(
        native["authenticity_certificate"], expected_request=native["authenticity_request"],
        policy=native["authenticity_policy"])["status"] == "FAIL"
    request, policy, evidence = selected(native)
    retained = json.loads(evidence)
    retained["association_certificate"] = None
    request, evidence = rebound(request, retained)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert result["evaluation"]["observations"]["native_statuses"] == {
        "association": "UNKNOWN", "authenticity": "FAIL"}


@pytest.mark.parametrize("available", ["association", "authenticity"])
def test_available_native_fail_is_replayed_despite_missing_peer(
        available: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selected(fixture())
    absent = "authenticity" if available == "association" else "association"
    retained = json.loads(evidence)
    retained[absent + "_certificate"] = None
    request, evidence = rebound(request, retained)
    calls = []

    def present(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append(available)
        return {"status": "FAIL"}

    def missing(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("missing native child was replayed")

    left, right = (present, missing) if available == "association" else (missing, present)
    monkeypatch.setattr(association, "recheck_subject_security_certificate", left)
    monkeypatch.setattr(authenticity, "recheck_receipt_authenticity_certificate", right)
    certificate = composed.build_verifier_composed_security_certificate(request, evidence, policy=policy)
    assert json.loads(certificate)["result"]["status"] == "FAIL"
    assert calls == [available]


@pytest.mark.parametrize("first,second,expected", [
    ("UNKNOWN", "FAIL", "FAIL"), ("FAIL", "UNKNOWN", "FAIL"), ("UNKNOWN", "PASS", "UNKNOWN"),
])
def test_both_native_recheckers_run_with_refutation_precedence(
        monkeypatch: pytest.MonkeyPatch, first: str, second: str, expected: str) -> None:
    request, policy, evidence = selection(fixture())
    calls = []

    def left(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("association")
        return {"status": first}

    def right(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("authenticity")
        return {"status": second}

    monkeypatch.setattr(association, "recheck_subject_security_certificate", left)
    monkeypatch.setattr(authenticity, "recheck_receipt_authenticity_certificate", right)
    certificate = composed.build_verifier_composed_security_certificate(request, evidence, policy=policy)
    assert json.loads(certificate)["result"]["status"] == expected
    assert calls == ["association", "authenticity"]


def test_later_native_cancellation_cannot_erase_an_observed_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selection(fixture())
    calls = []

    def left(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("association")
        return {"status": "FAIL"}

    def right(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("authenticity")
        raise CancelledError()

    monkeypatch.setattr(association, "recheck_subject_security_certificate", left)
    monkeypatch.setattr(authenticity, "recheck_receipt_authenticity_certificate", right)
    certificate = composed.build_verifier_composed_security_certificate(request, evidence, policy=policy)
    assert json.loads(certificate)["result"]["status"] == "FAIL"
    assert calls == ["association", "authenticity"]


@pytest.mark.parametrize("outage_type", [ImportError, MemoryError, RuntimeError])
def test_later_typed_native_outage_cannot_erase_an_observed_fail(
        monkeypatch: pytest.MonkeyPatch, outage_type: type[Exception]) -> None:
    request, policy, evidence = selected(fixture())
    calls = []

    def left(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("association")
        return {"status": "FAIL"}

    def right(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("authenticity")
        raise outage_type("test typed native outage")

    monkeypatch.setattr(association, "recheck_subject_security_certificate", left)
    monkeypatch.setattr(authenticity, "recheck_receipt_authenticity_certificate", right)
    certificate = composed.build_verifier_composed_security_certificate(request, evidence, policy=policy)
    assert json.loads(certificate)["result"]["status"] == "FAIL"
    assert calls == ["association", "authenticity"]


@pytest.mark.parametrize("outage_type", [ImportError, MemoryError, RuntimeError])
def test_honest_both_typed_native_outages_are_unknown_and_old_pass_is_unavailable(
        monkeypatch: pytest.MonkeyPatch, outage_type: type[Exception]) -> None:
    request, policy, evidence = selected(fixture())
    old_certificate, original = replay(request, policy, evidence)
    assert original["status"] == "PASS"
    calls = []

    def left(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("association")
        raise outage_type("test first typed outage")

    def right(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("authenticity")
        raise outage_type("test second typed outage")

    monkeypatch.setattr(association, "recheck_subject_security_certificate", left)
    monkeypatch.setattr(authenticity, "recheck_receipt_authenticity_certificate", right)
    fresh = composed.build_verifier_composed_security_certificate(request, evidence, policy=policy)
    current = json.loads(fresh)["result"]
    assert current["status"] == "UNKNOWN"
    assert current["evaluation"]["observations"]["native_statuses"] == {
        "association": "UNKNOWN", "authenticity": "UNKNOWN"}
    assert current["evaluation"]["observations"]["checking_dependency"] == "NATIVE_REPLAY_UNAVAILABLE"
    assert calls == ["association", "authenticity"]
    calls.clear()
    old = composed.recheck_verifier_composed_security_certificate(
        old_certificate, expected_request=request, policy=policy)
    assert old["status"] == "UNKNOWN" and old["replay_status"] == "UNAVAILABLE"
    assert calls == ["association", "authenticity"]


@pytest.mark.parametrize("outage_type", [ImportError, MemoryError, RuntimeError])
def test_typed_source_admission_outage_preserves_unknown_unavailable(
        monkeypatch: pytest.MonkeyPatch, outage_type: type[Exception]) -> None:
    request, policy, evidence = selected(fixture())
    certificate, _ = replay(request, policy, evidence)

    def missing() -> str:
        raise outage_type("test source admission outage")

    monkeypatch.setattr(composed, "mechanism_digest", missing)
    current = json.loads(composed.build_verifier_composed_security_certificate(
        request, evidence, policy=policy))["result"]
    assert current["status"] == "UNKNOWN"
    assert current["evaluation"]["observations"]["native_statuses"] == {
        "association": "PASS", "authenticity": "PASS"}
    old = composed.recheck_verifier_composed_security_certificate(
        certificate, expected_request=request, policy=policy)
    assert old["status"] == "UNKNOWN" and old["replay_status"] == "UNAVAILABLE"


@pytest.mark.parametrize("outage_type", [ImportError, MemoryError, RuntimeError])
def test_typed_source_admission_outage_cannot_erase_native_fail(
        monkeypatch: pytest.MonkeyPatch, outage_type: type[Exception]) -> None:
    request, policy, evidence = selected(fixture())
    calls = []

    def missing() -> str:
        raise outage_type("test source admission outage")

    def left(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("association")
        return {"status": "FAIL"}

    def right(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("authenticity")
        return {"status": "PASS"}

    monkeypatch.setattr(composed, "mechanism_digest", missing)
    monkeypatch.setattr(association, "recheck_subject_security_certificate", left)
    monkeypatch.setattr(authenticity, "recheck_receipt_authenticity_certificate", right)
    certificate = composed.build_verifier_composed_security_certificate(request, evidence, policy=policy)
    assert json.loads(certificate)["result"]["status"] == "FAIL"
    assert calls == ["association", "authenticity"]


def test_honest_backend_outage_returns_unavailable_without_reproducing_old_pass(
        monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selection(fixture())
    certificate, original = replay(request, policy, evidence)
    assert original["status"] == "PASS"
    unavailable_backend(monkeypatch)
    result = composed.recheck_verifier_composed_security_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN" and result["replay_status"] == "UNAVAILABLE"
    assert result["composed_security_admission"] == "UNKNOWN"
    fresh, current = replay(request, policy, evidence)
    assert current["status"] == "UNKNOWN" and fresh != certificate


def test_backend_outage_does_not_hide_rehashed_forged_positive_observations(
        monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selection(fixture())
    certificate, _ = replay(request, policy, evidence)
    changed = json.loads(certificate)
    changed["result"]["evaluation"]["observations"]["context_digest"] = digest(b"forged context")
    changed["digest"] = digest(encoded({key: value for key, value in changed.items() if key != "digest"}))
    unavailable_backend(monkeypatch)
    with pytest.raises(composed.VerifierComposedSecurityError, match="observations"):
        composed.recheck_verifier_composed_security_certificate(
            encoded(changed), expected_request=request, policy=policy)


@pytest.mark.parametrize("missing", ["whole", "association_certificate", "authenticity_certificate"])
def test_missing_evidence_remains_unknown_and_cannot_be_supplied_by_selector(missing: str) -> None:
    request, policy, evidence = selection(fixture())
    if missing == "whole":
        evidence = None
    else:
        changed = json.loads(evidence)
        changed[missing] = None
        request, evidence = rebound(request, changed)
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    if missing == "whole":
        assert len(json.loads(certificate)["evidence_refs"]) == 1


def test_selected_cancel_and_capacity_are_unknown_unless_selection_is_refuted() -> None:
    request, policy, evidence = selection(fixture())
    request["cancelled"] = True
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    request["cancelled"] = False
    request["max_evidence_bytes"] = 1
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    request["association_request"]["context_digest"] = digest(b"wrong")
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [
    ("generation", True), ("generation", -1), ("generation", 2**53),
    ("artifact_digests", []), ("artifact_digests", [digest(b"a"), digest(b"a")]),
    ("artifact_digests", sorted([digest(b"a"), digest(b"b")], reverse=True)),
])
def test_malformed_context_is_refused_without_coercion(field: str, value: Any) -> None:
    binding = context()
    binding[field] = value
    with pytest.raises(composed.VerifierComposedSecurityError):
        composed.context_binding(binding)


def test_foreign_recursive_values_are_refused_before_callbacks() -> None:
    class Foreign:
        def __eq__(self, other: object) -> bool:
            raise AssertionError("foreign equality executed")

        def __str__(self) -> str:
            raise AssertionError("foreign coercion executed")

    binding = context()
    binding["artifact_digests"] = [Foreign()]
    with pytest.raises(composed.VerifierComposedSecurityError):
        composed.context_binding(binding)


@pytest.mark.parametrize("field", ["association_certificate", "authenticity_certificate"])
def test_wrong_selected_child_certificate_digest_is_not_hidden_by_peer_absence(field: str) -> None:
    request, policy, evidence = selection(fixture())
    changed = json.loads(evidence)
    changed["authenticity_certificate" if field == "association_certificate" else "association_certificate"] = None
    request[field + "_digest"] = digest(b"wrong selected certificate")
    request, evidence = rebound(request, changed)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_changed_selected_chain_policy_cannot_be_hidden_by_cancel_or_missing() -> None:
    request, policy, _ = selection(fixture())
    policy["authenticity_policy"]["chain_policy"]["trust_roots"] = ["different-chain-selection"]
    request["policy_digest"] = digest(encoded(policy))
    request["cancelled"] = True
    assert replay(request, policy, None)[1]["status"] == "FAIL"


@pytest.mark.parametrize("change", ["extra", "duplicate", "noncanonical", "bad_base64"])
def test_closed_evidence_and_canonical_bytes_fail_after_exact_rebinding(change: str) -> None:
    request, policy, evidence = selection(fixture())
    parsed = json.loads(evidence)
    if change == "extra":
        parsed["invented_witness"] = {}
        raw = encoded(parsed)
    elif change == "duplicate":
        raw = evidence[:-1] + b',"schema_version":"' + composed.EVIDENCE_VERSION.encode() + b'"}'
    elif change == "noncanonical":
        raw = json.dumps(parsed, indent=2).encode()
    else:
        parsed["association_certificate"] = "!!!!"
        raw = encoded(parsed)
    request["evidence_ref"] = digest(raw)
    assert replay(request, policy, raw)[1]["status"] == "FAIL"


def test_outer_envelope_hash_cannot_repair_forged_pass_or_claim_promotion() -> None:
    request, policy, evidence = selection(fixture(wrong_signature=True))
    certificate, _ = replay(request, policy, evidence)
    changed = json.loads(certificate)
    changed["result"]["status"] = changed["result"]["evaluation"]["outcome"] = "PASS"
    changed["result"]["authority"] = "ESTABLISHED"
    changed["digest"] = digest(encoded({key: value for key, value in changed.items() if key != "digest"}))
    with pytest.raises(composed.VerifierComposedSecurityError):
        composed.recheck_verifier_composed_security_certificate(
            encoded(changed), expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/verifier_composed_security.py",
    "domains/contracts/subject_security.py", "domains/contracts/receipt_authenticity.py",
    "domains/contracts/receipt_chain.py", "domains/contracts/retained_selection.py",
    "domains/common.py", "core/certificate.py", "core/evidence.py", "core/namespace.py",
    "core/receipt.py", "core/signature_keys.py",
    "standard/CURRENT_VERIFIER_COMPOSED_SECURITY.md", "standard/CURRENT_SUBJECT_SECURITY.md",
    "standard/CURRENT_RECEIPT_AUTHENTICITY.md", "standard/CURRENT_RECEIPT_CHAIN.md",
    "standard/NAMESPACE_OBJECTS.md", "standard/CURRENT_TEN_TIER_PROGRESSION.md",
])
def test_any_pinned_native_or_composed_source_change_invalidates_policy(
        relative: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selection(fixture())
    certificate, _ = replay(request, policy, evidence)
    target = Path(composed.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        raw = original(path)
        return raw + b"\nchanged pinned bytes\n" if path == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"
    with pytest.raises(composed.VerifierComposedSecurityError):
        composed.recheck_verifier_composed_security_certificate(
            certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/verifier_composed_security.py",
    "domains/contracts/subject_security.py", "domains/contracts/receipt_authenticity.py",
    "domains/contracts/receipt_chain.py", "core/evidence.py", "core/signature_keys.py",
    "standard/CURRENT_VERIFIER_COMPOSED_SECURITY.md",
])
@pytest.mark.parametrize("contradiction", ["selected_context", "retained_context", "selected_certificate"])
def test_known_binding_fail_survives_unreadable_pinned_source(
        relative: str, contradiction: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selected(fixture())
    if contradiction == "selected_context":
        request["association_request"]["context_digest"] = digest(b"wrong selected context")
    elif contradiction == "retained_context":
        retained = json.loads(evidence)
        retained["context_binding"]["generation"] += 1
        request, evidence = rebound(request, retained)
    else:
        request["association_certificate_digest"] = digest(b"wrong selected certificate")
    request["cancelled"] = True
    target = Path(composed.__file__).parents[2] / relative
    original = Path.read_bytes
    attempted = []

    def missing(path: Path) -> bytes:
        attempted.append(path)
        if path == target:
            raise OSError("test selected dependency unavailable")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", missing)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"
    assert attempted == []


@pytest.mark.parametrize("relative", [
    "domains/contracts/verifier_composed_security.py",
    "domains/contracts/subject_security.py", "domains/contracts/receipt_authenticity.py",
    "core/signature_keys.py",
])
def test_honest_missing_source_gives_unknown_and_old_positive_replay_unavailable(
        relative: str, monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selected(fixture())
    certificate, _ = replay(request, policy, evidence)
    target = Path(composed.__file__).parents[2] / relative
    original = Path.read_bytes

    def missing(path: Path) -> bytes:
        if path == target:
            raise OSError("test selected dependency unavailable")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", missing)
    _, fresh = replay(request, policy, evidence)
    assert fresh["status"] == "UNKNOWN"
    old = composed.recheck_verifier_composed_security_certificate(
        certificate, expected_request=request, policy=policy)
    assert old["status"] == "UNKNOWN" and old["replay_status"] == "UNAVAILABLE"


def test_wrong_actual_retained_chain_cannot_hide_behind_peer_absence_source_or_backend(
        monkeypatch: pytest.MonkeyPatch) -> None:
    native, unrelated = fixture(), fixture(chain_name="independently-valid-other-chain")
    assert receipt_chain.recheck_receipt_chain_certificate(unrelated["chain_certificate"],
        expected_request=unrelated["chain_request"], policy=unrelated["chain_policy"])["status"] == "PASS"
    retained = json.loads(native["authenticity_evidence"])
    retained["chain_certificate"] = unrelated["chain_certificate"].decode()
    raw = encoded(retained)
    native["authenticity_request"]["evidence_ref"] = digest(raw)
    envelope = json.loads(native["authenticity_certificate"])
    envelope["request"] = native["authenticity_request"]
    envelope["evidence_refs"] = [digest(raw)]
    envelope["evidence_payloads"] = {digest(raw): b64(raw)}
    envelope["digest"] = digest(encoded({key: value for key, value in envelope.items() if key != "digest"}))
    native["authenticity_certificate"] = encoded(envelope)
    request, policy, evidence = selected(native)
    parsed = json.loads(evidence)
    parsed["association_certificate"] = None
    request, evidence = rebound(request, parsed)
    request["cancelled"] = True
    unavailable_backend(monkeypatch)

    def missing(path: Path) -> bytes:
        raise OSError("source reads must follow known retained chain refutation")

    monkeypatch.setattr(Path, "read_bytes", missing)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_sequence_within_selected_capacity_needs_retained_chain_before_refutation():
    request, policy, evidence = selection(fixture())
    request["association_request"]["chain_sequence"] = 8
    request["cancelled"] = True
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"
