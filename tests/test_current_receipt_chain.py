"""Refutable current RECEIPT-9.1 finite hash-chain checks."""
from __future__ import annotations

import base64
import hashlib

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import receipt_chain
from verifier.domains.contracts.current_object_routes import (
    current_object_route_catalog, replay_current_object_certificate,
)
from verifier.domains.inventory import get_slot
from verifier.runtime.public_cli import main


GENESIS = "sha256:" + "0" * 64
DOMAIN = "claimgarden.example/receipts"
OBJECT_ID = "receipt-chain-7"


def _receipt_object(tip: str, *, domain: str = DOMAIN, genesis: str = GENESIS,
                    first: int = 7) -> NamespaceObject:
    return NamespaceObject.create(OBJECT_ID, "RECEIPT", {
        "chain_domain": domain, "chain_genesis_digest": genesis,
        "chain_first_sequence": first, "chain_tip_digest": tip})


def _evidence(receipts: tuple[bytes, ...], *, first: int = 7,
              domain: str = DOMAIN, genesis: str = GENESIS,
              sequences: tuple[int, ...] | None = None,
              object_tip: str | None = None) -> tuple[bytes, str]:
    entries = []
    previous = genesis
    for index, payload in enumerate(receipts):
        sequence = sequences[index] if sequences is not None else first + index
        entries.append({"sequence": sequence,
                        "receipt_base64": base64.b64encode(payload).decode("ascii")})
        previous = "sha256:" + canonical_digest({
            "schema_version": "verifier-receipt-chain-link-1", "domain": domain,
            "sequence": sequence, "previous": previous,
            "receipt_digest": "sha256:" + hashlib.sha256(payload).hexdigest()})
    record = _receipt_object(object_tip or previous, domain=domain,
                             genesis=genesis, first=first)
    return canonical_bytes({"schema_version": "verifier-receipt-chain-evidence-1",
                            "domain": domain, "receipt_object": record.to_dict(),
                            "entries": entries}), previous


def _selection(evidence: bytes, tip: str, *, policy: dict,
               first: int = 7, domain: str = DOMAIN,
               genesis: str = GENESIS, max_entries: int = 64) -> dict:
    return receipt_chain.receipt_chain_request(
        domain=domain, genesis_digest=genesis, first_sequence=first,
        tip_digest=tip, evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        receipt_object_id=OBJECT_ID,
        receipt_object_digest=_receipt_object(tip, domain=domain, genesis=genesis,
                                              first=first).digest,
        policy=policy, max_entries=max_entries)


def test_exact_two_receipt_chain_replays_against_external_tip():
    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    evidence, tip = _evidence((b'\x00first', b'{"id":"second"}'))
    request = _selection(evidence, tip, policy=policy)
    certificate = receipt_chain.build_receipt_chain_certificate(request, evidence, policy=policy)
    result = receipt_chain.recheck_receipt_chain_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert result["tip_digest"] == tip
    assert result["receipt_object_digest"] == request["receipt_object_digest"]
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["issuer_authenticity"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("receipts,sequences", [
    ((b"second", b"first"), None),
    ((b"first",), None),
    ((b"first", b"second"), (7, 9)),
])
def test_reordered_omitted_or_gapped_chain_fails_selected_tip(receipts, sequences):
    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    _, selected_tip = _evidence((b"first", b"second"))
    evidence, _ = _evidence(receipts, sequences=sequences, object_tip=selected_tip)
    request = _selection(evidence, selected_tip, policy=policy)
    certificate = receipt_chain.build_receipt_chain_certificate(request, evidence, policy=policy)
    assert receipt_chain.recheck_receipt_chain_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_missing_evidence_is_unknown_and_entry_budget_is_unknown():
    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    evidence, tip = _evidence((b"first", b"second"))
    request = _selection(evidence, tip, policy=policy)
    missing = receipt_chain.build_receipt_chain_certificate(request, None, policy=policy)
    assert receipt_chain.recheck_receipt_chain_certificate(
        missing, expected_request=request, policy=policy)["status"] == "UNKNOWN"
    bounded = _selection(evidence, tip, policy=policy, max_entries=1)
    certificate = receipt_chain.build_receipt_chain_certificate(bounded, evidence, policy=policy)
    assert receipt_chain.recheck_receipt_chain_certificate(
        certificate, expected_request=bounded, policy=policy)["status"] == "UNKNOWN"


def test_rehashed_result_and_reselected_policy_cannot_promote_chain():
    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    evidence, tip = _evidence((b"first",))
    request = _selection(evidence, tip, policy=policy)
    certificate = receipt_chain.build_receipt_chain_certificate(request, evidence, policy=policy)
    forged = strict_json_loads(certificate.decode("utf-8"))
    forged["result"]["issuer_authenticity"] = "PASS"
    forged["digest"] = "sha256:" + canonical_digest({k: v for k, v in forged.items() if k != "digest"})
    with pytest.raises(receipt_chain.ReceiptChainError):
        receipt_chain.recheck_receipt_chain_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    other_policy = receipt_chain.receipt_chain_policy(trust_roots=("other-register",))
    with pytest.raises(receipt_chain.ReceiptChainError):
        receipt_chain.recheck_receipt_chain_certificate(
            certificate, expected_request=request, policy=other_policy)


def test_noncanonical_or_duplicate_key_evidence_fails():
    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    evidence, tip = _evidence((b"first",))
    malformed = [evidence + b" ", evidence.replace(b'"domain":', b'"domain":"x","domain":', 1)]
    for candidate in malformed:
        request = _selection(candidate, tip, policy=policy)
        certificate = receipt_chain.build_receipt_chain_certificate(
            request, candidate, policy=policy)
        assert receipt_chain.recheck_receipt_chain_certificate(
            certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_substituted_namespace_object_kind_or_anchor_fails_even_with_new_evidence_ref():
    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    evidence, tip = _evidence((b"first",))
    for replacement in (
        {"kind": "OBJECT"},
        {"payload": dict(_receipt_object(tip).payload, chain_tip_digest=GENESIS)},
    ):
        mutated = strict_json_loads(evidence.decode("utf-8"))
        mutated["receipt_object"].update(replacement)
        candidate = canonical_bytes(mutated)
        request = _selection(candidate, tip, policy=policy)
        certificate = receipt_chain.build_receipt_chain_certificate(
            request, candidate, policy=policy)
        assert receipt_chain.recheck_receipt_chain_certificate(
            certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_boolean_namespace_anchor_does_not_equal_selected_integer():
    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    evidence, tip = _evidence((b"first",), first=1)
    altered = strict_json_loads(evidence.decode("utf-8"))
    altered["receipt_object"]["payload"]["chain_first_sequence"] = True
    candidate = canonical_bytes(altered)
    request = _selection(candidate, tip, policy=policy, first=1)
    request["receipt_object_digest"] = "sha256:" + canonical_digest(altered["receipt_object"])
    certificate = receipt_chain.build_receipt_chain_certificate(request, candidate, policy=policy)
    assert receipt_chain.recheck_receipt_chain_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_hostile_external_selection_refuses_before_user_comparison():
    class Callback(str):
        def __ne__(self, other):
            raise AssertionError("caller-defined comparison executed")

    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    evidence, tip = _evidence((b"first",))
    request = _selection(evidence, tip, policy=policy)
    with pytest.raises(receipt_chain.ReceiptChainError):
        receipt_chain.build_receipt_chain_certificate(
            dict(request, schema_version=Callback(request["schema_version"])),
            evidence, policy=policy)
    with pytest.raises(receipt_chain.ReceiptChainError):
        receipt_chain.build_receipt_chain_certificate(
            request, evidence,
            policy=dict(policy, schema_version=Callback(policy["schema_version"])))


def test_registered_public_route_and_inventory_bind_exact_receipt_security_slice():
    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    evidence, tip = _evidence((b"first", b"second"))
    request = _selection(evidence, tip, policy=policy)
    certificate = receipt_chain.build_receipt_chain_certificate(request, evidence, policy=policy)
    report = replay_current_object_certificate(
        certificate, semantic_version=receipt_chain.SEMANTIC_VERSION,
        objective="RECEIPT-9.1", represented_kind="RECEIPT",
        expected_request=request, policy=policy)
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["issuer_authenticity"] == "NOT_ESTABLISHED"
    assert "selected RECEIPT object and finite receipt chain" in report["claim_boundary"]
    slot = get_slot("RECEIPT", 9)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "RECEIPT-9.1"
    assert any(row["objective"] == "RECEIPT-9.1" for row in current_object_route_catalog())


def test_public_cli_replays_selected_receipt_chain(tmp_path, capsys):
    policy = receipt_chain.receipt_chain_policy(trust_roots=("external-tip-register",))
    evidence, tip = _evidence((b"first", b"second"))
    request = _selection(evidence, tip, policy=policy)
    certificate = receipt_chain.build_receipt_chain_certificate(request, evidence, policy=policy)
    certificate_path = tmp_path / "certificate.json"
    request_path = tmp_path / "request.json"
    policy_path = tmp_path / "policy.json"
    certificate_path.write_bytes(certificate)
    request_path.write_bytes(canonical_bytes(request))
    policy_path.write_bytes(canonical_bytes(policy))
    assert main(["current-object", "check", str(certificate_path),
        "--semantic-version", receipt_chain.SEMANTIC_VERSION,
        "--objective", "RECEIPT-9.1", "--represented-kind", "RECEIPT",
        "--request", str(request_path), "--policy", str(policy_path), "--json"]) == 0
    report = strict_json_loads(capsys.readouterr().out)
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "PASS"
    assert certificate_path.read_bytes() == certificate
