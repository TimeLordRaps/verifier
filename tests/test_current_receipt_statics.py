"""Selected RECEIPT-3.1 canonical VSTD-1 receipt statics, not claim truth.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Byte limits measure exact bytes; counts and
operation budgets are dimensionless. The oracle below re-derives the VSTD-1
stable payload and canonical form from the specification text with plain
dictionary mapping and the standard JSON encoder, not the checker under test.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.checker import IndependentAuditor
from verifier.core.namespace import NamespaceObject
from verifier.core.provenance import GitProvenance, ProvenanceRecord, RuntimeEnvironment
from verifier.core.receipt import ClaimSpec, EvidencePayload, ExecutionMetadata, VstdReceipt
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import receipt_statics
from verifier.domains.inventory import get_slot


def canonical(value: object) -> bytes:
    """VSTD-1 section 7: sorted keys, compact separators, finite numbers."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def stable_digest(row: dict) -> str:
    """Independent VSTD-1 stable-payload digest from the serialized fields."""
    stable = {key: row[key] for key in (
        "schema_version", "receipt_kind", "receipt_id", "claim", "evidence",
        "target_result", "independent_audit", "reproducibility")}
    provenance = row["provenance"]
    stable["provenance_stable"] = {
        "target_name": provenance["target_name"],
        "portable_repository_id": provenance["portable_repository_id"],
        "git_commit_sha": provenance["git"]["commit_sha"],
        "git_branch": provenance["git"]["branch"],
        "git_is_dirty": provenance["git"]["is_dirty"],
        "git_dirty_files": provenance["git"]["dirty_files"],
        "source_file_hashes": provenance["source_file_hashes"],
        "runtime_python_version": provenance["runtime"]["python_version"],
    }
    return hashlib.sha256(canonical(stable)).hexdigest()


def redigest(row: dict) -> dict:
    changed = deepcopy(row)
    changed["canonical_digest"] = stable_digest(changed)
    return changed


def receipt_row(*, claim_id: str = "claim-1", n_vars: int = 1,
                clauses: tuple = ((1,),)) -> dict:
    reasons = ({"reason_id": "r1", "proposition": "x1 holds",
                "evidence_kind": "OBSERVED", "parent_reason_ids": []},)
    audit = IndependentAuditor.audit_claim_derivation(
        claim_id=claim_id, n_vars=n_vars, clauses=clauses, atomic_reasons=reasons)
    receipt = VstdReceipt(
        schema_version="VSTD-1", receipt_kind="claim_mechanics",
        receipt_id="VFY-000001",
        claim=ClaimSpec(id=claim_id, title="unit clause", statement="x1 is satisfiable",
                        status="draft", scope="one clause", limitations=("toy",),
                        falsification_condition="formula unsatisfiable",
                        last_verified="2026-10-01"),
        evidence=EvidencePayload(domain="sat", input_text_or_formula="x1",
                                 n_vars=n_vars, clauses=clauses, atomic_reasons=reasons,
                                 assumptions=(), source_artifacts={"formula": "sha256:" + "a" * 64}),
        target_result={"satisfiable": True}, independent_audit=audit,
        provenance=ProvenanceRecord(
            target_name="fixture", portable_repository_id="fixture-repository",
            local_repository_path="fixture/repository",
            git=GitProvenance("a" * 40, "main", False),
            runtime=RuntimeEnvironment("3.12", "CPython", "test", "test", "test", "masked"),
            captured_at_utc="2026-10-01T00:00:00+00:00", command_executed="fixture"),
        reproducibility={"level": "CONTENT_IDENTICAL"},
        execution_metadata=ExecutionMetadata("2026-10-01T00:00:00+00:00", 1.5,
                                             "fixture", "", ""))
    return receipt.to_dict()


def selected(receipt: bytes, *, subject: str = "receipt-a", prerequisites=(),
             commit: bytes | None = None, limits: dict | None = None):
    record = NamespaceObject.create(subject, "RECEIPT", {
        "receipt_kind": "claim_mechanics", "receipt_schema_version": "VSTD-1",
        "receipt_sha256": "sha256:" + hashlib.sha256(
            receipt if commit is None else commit).hexdigest(),
        "prerequisites": list(prerequisites)})
    evidence = canonical_bytes({
        "schema_version": receipt_statics.EVIDENCE_VERSION,
        "receipt_object": record.to_dict(),
        "receipt_base64": base64.b64encode(receipt).decode("ascii")})
    policy = receipt_statics.receipt_statics_policy(trust_roots=["statics-root"])
    request = receipt_statics.receipt_statics_request(
        subject_id=record.object_id, object_digest=record.digest,
        evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = receipt_statics.build_receipt_statics_certificate(
        request, evidence, policy=policy)
    result = receipt_statics.recheck_receipt_statics_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def test_inventory_selects_the_receipt_statics_recheck():
    slot = get_slot("RECEIPT", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "RECEIPT-3.1"
    assert slot.mechanized_route["artifact_coordinate"] == "RECEIPT-3.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.receipt_statics.recheck_receipt_statics_certificate")


def test_canonical_vstd1_receipt_passes_and_rechecks_from_decoded_bytes():
    row = receipt_row()
    assert row["canonical_digest"] == stable_digest(row)
    request, policy, evidence = selected(canonical(row))
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["receipt_canonical_statics"] == "PASS"
    for field in ("claim_truth", "audit_validation_replay", "external_referent_bytes",
                  "prerequisite_resolution", "hash_chain_continuity",
                  "issuer_authenticity", "typed_composition",
                  "whole_receipt_statics", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    decoded = json.loads(certificate.decode("utf-8"))
    retained = base64.b64decode(decoded["evidence_payloads"][request["evidence_ref"]])
    assert retained == evidence
    assert receipt_statics.recheck_receipt_statics_certificate(
        bytes(certificate), expected_request=json.loads(json.dumps(request)),
        policy=json.loads(json.dumps(policy)))["status"] == "PASS"


def _pretty(row: dict) -> bytes:
    return json.dumps(row, sort_keys=True, indent=2).encode("ascii")


def _stale_digest(row: dict) -> bytes:
    changed = deepcopy(row)
    changed["target_result"]["satisfiable"] = False
    assert stable_digest(changed) != changed["canonical_digest"]
    return canonical(changed)


def _forged_independence(row: dict) -> bytes:
    changed = deepcopy(row)
    changed["independent_audit"]["independence_basis"]["independently_verified"] = True
    return canonical(redigest(changed))


def _serialized_evidenced(row: dict) -> bytes:
    changed = deepcopy(row)
    changed["independent_audit"]["independence_basis"]["actor_independence"] = "EVIDENCED"
    return canonical(redigest(changed))


def _string_variable_count(row: dict) -> bytes:
    changed = deepcopy(row)
    changed["evidence"]["n_vars"] = "1"
    return canonical(redigest(changed))


def _extra_claim_field(row: dict) -> bytes:
    changed = deepcopy(row)
    changed["claim"]["unreviewed"] = "extra"
    return canonical(redigest(changed))


def _other_schema(row: dict) -> bytes:
    changed = deepcopy(row)
    changed["schema_version"] = "VSTD-2"
    return canonical(redigest(changed))


@pytest.mark.parametrize("mutate,reason", [
    (_pretty, "not VSTD-1 canonical"),
    (_stale_digest, "canonical_digest"),
    (_forged_independence, "model serialization"),
    (_serialized_evidenced, "EVIDENCED"),
    (_string_variable_count, "integer"),
    (_extra_claim_field, "claim fields"),
    (_other_schema, "schema version"),
], ids=["noncanonical", "stale-digest", "forged-independence", "evidenced",
        "string-n-vars", "extra-claim-field", "other-schema"])
def test_refuting_receipt_mutants_fail_for_their_own_reason(mutate, reason):
    receipt = mutate(receipt_row())
    request, policy, evidence = selected(receipt)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL", result["evaluation"]["details"]
    assert reason in result["evaluation"]["details"]
    assert result["receipt_canonical_statics"] == "NOT_ESTABLISHED"


def test_record_commitment_to_other_bytes_fails():
    receipt = canonical(receipt_row())
    request, policy, evidence = selected(receipt, commit=receipt + b" ")
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "record commitment" in result["evaluation"]["details"]


def test_unsorted_declared_prerequisites_fail():
    request, policy, evidence = selected(canonical(receipt_row()),
                                         prerequisites=["receipt-z", "receipt-b"])
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "prerequisite" in result["evaluation"]["details"]


@pytest.mark.parametrize("limits", [{"max_operations": 8}, {"max_receipt_bytes": 64}],
                         ids=["operations", "receipt-bytes"])
def test_exhausted_budget_is_unknown(limits):
    request, policy, evidence = selected(canonical(receipt_row()), limits=limits)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    assert result["receipt_canonical_statics"] == "NOT_ESTABLISHED"


def test_missing_evidence_is_unknown():
    request, policy, _ = selected(canonical(receipt_row()))
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_one_bit_certificate_tamper_raises():
    request, policy, evidence = selected(canonical(receipt_row()))
    certificate, _ = replay(request, policy, evidence)
    index = certificate.index(b'"status":"PASS"') + len(b'"status":"')
    tampered = bytearray(certificate)
    tampered[index] ^= 0x01
    with pytest.raises(receipt_statics.ReceiptStaticsError):
        receipt_statics.recheck_receipt_statics_certificate(
            bytes(tampered), expected_request=request, policy=policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = "sha256:" + hashlib.sha256(canonical_bytes(forged)).hexdigest()
    with pytest.raises(receipt_statics.ReceiptStaticsError):
        receipt_statics.recheck_receipt_statics_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def test_wrong_subject_and_substituted_request_or_policy_are_refused():
    receipt = canonical(receipt_row())
    request, policy, evidence = selected(receipt)
    certificate, _ = replay(request, policy, evidence)
    other_request, _, _ = selected(receipt, subject="receipt-b")
    with pytest.raises(receipt_statics.ReceiptStaticsError):
        receipt_statics.recheck_receipt_statics_certificate(
            certificate, expected_request=other_request, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(receipt_statics.ReceiptStaticsError):
        receipt_statics.recheck_receipt_statics_certificate(
            certificate, expected_request=request, policy=other_policy)
    wrong_subject = deepcopy(request)
    wrong_subject["subject_id"] = "receipt-b"
    assert replay(wrong_subject, policy, evidence)[1]["status"] == "FAIL"


def test_public_route_reaches_pass():
    request, policy, evidence = selected(canonical(receipt_row()))
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=receipt_statics.SEMANTIC_VERSION,
        objective=receipt_statics.COORDINATE, represented_kind="RECEIPT",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["claim_truth"] == "NOT_ESTABLISHED"


def test_retained_statics_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence = selected(canonical(receipt_row()))
    certificate, _ = replay(request, policy, evidence)
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("RECEIPT", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/receipt_statics.py",
    "standard/CURRENT_RECEIPT_STATICS.md",
    "standard/VSTD-1.md",
    "core/receipt.py",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected(canonical(receipt_row()))
    certificate, _ = replay(request, policy, evidence)
    target = Path(receipt_statics.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        receipt_statics.recheck_receipt_statics_certificate(
            certificate, expected_request=request, policy=policy)
