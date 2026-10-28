"""Selected RECEIPT-2.1 VSTD-1 audit validation replay, not claim truth.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Boolean satisfiability problem (SAT). Byte limits measure
exact bytes; counts, search steps and operation budgets are dimensionless.
The satisfiability oracle below enumerates every assignment, a simpler method
than the Davis-Putnam-Logemann-Loveland (DPLL) search under test.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import dataclasses
import hashlib
import itertools
import json
from pathlib import Path

import pytest

from verifier.core import checker
from verifier.core.certificate import canonical_bytes
from verifier.core.checker import IndependenceBasis, IndependenceStatus, IndependentAuditor
from verifier.core.namespace import NamespaceObject
from verifier.core.provenance import GitProvenance, ProvenanceRecord, RuntimeEnvironment
from verifier.core.receipt import ClaimSpec, EvidencePayload, VstdReceipt
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import receipt_validation_replay as replay_module
from verifier.domains.inventory import get_slot


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def stable_digest(row: dict) -> str:
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


def brute_force_satisfiable(n_vars: int, clauses) -> bool:
    variables = sorted({abs(literal) for clause in clauses for literal in clause}
                       | set(range(1, n_vars + 1)))
    for values in itertools.product((False, True), repeat=len(variables)):
        assignment = dict(zip(variables, values))
        if all(any(assignment[abs(literal)] == (literal > 0) for literal in clause)
               for clause in clauses):
            return True
    return False


REASONS = ({"reason_id": "r1", "proposition": "x1 holds",
            "evidence_kind": "OBSERVED", "parent_reason_ids": []},)


def receipt_row(*, clauses: tuple = ((1,),), n_vars: int = 1,
                expected_satisfiable: bool = True,
                basis: IndependenceBasis | None = None) -> dict:
    audit = IndependentAuditor.audit_claim_derivation(
        claim_id="claim-1", n_vars=n_vars, clauses=clauses, atomic_reasons=REASONS,
        expected_satisfiable=expected_satisfiable)
    if basis is not None:
        audit = dataclasses.replace(audit, independence_basis=basis)
    receipt = VstdReceipt(
        schema_version="VSTD-1", receipt_kind="claim_mechanics",
        receipt_id="VFY-000002",
        claim=ClaimSpec(id="claim-1", title="formula", statement="formula status",
                        status="draft", scope="one formula", limitations=("toy",),
                        falsification_condition="replay differs",
                        last_verified="2026-10-01"),
        evidence=EvidencePayload(domain="sat", input_text_or_formula="formula",
                                 n_vars=n_vars, clauses=clauses, atomic_reasons=REASONS,
                                 assumptions=(), source_artifacts={}),
        target_result={"satisfiable": expected_satisfiable}, independent_audit=audit,
        provenance=ProvenanceRecord(
            target_name="fixture", portable_repository_id="fixture-repository",
            local_repository_path="fixture/repository",
            git=GitProvenance("b" * 40, "main", False),
            runtime=RuntimeEnvironment("3.12", "CPython", "test", "test", "test", "masked"),
            captured_at_utc="2026-10-01T00:00:00+00:00", command_executed="fixture"),
        reproducibility={"level": "CONTENT_IDENTICAL"})
    return receipt.to_dict()


def selected(receipt: bytes, *, subject: str = "receipt-a", expected: bool = True,
             limits: dict | None = None):
    record = NamespaceObject.create(subject, "RECEIPT", {
        "receipt_kind": "claim_mechanics", "receipt_schema_version": "VSTD-1",
        "receipt_sha256": "sha256:" + hashlib.sha256(receipt).hexdigest(),
        "prerequisites": []})
    evidence = canonical_bytes({
        "schema_version": replay_module.EVIDENCE_VERSION,
        "receipt_object": record.to_dict(),
        "receipt_base64": base64.b64encode(receipt).decode("ascii")})
    policy = replay_module.receipt_validation_replay_policy(trust_roots=["replay-root"])
    request = replay_module.receipt_validation_replay_request(
        subject_id=record.object_id, object_digest=record.digest,
        expected_satisfiable=expected,
        evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = replay_module.build_receipt_validation_replay_certificate(
        request, evidence, policy=policy)
    result = replay_module.recheck_receipt_validation_replay_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def test_inventory_selects_the_receipt_validation_replay_recheck():
    slot = get_slot("RECEIPT", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "RECEIPT-2.1"
    assert slot.mechanized_route["artifact_coordinate"] == "RECEIPT-2.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.receipt_validation_replay."
        "recheck_receipt_validation_replay_certificate")


@pytest.mark.parametrize("clauses,expected", [(((1,),), True), (((1,), (-1,)), False)],
                         ids=["satisfiable", "unsatisfiable"])
def test_retained_audit_replays_and_rechecks_from_decoded_bytes(clauses, expected):
    row = receipt_row(clauses=clauses, expected_satisfiable=expected)
    assert brute_force_satisfiable(1, clauses) is expected
    assert row["independent_audit"]["sat_result"]["satisfiable"] is expected
    request, policy, evidence = selected(canonical(row), expected=expected)
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS", result["evaluation"]["details"]
    assert result["receipt_validation_replay"] == "PASS"
    for field in ("claim_truth", "independence_basis_replay", "target_solver_replay",
                  "external_referent_bytes", "receipt_generation",
                  "revocation_event_logging", "ledger_registration",
                  "prerequisite_resolution", "hash_chain_continuity",
                  "issuer_authenticity", "whole_receipt_dynamics",
                  "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    decoded = json.loads(certificate.decode("utf-8"))
    assert base64.b64decode(decoded["evidence_payloads"][request["evidence_ref"]]) == evidence
    assert replay_module.recheck_receipt_validation_replay_certificate(
        bytes(certificate), expected_request=json.loads(json.dumps(request)),
        policy=json.loads(json.dumps(policy)))["status"] == "PASS"


def test_declared_independence_basis_is_excluded_not_replayed():
    basis = IndependenceBasis(actor_independence=IndependenceStatus.DECLARED,
                              evidence=("separate operator log",))
    request, policy, evidence = selected(canonical(receipt_row(basis=basis)))
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "PASS"
    assert result["independence_basis_replay"] == "NOT_ESTABLISHED"


def _flip_overall(row):
    row["independent_audit"]["overall_verdict"] = "INDETERMINATE"


def _altered_formula(row):
    row["evidence"]["clauses"] = [[1], [-1]]
    assert not brute_force_satisfiable(1, row["evidence"]["clauses"])


def _decisions(row):
    row["independent_audit"]["sat_result"]["decisions_count"] += 5


def _claim_id(row):
    row["independent_audit"]["claim_id"] = "claim-other"


def _grounding(row):
    row["independent_audit"]["grounding_result"]["grounding_status"] = "ASSUMED"


def _foreign_checker(row):
    row["independent_audit"]["trusted_computing_base"]["implementation_hash"] = (
        "sha256:" + "c" * 64)


@pytest.mark.parametrize("mutate,reason", [
    (_flip_overall, "overall_verdict"),
    (_altered_formula, "sat_result"),
    (_decisions, "sat_result"),
    (_claim_id, "claim_id"),
    (_grounding, "grounding_result"),
    (_foreign_checker, "trusted_computing_base"),
], ids=["overall-verdict", "altered-formula", "decision-count", "claim-id",
        "grounding-status", "foreign-checker"])
def test_refuting_audit_mutants_fail_at_their_own_field(mutate, reason):
    row = receipt_row()
    mutate(row)
    request, policy, evidence = selected(canonical(redigest(row)))
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL", result["evaluation"]["details"]
    assert reason in result["evaluation"]["details"]
    assert result["receipt_validation_replay"] == "NOT_ESTABLISHED"


def test_externally_selected_expectation_mismatch_fails():
    request, policy, evidence = selected(canonical(receipt_row()), expected=False)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "sat_result" in result["evaluation"]["details"]


def test_statics_failure_is_replay_failure():
    row = receipt_row()
    row["target_result"]["satisfiable"] = False
    request, policy, evidence = selected(canonical(row))
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "canonical_digest" in result["evaluation"]["details"]


@pytest.mark.parametrize("limits,clauses,n_vars", [
    ({"max_search_steps": 8}, ((1,),), 1),
    ({"max_sat_variables": 2}, ((1, 2, 3),), 3),
    ({"max_operations": 8}, ((1,),), 1),
], ids=["search-steps", "sat-variables", "operations"])
def test_exhausted_budget_is_unknown(limits, clauses, n_vars):
    row = receipt_row(clauses=clauses, n_vars=n_vars)
    request, policy, evidence = selected(canonical(row), limits=limits)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN", result["evaluation"]["details"]
    assert result["receipt_validation_replay"] == "NOT_ESTABLISHED"


def test_missing_evidence_is_unknown():
    request, policy, _ = selected(canonical(receipt_row()))
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_installed_checker_without_its_bound_hashes_is_unknown(monkeypatch):
    request, policy, evidence = selected(canonical(receipt_row()))
    installed = IndependentAuditor.tcb()

    def unavailable(cls):
        return {**installed, "specification_hash": checker.UNAVAILABLE_PREFIX + "standard/VSTD-1.md"}

    monkeypatch.setattr(IndependentAuditor, "tcb", classmethod(unavailable))
    result = replay_module.recheck_receipt_validation_replay_certificate(
        replay_module.build_receipt_validation_replay_certificate(
            request, evidence, policy=policy), expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN"


def test_one_bit_certificate_tamper_raises():
    request, policy, evidence = selected(canonical(receipt_row()))
    certificate, _ = replay(request, policy, evidence)
    index = certificate.index(b'"status":"PASS"') + len(b'"status":"')
    tampered = bytearray(certificate)
    tampered[index] ^= 0x01
    with pytest.raises(replay_module.ReceiptValidationReplayError):
        replay_module.recheck_receipt_validation_replay_certificate(
            bytes(tampered), expected_request=request, policy=policy)


def test_wrong_subject_and_substituted_request_or_policy_are_refused():
    receipt = canonical(receipt_row())
    request, policy, evidence = selected(receipt)
    certificate, _ = replay(request, policy, evidence)
    other_request, _, _ = selected(receipt, subject="receipt-b")
    flipped_request, _, _ = selected(receipt, expected=False)
    for substituted in (other_request, flipped_request):
        with pytest.raises(replay_module.ReceiptValidationReplayError):
            replay_module.recheck_receipt_validation_replay_certificate(
                certificate, expected_request=substituted, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(replay_module.ReceiptValidationReplayError):
        replay_module.recheck_receipt_validation_replay_certificate(
            certificate, expected_request=request, policy=other_policy)
    wrong_subject = deepcopy(request)
    wrong_subject["subject_id"] = "receipt-b"
    assert replay(wrong_subject, policy, evidence)[1]["status"] == "FAIL"
    with pytest.raises(replay_module.ReceiptValidationReplayError):
        replay_module.receipt_validation_replay_request(
            subject_id="receipt-a", object_digest=request["object_digest"],
            expected_satisfiable=1, evidence_ref=request["evidence_ref"], policy=policy)


def test_public_route_reaches_pass():
    request, policy, evidence = selected(canonical(receipt_row()))
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=replay_module.SEMANTIC_VERSION,
        objective=replay_module.COORDINATE, represented_kind="RECEIPT",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["claim_truth"] == "NOT_ESTABLISHED"


def test_retained_replay_certificate_refuses_evidence_redaction():
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
    "domains/contracts/receipt_validation_replay.py",
    "standard/CURRENT_RECEIPT_VALIDATION_REPLAY.md",
    "domains/contracts/receipt_statics.py",
    "core/checker.py",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected(canonical(receipt_row()))
    certificate, _ = replay(request, policy, evidence)
    target = Path(replay_module.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        replay_module.recheck_receipt_validation_replay_certificate(
            certificate, expected_request=request, policy=policy)
