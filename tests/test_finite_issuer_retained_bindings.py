"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

real finite receipts, pure bindings and cancellation controls.
"""
from __future__ import annotations

import asyncio
import base64
from copy import deepcopy
from dataclasses import replace
import json
import sqlite3

import pytest
from verifier.core.certificate import canonical_bytes
from verifier.runtime import finite_record_issuance as issuer, polish_invocation_ledger as ledger
from verifier.runtime import polish_public_authority as authority
from finite_record_fixture import FinitePackage, digest


@pytest.fixture
def finite(tmp_path):
    value = FinitePackage(tmp_path)
    value.authorize()
    return value


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def retained_body_digest(record):
    record.pop("assessment_digest", None)
    record["assessment_digest"] = digest(canonical_bytes(record))
    return record


def primitive_receipt(finite, invocation, instant):
    result = ledger.commit_issuance(finite.proposal, expected_proposal_digest=digest(finite.proposal),
        invocation_id=invocation, authority_status_digest=finite.ready["authority_status_digest"],
        commit_time=instant, selection=finite.ledger)
    assert result["status"] == "PASS" and result["polished"] is False
    finite.public.time = instant  # Current signed postcommit observation, not action time.
    finite.postcommit(result)
    return result


@pytest.mark.parametrize("mutation", ["invocation", "time", "both"])
def test_actual_other_invocation_or_time_receipt_cannot_issue_authorized_action(finite, mutation):
    receipt = primitive_receipt(finite, "fixture:other" if mutation != "time" else "fixture:one",
        110 if mutation != "invocation" else 100)
    result = issuer.finalize_finite_record_issuance(finite.proposal, **finite.final_selection(receipt))
    assert result["status"] == "FAIL" and result["polished"] is False
    assert result["full_application_status"] == "UNKNOWN"
    with sqlite3.connect(finite.ledger.path) as connection:
        rows = connection.execute("SELECT invocation_id, commit_time FROM issuance").fetchall()
    assert rows == [(receipt["invocation_id"], receipt["commit_time"])]
    if mutation != "time":
        assert all(invocation != finite.ready["subject"]["invocation_id"] for invocation, _ in rows)


@pytest.mark.parametrize("later_loss", ["source", "ledger", "postcommit", "bundle"])
def test_actual_wrong_receipt_tuple_refuses_before_later_unavailability(finite, monkeypatch, later_loss):
    receipt = primitive_receipt(finite, "fixture:other", 100)
    selection = finite.final_selection(receipt)
    calls = []
    def absent(*args, **kwargs):
        calls.append(True)
        raise OSError("negative-only later unavailable mechanism")
    if later_loss == "source":
        monkeypatch.setattr(issuer, "mechanism_digest", absent)
    elif later_loss == "ledger":
        monkeypatch.setattr(ledger, "recheck_issuance_commit", absent)
    else:
        selection["public_commit_bytes" if later_loss == "postcommit" else "bundle_bytes"] = None
    result = issuer.finalize_finite_record_issuance(finite.proposal, **selection)
    assert result["status"] == "FAIL" and calls == []


def selected_inputs(finite, docs=None, action=None):
    docs = dict(finite.docs if docs is None else docs)
    policy, request = deepcopy(finite.policy), json.loads(finite.request)
    if action is not None:
        policy["action"] = request["action"] = action
    policy["input_digests"] = {name: digest(raw) for name, raw in docs.items()}
    bundle = json.loads(finite.bundle)
    bundle["documents"] = [{"name": name, "base64": b64(raw)} for name, raw in sorted(docs.items())]
    bundle_bytes, policy_bytes = canonical_bytes(bundle), canonical_bytes(policy)
    request["bundle_digest"], request["host_policy_digest"] = digest(bundle_bytes), digest(policy_bytes)
    declared_authority = deepcopy(finite.authority_policy)
    declared_authority["scopes"] = [{name: request["action"][name] for name in authority._SCOPE_FIELDS}]
    authority_bytes = canonical_bytes(declared_authority)
    host = replace(finite.host, policy_bytes=policy_bytes, expected_policy_digest=digest(policy_bytes),
        authority_policy_bytes=authority_bytes, expected_authority_policy_digest=digest(authority_bytes))
    return bundle_bytes, canonical_bytes(request), host


@pytest.mark.parametrize("mutation", ["public_native_bundle", "public_native_policy", "public_certificate", "profile", "source", "collection"])
@pytest.mark.parametrize("loss", ["source", "cancel", "missing_host"])
def test_bounded_declared_tuple_refutations_precede_source_availability(finite, monkeypatch, mutation, loss):
    docs, action = dict(finite.docs), dict(finite.action)
    if mutation.startswith("public_"):
        carried = json.loads(docs["public_bundle"])
        if mutation == "public_native_bundle":
            alternate = json.loads(docs["native_bundle"])
            alternate["objects"][0]["payload"] = {"known": "different"}
            carried["dependency_bundle_base64"] = b64(canonical_bytes(alternate))
        elif mutation == "public_native_policy":
            alternate = json.loads(docs["native_policy"])
            alternate["required_roots"] = []
            carried["dependency_policy_base64"] = b64(canonical_bytes(alternate))
        else:
            carried["artifact_files"][0]["base64"] = b64(b'{"known":"different"}')
        docs["public_bundle"] = canonical_bytes(carried)
    else:
        action[{"profile": "profile_digest", "source": "source_scope_digest", "collection": "collection_digest"}[mutation]] = digest(b"known-other-binding")
    bundle, request, host = selected_inputs(finite, docs, action)
    calls = []
    def absent():
        calls.append(True)
        if loss == "cancel":
            raise asyncio.CancelledError("negative-only cancelled source")
        raise OSError("negative-only absent source")
    monkeypatch.setattr(issuer, "mechanism_digest", absent)
    result = issuer.assess_finite_record_issuance(bundle, request_bytes=request,
        issue_evidence_bytes=canonical_bytes(finite.evidence), host_selection=None if loss == "missing_host" else host,
        evaluation_time=100)
    assert result["status"] == "FAIL" and calls == []
    assert result["polished"] is False and result["full_application_status"] == "UNKNOWN"


def test_clean_absence_and_full_mode_remain_unknown_without_positive_credit(finite, monkeypatch):
    def absent():
        raise OSError("negative-only missing source")
    monkeypatch.setattr(issuer, "mechanism_digest", absent)
    for host in (finite.host, None):
        result = issuer.assess_finite_record_issuance(finite.bundle, request_bytes=finite.request,
            issue_evidence_bytes=canonical_bytes(finite.evidence), host_selection=host, evaluation_time=100)
        assert result["status"] == "UNKNOWN" and result["polished"] is False
    policy, request = deepcopy(finite.policy), json.loads(finite.request)
    policy["mode"] = request["mode"] = issuer.FULL
    raw = canonical_bytes(policy)
    host = replace(finite.host, policy_bytes=raw, expected_policy_digest=digest(raw))
    request["host_policy_digest"] = digest(raw)
    result = issuer.assess_finite_record_issuance(finite.bundle, request_bytes=canonical_bytes(request),
        issue_evidence_bytes=canonical_bytes(finite.evidence), host_selection=host, evaluation_time=100)
    assert result["status"] == "UNKNOWN" and result["full_application_status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["shape", "roles", "scope", "time", "postcommit_role"])
def test_present_selected_authority_policy_refusal_precedes_finite_source_loss(finite, monkeypatch, mutation):
    declared_authority, policy, request = deepcopy(finite.authority_policy), deepcopy(finite.policy), json.loads(finite.request)
    if mutation == "shape":
        declared_authority["unexpected"] = True
    elif mutation == "roles":
        declared_authority["status_key_id"] = "a"
    elif mutation == "scope":
        declared_authority["scopes"][0]["jurisdiction"] = "different:jurisdiction"
    elif mutation == "time":
        declared_authority["effective_until"] = 99
    else:
        policy["postcommit_key_id"] = "a"
    authority_bytes, policy_bytes = canonical_bytes(declared_authority), canonical_bytes(policy)
    host = replace(finite.host, authority_policy_bytes=authority_bytes, expected_authority_policy_digest=digest(authority_bytes),
        policy_bytes=policy_bytes, expected_policy_digest=digest(policy_bytes))
    request["host_policy_digest"] = digest(policy_bytes)
    calls = []
    def absent():
        calls.append(True)
        raise OSError("negative-only finite source absent")
    monkeypatch.setattr(issuer, "mechanism_digest", absent)
    result = issuer.assess_finite_record_issuance(finite.bundle, request_bytes=canonical_bytes(request),
        issue_evidence_bytes=canonical_bytes(finite.evidence), host_selection=host, evaluation_time=100)
    assert result["status"] == "FAIL" and calls == []


def inconsistent_proposal(finite, mutation):
    ready = deepcopy(finite.ready)
    subject, context = ready["subject"], ready["authority_context"]
    if mutation in ("mechanism_digest", "native_assessment_digest", "public_assessment_digest", "host_policy_digest", "authority_policy_digest"):
        subject[mutation] = digest(b"known-different-nested-pin")
    elif mutation == "source_commitments":
        subject["source_commitments"]["source_tree_digest"] = digest(b"known-different-source")
    elif mutation == "context_action":
        context["purpose"] = "DIFFERENT_PURPOSE"
    elif mutation == "context_policy":
        context["policy_digest"] = digest(b"known-different-policy")
    elif mutation == "context_mechanism":
        context["mechanism_digest"] = digest(b"known-different-authority-mechanism")
    elif mutation == "clock":
        subject["timestamp"] = context["timestamp"] = 101
    else:
        subject["policy_epoch"] = context["policy_epoch"] = True
    context["subject_digest"] = digest(canonical_bytes(subject))
    return issuer.finite_precommit_proposal(retained_body_digest(ready))


@pytest.mark.parametrize("mutation", ["mechanism_digest", "native_assessment_digest", "public_assessment_digest",
    "host_policy_digest", "authority_policy_digest", "source_commitments", "context_action", "context_policy", "context_mechanism", "clock", "boolean_epoch"])
def test_rehashed_nested_ready_contradictions_refuse_before_source_or_missing_receipt(finite, monkeypatch, mutation):
    proposal = inconsistent_proposal(finite, mutation)
    calls = []
    def absent():
        calls.append(True)
        raise OSError("negative-only absent source")
    monkeypatch.setattr(issuer, "mechanism_digest", absent)
    committed = issuer.commit_finite_record_issuance(proposal, bundle_bytes=finite.bundle, request_bytes=finite.request,
        issue_evidence_bytes=canonical_bytes(finite.evidence), host_selection=finite.host, commit_time=100)
    final = issuer.finalize_finite_record_issuance(proposal, receipt_bytes=None, public_commit_bytes=None,
        bundle_bytes=finite.bundle, request_bytes=finite.request, issue_evidence_bytes=canonical_bytes(finite.evidence),
        host_selection=finite.host, evaluation_time=100)
    assert committed["status"] == final["status"] == "FAIL" and calls == []


@pytest.mark.parametrize("field", ["historical_evaluation_time", "subject_digest", "mechanism_digest", "host_policy_digest", "authority_policy_digest"])
def test_rehashed_attestation_proposal_contradictions_refuse_before_source_loss(finite, monkeypatch, field):
    receipt = finite.commit()["local_commit"]
    finite.postcommit(receipt)
    selection = finite.final_selection(receipt)
    final = issuer.finalize_finite_record_issuance(finite.proposal, **selection)
    assert final["status"] == "PASS" and final["polished"] is False
    changed = deepcopy(final)
    changed[field] = 101 if field == "historical_evaluation_time" else digest(b"known-other-attestation-pin")
    retained_body_digest(changed)
    calls = []
    def absent():
        calls.append(True)
        raise OSError("negative-only missing source")
    monkeypatch.setattr(issuer, "mechanism_digest", absent)
    replay = issuer.recheck_finite_record_issuance(canonical_bytes(changed), finite.proposal, **selection)
    assert replay["status"] == "FAIL" and replay["replay_status"] == "REJECTED" and calls == []


def test_finite_wrapper_keeps_cheap_authority_fail_through_backend_cancel(finite, monkeypatch):
    row = {**finite.evidence["decisions"][0]["payload"], "actor_id": "foreign:actor"}
    finite.evidence["decisions"][0] = finite.envelope(row, "a")
    def cancel(*args, **kwargs):
        raise asyncio.CancelledError("negative-only cancelled authority backend")
    monkeypatch.setattr(authority, "_authenticate", cancel)
    result = finite.assess()
    assert result["status"] == "FAIL" and "CONFIGURED_AUTHORITY_REFUSED" in result["checks"]
    assert result["replayable"] is False and result["polished"] is False


def test_finite_readonly_rechecker_capacity_cancel_is_unavailable(finite, monkeypatch):
    receipt = finite.commit()["local_commit"]
    finite.postcommit(receipt)
    selection = finite.final_selection(receipt)
    final = issuer.finalize_finite_record_issuance(finite.proposal, **selection)
    assert final["status"] == "PASS"
    retained = canonical_bytes(final)
    original = issuer._load
    def load(raw, cap=issuer.MAX_BYTES):
        if raw == retained:
            raise asyncio.CancelledError("negative-only cancelled retained decoder")
        return original(raw, cap)
    monkeypatch.setattr(issuer, "_load", load)
    replay = issuer.recheck_finite_record_issuance(retained, finite.proposal, **selection)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"


def test_finite_output_cancellation_preserves_observed_authority_refusal(finite, monkeypatch):
    row = {**finite.evidence["decisions"][0]["payload"], "actor_id": "foreign:actor"}
    finite.evidence["decisions"][0] = finite.envelope(row, "a")
    original = issuer.canonical_bytes
    def encode(value):
        if type(value) is dict and value.get("schema_version") == issuer.ASSESSMENT:
            raise asyncio.CancelledError("negative-only cancelled finite diagnostic formatter")
        return original(value)
    monkeypatch.setattr(issuer, "canonical_bytes", encode)
    result = finite.assess()
    assert result["status"] == "FAIL" and result["replayable"] is False and "assessment_digest" not in result
    assert result["polished"] is False and len(canonical_bytes(result)) <= issuer.MAX_BYTES
