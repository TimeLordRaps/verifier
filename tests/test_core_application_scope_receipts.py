from __future__ import annotations

import copy
import dataclasses

import pytest

pytest.importorskip(
    "cryptography",
    reason=(
        "OPTIONAL_DEPENDENCY_ABSENT: core application authority receipts use "
        "Ed25519 and require the seal extra (cryptography)"
    ),
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifier.runtime import core_application_authority as binding

import test_application_authority_binding as owner


H = "sha256:" + "a" * 64
NOW = 1_800_000_000


def _signed(payload, *, key_id, private_key):
    raw = binding.canonical_bytes(payload)
    return {
        "schema_version": binding.AUTHORITY_SIGNATURE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "payload": payload,
        "payload_digest": binding.bytes_digest(raw),
        "signature": private_key.sign(
            binding.authority_signing_bytes(raw, key_id=key_id)).hex(),
    }


def _selection(operation, subject_digest, *, execution_status="COMPLETED",
               evidence_state="CURRENT", mutate_receipt=None):
    voter_a = Ed25519PrivateKey.generate()
    voter_b = Ed25519PrivateKey.generate()
    status = Ed25519PrivateKey.generate()
    keys = {
        "voter-a": ("reviewer-a", voter_a),
        "voter-b": ("reviewer-b", voter_b),
        "status": ("status-operator", status),
    }
    public_rows = []
    for key_id, (actor_id, private) in keys.items():
        public_rows.append({
            "key_id": key_id,
            "actor_id": actor_id,
            "public_key": private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ).hex(),
        })
    mechanism = binding.qualified_authority_mechanism_digest(operation)
    operation_revision = "sha256:" + "1" * 64
    instruction_revision = "sha256:" + "2" * 64
    context_revision = "sha256:" + "3" * 64
    policy = {
        "schema_version": binding.AUTHORITY_POLICY_SCHEMA,
        "mechanism_digest": mechanism,
        "policy_id": "selected-core-authority",
        "revision": 7,
        "operation": operation,
        "operation_revision_digest": operation_revision,
        "instruction_revision_digest": instruction_revision,
        "context_revision_digest": context_revision,
        "keys": public_rows,
        "approval_key_ids": ["voter-a", "voter-b"],
        "status_key_id": "status",
        "quorum": 2,
        "effective_from": NOW - 100,
        "effective_until": NOW + 100,
        "max_status_age_seconds": 20,
    }
    policy_bytes = binding.canonical_bytes(policy)
    policy_digest = binding.bytes_digest(policy_bytes)
    body = {
        "schema_version": binding.AUTHORITY_RECEIPT_SCHEMA,
        "mechanism_digest": mechanism,
        "receipt_id": "receipt-" + operation.lower(),
        "requester_id": "candidate-producer",
        "policy_digest": policy_digest,
        "operation": operation,
        "operation_revision_digest": operation_revision,
        "instruction_revision_digest": instruction_revision,
        "context_revision_digest": context_revision,
        "subject_digest": subject_digest,
        "decision": "ADMIT",
        "execution_status": execution_status,
        "evidence_state": evidence_state,
        "issued_at": NOW - 10,
        "expires_at": NOW + 50,
    }
    receipt_body_digest = binding.value_digest(body)
    approvals = []
    for index, key_id in enumerate(("voter-a", "voter-b"), 1):
        actor_id, private = keys[key_id]
        approvals.append(_signed({
            "schema_version": binding.AUTHORITY_APPROVAL_SCHEMA,
            "approval_id": f"approval-{index}",
            "actor_id": actor_id,
            "receipt_body_digest": receipt_body_digest,
            "decision": "APPROVE",
            "issued_at": NOW - 10,
            "expires_at": NOW + 50,
        }, key_id=key_id, private_key=private))
    status_payload = {
        "schema_version": binding.AUTHORITY_STATUS_SCHEMA,
        "policy_digest": policy_digest,
        "receipt_id": body["receipt_id"],
        "sequence": 11,
        "observed_at": NOW - 5,
        "expires_at": NOW + 20,
        "revoked_approval_ids": [],
        "revoked_actor_ids": [],
    }
    receipt = {**body, "approvals": approvals,
               "status": _signed(status_payload, key_id="status", private_key=status)}
    if mutate_receipt is not None:
        mutate_receipt(receipt)
    receipt_bytes = binding.canonical_bytes(receipt)
    return binding.QualifiedAuthorityReplaySelection(
        policy_bytes=policy_bytes,
        expected_policy_digest=policy_digest,
        receipt_bytes=receipt_bytes,
        expected_receipt_digest=binding.bytes_digest(receipt_bytes),
        expected_mechanism_digest=mechanism,
        expected_operation=operation,
        expected_operation_revision_digest=operation_revision,
        expected_instruction_revision_digest=instruction_revision,
        expected_context_revision_digest=context_revision,
        expected_subject_digest=subject_digest,
        evaluation_time=NOW,
        minimum_status_sequence=10,
    )


def _with_scope(inputs, selection):
    host = inputs["host_selection"]
    inputs["host_selection"] = dataclasses.replace(
        host,
        scope_admission_receipt_bytes=selection.receipt_bytes,
        expected_scope_admission_receipt_digest=selection.expected_receipt_digest,
        scope_admission_replay=selection,
    )


def _semantic_subject(inputs, scope_selection):
    host = inputs["host_selection"]
    compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
    return binding.semantic_completeness_subject(
        profile_digest=host.expected_profile_digest,
        requirements_digest=binding.bytes_digest(inputs["requirements_bytes"]),
        union_authority_digest=host.expected_union_authority_digest,
        union_contributions_digest=host.expected_union_contributions_digest,
        compiler_manifest_digest=binding.bytes_digest(inputs["compiler_manifest_bytes"]),
        scope_admission_subject_digest=compiler["scope_admission"]["admission_subject_digest"],
        scope_admission_receipt_digest=scope_selection.expected_receipt_digest,
        consumer_source_coordinate_digest=host.expected_consumer_source_coordinate_digest,
        application_mechanism_digest=host.expected_application_mechanism_digest,
        compiler_mechanism_digest=host.expected_compiler_mechanism_digest,
        union_validator_digest=host.expected_union_validator_digest,
    )


def test_installed_scope_replay_establishes_only_selected_authority():
    inputs, *_ = owner.fixture()
    compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
    scope = _selection(binding.SCOPE_OPERATION,
                       compiler["scope_admission"]["admission_subject_digest"])
    _with_scope(inputs, scope)

    report = binding.assess_application_authority_binding(**inputs)

    assert report["binding_status"] == "PASS"
    assert report["authority_status"] == "PASS"
    assert report["scope_admission_replay"]["status"] == "PASS"
    assert report["semantic_completeness"] == "UNKNOWN"
    assert report["status"] == "UNKNOWN"
    assert report["release_authorized"] is False


def test_distinct_source_selected_semantic_replay_can_close_only_that_field():
    inputs, *_ = owner.fixture()
    compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
    scope = _selection(binding.SCOPE_OPERATION,
                       compiler["scope_admission"]["admission_subject_digest"])
    _with_scope(inputs, scope)
    semantic_subject = _semantic_subject(inputs, scope)
    semantic = _selection(binding.SEMANTIC_COMPLETENESS_OPERATION,
                          binding.value_digest(semantic_subject))
    inputs["host_selection"] = dataclasses.replace(
        inputs["host_selection"], semantic_completeness_replay=semantic)

    report = binding.assess_application_authority_binding(**inputs)

    assert report["authority_status"] == "PASS"
    assert report["semantic_completeness"] == "PASS"
    assert report["semantic_completeness_replay"]["status"] == "PASS"
    assert report["status"] == "UNKNOWN"
    assert report["full_application_status"] == "UNKNOWN"
    assert report["release_authorized"] is False
    assert "CHILD_REQUIREMENTS_UNKNOWN" in report["blockers"]


def test_cancelled_and_carried_receipts_never_grant_authority():
    for field, value in (("execution_status", "CANCELLED"),
                         ("evidence_state", "CARRIED")):
        inputs, *_ = owner.fixture()
        compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
        kwargs = {field: value}
        scope = _selection(binding.SCOPE_OPERATION,
                           compiler["scope_admission"]["admission_subject_digest"], **kwargs)
        _with_scope(inputs, scope)
        report = binding.assess_application_authority_binding(**inputs)
        assert report["binding_status"] == "PASS"
        assert report["authority_status"] == "UNKNOWN"
        assert report["scope_admission_replay"]["status"] == "UNKNOWN"
        assert report["release_authorized"] is False


def test_substituted_subject_and_revision_are_refused_not_downgraded():
    for selected_field in (
            "expected_subject_digest",
            "expected_operation_revision_digest",
            "expected_instruction_revision_digest",
            "expected_context_revision_digest"):
        inputs, *_ = owner.fixture()
        compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
        scope = _selection(binding.SCOPE_OPERATION,
                           compiler["scope_admission"]["admission_subject_digest"])
        scope = dataclasses.replace(scope, **{selected_field: H})
        _with_scope(inputs, scope)
        report = binding.assess_application_authority_binding(**inputs)
        assert report["status"] == "FAIL", selected_field
        assert report["authority_status"] == "FAIL", selected_field
        assert report["release_authorized"] is False


def test_post_signature_receipt_substitution_is_refused():
    inputs, *_ = owner.fixture()
    compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
    scope = _selection(binding.SCOPE_OPERATION,
                       compiler["scope_admission"]["admission_subject_digest"])
    receipt = binding._decode(scope.receipt_bytes, "test")
    receipt["decision"] = "DENY"
    substituted = binding.canonical_bytes(receipt)
    scope = dataclasses.replace(
        scope,
        receipt_bytes=substituted,
        expected_receipt_digest=binding.bytes_digest(substituted),
    )
    _with_scope(inputs, scope)

    report = binding.assess_application_authority_binding(**inputs)

    assert report["status"] == "FAIL"
    assert report["authority_status"] == "FAIL"
    assert "AUTHORITY_RECEIPT_SIGNATURE_REFUSED" in report["blockers"]


def test_scope_receipt_cannot_be_cast_as_semantic_completeness():
    inputs, *_ = owner.fixture()
    compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
    scope = _selection(binding.SCOPE_OPERATION,
                       compiler["scope_admission"]["admission_subject_digest"])
    _with_scope(inputs, scope)
    inputs["host_selection"] = dataclasses.replace(
        inputs["host_selection"], semantic_completeness_replay=scope)

    report = binding.assess_application_authority_binding(**inputs)

    assert report["status"] == "FAIL"
    assert report["semantic_completeness"] == "FAIL"
    assert "SEMANTIC_COMPLETENESS_OPERATION_DIFFERS" in report["blockers"]


def test_stale_status_and_revoked_approval_do_not_establish_receipt():
    inputs, *_ = owner.fixture()
    compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
    subject = compiler["scope_admission"]["admission_subject_digest"]
    scope = _selection(binding.SCOPE_OPERATION, subject)
    stale = dataclasses.replace(scope, evaluation_time=NOW + 25)
    _with_scope(inputs, stale)
    report = binding.assess_application_authority_binding(**inputs)
    assert report["authority_status"] == "UNKNOWN"
    assert "AUTHORITY_STATUS_NOT_CURRENT" in report["blockers"]

    def revoke(receipt):
        # Changing a signed status payload without resigning is a forgery, not UNKNOWN.
        receipt["status"]["payload"]["revoked_approval_ids"] = ["approval-1"]

    inputs, *_ = owner.fixture()
    compiler = binding._decode(inputs["compiler_manifest_bytes"], "test")
    forged = _selection(binding.SCOPE_OPERATION,
                        compiler["scope_admission"]["admission_subject_digest"],
                        mutate_receipt=revoke)
    _with_scope(inputs, forged)
    report = binding.assess_application_authority_binding(**inputs)
    assert report["status"] == "FAIL"
    assert "AUTHORITY_RECEIPT_SIGNATURE_REFUSED" in report["blockers"]
