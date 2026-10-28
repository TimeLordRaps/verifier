from __future__ import annotations

import dataclasses

import pytest

pytest.importorskip(
    "cryptography",
    reason=(
        "OPTIONAL_DEPENDENCY_ABSENT: estate authority receipts use Ed25519 "
        "and require the seal extra (cryptography)"
    ),
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifier.runtime import core_application_authority as binding
from verifier.runtime import self_polish_estate_authority as authority


NOW = 1_800_000_000


def _subject(**changes: str) -> dict:
    names = (
        "source_coordinate_digest",
        "estate_source_coordinate_digest",
        "candidate_source_census_digest",
        "estate_digest",
        "candidate_universe_digest",
        "required_categories_digest",
        "category_summaries_digest",
        "applicability_ledger_digest",
        "installed_inventory_digest",
        "objective_catalog_digest",
        "structural_route_crosswalk_digest",
        "structural_identity_digest",
        "route_identity_digest",
        "shared_identity_digest",
    )
    values = {
        name: "sha256:" + f"{index:064x}"
        for index, name in enumerate(names, 1)
    }
    values.update(changes)
    return authority.estate_authority_subject(**values)


def _signed(payload: dict, *, key_id: str,
        private_key: Ed25519PrivateKey) -> dict:
    raw = binding.canonical_bytes(payload)
    return {
        "schema_version": binding.AUTHORITY_SIGNATURE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "payload": payload,
        "payload_digest": binding.bytes_digest(raw),
        "signature": private_key.sign(
            binding.authority_signing_bytes(raw, key_id=key_id)
        ).hex(),
    }


def _selection(subject_digest: str, *, approval_count: int = 2,
        revoked: bool = False,
        execution_status: str = "COMPLETED",
        evidence_state: str = "CURRENT",
        evaluation_time: int = NOW,
        mutate_receipt=None,
        ) -> binding.QualifiedAuthorityReplaySelection:
    voter_a = Ed25519PrivateKey.generate()
    voter_b = Ed25519PrivateKey.generate()
    status_key = Ed25519PrivateKey.generate()
    keys = {
        "voter-a": ("reviewer-a", voter_a),
        "voter-b": ("reviewer-b", voter_b),
        "status": ("status-operator", status_key),
    }
    public_rows = [{
        "key_id": key_id,
        "actor_id": actor_id,
        "public_key": private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex(),
    } for key_id, (actor_id, private) in keys.items()]
    mechanism = binding.qualified_authority_mechanism_digest(
        authority.OPERATION
    )
    operation_revision = "sha256:" + "a" * 64
    instruction_revision = "sha256:" + "b" * 64
    context_revision = "sha256:" + "c" * 64
    policy = {
        "schema_version": binding.AUTHORITY_POLICY_SCHEMA,
        "mechanism_digest": mechanism,
        "policy_id": "selected-estate-authority",
        "revision": 1,
        "operation": authority.OPERATION,
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
        "receipt_id": "estate-authority-receipt",
        "requester_id": "candidate-producer",
        "policy_digest": policy_digest,
        "operation": authority.OPERATION,
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
    body_digest = binding.value_digest(body)
    approvals = []
    for index, key_id in enumerate(("voter-a", "voter-b")[:approval_count], 1):
        actor_id, private = keys[key_id]
        approvals.append(_signed({
            "schema_version": binding.AUTHORITY_APPROVAL_SCHEMA,
            "approval_id": f"approval-{index}",
            "actor_id": actor_id,
            "receipt_body_digest": body_digest,
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
        "revoked_approval_ids": ["approval-1"] if revoked else [],
        "revoked_actor_ids": [],
    }
    receipt = {
        **body,
        "approvals": approvals,
        "status": _signed(
            status_payload, key_id="status", private_key=status_key
        ),
    }
    if mutate_receipt is not None:
        mutate_receipt(receipt)
    receipt_bytes = binding.canonical_bytes(receipt)
    return binding.QualifiedAuthorityReplaySelection(
        policy_bytes=policy_bytes,
        expected_policy_digest=policy_digest,
        receipt_bytes=receipt_bytes,
        expected_receipt_digest=binding.bytes_digest(receipt_bytes),
        expected_mechanism_digest=mechanism,
        expected_operation=authority.OPERATION,
        expected_operation_revision_digest=operation_revision,
        expected_instruction_revision_digest=instruction_revision,
        expected_context_revision_digest=context_revision,
        expected_subject_digest=subject_digest,
        evaluation_time=evaluation_time,
        minimum_status_sequence=10,
    )


def test_subject_binds_every_estate_selection_digest() -> None:
    baseline = _subject()
    baseline_digest = binding.value_digest(baseline)

    for index, field in enumerate(authority._SUBJECT_DIGEST_FIELDS[1:], 100):
        changed = _subject(**{field: "sha256:" + f"{index:064x}"})
        assert binding.value_digest(changed) != baseline_digest


def test_missing_receipt_remains_unknown() -> None:
    report = authority.replay_estate_authority(
        _subject(), authority_replay=None
    )

    assert report["status"] == "UNKNOWN"
    assert report["independent_authority_status"] == "NOT_ESTABLISHED"
    assert report["semantic_applicability_status"] == "NOT_ESTABLISHED"
    assert report["per_candidate_evidence_status"] == "NOT_ESTABLISHED"
    assert report["full_estate_closure"] == "NOT_ESTABLISHED"
    assert report["blockers"] == ["ESTATE_AUTHORITY_RECEIPT_UNAVAILABLE"]


def test_valid_independent_authority_does_not_promote_semantic_closure() -> None:
    subject = _subject()
    selection = _selection(binding.value_digest(subject))

    report = authority.replay_estate_authority(
        subject, authority_replay=selection
    )

    assert report["status"] == "PASS"
    assert report["replay_status"] == "REPRODUCED"
    assert report["independent_authority_status"] == "PASS"
    assert report["approving_actors"] == ["reviewer-a", "reviewer-b"]
    assert report["semantic_applicability_status"] == "NOT_ESTABLISHED"
    assert report["per_candidate_evidence_status"] == "NOT_ESTABLISHED"
    assert report["full_estate_closure"] == "NOT_ESTABLISHED"
    assert report["blockers"] == []


@pytest.mark.parametrize(
    ("selection_change", "expected_blocker"),
    [
        ({"expected_subject_digest": "sha256:" + "f" * 64},
         "AUTHORITY_SUBJECT_DIFFERS"),
        ({"expected_mechanism_digest": "sha256:" + "e" * 64},
         "AUTHORITY_MECHANISM_DIFFERS"),
        ({"expected_receipt_digest": "sha256:" + "d" * 64},
         "AUTHORITY_RECEIPT_DIGEST_DIFFERS"),
    ],
)
def test_substituted_pins_are_definite_failures(
        selection_change: dict, expected_blocker: str) -> None:
    subject = _subject()
    selection = dataclasses.replace(
        _selection(binding.value_digest(subject)), **selection_change
    )

    report = authority.replay_estate_authority(
        subject, authority_replay=selection
    )

    assert report["status"] == "FAIL"
    assert report["independent_authority_status"] == "FAIL"
    assert report["replay_status"] == "REJECTED"
    assert expected_blocker in report["blockers"]


@pytest.mark.parametrize(
    ("selection_kwargs", "blocker"),
    [
        ({"approval_count": 1}, "AUTHORITY_QUORUM_NOT_ESTABLISHED"),
        ({"revoked": True}, "AUTHORITY_APPROVAL_REVOKED"),
        ({"execution_status": "UNKNOWN"},
         "AUTHORITY_EXECUTION_NOT_COMPLETED"),
        ({"evidence_state": "CARRIED"}, "AUTHORITY_EVIDENCE_NOT_CURRENT"),
        ({"evaluation_time": NOW + 25}, "AUTHORITY_STATUS_NOT_CURRENT"),
    ],
)
def test_insufficient_or_refuted_authority_is_a_definite_failure(
        selection_kwargs: dict, blocker: str) -> None:
    subject = _subject()
    selection = _selection(binding.value_digest(subject), **selection_kwargs)

    report = authority.replay_estate_authority(
        subject, authority_replay=selection
    )

    assert report["status"] == "FAIL"
    assert report["independent_authority_status"] == "FAIL"
    assert report["replay_status"] == "REJECTED"
    assert blocker in report["blockers"]
    assert report["semantic_applicability_status"] == "NOT_ESTABLISHED"
    assert report["full_estate_closure"] == "NOT_ESTABLISHED"


def test_mutated_signed_receipt_is_rejected() -> None:
    subject = _subject()

    def mutate(receipt: dict) -> None:
        receipt["approvals"][0]["payload"]["actor_id"] = "substitute"

    selection = _selection(
        binding.value_digest(subject), mutate_receipt=mutate
    )
    report = authority.replay_estate_authority(
        subject, authority_replay=selection
    )

    assert report["status"] == "FAIL"
    assert report["independent_authority_status"] == "FAIL"
    assert "AUTHORITY_RECEIPT_SIGNATURE_REFUSED" in report["blockers"]


def test_malformed_subject_is_rejected_without_replay() -> None:
    subject = _subject()
    subject["candidate_universe_digest"] = "not-a-digest"

    report = authority.replay_estate_authority(
        subject, authority_replay=None
    )

    assert report["status"] == "FAIL"
    assert report["independent_authority_status"] == "FAIL"
    assert report["blockers"] == ["ESTATE_AUTHORITY_SUBJECT_REJECTED"]
