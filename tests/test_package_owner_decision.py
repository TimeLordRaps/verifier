"""Configured-key package owner-decision admission tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import time

import pytest

from verifier.runtime import core_obligation_union
from verifier.runtime import package_owner_decision as owner


def _candidate_ledger() -> dict:
    decisions = [
        {
            "decision_id": f"CTC-{index}",
            "topic": f"cross-kind topic {index}",
            "scope": f"cross-kind scope {index}",
            "scope_basis": "INFERRED_IMPLEMENTER_MAPPING",
            "status": "NOT_ESTABLISHED",
        }
        for index in range(1, 7)
    ]
    kinds = [
        "ACTOR", "AGENT", "ARCH", "BENCH", "BOT", "COLLECTIVE", "DATA",
        "ENV", "EVENT", "GRAPH", "HARDWARE", "HARNESS", "HUMAN",
        "HYPER", "IDENTITY", "MODEL", "OBJECT", "OWNER", "RECEIPT",
        "ROLE", "SIM", "SPACE", "TIME", "TOKEN", "TRAIN", "VERIFIER",
    ]
    for kind in kinds:
        for index in range(1, 5):
            decisions.append({
                "decision_id": f"{kind}-Q{index}",
                "object_kind": kind,
                "question_digest": "sha256:" + f"{len(decisions):064x}",
                "scope_basis": "INFERRED_CANDIDATE_CARD_SCOPE",
                "status": "NOT_ESTABLISHED",
            })
    ledger = {
        "status": "PASS",
        "semantic_identity_status": "PASS",
        "owner_decision_count": 110,
        "owner_decisions": decisions,
    }
    ledger["selection_digest"] = core_obligation_union.value_digest(ledger)
    return ledger


def _write_selection(
        tmp_path: Path, *, now: int = 1_000,
        source_digest: str = "sha256:" + "d" * 64,
        ) -> tuple[Path, str, Path, str, dict, object]:
    cryptography = pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: cryptography (seal extra) is absent, so the Ed25519 owner-selection signing fixture _write_selection and every test that calls it stay unexecuted here; the platform-python-contracts workflow job installs the seal extra and runs the complete suite, including this file")
    assert cryptography.__version__ == "50.0.0"
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    ledger = _candidate_ledger()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    policy = {
        "schema_version": owner.POLICY_SCHEMA,
        "mechanism_digest": owner.mechanism_digest(),
        "policy_id": "tyler-package-owner-policy",
        "revision": 1,
        "owner_id": "tyler",
        "key_id": "tyler-owner-key-1",
        "public_key": public.hex(),
        "effective_from": now - 100,
        "effective_until": now + 100,
        "max_decision_age_seconds": 100,
    }
    policy_raw = core_obligation_union.canonical_bytes(policy)
    policy_path = tmp_path / "owner-policy.json"
    policy_path.write_bytes(policy_raw)
    decisions = owner.expected_owner_decisions(ledger)
    payload = {
        "schema_version": owner.PAYLOAD_SCHEMA,
        "policy_id": policy["policy_id"],
        "policy_revision": policy["revision"],
        "owner_id": policy["owner_id"],
        "candidate_selection_digest": ledger["selection_digest"],
        "source_coordinate_digest": source_digest,
        "decision_set_digest": core_obligation_union.value_digest(decisions),
        "decisions": decisions,
        "issued_at": now - 10,
        "valid_until": now + 10,
        "nonce": "owner-decision-fixture-1",
    }
    payload_raw = core_obligation_union.canonical_bytes(payload)
    envelope = {
        "schema_version": owner.ENVELOPE_SCHEMA,
        "algorithm": "Ed25519",
        "key_id": policy["key_id"],
        "payload": payload,
        "payload_digest": core_obligation_union.bytes_digest(payload_raw),
        "signature": private.sign(owner.decision_signing_bytes(
            payload_raw, key_id=policy["key_id"]
        )).hex(),
    }
    envelope_raw = core_obligation_union.canonical_bytes(envelope)
    envelope_path = tmp_path / "owner-decisions.json"
    envelope_path.write_bytes(envelope_raw)
    return (
        policy_path, core_obligation_union.bytes_digest(policy_raw),
        envelope_path, core_obligation_union.bytes_digest(envelope_raw), ledger,
        private,
    )


def test_exact_configured_key_owner_decisions_admit_all_110(
        tmp_path: Path) -> None:
    policy, policy_digest, decisions, decisions_digest, ledger, _private = (
        _write_selection(tmp_path)
    )

    result = owner.load_owner_decision_admission(
        ledger,
        source_coordinate_digest="sha256:" + "d" * 64,
        policy_path=policy,
        expected_policy_digest=policy_digest,
        decision_path=decisions,
        expected_decision_digest=decisions_digest,
        evaluation_time=1_000,
    )

    assert result["status"] == "PASS"
    assert result["owner_id"] == "tyler"
    assert result["decision_count"] == 110
    assert len(result["adopted_decision_ids"]) == 110
    assert result["candidate_selection_digest"] == ledger["selection_digest"]
    assert result["error"] is None


def test_owner_decision_selection_is_absent_not_inferred() -> None:
    result = owner.load_owner_decision_admission(
        _candidate_ledger(),
        source_coordinate_digest="sha256:" + "d" * 64,
        policy_path=None,
        expected_policy_digest=None,
        decision_path=None,
        expected_decision_digest=None,
        evaluation_time=1_000,
    )

    assert result["status"] == "NOT_SELECTED"
    assert result["decision_count"] == 0
    assert result["adopted_decision_ids"] == []


def test_candidate_selection_digest_is_recomputed() -> None:
    ledger = _candidate_ledger()
    ledger["selection_digest"] = "sha256:" + "0" * 64

    with pytest.raises(
        owner.OwnerDecisionError,
        match="PACKAGE_OWNER_CANDIDATE_SELECTION_DIGEST_DIFFERS",
    ):
        owner.expected_owner_decisions(ledger)


def test_candidate_owner_decision_id_set_is_exact() -> None:
    ledger = _candidate_ledger()
    ledger["owner_decisions"][0]["decision_id"] = "ATTACKER-Q1"
    ledger["selection_digest"] = core_obligation_union.value_digest({
        key: value for key, value in ledger.items()
        if key != "selection_digest"
    })

    with pytest.raises(
        owner.OwnerDecisionError,
        match="PACKAGE_OWNER_DECISION_DENOMINATOR_DIFFERS",
    ):
        owner.expected_owner_decisions(ledger)


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("signature", "PACKAGE_OWNER_DECISION_SIGNATURE_REFUSED"),
        ("source", "PACKAGE_OWNER_DECISION_SUBJECT_DIFFERS"),
        ("decision", "PACKAGE_OWNER_DECISION_SET_DIFFERS"),
        ("stale", "PACKAGE_OWNER_DECISION_NOT_CURRENT"),
    ],
)
def test_owner_decision_substitution_or_staleness_fails(
        tmp_path: Path, mutation: str, code: str) -> None:
    policy, policy_digest, decisions, _decisions_digest, ledger, private = (
        _write_selection(tmp_path)
    )
    envelope = json.loads(decisions.read_text(encoding="utf-8"))
    if mutation == "signature":
        envelope["signature"] = "00" * 64
    elif mutation == "source":
        envelope["payload"]["source_coordinate_digest"] = "sha256:" + "e" * 64
    elif mutation == "decision":
        selected = envelope["payload"]["decisions"][0]
        selected["disposition"] = (
            "ADOPT_PROPOSED_MAPPING"
            if selected["disposition"] == "ADOPT_PROPOSED_DEFAULT"
            else "ADOPT_PROPOSED_DEFAULT"
        )
    if mutation in ("source", "decision"):
        payload_raw = core_obligation_union.canonical_bytes(envelope["payload"])
        envelope["payload_digest"] = core_obligation_union.bytes_digest(
            payload_raw
        )
        envelope["signature"] = private.sign(owner.decision_signing_bytes(
            payload_raw, key_id=envelope["key_id"]
        )).hex()
    raw = core_obligation_union.canonical_bytes(envelope)
    decisions.write_bytes(raw)

    with pytest.raises(owner.OwnerDecisionError, match=code):
        owner.load_owner_decision_admission(
            ledger,
            source_coordinate_digest="sha256:" + "d" * 64,
            policy_path=policy,
            expected_policy_digest=policy_digest,
            decision_path=decisions,
            expected_decision_digest=core_obligation_union.bytes_digest(raw),
            evaluation_time=1_101 if mutation == "stale" else 1_000,
        )


def test_selected_unreadable_owner_decisions_remain_unavailable(
        tmp_path: Path) -> None:
    policy, policy_digest, _decisions, decisions_digest, ledger, _private = (
        _write_selection(tmp_path)
    )

    with pytest.raises(
        owner.OwnerDecisionUnavailable,
        match="PACKAGE_OWNER_DECISION_UNAVAILABLE",
    ):
        owner.load_owner_decision_admission(
            ledger,
            source_coordinate_digest="sha256:" + "d" * 64,
            policy_path=policy,
            expected_policy_digest=policy_digest,
            decision_path=tmp_path / "missing.json",
            expected_decision_digest=decisions_digest,
            evaluation_time=1_000,
        )


def test_maximum_decision_age_is_enforced_independently(
        tmp_path: Path) -> None:
    policy, _policy_digest, decisions, decisions_digest, ledger, _private = (
        _write_selection(tmp_path)
    )
    value = json.loads(policy.read_text(encoding="utf-8"))
    value["max_decision_age_seconds"] = 5
    raw = core_obligation_union.canonical_bytes(value)
    policy.write_bytes(raw)

    with pytest.raises(
        owner.OwnerDecisionError,
        match="PACKAGE_OWNER_DECISION_NOT_CURRENT",
    ):
        owner.load_owner_decision_admission(
            ledger,
            source_coordinate_digest="sha256:" + "d" * 64,
            policy_path=policy,
            expected_policy_digest=core_obligation_union.bytes_digest(raw),
            decision_path=decisions,
            expected_decision_digest=decisions_digest,
            evaluation_time=1_000,
        )


def test_authenticated_statement_with_unestablished_candidate_is_unknown(
        tmp_path: Path) -> None:
    policy, policy_digest, decisions, decisions_digest, ledger, _private = (
        _write_selection(tmp_path)
    )
    ledger = dict(ledger)
    ledger["status"] = "UNKNOWN"
    ledger["semantic_identity_status"] = "NOT_ESTABLISHED"
    ledger.pop("selection_digest")

    with pytest.raises(
        owner.OwnerDecisionUnavailable,
        match="PACKAGE_OWNER_DECISION_SUBJECT_NOT_ESTABLISHED",
    ):
        owner.load_owner_decision_admission(
            ledger,
            source_coordinate_digest="sha256:" + "d" * 64,
            policy_path=policy,
            expected_policy_digest=policy_digest,
            decision_path=decisions,
            expected_decision_digest=decisions_digest,
            evaluation_time=1_000,
        )


def test_forged_statement_still_fails_when_candidate_is_unestablished(
        tmp_path: Path) -> None:
    policy, policy_digest, decisions, _digest, ledger, _private = (
        _write_selection(tmp_path)
    )
    envelope = json.loads(decisions.read_text(encoding="utf-8"))
    envelope["signature"] = "00" * 64
    raw = core_obligation_union.canonical_bytes(envelope)
    decisions.write_bytes(raw)
    ledger = dict(ledger)
    ledger["status"] = "UNKNOWN"
    ledger["semantic_identity_status"] = "NOT_ESTABLISHED"
    ledger.pop("selection_digest")

    with pytest.raises(
        owner.OwnerDecisionError,
        match="PACKAGE_OWNER_DECISION_SIGNATURE_REFUSED",
    ):
        owner.load_owner_decision_admission(
            ledger,
            source_coordinate_digest="sha256:" + "d" * 64,
            policy_path=policy,
            expected_policy_digest=policy_digest,
            decision_path=decisions,
            expected_decision_digest=core_obligation_union.bytes_digest(raw),
            evaluation_time=1_000,
        )


@pytest.mark.parametrize("mutation", ["nonfinite", "surrogate", "deep"])
def test_malformed_pinned_json_is_bounded_fail(
        tmp_path: Path, mutation: str) -> None:
    policy, policy_digest, decisions, _digest, ledger, _private = (
        _write_selection(tmp_path)
    )
    raw = decisions.read_bytes()
    if mutation == "nonfinite":
        raw = raw.replace(b'"owner-decision-fixture-1"', b'NaN')
    elif mutation == "surrogate":
        raw = raw.replace(b'"owner-decision-fixture-1"', b'"\\ud800"')
    else:
        raw = b'{"x":' + b'[' * 200_000 + b'0' + b']' * 200_000 + b'}'
    decisions.write_bytes(raw)

    with pytest.raises(
        owner.OwnerDecisionError,
        match="PACKAGE_OWNER_DECISION_ENVELOPE_INVALID",
    ):
        owner.load_owner_decision_admission(
            ledger,
            source_coordinate_digest="sha256:" + "d" * 64,
            policy_path=policy,
            expected_policy_digest=policy_digest,
            decision_path=decisions,
            expected_decision_digest=core_obligation_union.bytes_digest(raw),
            evaluation_time=1_000,
        )


def test_detectable_decision_substitution_wins_over_missing_policy(
        tmp_path: Path) -> None:
    _policy, policy_digest, decisions, decisions_digest, ledger, _private = (
        _write_selection(tmp_path)
    )
    decisions.write_bytes(decisions.read_bytes() + b"\n")

    with pytest.raises(
        owner.OwnerDecisionError,
        match="PACKAGE_OWNER_DECISION_DIGEST_DIFFERS",
    ):
        owner.load_owner_decision_admission(
            ledger,
            source_coordinate_digest="sha256:" + "d" * 64,
            policy_path=tmp_path / "missing-policy.json",
            expected_policy_digest=policy_digest,
            decision_path=decisions,
            expected_decision_digest=decisions_digest,
            evaluation_time=1_000,
        )


def test_symlink_policy_is_refused_before_read(
        tmp_path: Path) -> None:
    policy, policy_digest, decisions, decisions_digest, ledger, _private = (
        _write_selection(tmp_path)
    )
    link = tmp_path / "owner-policy-link.json"
    try:
        link.symlink_to(policy)
    except OSError:
        pytest.skip(
            "OS_CAPABILITY_GUARD: symlink creation unavailable"
        )

    with pytest.raises(
        owner.OwnerDecisionError,
        match="PACKAGE_OWNER_POLICY_UNAVAILABLE",
    ):
        owner.load_owner_decision_admission(
            ledger,
            source_coordinate_digest="sha256:" + "d" * 64,
            policy_path=link,
            expected_policy_digest=policy_digest,
            decision_path=decisions,
            expected_decision_digest=decisions_digest,
            evaluation_time=1_000,
        )


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"),
    reason="OS_CAPABILITY_GUARD: POSIX named-pipe primitive unavailable",
)
def test_named_pipe_is_refused_without_blocking(tmp_path: Path) -> None:
    pipe = tmp_path / "owner-policy.fifo"
    os.mkfifo(pipe)
    started = time.monotonic()

    with pytest.raises(
        owner.OwnerDecisionUnavailable,
        match="PACKAGE_OWNER_POLICY_UNAVAILABLE",
    ):
        owner.load_owner_decision_admission(
            _candidate_ledger(),
            source_coordinate_digest="sha256:" + "d" * 64,
            policy_path=pipe,
            expected_policy_digest="sha256:" + "0" * 64,
            decision_path=tmp_path / "missing-decisions.json",
            expected_decision_digest="sha256:" + "0" * 64,
            evaluation_time=1_000,
        )

    assert time.monotonic() - started < 2.0
