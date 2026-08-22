from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from verifier.hardware.anchors import AnchorError, FileAnchorProvider, LocalAnchorProvider
from verifier.hardware.continuity import verify_continuity
from verifier.hardware.emulator import FirmwareContractError, VirtualVSTDAccelerator
from verifier.hardware.models import (
    AccountingExactness,
    AccountingMethod,
    AccountingQuantity,
    ClaimKind,
    ClaimStatus,
    ContinuityRecord,
    ExecutionIdentity,
    WorkloadIdentity,
)
from verifier.hardware.receipt import (
    VSTD3ReceiptError,
    load_vstd3_receipt,
    save_vstd3_receipt,
)
from verifier.hardware.validation import validate_vstd3_receipt


DEVICE_KEY = b"vstd3-emulator-device-key-32bytes"
ANCHOR_KEY = b"vstd3-external-anchor-key-32byte"


def _populated_emulator(*, reset: bool = False) -> VirtualVSTDAccelerator:
    device = VirtualVSTDAccelerator("virtual-0", "1.0.0", DEVICE_KEY)
    device.configure_partitions(
        (
            ("partition:virtual-0:a", "virtual-slice", 500_000),
            ("partition:virtual-0:b", "virtual-slice", 500_000),
        )
    )
    device.boot(boot_id="boot-0", timestamp="2026-08-21T16:00:00Z")
    challenge = device.issue_challenge(
        challenge_id="challenge-0",
        nonce=b"nonce-0000000001",
        issued_at="2026-08-21T16:00:01Z",
        expires_at="2026-08-21T17:00:00Z",
        verifier_id="test-verifier",
    )
    device.attest(challenge)
    execution = ExecutionIdentity(
        execution_id="execution-0",
        workload=WorkloadIdentity(
            workload_id="workload-0",
            executable_digest="a" * 64,
            input_commitments=("b" * 64,),
        ),
        logical_device_ids=("logical:partition:virtual-0:a",),
        topology_snapshot_id=device.current_topology_snapshot_id,
        submitted_at="2026-08-21T16:00:02Z",
    )
    device.submit_execution(execution, timestamp="2026-08-21T16:00:02Z")
    device.observe_execution(
        execution.execution_id,
        (
            AccountingQuantity(
                name="issued_operations",
                value="42000000",
                unit="operations",
                method=AccountingMethod.FIRMWARE_COUNTER,
                evidence_source_id=device.evidence_source_id,
                scope="virtual instruction issue counter",
                exactness=AccountingExactness.EXACT_FOR_DECLARED_SCOPE,
            ),
        ),
        timestamp="2026-08-21T16:00:03Z",
    )
    device.complete_execution(execution.execution_id, timestamp="2026-08-21T16:00:04Z")
    if reset:
        anchor = LocalAnchorProvider("test-anchor", "anchor-key", ANCHOR_KEY)
        device.reset(
            boot_id="boot-1",
            reason="test reset",
            timestamp="2026-08-21T16:00:05Z",
            anchor_provider=anchor,
        )
    return device


def _key_resolver(key_id: str) -> bytes | None:
    return {
        "vstd3-virtual-device-key": DEVICE_KEY,
        "anchor-key": ANCHOR_KEY,
    }.get(key_id)


def test_reference_emulator_receipt_is_canonical_and_independently_verifiable(
    tmp_path: Path,
) -> None:
    device = _populated_emulator(reset=True)
    receipt = device.build_receipt(
        receipt_id="receipt-0", created_at="2026-08-21T16:00:06Z"
    )

    validation = validate_vstd3_receipt(receipt, key_resolver=_key_resolver)
    assert validation.valid, validation.errors
    assert all(result.status is ClaimStatus.PASS for result in validation.continuity)
    claims = {claim.claim_kind: claim.status for claim in receipt.claim_evaluations}
    assert claims[ClaimKind.DEVICE_IDENTITY] is ClaimStatus.PASS
    assert claims[ClaimKind.FIRMWARE_INTEGRITY] is ClaimStatus.PASS
    assert claims[ClaimKind.EXECUTION_ATTESTATION] is ClaimStatus.PASS
    assert claims[ClaimKind.EXECUTION_ACCOUNTING] is ClaimStatus.PASS
    assert claims[ClaimKind.COMPLETE_MEDIATION] is ClaimStatus.PASS
    assert claims[ClaimKind.FLEET_COMPLETENESS] is ClaimStatus.UNKNOWN
    assert claims[ClaimKind.PHYSICAL_WORLD_COMPLETENESS] is ClaimStatus.UNSUPPORTED

    path = save_vstd3_receipt(receipt, tmp_path)
    assert path.read_bytes().endswith(b"\n")
    loaded = load_vstd3_receipt(path)
    assert loaded.to_dict() == receipt.to_dict()
    assert save_vstd3_receipt(loaded, tmp_path / "second.json").read_bytes() == path.read_bytes()


def test_verified_flags_without_keys_cannot_bootstrap_strong_claims() -> None:
    receipt = _populated_emulator().build_receipt(
        receipt_id="receipt-no-key", created_at="2026-08-21T16:00:05Z"
    )
    validation = validate_vstd3_receipt(receipt)
    assert not validation.valid
    assert validation.status is ClaimStatus.UNKNOWN
    assert any("could not be independently verified" in warning for warning in validation.warnings)
    overclaims = "\n".join(validation.errors)
    assert "overclaims DEVICE_IDENTITY" in overclaims
    assert "overclaims FIRMWARE_INTEGRITY" in overclaims
    assert "overclaims EXECUTION_ATTESTATION" in overclaims
    assert "overclaims EXECUTION_ACCOUNTING" in overclaims
    assert "overclaims COMPLETE_MEDIATION" in overclaims


def test_attestation_tampering_and_challenge_replay_fail_closed() -> None:
    device = _populated_emulator()
    receipt = device.build_receipt(
        receipt_id="receipt-tamper", created_at="2026-08-21T16:00:05Z"
    )
    original = receipt.attestation_evidence[0]
    receipt.attestation_evidence = (
        replace(original, nonce_b64="bm9uY2UtdGFtcGVyZWQ="),
    )
    receipt.compute_and_set_digest()
    validation = validate_vstd3_receipt(receipt, key_resolver=_key_resolver)
    assert not validation.valid
    assert any("nonce does not match" in error for error in validation.errors)
    assert any("signature covers the wrong digest" in error for error in validation.errors)

    with pytest.raises(FirmwareContractError, match="already been consumed"):
        device.attest(device._challenges[0])
    with pytest.raises(FirmwareContractError, match="challenge replay"):
        device.issue_challenge(
            challenge_id="challenge-0",
            nonce=b"different-nonce",
            issued_at="2026-08-21T16:00:05Z",
            expires_at="2026-08-21T17:00:00Z",
            verifier_id="test-verifier",
        )


@pytest.mark.parametrize("mutation", ["delete", "reorder", "duplicate", "fork"])
def test_continuity_adversarial_mutations_are_never_pass(mutation: str) -> None:
    record = _populated_emulator().continuity_record()
    events = list(record.events)
    if mutation == "delete":
        del events[2]
    elif mutation == "reorder":
        events[1], events[2] = events[2], events[1]
    elif mutation == "duplicate":
        events.insert(2, events[1])
    else:
        events.insert(2, replace(events[1], event_id="event:fork", rolling_root="f" * 64))
    mutated = ContinuityRecord(
        device_identity_id=record.device_identity_id,
        events=tuple(events),
        reset_epochs=record.reset_epochs,
        anchors=record.anchors,
    )
    result = verify_continuity(mutated, key_resolver=_key_resolver)
    assert result.status is not ClaimStatus.PASS
    assert result.errors or result.gaps


def test_receipt_digest_and_unknown_signed_fields_are_rejected(tmp_path: Path) -> None:
    receipt = _populated_emulator().build_receipt(
        receipt_id="receipt-roundtrip", created_at="2026-08-21T16:00:05Z"
    )
    path = save_vstd3_receipt(receipt, tmp_path)
    payload = path.read_text(encoding="utf-8")
    path.write_text(payload.replace('"receipt_id":"receipt-roundtrip"', '"receipt_id":"tampered"'), encoding="utf-8")
    with pytest.raises(VSTD3ReceiptError, match="digest mismatch"):
        load_vstd3_receipt(path)

    clean_path = save_vstd3_receipt(receipt, tmp_path / "unknown.json")
    import json

    data = json.loads(clean_path.read_text(encoding="utf-8"))
    data["unknown_signed_field"] = "forbidden"
    clean_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(VSTD3ReceiptError, match="unknown fields"):
        load_vstd3_receipt(clean_path)


def test_accounting_exactness_labels_reject_estimates_as_exact() -> None:
    with pytest.raises(ValueError, match="cannot be represented as an exact counter"):
        AccountingQuantity(
            name="estimated_flops",
            value="1.5",
            unit="FLOP",
            method=AccountingMethod.MODEL_ESTIMATE,
            evidence_source_id="source",
            scope="model estimate",
            exactness=AccountingExactness.EXACT_FOR_DECLARED_SCOPE,
        )
    with pytest.raises(ValueError, match="upper bound"):
        AccountingQuantity(
            name="capacity_time",
            value="1",
            unit="accelerator-second",
            method=AccountingMethod.CAPACITY_TIME_UPPER_BOUND,
            evidence_source_id="source",
            scope="allocation",
            exactness=AccountingExactness.ESTIMATE,
        )


def test_measurement_signature_device_swap_and_staleness_are_rejected() -> None:
    device = _populated_emulator()
    receipt = device.build_receipt(
        receipt_id="receipt-attacks", created_at="2026-08-21T16:00:05Z"
    )
    attestation = receipt.attestation_evidence[0]
    altered_measurement = replace(attestation.firmware_measurements[0], digest="0" * 64)
    receipt.attestation_evidence = (
        replace(attestation, firmware_measurements=(altered_measurement,)),
    )
    receipt.compute_and_set_digest()
    result = validate_vstd3_receipt(receipt, key_resolver=_key_resolver)
    assert not result.valid
    assert any("signature covers the wrong digest" in error for error in result.errors)

    receipt = device.build_receipt(
        receipt_id="receipt-device-swap", created_at="2026-08-21T16:00:05Z"
    )
    receipt.physical_identities = (
        replace(receipt.physical_identities[0], certificate_digest="d" * 64),
    )
    receipt.compute_and_set_digest()
    result = validate_vstd3_receipt(receipt, key_resolver=_key_resolver)
    assert any("certificate does not bind" in error for error in result.errors)

    receipt = device.build_receipt(
        receipt_id="receipt-stale", created_at="2026-08-21T18:00:00Z"
    )
    result = validate_vstd3_receipt(receipt, key_resolver=_key_resolver)
    assert any("was stale" in error for error in result.errors)


def test_workload_accounting_partition_and_end_bindings_fail_closed() -> None:
    device = _populated_emulator()
    receipt = device.build_receipt(
        receipt_id="receipt-bindings", created_at="2026-08-21T16:00:05Z"
    )
    execution = receipt.executions[0]
    receipt.executions = (
        replace(execution, workload=replace(execution.workload, driver="tampered-driver")),
    )
    receipt.compute_and_set_digest()
    result = validate_vstd3_receipt(receipt, key_resolver=_key_resolver)
    assert any("does not bind the workload identity" in error for error in result.errors)

    receipt = device.build_receipt(
        receipt_id="receipt-partition", created_at="2026-08-21T16:00:05Z"
    )
    receipt.accounting_observations = (
        replace(
            receipt.accounting_observations[0],
            device_scope_ids=("logical:partition:virtual-0:b",),
        ),
    )
    receipt.compute_and_set_digest()
    result = validate_vstd3_receipt(receipt, key_resolver=_key_resolver)
    assert any("outside its execution topology" in error for error in result.errors)

    receipt = device.build_receipt(
        receipt_id="receipt-missing-end", created_at="2026-08-21T16:00:05Z"
    )
    receipt.execution_ends = ()
    receipt.compute_and_set_digest()
    result = validate_vstd3_receipt(receipt, key_resolver=_key_resolver)
    assert not result.valid
    assert any("overclaims COMPLETE_MEDIATION" in error for error in result.errors)


def test_wrong_predecessor_reset_transition_and_clock_rollback_fail() -> None:
    record = _populated_emulator(reset=True).continuity_record()
    events = list(record.events)
    events[1] = replace(events[1], previous_root="0" * 64)
    wrong_predecessor = replace(record, events=tuple(events))
    result = verify_continuity(wrong_predecessor, key_resolver=_key_resolver)
    assert result.status is ClaimStatus.FAIL
    assert any("wrong predecessor" in error for error in result.errors)

    bad_resets = list(record.reset_epochs)
    bad_resets[1] = replace(bad_resets[1], prior_epoch=None)
    reset_result = verify_continuity(
        replace(record, reset_epochs=tuple(bad_resets)), key_resolver=_key_resolver
    )
    assert reset_result.status is ClaimStatus.FAIL
    assert any("does not name prior epoch" in error for error in reset_result.errors)

    no_anchor_resets = list(record.reset_epochs)
    no_anchor_resets[1] = replace(no_anchor_resets[1], external_anchor_id="")
    no_anchor = verify_continuity(
        replace(record, reset_epochs=tuple(no_anchor_resets), anchors=()),
        key_resolver=_key_resolver,
    )
    assert no_anchor.status is ClaimStatus.FAIL
    assert any(gap.gap_type == "RESET_WITHOUT_EXTERNAL_ANCHOR" for gap in no_anchor.gaps)

    events = list(record.events)
    events[2] = replace(events[2], timestamp="2026-08-21T15:59:59Z")
    clock_result = verify_continuity(
        replace(record, events=tuple(events)), key_resolver=_key_resolver
    )
    assert clock_result.status is ClaimStatus.FAIL
    assert any("timestamp rolled backward" in error for error in clock_result.errors)


def test_multiple_jobs_preserve_monotonic_authenticated_sequence() -> None:
    device = _populated_emulator()
    second = ExecutionIdentity(
        "execution-1",
        WorkloadIdentity("workload-1", executable_digest="c" * 64),
        ("logical:partition:virtual-0:b",),
        device.current_topology_snapshot_id,
        "2026-08-21T16:00:05Z",
    )
    device.submit_execution(second, timestamp="2026-08-21T16:00:05Z")
    device.observe_execution(
        second.execution_id,
        (
            AccountingQuantity(
                "operations",
                "7",
                "operations",
                AccountingMethod.FIRMWARE_COUNTER,
                device.evidence_source_id,
                "counter",
                AccountingExactness.EXACT_FOR_DECLARED_SCOPE,
            ),
        ),
        timestamp="2026-08-21T16:00:06Z",
    )
    device.complete_execution(second.execution_id, timestamp="2026-08-21T16:00:07Z")
    receipt = device.build_receipt(
        receipt_id="receipt-two-jobs", created_at="2026-08-21T16:00:08Z"
    )
    result = validate_vstd3_receipt(receipt, key_resolver=_key_resolver)
    assert result.valid, result.errors
    assert len(receipt.executions) == 2
    assert [event.sequence for event in receipt.continuity_records[0].events] == list(
        range(len(receipt.continuity_records[0].events))
    )


def test_file_anchor_is_append_only_reloadable_and_fork_rejecting(tmp_path: Path) -> None:
    record = _populated_emulator().continuity_record()
    path = tmp_path / "anchors.jsonl"
    provider = FileAnchorProvider(
        path,
        provider_id="file-anchor",
        key_id="anchor-key",
        signing_key=ANCHOR_KEY,
    )
    first = provider.anchor(record.events[-1], anchored_at="2026-08-21T16:00:05Z")
    duplicate = provider.anchor(record.events[-1], anchored_at="2026-08-21T16:00:05Z")
    assert duplicate == first
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1

    reloaded = FileAnchorProvider(
        path,
        provider_id="file-anchor",
        key_id="anchor-key",
        signing_key=ANCHOR_KEY,
    )
    assert reloaded.get(first.anchor_id) == first
    assert reloaded.verify(first)
    with pytest.raises(AnchorError, match="anchor fork"):
        reloaded.anchor(record.events[-1], anchored_at="2026-08-21T16:00:06Z")

    path.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(AnchorError, match="malformed anchor log"):
        FileAnchorProvider(
            path,
            provider_id="file-anchor",
            key_id="anchor-key",
            signing_key=ANCHOR_KEY,
        )
