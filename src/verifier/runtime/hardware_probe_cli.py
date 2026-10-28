"""Terminology: application programming interface (API); command-line interface (CLI);
hash-based message authentication code (HMAC); Verifier Standard (VSTD).

Deterministic virtual firmware probe commands for the VSTD 3 CLI.
"""

from __future__ import annotations

import argparse
from datetime import timedelta
import hashlib
from pathlib import Path

from verifier.hardware.emulator import VirtualVSTDAccelerator
from verifier.hardware.models import (
    AccountingExactness,
    AccountingMethod,
    AccountingQuantity,
    ExecutionIdentity,
    WorkloadIdentity,
)
from verifier.hardware.receipt import save_vstd3_receipt
from verifier.hardware.validation import validate_vstd3_receipt
from verifier.runtime.hardware_cli_support import (
    add_output_flags,
    emit,
    parse_timestamp,
    status_exit,
    timestamp,
)


def add_probe_parsers(hardware_commands: argparse._SubParsersAction) -> None:
    emulate = hardware_commands.add_parser(
        "emulate", help="Run the deterministic virtual firmware contract probe."
    )
    emulate.add_argument("--output", type=Path, required=True)
    emulate.add_argument("--created-at", required=True, help="Final ISO-8601 receipt timestamp.")
    emulate.add_argument("--device-id", default="vstd3-virtual-0")
    emulate.add_argument("--firmware-version", default="1.0.0")
    emulate.add_argument("--key-id", default="vstd3-virtual-device-key")
    emulate.add_argument("--key-hex", required=True, help="Test-only emulator HMAC key in hex.")
    add_output_flags(emulate)

    attest = hardware_commands.add_parser(
        "attest", help="Run an explicitly virtual attestation probe; no commodity claim is made."
    )
    attest.add_argument("--virtual", action="store_true", required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.add_argument("--created-at", required=True)
    attest.add_argument("--device-id", default="vstd3-virtual-0")
    attest.add_argument("--firmware-version", default="1.0.0")
    attest.add_argument("--key-id", default="vstd3-virtual-device-key")
    attest.add_argument("--key-hex", required=True)
    add_output_flags(attest)


def handle_probe_command(args: argparse.Namespace) -> int:
    created = parse_timestamp(args.created_at)
    try:
        key = bytes.fromhex(args.key_hex)
    except ValueError as exc:
        raise ValueError("--key-hex is not valid hex") from exc
    if len(key) < 16:
        raise ValueError("--key-hex must contain at least 16 bytes")

    device = VirtualVSTDAccelerator(
        args.device_id,
        args.firmware_version,
        key,
        key_id=args.key_id,
    )
    device.configure_partitions(())
    device.boot(boot_id="cli-probe-boot", timestamp=timestamp(created - timedelta(seconds=5)))
    nonce = hashlib.sha256(
        f"VSTD3-CLI-PROBE:{args.device_id}:{args.created_at}".encode()
    ).digest()[:16]
    challenge = device.issue_challenge(
        challenge_id="cli-probe-challenge",
        nonce=nonce,
        issued_at=timestamp(created - timedelta(seconds=4)),
        expires_at=timestamp(created + timedelta(hours=1)),
        verifier_id="vstd3-cli",
    )
    device.attest(challenge)
    execution = ExecutionIdentity(
        execution_id="cli-probe-execution",
        workload=WorkloadIdentity(
            workload_id="vstd3-firmware-contract-probe",
            executable_digest=hashlib.sha256(b"VSTD3-CLI-PROBE-1").hexdigest(),
            invocation_commitment=hashlib.sha256(b"virtual-probe").hexdigest(),
        ),
        logical_device_ids=(f"logical:partition:{args.device_id}:whole",),
        topology_snapshot_id=device.current_topology_snapshot_id,
        submitted_at=timestamp(created - timedelta(seconds=3)),
    )
    device.submit_execution(execution, timestamp=timestamp(created - timedelta(seconds=3)))
    device.observe_execution(
        execution.execution_id,
        (
            AccountingQuantity(
                name="virtual_probe_operations",
                value="1",
                unit="operations",
                method=AccountingMethod.FIRMWARE_COUNTER,
                evidence_source_id=device.evidence_source_id,
                scope="one reference-emulator probe operation",
                exactness=AccountingExactness.EXACT_FOR_DECLARED_SCOPE,
            ),
        ),
        timestamp=timestamp(created - timedelta(seconds=2)),
    )
    device.complete_execution(
        execution.execution_id, timestamp=timestamp(created - timedelta(seconds=1))
    )
    receipt = device.build_receipt(
        receipt_id=f"vstd3-emulator-{args.device_id}", created_at=timestamp(created)
    )
    path = save_vstd3_receipt(receipt, args.output)
    validation = validate_vstd3_receipt(
        receipt, key_resolver=lambda key_id: key if key_id == args.key_id else None
    )
    status = validation.status.value
    payload = {
        "status": status,
        "operation": "hardware.emulate",
        "summary": (
            "Virtual firmware contract probe completed; "
            "this is not physical-hardware attestation."
        ),
        "receipt": str(path.resolve()),
        "canonical_digest": receipt.canonical_digest,
        "key_id": args.key_id,
        "limitations": [
            "HMAC-SHA256 is test-only.",
            "Complete mediation is bounded to the reference emulator API.",
            "No claim about commodity or physical hardware is made.",
        ],
        "errors": list(validation.errors),
    }
    emit(payload, as_json=args.json)
    return status_exit(status)
