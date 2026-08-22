"""Public VSTD 3 accelerator-accountability CLI surfaces."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from verifiable.hardware.adapters.amd import AmdAdapter
from verifiable.hardware.adapters.generic import GenericFixtureAdapter
from verifiable.hardware.adapters.intel import IntelGaudiAdapter
from verifiable.hardware.adapters.nvidia import NvidiaAdapter
from verifiable.hardware.claims import explain_claim
from verifiable.hardware.conformance import ConformanceProfile, evaluate_conformance
from verifiable.hardware.continuity import KeyResolver, verify_continuity
from verifiable.hardware.emulator import VirtualVSTDAccelerator
from verifiable.hardware.fleet import verify_fleet_observation
from verifiable.hardware.models import (
    AccountingExactness,
    AccountingMethod,
    AccountingQuantity,
    AdapterResult,
    ClaimKind,
    ClaimStatus,
    ExecutionIdentity,
    WorkloadIdentity,
)
from verifiable.hardware.receipt import load_vstd3_receipt, save_vstd3_receipt
from verifiable.hardware.registry import load_builtin_registry
from verifiable.hardware.validation import validate_vstd3_receipt


PASS_EXIT = 0
FAIL_EXIT = 1
UNKNOWN_EXIT = 2


def _add_output_flags(parser: argparse.ArgumentParser, *, keys: bool = False) -> None:
    parser.add_argument("--json", action="store_true", help="Emit stable machine-readable JSON.")
    if keys:
        parser.add_argument(
            "--key",
            action="append",
            default=[],
            metavar="KEY_ID=HEX",
            help="Test-only HMAC verification key; repeat for multiple key ids.",
        )


def add_vstd3_parsers(subparsers: argparse._SubParsersAction) -> None:
    hardware = subparsers.add_parser("hardware", help="Discover or emulate accelerator evidence.")
    hardware_commands = hardware.add_subparsers(dest="hardware_command", required=True)

    registry_list = hardware_commands.add_parser("list", help="List accelerator profiles.")
    registry_list.add_argument("--vendor")
    _add_output_flags(registry_list)

    registry_inspect = hardware_commands.add_parser("inspect", help="Inspect one accelerator profile.")
    registry_inspect.add_argument("profile_id")
    _add_output_flags(registry_inspect)

    discover = hardware_commands.add_parser("discover", help="Run a vendor or generic adapter.")
    discover.add_argument("--adapter", choices=("generic", "nvidia", "amd", "intel"), required=True)
    discover.add_argument("--fixture", type=Path)
    discover.add_argument("--output", type=Path, help="Write the normalized adapter result JSON.")
    _add_output_flags(discover)

    emulate = hardware_commands.add_parser(
        "emulate", help="Run the deterministic virtual firmware contract probe."
    )
    emulate.add_argument("--output", type=Path, required=True)
    emulate.add_argument("--created-at", required=True, help="Final ISO-8601 receipt timestamp.")
    emulate.add_argument("--device-id", default="vstd3-virtual-0")
    emulate.add_argument("--firmware-version", default="1.0.0")
    emulate.add_argument("--key-id", default="vstd3-virtual-device-key")
    emulate.add_argument("--key-hex", required=True, help="Test-only emulator HMAC key in hex.")
    _add_output_flags(emulate)

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
    _add_output_flags(attest)

    capabilities = hardware_commands.add_parser(
        "capabilities", help="Evaluate incremental VSTD 3 conformance profiles."
    )
    capabilities.add_argument("receipt", type=Path)
    _add_output_flags(capabilities, keys=True)

    hardware_verify = hardware_commands.add_parser(
        "verify", help="Verify a VSTD 3 receipt and all recorded passing claims."
    )
    hardware_verify.add_argument("receipt", type=Path)
    _add_output_flags(hardware_verify, keys=True)

    continuity = subparsers.add_parser("continuity", help="Verify authenticated event continuity.")
    continuity_commands = continuity.add_subparsers(dest="continuity_command", required=True)
    continuity_verify = continuity_commands.add_parser("verify")
    continuity_verify.add_argument("receipt", type=Path)
    _add_output_flags(continuity_verify, keys=True)

    fleet = subparsers.add_parser("fleet", help="Verify a declared enrolled fleet boundary.")
    fleet_commands = fleet.add_subparsers(dest="fleet_command", required=True)
    fleet_verify = fleet_commands.add_parser("verify")
    fleet_verify.add_argument("receipt", type=Path)
    _add_output_flags(fleet_verify)

    evidence = subparsers.add_parser("evidence", help="Inspect VSTD 3 evidence strength.")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_inspect = evidence_commands.add_parser("inspect")
    evidence_inspect.add_argument("receipt", type=Path)
    _add_output_flags(evidence_inspect, keys=True)

    claims = subparsers.add_parser("claims", help="Evaluate or explain VSTD 3 claims.")
    claim_commands = claims.add_subparsers(dest="claims_command", required=True)
    claim_evaluate = claim_commands.add_parser("evaluate")
    claim_evaluate.add_argument("receipt", type=Path)
    _add_output_flags(claim_evaluate, keys=True)
    claim_explain = claim_commands.add_parser("explain")
    claim_explain.add_argument("kind", choices=tuple(item.value for item in ClaimKind))
    _add_output_flags(claim_explain)


def parse_verification_keys(values: list[str]) -> tuple[KeyResolver, dict[str, bytes]]:
    keys: dict[str, bytes] = {}
    for value in values:
        key_id, separator, hex_value = value.partition("=")
        if not separator or not key_id:
            raise ValueError("verification keys must use KEY_ID=HEX")
        try:
            key = bytes.fromhex(hex_value)
        except ValueError as exc:
            raise ValueError(f"verification key {key_id} is not valid hex") from exc
        if not key:
            raise ValueError(f"verification key {key_id} must not be empty")
        if key_id in keys and keys[key_id] != key:
            raise ValueError(f"conflicting verification keys for {key_id}")
        keys[key_id] = key
    return keys.get, keys


def _status_exit(status: str) -> int:
    if status == ClaimStatus.PASS.value:
        return PASS_EXIT
    if status == ClaimStatus.FAIL.value:
        return FAIL_EXIT
    return UNKNOWN_EXIT


def _emit(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"[{payload['status']}] {payload.get('summary', payload.get('operation', 'VSTD 3'))}")
    for key, value in payload.items():
        if key not in {"status", "summary"}:
            print(f"  {key}: {json.dumps(value, sort_keys=True)}")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("--created-at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("--created-at must include a timezone")
    return parsed


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _handle_hardware(args: argparse.Namespace) -> int:
    registry = load_builtin_registry()
    if args.hardware_command == "list":
        profiles = registry.list()
        if args.vendor:
            profiles = tuple(item for item in profiles if item.vendor.casefold() == args.vendor.casefold())
        payload: dict[str, Any] = {
            "status": ClaimStatus.PASS.value,
            "operation": "hardware.list",
            "registry_version": registry.registry_version,
            "profiles": [
                {
                    "profile_id": item.profile_id,
                    "vendor": item.vendor,
                    "family": item.family,
                    "models": list(item.models),
                }
                for item in profiles
            ],
        }
        _emit(payload, as_json=args.json)
        return PASS_EXIT
    if args.hardware_command == "inspect":
        payload = {
            "status": ClaimStatus.PASS.value,
            "operation": "hardware.inspect",
            "profile": registry.get(args.profile_id).to_dict(),
        }
        _emit(payload, as_json=args.json)
        return PASS_EXIT
    if args.hardware_command == "discover":
        adapters: dict[str, Callable[[], AdapterResult]] = {
            "generic": lambda: GenericFixtureAdapter(_required_fixture(args)).discover(),
            "nvidia": lambda: NvidiaAdapter(fixture_path=args.fixture).discover(),
            "amd": lambda: AmdAdapter(fixture_path=args.fixture).discover(),
            "intel": lambda: IntelGaudiAdapter(fixture_path=args.fixture).discover(),
        }
        result = adapters[args.adapter]()
        result_payload = result.to_dict()
        status = ClaimStatus.PASS.value if result_payload["descriptors"] else ClaimStatus.UNSUPPORTED.value
        payload = {
            "status": status,
            "operation": "hardware.discover",
            "adapter_result": result_payload,
        }
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            payload["output"] = str(args.output.resolve())
        _emit(payload, as_json=args.json)
        return _status_exit(status)
    if args.hardware_command in {"capabilities", "verify"}:
        receipt = load_vstd3_receipt(args.receipt)
        resolver, _ = parse_verification_keys(args.key)
        validation = validate_vstd3_receipt(receipt, key_resolver=resolver)
        if args.hardware_command == "verify":
            status = validation.status.value
            payload = {
                "status": status,
                "operation": "hardware.verify",
                "receipt_id": receipt.receipt_id,
                "canonical_digest": receipt.canonical_digest,
                "errors": list(validation.errors),
                "warnings": list(validation.warnings),
            }
            _emit(payload, as_json=args.json)
            return _status_exit(status)
        evaluations = []
        if validation.valid:
            continuity = validation.continuity[0] if len(validation.continuity) == 1 else None
            fleet_pass = any(
                claim.claim_kind is ClaimKind.FLEET_COMPLETENESS
                and claim.status is ClaimStatus.PASS
                for claim in receipt.claim_evaluations
            )
            evaluations = [
                evaluate_conformance(
                    profile,
                    sources=receipt.evidence_sources,
                    attestation=receipt.attestation_evidence,
                    declarations=receipt.capability_declarations,
                    continuity=continuity,
                    fleet_boundary_verified=fleet_pass,
                ).to_dict()
                for profile in ConformanceProfile
            ]
            profile_statuses = {item["status"] for item in evaluations}
            status = (
                ClaimStatus.UNKNOWN.value
                if ClaimStatus.UNKNOWN.value in profile_statuses
                or ClaimStatus.UNSUPPORTED.value in profile_statuses
                else ClaimStatus.PASS.value
            )
        else:
            status = validation.status.value
        payload = {
            "status": status,
            "operation": "hardware.capabilities",
            "profiles": evaluations,
            "validation_errors": list(validation.errors),
            "validation_warnings": list(validation.warnings),
        }
        _emit(payload, as_json=args.json)
        return _status_exit(status)
    return _emulate(args)


def _required_fixture(args: argparse.Namespace) -> Path:
    if args.fixture is None:
        raise ValueError("the generic adapter requires --fixture")
    return args.fixture


def _emulate(args: argparse.Namespace) -> int:
    created = _parse_timestamp(args.created_at)
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
    device.boot(boot_id="cli-probe-boot", timestamp=_timestamp(created - timedelta(seconds=5)))
    nonce = hashlib.sha256(
        f"VSTD3-CLI-PROBE:{args.device_id}:{args.created_at}".encode()
    ).digest()[:16]
    challenge = device.issue_challenge(
        challenge_id="cli-probe-challenge",
        nonce=nonce,
        issued_at=_timestamp(created - timedelta(seconds=4)),
        expires_at=_timestamp(created + timedelta(hours=1)),
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
        submitted_at=_timestamp(created - timedelta(seconds=3)),
    )
    device.submit_execution(execution, timestamp=_timestamp(created - timedelta(seconds=3)))
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
        timestamp=_timestamp(created - timedelta(seconds=2)),
    )
    device.complete_execution(
        execution.execution_id, timestamp=_timestamp(created - timedelta(seconds=1))
    )
    receipt = device.build_receipt(
        receipt_id=f"vstd3-emulator-{args.device_id}", created_at=_timestamp(created)
    )
    path = save_vstd3_receipt(receipt, args.output)
    validation = validate_vstd3_receipt(
        receipt, key_resolver=lambda key_id: key if key_id == args.key_id else None
    )
    status = validation.status.value
    payload = {
        "status": status,
        "operation": "hardware.emulate",
        "summary": "Virtual firmware contract probe completed; this is not physical-hardware attestation.",
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
    _emit(payload, as_json=args.json)
    return _status_exit(status)


def _handle_continuity(args: argparse.Namespace) -> int:
    receipt = load_vstd3_receipt(args.receipt)
    resolver, _ = parse_verification_keys(args.key)
    results = [verify_continuity(record, key_resolver=resolver) for record in receipt.continuity_records]
    if not results:
        status = ClaimStatus.UNSUPPORTED.value
    elif any(item.status is ClaimStatus.FAIL for item in results):
        status = ClaimStatus.FAIL.value
    elif any(item.status is ClaimStatus.UNKNOWN for item in results):
        status = ClaimStatus.UNKNOWN.value
    else:
        status = ClaimStatus.PASS.value
    payload = {
        "status": status,
        "operation": "continuity.verify",
        "records": [
            {
                "status": item.status.value,
                "verified_event_count": item.verified_event_count,
                "errors": list(item.errors),
                "gaps": [gap.to_dict() for gap in item.gaps],
                "first_anchor_id": item.first_anchor_id,
                "last_anchor_id": item.last_anchor_id,
            }
            for item in results
        ],
    }
    _emit(payload, as_json=args.json)
    return _status_exit(status)


def _handle_fleet(args: argparse.Namespace) -> int:
    receipt = load_vstd3_receipt(args.receipt)
    manifests = {item.manifest_id: item for item in receipt.fleet_manifests}
    results: list[dict[str, Any]] = []
    for observation in receipt.fleet_observations:
        manifest = manifests.get(observation.manifest_id)
        if manifest is None:
            results.append({"observation_id": observation.observation_id, "valid": False, "errors": ["missing manifest"]})
            continue
        result = verify_fleet_observation(manifest, observation)
        results.append(
            {
                "observation_id": observation.observation_id,
                "valid": result.valid,
                "errors": list(result.errors),
                "expected_member_ids": list(result.expected_member_ids),
                "observed_member_ids": list(result.observed_member_ids),
            }
        )
    if not results:
        status = ClaimStatus.UNSUPPORTED.value
    else:
        status = ClaimStatus.PASS.value if all(item["valid"] for item in results) else ClaimStatus.FAIL.value
    payload = {"status": status, "operation": "fleet.verify", "observations": results}
    _emit(payload, as_json=args.json)
    return _status_exit(status)


def _handle_evidence(args: argparse.Namespace) -> int:
    receipt = load_vstd3_receipt(args.receipt)
    resolver, _ = parse_verification_keys(args.key)
    validation = validate_vstd3_receipt(receipt, key_resolver=resolver)
    status = validation.status.value
    payload: dict[str, Any] = {
        "status": status,
        "operation": "evidence.inspect",
        "sources": [
            {
                "source_id": source.source_id,
                "producer": source.producer.value,
                "verification_state_recorded": source.verification_state.value,
                "capabilities_recorded": [item.value for item in source.capabilities],
                "raw_evidence_digest": source.raw_evidence_digest,
                "limitations": list(source.limitations),
            }
            for source in receipt.evidence_sources
        ],
        "attestations": [
            {
                "evidence_id": item.evidence_id,
                "challenge_id": item.challenge_id,
                "verification_state_recorded": item.verification_state.value,
                "signature_algorithm": item.signature.algorithm if item.signature else None,
            }
            for item in receipt.attestation_evidence
        ],
        "validation_errors": list(validation.errors),
        "validation_warnings": list(validation.warnings),
    }
    _emit(payload, as_json=args.json)
    return _status_exit(status)


def _handle_claims(args: argparse.Namespace) -> int:
    if args.claims_command == "explain":
        payload: dict[str, Any] = {
            "status": ClaimStatus.PASS.value,
            "operation": "claims.explain",
            "claim": dict(explain_claim(ClaimKind(args.kind))),
        }
        _emit(payload, as_json=args.json)
        return PASS_EXIT
    receipt = load_vstd3_receipt(args.receipt)
    resolver, _ = parse_verification_keys(args.key)
    validation = validate_vstd3_receipt(receipt, key_resolver=resolver)
    if not validation.valid:
        status = validation.status.value
    elif any(item.status is ClaimStatus.UNKNOWN for item in receipt.claim_evaluations):
        status = ClaimStatus.UNKNOWN.value
    elif receipt.claim_evaluations and all(
        item.status is ClaimStatus.UNSUPPORTED for item in receipt.claim_evaluations
    ):
        status = ClaimStatus.UNSUPPORTED.value
    else:
        status = ClaimStatus.PASS.value
    payload = {
        "status": status,
        "operation": "claims.evaluate",
        "claims": [item.to_dict() for item in receipt.claim_evaluations],
        "validation_errors": list(validation.errors),
        "validation_warnings": list(validation.warnings),
        "note": "Claim statuses are accepted only when receipt validation independently reproduces every PASS.",
    }
    _emit(payload, as_json=args.json)
    return _status_exit(status)


def handle_vstd3_command(args: argparse.Namespace) -> int:
    if args.command == "hardware":
        return _handle_hardware(args)
    if args.command == "continuity":
        return _handle_continuity(args)
    if args.command == "fleet":
        return _handle_fleet(args)
    if args.command == "evidence":
        return _handle_evidence(args)
    if args.command == "claims":
        return _handle_claims(args)
    raise ValueError(f"unsupported VSTD 3 command {args.command}")
