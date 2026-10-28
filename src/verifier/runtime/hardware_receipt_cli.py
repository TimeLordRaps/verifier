"""Terminology: command-line interface (CLI); Verifier Standard (VSTD).

Receipt validation and explanation commands for the VSTD 3 CLI.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from verifier.hardware.claims import explain_claim
from verifier.hardware.conformance import ConformanceProfile, evaluate_conformance
from verifier.hardware.continuity import verify_continuity
from verifier.hardware.fleet import verify_fleet_observation
from verifier.hardware.models import ClaimKind, ClaimStatus
from verifier.hardware.receipt import load_vstd3_receipt
from verifier.hardware.validation import validate_vstd3_receipt
from verifier.runtime.hardware_cli_support import (
    PASS_EXIT,
    add_output_flags,
    emit,
    parse_verification_keys,
    status_exit,
)


def add_hardware_receipt_parsers(hardware_commands: argparse._SubParsersAction) -> None:
    capabilities = hardware_commands.add_parser(
        "capabilities", help="Evaluate incremental VSTD 3 conformance profiles."
    )
    capabilities.add_argument("receipt", type=Path)
    add_output_flags(capabilities, keys=True)

    hardware_verify = hardware_commands.add_parser(
        "verify", help="Verify a VSTD 3 receipt and all recorded passing claims."
    )
    hardware_verify.add_argument("receipt", type=Path)
    add_output_flags(hardware_verify, keys=True)


def add_receipt_family_parsers(subparsers: argparse._SubParsersAction) -> None:
    continuity = subparsers.add_parser("continuity", help="Verify authenticated event continuity.")
    continuity_commands = continuity.add_subparsers(dest="continuity_command", required=True)
    continuity_verify = continuity_commands.add_parser("verify")
    continuity_verify.add_argument("receipt", type=Path)
    add_output_flags(continuity_verify, keys=True)

    fleet = subparsers.add_parser("fleet", help="Verify a declared enrolled fleet boundary.")
    fleet_commands = fleet.add_subparsers(dest="fleet_command", required=True)
    fleet_verify = fleet_commands.add_parser("verify")
    fleet_verify.add_argument("receipt", type=Path)
    add_output_flags(fleet_verify)

    evidence = subparsers.add_parser("evidence", help="Inspect VSTD 3 evidence strength.")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_inspect = evidence_commands.add_parser("inspect")
    evidence_inspect.add_argument("receipt", type=Path)
    add_output_flags(evidence_inspect, keys=True)

    claims = subparsers.add_parser("claims", help="Evaluate or explain VSTD 3 claims.")
    claim_commands = claims.add_subparsers(dest="claims_command", required=True)
    claim_evaluate = claim_commands.add_parser("evaluate")
    claim_evaluate.add_argument("receipt", type=Path)
    add_output_flags(claim_evaluate, keys=True)
    claim_explain = claim_commands.add_parser("explain")
    claim_explain.add_argument("kind", choices=tuple(item.value for item in ClaimKind))
    add_output_flags(claim_explain)


def handle_hardware_receipt_command(args: argparse.Namespace) -> int:
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
        emit(payload, as_json=args.json)
        return status_exit(status)

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
    emit(payload, as_json=args.json)
    return status_exit(status)


def _handle_continuity(args: argparse.Namespace) -> int:
    receipt = load_vstd3_receipt(args.receipt)
    resolver, _ = parse_verification_keys(args.key)
    results = [
        verify_continuity(record, key_resolver=resolver) for record in receipt.continuity_records
    ]
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
    emit(payload, as_json=args.json)
    return status_exit(status)


def _handle_fleet(args: argparse.Namespace) -> int:
    receipt = load_vstd3_receipt(args.receipt)
    manifests = {item.manifest_id: item for item in receipt.fleet_manifests}
    results: list[dict[str, Any]] = []
    for observation in receipt.fleet_observations:
        manifest = manifests.get(observation.manifest_id)
        if manifest is None:
            results.append(
                {
                    "observation_id": observation.observation_id,
                    "valid": False,
                    "errors": ["missing manifest"],
                }
            )
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
        status = (
            ClaimStatus.PASS.value
            if all(item["valid"] for item in results)
            else ClaimStatus.FAIL.value
        )
    payload = {"status": status, "operation": "fleet.verify", "observations": results}
    emit(payload, as_json=args.json)
    return status_exit(status)


def _handle_evidence(args: argparse.Namespace) -> int:
    receipt = load_vstd3_receipt(args.receipt)
    resolver, _ = parse_verification_keys(args.key)
    validation = validate_vstd3_receipt(receipt, key_resolver=resolver)
    status = validation.status.value
    payload = {
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
    emit(payload, as_json=args.json)
    return status_exit(status)


def _handle_claims(args: argparse.Namespace) -> int:
    if args.claims_command == "explain":
        payload = {
            "status": ClaimStatus.PASS.value,
            "operation": "claims.explain",
            "claim": dict(explain_claim(ClaimKind(args.kind))),
        }
        emit(payload, as_json=args.json)
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
        "note": (
            "Claim statuses are accepted only when receipt validation recomputes every PASS "
            "from bound evidence; this does not establish distinct actors."
        ),
    }
    emit(payload, as_json=args.json)
    return status_exit(status)


def handle_receipt_family_command(args: argparse.Namespace) -> int:
    if args.command == "continuity":
        return _handle_continuity(args)
    if args.command == "fleet":
        return _handle_fleet(args)
    if args.command == "evidence":
        return _handle_evidence(args)
    if args.command == "claims":
        return _handle_claims(args)
    raise ValueError(f"unsupported VSTD 3 command {args.command}")
