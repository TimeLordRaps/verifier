"""Terminology: command-line interface (CLI); Verifier Standard (VSTD).

JavaScript Object Notation (JSON). Only built-in native mechanisms execute here;
external domain mechanisms require explicit registration through the Python interface.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_digest
from verifier.core.certification_mechanisms import NativeCertificationMechanism
from verifier.core.evidence import EvidenceStore, VerificationSession
from verifier.core.grounded_certification import (
    MAX_DOCUMENT_BYTES, CertificationError, CertificationPolicy, CertificationRequest,
    build_grounded_certificate, recheck_grounded_certificate,
)
from verifier.core.profile_obligations import obligation_catalog
from verifier.core.receipt import strict_json_loads


def add_certification_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("certification", help="Inspect and replay grounded object-profile obligations.")
    commands = parser.add_subparsers(dest="certification_command", required=True)
    catalog = commands.add_parser("catalog", help="List all X.M obligations and native mechanism coverage.")
    catalog.add_argument("--json", action="store_true")
    assess = commands.add_parser("assess", help="Execute admitted built-in checks and emit a fresh certificate.")
    assess.add_argument("request", help="Externally selected grounded request file.")
    assess.add_argument("--evidence", required=True, help="Object mapping evidence addresses to base64 bytes.")
    assess.add_argument("--policy", required=True, help="Checker-selected admission policy file.")
    assess.add_argument("--output", help="New certificate file; existing files are never overwritten.")
    assess.add_argument("--json", action="store_true")
    check = commands.add_parser("check", help="Rehash and rerun a certificate against an external request and policy.")
    check.add_argument("certificate")
    check.add_argument("--request", required=True, help="The request the consumer intends to check.")
    check.add_argument("--policy", required=True, help="Checker-selected policy, not authority supplied by the certificate.")
    check.add_argument("--json", action="store_true")


def _read(path: str) -> Any:
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_DOCUMENT_BYTES + 1)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise CertificationError("input document exceeds the byte bound")
    return strict_json_loads(data.decode("utf-8"))


def handle_certification_command(args: argparse.Namespace) -> int:
    try:
        mechanism = NativeCertificationMechanism()
        if args.certification_command == "catalog":
            result = obligation_catalog()
            result["native_mechanism"] = {
                "mechanism_id": mechanism.mechanism_id,
                "mechanism_digest": mechanism.mechanism_digest,
                "supported_obligations": list(mechanism.supported_obligations),
            }
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                for row in result["obligations"]:
                    coverage = "native checker" if row["id"] in mechanism.supported_obligations else "domain mechanism required"
                    print(f"{row['id']} {row['name']} ({coverage})")
            return 0
        policy = CertificationPolicy.from_dict(_read(args.policy))
        request = CertificationRequest.from_dict(_read(args.request))
        if args.certification_command == "assess":
            payloads = _read(args.evidence)
            if not isinstance(payloads, dict) or any(not isinstance(v, str) for v in payloads.values()):
                raise CertificationError("evidence file must map references to base64 strings")
            references = {r for p in request.obligations.values() for r in p.evidence_refs}
            if set(payloads) - references:
                raise CertificationError("unreferenced evidence is not admitted")
            store = EvidenceStore()
            store.import_base64(payloads)
            session = VerificationSession(store)
            session.register(mechanism)
            certificate = build_grounded_certificate(request, policy=policy, session=session)
            result = certificate["result"]
            if args.output:
                with Path(args.output).open("x", encoding="utf-8", newline="\n") as handle:
                    json.dump(certificate, handle, sort_keys=True, indent=2, allow_nan=False)
                    handle.write("\n")
        else:
            certificate = _read(args.certificate)
            result = recheck_grounded_certificate(certificate, policy=policy,
                mechanisms=(mechanism,), expected_request_digest=canonical_digest(request.to_dict()))
        if args.json:
            print(json.dumps(certificate if args.certification_command == "assess" else result,
                             sort_keys=True, indent=2, allow_nan=False))
        else:
            print(f"[{result['status']}] grounded certification: {result['certification_status']}")
            print(f"Certified profile depth: {result['certified_profile_depth']}")
            for coordinate, row in result["obligations"].items():
                print(f"  {coordinate}: {row['outcome']}; established={row['established']}; {row['reason']}")
        return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        if args.json:
            print(json.dumps({"status": "REJECTED", "error": str(exc)}, sort_keys=True))
        else:
            print(f"[REJECTED] {exc}")
        return 1
