"""Read-only dangerous-pathway security command-line interface helpers.

Verifier Standard (VSTD); command-line interface (CLI); JavaScript Object
Notation (JSON). These helpers perform local bounded replay only. The shared
public CLI must explicitly register and dispatch them before ``vstd security``
is reachable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from verifier.domains.contracts.dangerous_pathway_security import (
    DangerousPathwaySecurityError,
    DangerousPathwaySecurityUnavailable,
    MAX_ASSESSMENT_BYTES,
    MAX_CERTIFICATE_BYTES,
    MAX_REQUEST_BYTES,
    dangerous_pathway_catalog,
    recheck_dangerous_pathway_assessment,
    recheck_dangerous_pathway_certificate,
)


def add_security_parsers(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "security",
        help="Replay bounded dangerous-pathway records; grant no publication authority.",
    )
    commands = parser.add_subparsers(dest="security_command", required=True)
    catalog = commands.add_parser(
        "catalog", help="Describe the installed mechanical dialect; select no host policy.")
    catalog.add_argument("--json", action="store_true")
    pathway = commands.add_parser(
        "pathway-check", help="Recheck one retained pathway certificate and external request.")
    pathway.add_argument("certificate", help="Canonical pathway certificate JSON file.")
    pathway.add_argument("--request", required=True,
                         help="Independently selected canonical request JSON file.")
    pathway.add_argument("--json", action="store_true")
    aggregate = commands.add_parser(
        "aggregate", help="Recheck one retained host-selected aggregate assessment.")
    aggregate.add_argument("assessment", help="Canonical aggregate assessment JSON file.")
    aggregate.add_argument("--json", action="store_true")


def _read_bounded(path: str, maximum: int) -> bytes:
    pieces: list[bytes] = []
    retained = 0
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(min(8192, maximum - retained + 1))
            if not chunk:
                break
            retained += len(chunk)
            if retained > maximum:
                raise DangerousPathwaySecurityUnavailable("local input exceeds byte capacity")
            pieces.append(chunk)
    return b"".join(pieces)


def _emit(result: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    else:
        security = result.get("security_outcome", "NOT_ESTABLISHED")
        print(f"[{result.get('status', 'PASS')}] security={security}; "
              "publication_authority=NOT_ESTABLISHED")
        if "claim_boundary" in result:
            print(result["claim_boundary"])


def _exit(result: dict[str, Any]) -> int:
    status = result.get("status")
    security = result.get("security_outcome")
    if status == "FAIL" or security == "FAIL":
        return 1
    if status == "PASS" and security == "ESTABLISHED":
        return 0
    return 2


def handle_security_command(args: argparse.Namespace) -> int:
    try:
        if args.security_command == "catalog":
            result = dangerous_pathway_catalog()
            _emit({"status": "PASS", **result}, as_json=args.json)
            return 0
        if args.security_command == "pathway-check":
            result = recheck_dangerous_pathway_certificate(
                _read_bounded(args.certificate, MAX_CERTIFICATE_BYTES),
                request_bytes=_read_bounded(args.request, MAX_REQUEST_BYTES),
            )
        elif args.security_command == "aggregate":
            result = recheck_dangerous_pathway_assessment(
                _read_bounded(args.assessment, MAX_ASSESSMENT_BYTES))
        else:
            raise DangerousPathwaySecurityError("unsupported security command")
    except (DangerousPathwaySecurityUnavailable, MemoryError, RecursionError):
        result = {
            "schema_version": "verifier-dangerous-pathway-cli-diagnostic-1",
            "status": "UNKNOWN",
            "security_outcome": "NOT_ESTABLISHED",
            "publication_authority": "NOT_ESTABLISHED",
            "reason": "SECURITY_CHECKER_UNAVAILABLE",
        }
    except (DangerousPathwaySecurityError, OSError, TypeError, UnicodeError,
            OverflowError) as exc:
        result = {
            "schema_version": "verifier-dangerous-pathway-cli-diagnostic-1",
            "status": "FAIL",
            "security_outcome": "NOT_ESTABLISHED",
            "publication_authority": "NOT_ESTABLISHED",
            "reason": "SECURITY_CONTRACT_REJECTED",
            "error": str(exc),
        }
    _emit(result, as_json=getattr(args, "json", False))
    code = _exit(result)
    if code and not getattr(args, "json", False):
        print("No security clearance or publication authority was granted.", file=sys.stderr)
    return code


__all__ = ["add_security_parsers", "handle_security_command"]
