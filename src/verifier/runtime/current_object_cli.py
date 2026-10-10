"""Local command-line replay of explicitly selected current-object objectives.

command-line interface (CLI); JavaScript Object Notation (JSON); Verifier
Standard (VSTD). This command uses no network client and performs no publication.
Caller-selected filesystem paths may be network-backed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts.current_object_routes import (
    CurrentObjectRouteRefusal, CurrentObjectRouteUnavailable, MAX_CERTIFICATE_BYTES,
    MAX_SELECTION_TEXT_BYTES, current_object_route_catalog,
    replay_current_object_certificate, select_current_object_route,
)


def add_current_object_parsers(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "current-object", help="Replay an explicitly selected current OBJECT objective.")
    commands = parser.add_subparsers(dest="current_object_command", required=True)
    catalog = commands.add_parser(
        "catalog", help="List registered native current-object objectives; no profile claim.")
    catalog.add_argument("--json", action="store_true")
    catalog.add_argument("--inventory", action="store_true",
                         help="Include the complete 234-slot applicability and objective inventory.")
    check = commands.add_parser(
        "check", help="Read-only native replay under an external route and policy.")
    check.add_argument("certificate", help="Local complete canonical certificate file.")
    check.add_argument("--semantic-version", required=True)
    check.add_argument("--objective", required=True)
    check.add_argument("--represented-kind", required=True)
    check.add_argument("--request", required=True,
                       help="Independently selected expected request JSON file.")
    check.add_argument("--policy", required=True,
                       help="Independently selected policy JSON file.")
    check.add_argument("--json", action="store_true")


def _read_bounded(path: str, bound: int) -> bytes:
    # Read only finite chunks: a tiny file must not request a maximum-sized buffer.
    pieces, retained = [], 0
    with Path(path).open("rb") as handle:
        while True:
            data = handle.read(min(8192, bound-retained+1))
            if not data:
                break
            retained += len(data)
            if retained > bound:
                raise CurrentObjectRouteRefusal("local input exceeds transport bound")
            pieces.append(data)
    return b"".join(pieces)


def _read_selection(path: str) -> dict[str, Any]:
    value = strict_json_loads(_read_bounded(path, MAX_SELECTION_TEXT_BYTES).decode("utf-8"))
    if type(value) is not dict:
        raise CurrentObjectRouteRefusal("external request and policy require JSON objects")
    return value


def handle_current_object_command(args: argparse.Namespace) -> int:
    if args.current_object_command == "catalog":
        rows = current_object_route_catalog()
        if getattr(args, "inventory", False):
            from verifier.domains.inventory import slot_inventory
            inventory = slot_inventory()
            if args.json:
                print(json.dumps({
                    "schema_version": "verifier-current-object-inventory-1",
                    "routes": rows,
                    "inventory": inventory,
                    "slot_count": len(inventory),
                }, sort_keys=True, indent=2, allow_nan=False))
            else:
                for row in rows:
                    print(f"{row['semantic_version']} {row['objective']} "
                          f"({row['scope']}; kind={row['represented_kind_rule']})")
                print(f"234-slot applicability and objective inventory ({len(inventory)} slots):")
                for slot in inventory:
                    mech = f" [mechanized: {slot['coordinate']}]" if slot["mechanized"] else ""
                    print(f"  {slot['coordinate']}: {slot['object_kind']} Tier {slot['tier']} ({slot['tier_name']}) "
                          f"- {slot['applicability']} ({slot['status']}){mech}")
                print("No whole-tier or object-profile conformance is established.")
            return 0
        if args.json:
            print(json.dumps({"schema_version": "verifier-current-object-route-catalog-1",
                              "routes": rows}, sort_keys=True, indent=2, allow_nan=False))
        else:
            for row in rows:
                print(f"{row['semantic_version']} {row['objective']} "
                      f"({row['scope']}; kind={row['represented_kind_rule']})")
            print("No whole-tier or object-profile conformance is established.")
        return 0
    if args.current_object_command != "check":
        raise CurrentObjectRouteRefusal("unsupported current-object command")
    try:
        # Select installed native code from caller arguments before opening any
        # potentially self-describing certificate bytes.
        select_current_object_route(
            semantic_version=args.semantic_version, objective=args.objective,
            represented_kind=args.represented_kind)
        request = _read_selection(args.request)
        policy = _read_selection(args.policy)
        certificate = _read_bounded(args.certificate, MAX_CERTIFICATE_BYTES)
        result = replay_current_object_certificate(
            certificate, semantic_version=args.semantic_version,
            objective=args.objective, represented_kind=args.represented_kind,
            expected_request=request, policy=policy)
    except (CurrentObjectRouteUnavailable, MemoryError):
        if args.json:
            print(json.dumps({
                "schema_version": "verifier-current-object-route-replay-1",
                "replay_status": "UNAVAILABLE", "computational_status": "UNKNOWN",
                "reason": "CHECKER_UNAVAILABLE",
            }, sort_keys=True, indent=2))
        else:
            print("[UNKNOWN] Selected native checker or input is unavailable.", file=sys.stderr)
        return 2
    except (CurrentObjectRouteRefusal, OSError, ValueError, TypeError,
            UnicodeError, OverflowError, RecursionError) as exc:
        if args.json:
            print(json.dumps({
                "schema_version": "verifier-current-object-route-replay-1",
                "replay_status": "REJECTED", "computational_status": "NOT_CHECKED",
                "error": str(exc),
            }, sort_keys=True, indent=2))
        else:
            print(f"[REJECTED] {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    else:
        print(f"[{result['computational_status']}] {result['selection']['semantic_version']} "
              f"{result['selection']['objective']} represented "
              f"{result['selection']['represented_kind']}; replay "
              f"{result['replay_status']}")
        print(result["claim_boundary"])
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["computational_status"]]


__all__ = ["add_current_object_parsers", "handle_current_object_command"]
