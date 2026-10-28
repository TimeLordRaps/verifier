"""Read-only native operation metadata through the command-line interface (CLI).

JavaScript Object Notation (JSON); Verifier Standard (VSTD). These exports describe
installed metadata. They execute no certificate replay and grant no conformance.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from verifier.runtime.native_operation_contracts import (
    DESCRIPTOR, LOOKUP, HISTORICAL, NativeOperationRefusal, NativeOperationUnavailable,
    export_native_operation_schema, lookup_native_replay_operation,
    native_replay_operation_catalog,
)


def add_native_operation_parsers(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "operations", help="Export finite native replay metadata as JSON; no replay or admission.")
    commands = parser.add_subparsers(dest="operations_command", required=True)
    catalog = commands.add_parser("catalog", help="Enumerate one explicitly selected semantic family.")
    catalog.add_argument("--semantic-version", default=HISTORICAL)
    lookup = commands.add_parser("lookup", help="Describe one exact registered replay and its source pins.")
    for flag in ("semantic-version", "objective", "represented-kind"):
        lookup.add_argument("--" + flag, required=True)
    lookup.add_argument("--expected-descriptor-digest")
    lookup.add_argument("--expected-mechanism-digest")
    schema = commands.add_parser("schema", help="Export the actual packaged descriptor or lookup schema.")
    schema.add_argument("schema_version", choices=(DESCRIPTOR, LOOKUP))


def handle_native_operation_command(args: argparse.Namespace) -> int:
    try:
        if args.operations_command == "schema":
            print(export_native_operation_schema(args.schema_version).decode("utf-8"))
            return 0
        if args.operations_command == "catalog":
            result = native_replay_operation_catalog(semantic_version=args.semantic_version)
        elif args.operations_command == "lookup":
            result = lookup_native_replay_operation(
                semantic_version=args.semantic_version, objective=args.objective,
                represented_kind=args.represented_kind,
                expected_descriptor_digest=args.expected_descriptor_digest,
                expected_mechanism_digest=args.expected_mechanism_digest)
        else:
            raise NativeOperationRefusal("OPERATION_METADATA_COMMAND_UNSUPPORTED")
    except (NativeOperationUnavailable, MemoryError):
        print("[UNKNOWN] Installed operation metadata or schema is unavailable.", file=sys.stderr)
        return 2
    except NativeOperationRefusal as exc:
        print(f"[REJECTED] {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]


__all__ = ["add_native_operation_parsers", "handle_native_operation_command"]
