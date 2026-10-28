"""Terminology: command-line interface (CLI); hash-based message authentication code
(HMAC); identifier (ID); International Organization for Standardization (ISO);
JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Shared formatting, parsing, and exit semantics for the VSTD 3 CLI modules.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from typing import Any

from verifier.hardware.continuity import KeyResolver
from verifier.hardware.models import ClaimStatus


PASS_EXIT = 0
FAIL_EXIT = 1
UNKNOWN_EXIT = 2


def add_output_flags(parser: argparse.ArgumentParser, *, keys: bool = False) -> None:
    parser.add_argument("--json", action="store_true", help="Emit stable machine-readable JSON.")
    if keys:
        parser.add_argument(
            "--key",
            action="append",
            default=[],
            metavar="KEY_ID=HEX",
            help="Test-only HMAC verification key; repeat for multiple key ids.",
        )


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


def status_exit(status: str) -> int:
    if status == ClaimStatus.PASS.value:
        return PASS_EXIT
    if status == ClaimStatus.FAIL.value:
        return FAIL_EXIT
    return UNKNOWN_EXIT


def emit(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"[{payload['status']}] {payload.get('summary', payload.get('operation', 'VSTD 3'))}")
    for key, value in payload.items():
        if key not in {"status", "summary"}:
            print(f"  {key}: {json.dumps(value, sort_keys=True)}")


def parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("--created-at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("--created-at must include a timezone")
    return parsed


def timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
