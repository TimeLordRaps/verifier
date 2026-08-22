"""Strict persistence helpers for VSTD 3 receipts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .canonical import canonical_json_bytes, strict_decode
from .models import VSTD3Receipt


class VSTD3ReceiptError(ValueError):
    pass


def save_vstd3_receipt(receipt: VSTD3Receipt, path_or_dir: Path) -> Path:
    if path_or_dir.suffix.lower() == ".json":
        path = path_or_dir
    else:
        path = path_or_dir / "receipt.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    receipt.compute_and_set_digest()
    path.write_bytes(canonical_json_bytes(receipt) + b"\n")
    return path


def load_vstd3_receipt(path_or_dir: Path) -> VSTD3Receipt:
    path = path_or_dir / "receipt.json" if path_or_dir.is_dir() else path_or_dir
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VSTD3ReceiptError(f"cannot read VSTD 3 receipt {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise VSTD3ReceiptError("VSTD 3 receipt must be a JSON object")
    try:
        receipt = strict_decode(VSTD3Receipt, payload)
    except ValueError as exc:
        raise VSTD3ReceiptError(str(exc)) from exc
    if not receipt.verify_digest_integrity():
        raise VSTD3ReceiptError("VSTD 3 canonical digest mismatch")
    return receipt


def is_vstd3_receipt(payload: Mapping[str, Any]) -> bool:
    return payload.get("schema_version") == "VSTD-3.0"

