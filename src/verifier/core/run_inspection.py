"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Human-readable inspection of structurally valid generic-run receipts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from verifier.core.run_validation import _run_payload_errors


def inspect_run_receipt(receipt_path_or_dir: Path) -> int:
    receipt_file = receipt_path_or_dir / "receipt.json" if receipt_path_or_dir.is_dir() else receipt_path_or_dir
    if not receipt_file.exists():
        print(f"Error: receipt not found at {receipt_file}")
        return 1
    try:
        data = json.loads(receipt_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[FAIL] Receipt is not readable JSON: {exc}")
        return 1
    if not isinstance(data, Mapping):
        print("[FAIL] Receipt root must be an object")
        return 1
    errors = _run_payload_errors(data)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print("=" * 70)
    print(f"GENERIC RUN RECEIPT: {data.get('receipt_id')} ({data.get('schema_version')}/{data.get('receipt_kind')})")
    print("=" * 70)
    print(f"Canonical Digest: {data.get('canonical_digest')}")
    print(f"Claim: {data.get('claim_statement')}")
    ex = data.get("execution", {})
    print(f"Command: {' '.join(ex.get('command', []))}")
    print(f"Outcome: {ex.get('outcome')}  (exit={ex.get('exit_code')})")
    c = data.get("claims", {})
    print("-" * 70)
    print("CLAIMS (distinct, not flattened):")
    print(f"  execution_completed:            {c.get('execution_completed')}")
    print(f"  output_digests_recorded:        {c.get('output_digests_recorded')}")
    print(f"  all_declared_artifacts_present: {c.get('all_declared_artifacts_present')}")
    ext = c.get("external_evaluation")
    if ext:
        print(
            "  external_evaluation:            "
            f"reported={ext.get('reported_value')} recorded_attested={ext.get('attested')} "
            "(not verified by inspect)"
        )
    else:
        print("  external_evaluation:            (none declared)")
    print("=" * 70)
    return 0
