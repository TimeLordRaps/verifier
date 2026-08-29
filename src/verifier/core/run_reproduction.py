"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Opt-in rerun and side-effect-free artifact-rehash reproduction assessment.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional

from verifier.core.provenance import sha256_file
from verifier.core.reproducibility import ReproducibilityLevel
from verifier.core.run_planning import load_manifest
from verifier.core.run_validation import _run_payload_errors


def reproduce_run_receipt(receipt_path_or_dir: Path, rerun: bool = False) -> int:
    """Assess reproduction fidelity.

    By default this rehashes the declared output artifacts as they currently
    exist on disk relative to the receipt directory's manifest base (safe,
    side-effect free, always available). Pass ``rerun=True`` to additionally
    re-execute the recorded command and compare freshly produced outputs —
    this mutates on-disk state at the declared output paths and is therefore
    opt-in only.
    """
    receipt_file = (
        receipt_path_or_dir / "receipt.json"
        if receipt_path_or_dir.is_dir()
        else receipt_path_or_dir
    )
    receipt_dir = receipt_file.parent
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
    # Inputs/outputs in the receipt are recorded as paths relative to the manifest's
    # own directory. The convention this runtime uses (see `vstd run`) is that
    # a receipt directory colocates receipt.json with a copy of the originating
    # manifest (manifest.source.json), so that directory is also the correct base
    # for resolving those relative paths during reproduction.
    base_dir = receipt_dir

    if rerun:
        manifest_path = base_dir / "manifest.source.json"
        if not manifest_path.exists():
            manifest_path = base_dir / "manifest.json"
        if not manifest_path.exists():
            print(f"[WARN] No source manifest found under {base_dir}; cannot rerun. Falling back to artifact rehash.")
            rerun = False
        else:
            from verifier.core.run import capture_run

            manifest = load_manifest(manifest_path)
            reproduced = capture_run(manifest, manifest_dir=base_dir, receipt_id=data.get("receipt_id"))
            original_outcome = data.get("execution", {}).get("outcome")
            reproduced_outcome = reproduced.execution.outcome
            original_outputs = {
                str(item.get("path")): item.get("sha256")
                for item in data.get("outputs", [])
            }
            reproduced_outputs = {item.path: item.sha256 for item in reproduced.outputs}
            outputs_match = bool(original_outputs) and original_outputs == reproduced_outputs
            outcomes_match = original_outcome == reproduced_outcome
            fidelity_state = (
                ReproducibilityLevel.CONTENT_IDENTICAL.value
                if outputs_match and outcomes_match
                else "NOT_DEMONSTRATED"
            )
            print(
                "[REPRODUCTION RESULT - RERUN] "
                f"Fidelity state: {fidelity_state} (declared-output scope)"
            )
            print(f"  Original outcome:   {original_outcome}")
            print(f"  Reproduced outcome: {reproduced_outcome}")
            print(f"  Outputs match:      {outputs_match}")
            print("  Scope: declared output artifacts and execution outcome")
            return 0 if outputs_match and outcomes_match else 1

    # Default path: rehash on-disk artifacts only (no execution).
    mismatches: list[tuple[Any, Any, Optional[str]]] = []
    checked = 0
    for out in data.get("outputs", []):
        recorded_hash = out.get("sha256")
        path = base_dir / out["path"]
        if not path.exists():
            mismatches.append((out["path"], recorded_hash, None))
            continue
        checked += 1
        current_hash = sha256_file(path)
        if current_hash != recorded_hash:
            mismatches.append((out["path"], recorded_hash, current_hash))

    if not data.get("outputs"):
        print("[REPRODUCTION RESULT - ARTIFACT REHASH] NOT_DEMONSTRATED: no outputs were declared.")
        return 1

    if mismatches:
        print(f"[REPRODUCTION RESULT - ARTIFACT REHASH] MISMATCH ({len(mismatches)} of {len(data.get('outputs', []))} outputs)")
        for path, recorded, current in mismatches:
            print(f"  {path}: recorded={recorded} current={current}")
        return 1

    print(f"[REPRODUCTION RESULT - ARTIFACT REHASH] All {checked} on-disk output artifact(s) match recorded digests.")
    print("  Declared-output bytes: MATCH")
    print("  Full-run reproduction: NOT_DEMONSTRATED (command was not re-executed; pass --rerun to assess it)")
    return 0
