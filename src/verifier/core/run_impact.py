"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Recorded-ancestry impact analysis for generic-run receipts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from verifier.core.run_support import RunError
from verifier.core.run_validation import is_generic_run_receipt


def compute_blast_radius_impacted_artifacts(dataset_receipt_file: Path, revoked_artifact_id: str) -> set[str]:
    """Forward blast radius of a revoked/invalidated artifact, plus the artifact itself.

    Reuses ``ProvenanceHypergraph.blast_radius`` from the existing VSTD-Graph-1
    runtime rather than reimplementing graph traversal here.
    """
    from verifier.data.models import ProvenanceHypergraph

    data = json.loads(dataset_receipt_file.read_text(encoding="utf-8"))
    hg = ProvenanceHypergraph.from_dict(data["hypergraph"])
    if revoked_artifact_id not in hg.artifacts:
        raise RunError(f"Artifact '{revoked_artifact_id}' not found in {dataset_receipt_file}.")
    affected = set(hg.blast_radius(revoked_artifact_id))
    affected.add(revoked_artifact_id)
    return affected


def find_run_receipts_impacted_by_revocation(
    search_root: Path,
    dataset_receipt_file: Path,
    revoked_artifact_id: str,
) -> list[dict[str, Any]]:
    """Answer: "which recorded runs need to be reconsidered because this upstream
    dataset-provenance artifact changed or became invalid?"

    Scans ``search_root`` recursively for ``receipt.json`` files that are generic
    run receipts (``receipt_kind == generic_computational_run``) and whose
    ``provenance_linkage`` references an artifact inside the forward blast radius
    of ``revoked_artifact_id`` (or the artifact itself). This composes the
    dataset-provenance hypergraph directly into run-receipt impact analysis
    instead of introducing a parallel lineage system.
    """
    impacted_artifacts = compute_blast_radius_impacted_artifacts(dataset_receipt_file, revoked_artifact_id)
    results: list[dict[str, Any]] = []
    for receipt_file in search_root.rglob("receipt.json"):
        try:
            data = json.loads(receipt_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not is_generic_run_receipt(data):
            continue
        for link in data.get("provenance_linkage", []):
            if link.get("artifact_id") in impacted_artifacts:
                results.append(
                    {
                        "receipt_path": str(receipt_file),
                        "receipt_id": data.get("receipt_id"),
                        "matched_artifact_id": link.get("artifact_id"),
                        "claim_statement": data.get("claim_statement"),
                    }
                )
                break
    return results
