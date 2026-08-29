"""Terminology: command-line interface (CLI); identifier (ID); JavaScript Object Notation (JSON);
Boolean satisfiability problem (SAT); Secure Hash Algorithm 256-bit (SHA-256);
trusted computing base (TCB); Unicode Transformation Format, 8-bit (UTF-8);
Verifier Standard (VSTD).

Canonical receipt model, canonicalization algorithm, and digest verification for
VSTD-1 claim-mechanics receipts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from .checker import IndependentAuditReport
from .provenance import ProvenanceRecord


CLAIM_SCHEMA_VERSION = "VSTD-1"
CLAIM_RECEIPT_KIND = "claim_mechanics"


def canonical_json_dumps(payload: Any) -> str:
    """Deterministic JSON serialization.

    Rules:
    1. Keys sorted alphabetically at all nesting levels.
    2. Compact separators (no trailing spaces: ',', ':').
    3. Floating point numbers formatted consistently.
    4. Strings encoded in UTF-8.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_canonical_digest(stable_payload: Mapping[str, Any]) -> str:
    """Compute SHA-256 digest of canonicalized stable payload."""
    serialized = canonical_json_dumps(stable_payload).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


@dataclass(frozen=True)
class ClaimSpec:
    id: str
    title: str
    statement: str
    status: str
    scope: str
    limitations: tuple[str, ...]
    falsification_condition: str
    last_verified: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "statement": self.statement,
            "status": self.status,
            "scope": self.scope,
            "limitations": list(self.limitations),
            "falsification_condition": self.falsification_condition,
            "last_verified": self.last_verified,
        }


@dataclass(frozen=True)
class EvidencePayload:
    domain: str
    input_text_or_formula: str
    n_vars: int
    clauses: tuple[tuple[int, ...], ...]
    atomic_reasons: tuple[dict[str, Any], ...]
    assumptions: tuple[str, ...]
    source_artifacts: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "input_text_or_formula": self.input_text_or_formula,
            "n_vars": self.n_vars,
            "clauses": [list(c) for c in self.clauses],
            "atomic_reasons": list(self.atomic_reasons),
            "assumptions": list(self.assumptions),
            "source_artifacts": dict(self.source_artifacts),
        }


@dataclass(frozen=True)
class ExecutionMetadata:
    executed_at_utc: str
    elapsed_ms: float
    command_executed: str
    stdout_snippet: str
    stderr_snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "executed_at_utc": self.executed_at_utc,
            "elapsed_ms": self.elapsed_ms,
            "command_executed": self.command_executed,
            "stdout_snippet": self.stdout_snippet,
            "stderr_snippet": self.stderr_snippet,
        }


@dataclass
class VstdReceipt:
    """Mutable in-memory model of a canonically digested VSTD-1 claim receipt."""

    schema_version: str
    receipt_kind: str
    receipt_id: str
    claim: ClaimSpec
    evidence: EvidencePayload
    target_result: dict[str, Any]
    independent_audit: IndependentAuditReport
    provenance: ProvenanceRecord
    reproducibility: dict[str, Any]
    canonical_digest: str = ""
    execution_metadata: Optional[ExecutionMetadata] = None

    def __post_init__(self) -> None:
        if self.schema_version != CLAIM_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {CLAIM_SCHEMA_VERSION}")
        if self.receipt_kind != CLAIM_RECEIPT_KIND:
            raise ValueError(f"receipt_kind must be {CLAIM_RECEIPT_KIND}")

    def get_stable_payload(self) -> dict[str, Any]:
        """Extract only deterministic, location-independent fields for canonical hashing."""
        return {
            "schema_version": self.schema_version,
            "receipt_kind": self.receipt_kind,
            "receipt_id": self.receipt_id,
            "claim": self.claim.to_dict(),
            "evidence": self.evidence.to_dict(),
            "target_result": self.target_result,
            "independent_audit": self.independent_audit.to_dict(),
            "provenance_stable": {
                "target_name": self.provenance.target_name,
                "portable_repository_id": self.provenance.portable_repository_id,
                "git_commit_sha": self.provenance.git.commit_sha,
                "git_branch": self.provenance.git.branch,
                "git_is_dirty": self.provenance.git.is_dirty,
                "git_dirty_files": list(self.provenance.git.dirty_files),
                "source_file_hashes": dict(self.provenance.source_file_hashes),
                "runtime_python_version": self.provenance.runtime.python_version,
            },
            "reproducibility": self.reproducibility,
        }

    def compute_and_set_digest(self) -> str:
        stable = self.get_stable_payload()
        self.canonical_digest = compute_canonical_digest(stable)
        return self.canonical_digest

    def verify_digest_integrity(self) -> bool:
        stable = self.get_stable_payload()
        recomputed = compute_canonical_digest(stable)
        return recomputed == self.canonical_digest

    def to_dict(self) -> dict[str, Any]:
        if not self.canonical_digest:
            self.compute_and_set_digest()
        return {
            "schema_version": self.schema_version,
            "receipt_kind": self.receipt_kind,
            "receipt_id": self.receipt_id,
            "canonical_digest": self.canonical_digest,
            "claim": self.claim.to_dict(),
            "evidence": self.evidence.to_dict(),
            "target_result": self.target_result,
            "independent_audit": self.independent_audit.to_dict(),
            "provenance": self.provenance.to_dict(),
            "reproducibility": self.reproducibility,
            "execution_metadata": self.execution_metadata.to_dict() if self.execution_metadata else None,
        }

    def save_to_directory(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        self.compute_and_set_digest()

        # 1. receipt.json
        receipt_path = out_dir / "receipt.json"
        receipt_path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

        # 2. claim.json
        claim_path = out_dir / "claim.json"
        claim_path.write_text(json.dumps(self.claim.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

        # 3. manifest.json
        manifest = {
            "receipt_id": self.receipt_id,
            "canonical_digest": self.canonical_digest,
            "schema_version": self.schema_version,
            "receipt_kind": self.receipt_kind,
            "files": {
                "receipt.json": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                "claim.json": hashlib.sha256(claim_path.read_bytes()).hexdigest(),
            },
        }
        manifest_path = out_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

        # 4. logs/
        logs_dir = out_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        if self.execution_metadata:
            log_content = (
                f"Command: {self.execution_metadata.command_executed}\n"
                f"Timestamp: {self.execution_metadata.executed_at_utc}\n"
                f"Elapsed: {self.execution_metadata.elapsed_ms:.2f} ms\n"
                f"--- STDOUT ---\n{self.execution_metadata.stdout_snippet}\n"
                f"--- STDERR ---\n{self.execution_metadata.stderr_snippet}\n"
            )
            (logs_dir / "execution.log").write_text(log_content, encoding="utf-8")

        # 5. report.md
        report_md = generate_receipt_markdown_report(self)
        (out_dir / "report.md").write_text(report_md, encoding="utf-8")

        return receipt_path


def generate_receipt_markdown_report(receipt: VstdReceipt) -> str:
    """Generate a human-readable checker report for the receipt."""
    audit = receipt.independent_audit
    prov = receipt.provenance
    claim = receipt.claim

    independence = audit.independence_basis

    return f"""# VSTD Receipt Report — {receipt.receipt_id}

> **Canonical Digest:** `{receipt.canonical_digest}`
> **Schema Version:** `{receipt.schema_version}`
> **Receipt Kind:** `{receipt.receipt_kind}`
> **Verification Status:** `{claim.status}`
> **Checker Verdict:** `{audit.overall_verdict.value}`
> **Independent Verification:** `{'EVIDENCED' if independence.independently_verified else 'NOT_DEMONSTRATED'}`

---

## 1. Declared Claim

- **Claim ID:** `{claim.id}`
- **Title:** {claim.title}
- **Statement:** {claim.statement}
- **Scope:** {claim.scope}
- **Falsification Condition:** {claim.falsification_condition}

### Bounded Limitations
{chr(10).join(f"- {lim}" for lim in claim.limitations)}

---

## 2. Bundled Checker Result

The bundled checker used its recorded implementation and trusted computing base. Running
it twice, or obtaining matching results, does not establish that separate independent
actors performed the runs. Actor, implementation, and runtime separation require their
own bound evidence.

- **SAT Status:** `{'Satisfiable' if audit.sat_result.satisfiable else 'Unsatisfiable'}` (decisions={audit.sat_result.decisions_count}, propagations={audit.sat_result.propagations_count})
- **Grounding Status:** `{audit.grounding_result.grounding_status.value}`
  - Observed leaves: `{len(audit.grounding_result.observed_leaves)}`
  - Inferred leaves: `{len(audit.grounding_result.inferred_leaves)}`
  - Placeholder leaves: `{len(audit.grounding_result.placeholder_leaves)}`
  - Undischarged assumptions: `{len(audit.grounding_result.undischarged_assumptions)}`
- **Acyclicity Verified:** `{'Passed (No cycles)' if not audit.grounding_result.cycle_detected else 'FAILED (Cycle detected)'}`
- **Structural Integrity:** `{'PASSED' if audit.structural_integrity_passed else 'FAILED'}`

### Trusted Computing Base (TCB)
```yaml
{chr(10).join(f"{k}: {v}" for k, v in audit.trusted_computing_base.items())}
```

### Independence Basis
```yaml
{chr(10).join(f"{k}: {v}" for k, v in independence.to_dict().items())}
```

---

## 3. Provenance & Execution Environment

- **Target Repository:** `{prov.portable_repository_id}`
- **Git Commit:** `{prov.git.commit_sha}`
- **Git Branch:** `{prov.git.branch}` (dirty: `{prov.git.is_dirty}`)
- **Python Version:** `{prov.runtime.python_version}` ({prov.runtime.platform_system} {prov.runtime.platform_release})
- **Execution Timestamp:** `{prov.captured_at_utc}`

### Source File Checksums
```json
{json.dumps(prov.source_file_hashes, indent=2)}
```

---

## 4. Reproducibility Instructions

To reproduce the stored checks using the VSTD CLI:

```bash
vstd reproduce receipts/{receipt.receipt_id}
```

Expected reproduction fidelity: `{receipt.reproducibility.get("highest_demonstrated_level", "CONTENT_IDENTICAL")}`.

---

*Generated by the VSTD-1 claim-mechanics reference runtime.*
"""
