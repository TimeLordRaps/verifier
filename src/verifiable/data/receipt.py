"""VSTD-Graph receipt model and canonical serialization.

Graph-1 receipts retain the frozen ``VSTD-DATA-0.1`` wire identifier.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from verifiable.core.checker import VerificationVerdict
from verifiable.core.provenance import ProvenanceRecord
from verifiable.core.receipt import compute_canonical_digest
from verifiable.data.models import CompletenessMetrics, ProvenanceHypergraph
from verifiable.data.policy import PolicyEvaluationResult


@dataclass(frozen=True)
class DatasetSpec:
    dataset_id: str
    title: str
    description: str
    target_artifact_id: str
    status: str
    falsification_condition: str
    last_verified: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "title": self.title,
            "description": self.description,
            "target_artifact_id": self.target_artifact_id,
            "status": self.status,
            "falsification_condition": self.falsification_condition,
            "last_verified": self.last_verified,
        }


@dataclass(frozen=True)
class DataIndependentAudit:
    overall_verdict: VerificationVerdict
    acyclic_hypergraph: bool
    integrity_passed: bool
    root_sources_count: int
    terminal_outputs_count: int
    transformations_count: int
    trusted_computing_base: dict[str, str]
    audit_notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_verdict": self.overall_verdict.value,
            "acyclic_hypergraph": self.acyclic_hypergraph,
            "integrity_passed": self.integrity_passed,
            "root_sources_count": self.root_sources_count,
            "terminal_outputs_count": self.terminal_outputs_count,
            "transformations_count": self.transformations_count,
            "trusted_computing_base": self.trusted_computing_base,
            "audit_notes": self.audit_notes,
        }


@dataclass
class VerifiableDataReceipt:
    schema_version: str
    receipt_id: str
    dataset_spec: DatasetSpec
    hypergraph: ProvenanceHypergraph
    completeness_metrics: CompletenessMetrics
    policy_evaluations: list[PolicyEvaluationResult]
    independent_audit: DataIndependentAudit
    provenance: ProvenanceRecord
    reproducibility: dict[str, Any]
    canonical_digest: str = ""
    execution_metadata: Optional[dict[str, Any]] = None

    def get_stable_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "dataset_spec": self.dataset_spec.to_dict(),
            "hypergraph": self.hypergraph.to_dict(),
            "completeness_metrics": self.completeness_metrics.to_dict(),
            "policy_evaluations": [p.to_dict() for p in self.policy_evaluations],
            "independent_audit": self.independent_audit.to_dict(),
            "provenance_stable": {
                "target_name": self.provenance.target_name,
                "portable_repository_id": self.provenance.portable_repository_id,
                "git_commit_sha": self.provenance.git.commit_sha,
                "git_branch": self.provenance.git.branch,
                "git_is_dirty": self.provenance.git.is_dirty,
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
        return compute_canonical_digest(stable) == self.canonical_digest

    def to_dict(self) -> dict[str, Any]:
        if not self.canonical_digest:
            self.compute_and_set_digest()
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "canonical_digest": self.canonical_digest,
            "dataset_spec": self.dataset_spec.to_dict(),
            "hypergraph": self.hypergraph.to_dict(),
            "completeness_metrics": self.completeness_metrics.to_dict(),
            "policy_evaluations": [p.to_dict() for p in self.policy_evaluations],
            "independent_audit": self.independent_audit.to_dict(),
            "provenance": self.provenance.to_dict(),
            "reproducibility": self.reproducibility,
            "execution_metadata": self.execution_metadata,
        }

    def save_to_directory(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        self.compute_and_set_digest()

        # 1. receipt.json
        receipt_path = out_dir / "receipt.json"
        receipt_path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

        # 2. manifest.json
        manifest = {
            "receipt_id": self.receipt_id,
            "canonical_digest": self.canonical_digest,
            "schema_version": self.schema_version,
            "files": {
                "receipt.json": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            },
        }
        (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

        # 3. report.md
        report_md = generate_data_receipt_markdown(self)
        (out_dir / "report.md").write_text(report_md, encoding="utf-8")

        # 4. Standalone reproduce.py
        reproduce_py = (
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))\n"
            "from verifiable.data.receipt import validate_data_receipt, reproduce_data_receipt\n\n"
            "if __name__ == '__main__':\n"
            "    r_dir = Path(__file__).parent\n"
            "    print(f'[*] Validating receipt {r_dir.name}...')\n"
            "    val = validate_data_receipt(r_dir)\n"
            "    if val == 0:\n"
            "        print('[*] Reproducing lineage hypergraph...')\n"
            "        sys.exit(reproduce_data_receipt(r_dir))\n"
            "    sys.exit(val)\n"
        )
        (out_dir / "reproduce.py").write_text(reproduce_py, encoding="utf-8")

        return receipt_path


def _receipt_file(path_or_dir: Path) -> Path:
    return path_or_dir / "receipt.json" if path_or_dir.is_dir() else path_or_dir


def _duplicate_ids(items: Any, key: str) -> list[str]:
    if not isinstance(items, list):
        return [f"hypergraph collection for {key} must be a list"]
    seen: set[str] = set()
    duplicates: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get(key), str):
            return [f"every hypergraph item in {key} collection must contain a string {key}"]
        identifier = item[key]
        if identifier in seen:
            duplicates.add(identifier)
        seen.add(identifier)
    return [f"duplicate {key}: {identifier}" for identifier in sorted(duplicates)]


def validate_data_receipt(receipt_path_or_dir: Path) -> int:
    """Validate a VSTD-DATA-0.1 receipt without a target-specific adapter."""
    receipt_file = _receipt_file(receipt_path_or_dir)
    if not receipt_file.exists():
        print(f"[FAIL] Receipt not found at {receipt_file}", file=sys.stderr)
        return 1

    try:
        data = json.loads(receipt_file.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[FAIL] Malformed JSON: {exc}", file=sys.stderr)
        return 1

    required = {
        "schema_version",
        "receipt_id",
        "canonical_digest",
        "dataset_spec",
        "hypergraph",
        "completeness_metrics",
        "policy_evaluations",
        "independent_audit",
        "provenance",
        "reproducibility",
    }
    missing = sorted(required - data.keys())
    if missing:
        print(f"[FAIL] Missing required fields: {', '.join(missing)}", file=sys.stderr)
        return 1
    if data.get("schema_version") != "VSTD-DATA-0.1":
        print(
            f"[FAIL] Unsupported dataset receipt schema: {data.get('schema_version')!r}",
            file=sys.stderr,
        )
        return 1

    provenance = data.get("provenance", {})
    provenance_stable = {
        "target_name": provenance.get("target_name"),
        "portable_repository_id": provenance.get("portable_repository_id"),
        "git_commit_sha": provenance.get("git", {}).get("commit_sha"),
        "git_branch": provenance.get("git", {}).get("branch"),
        "git_is_dirty": provenance.get("git", {}).get("is_dirty"),
        "runtime_python_version": provenance.get("runtime", {}).get("python_version"),
    }
    stable_payload = {
        "schema_version": data.get("schema_version"),
        "receipt_id": data.get("receipt_id"),
        "dataset_spec": data.get("dataset_spec"),
        "hypergraph": data.get("hypergraph"),
        "completeness_metrics": data.get("completeness_metrics"),
        "policy_evaluations": data.get("policy_evaluations"),
        "independent_audit": data.get("independent_audit"),
        "provenance_stable": provenance_stable,
        "reproducibility": data.get("reproducibility"),
    }
    recorded_digest = data.get("canonical_digest")
    recomputed = compute_canonical_digest(stable_payload)
    if recomputed != recorded_digest:
        print(
            f"[FAIL] Digest mismatch:\n  Recorded:   {recorded_digest}\n  Recomputed: {recomputed}",
            file=sys.stderr,
        )
        return 1

    graph_payload = data.get("hypergraph")
    if not isinstance(graph_payload, dict):
        print("[FAIL] hypergraph must be an object", file=sys.stderr)
        return 1
    graph_errors: list[str] = []
    for collection, key in (
        ("artifacts", "artifact_id"),
        ("transformations", "transformation_id"),
        ("contributors", "contributor_id"),
        ("rights", "rights_id"),
    ):
        graph_errors.extend(_duplicate_ids(graph_payload.get(collection), key))
    try:
        hypergraph = ProvenanceHypergraph.from_dict(graph_payload)
    except (KeyError, TypeError, ValueError) as exc:
        print(f"[FAIL] Cannot parse hypergraph: {exc}", file=sys.stderr)
        return 1
    graph_errors.extend(hypergraph.validate_structure())

    target_artifact_id = data.get("dataset_spec", {}).get("target_artifact_id")
    if target_artifact_id not in hypergraph.artifacts:
        graph_errors.append(f"dataset target artifact is missing: {target_artifact_id}")

    try:
        acyclic = hypergraph.verify_acyclicity()
    except (KeyError, TypeError, ValueError) as exc:
        graph_errors.append(f"acyclicity check failed: {exc}")
        acyclic = False
    completeness = hypergraph.compute_completeness()
    recorded_completeness = data.get("completeness_metrics")
    if completeness.to_dict() != recorded_completeness:
        graph_errors.append("recorded completeness metrics do not match the stored hypergraph")

    audit = data.get("independent_audit")
    if not isinstance(audit, dict):
        graph_errors.append("independent_audit must be an object")
        audit = {}
    expected_audit_fields = {
        "acyclic_hypergraph": acyclic,
        "integrity_passed": completeness.content_integrity == 1.0,
        "root_sources_count": len(hypergraph.root_sources()),
        "terminal_outputs_count": len(
            [artifact_id for artifact_id in hypergraph.artifacts if not hypergraph.outgoing_hyperedges(artifact_id)]
        ),
        "transformations_count": len(hypergraph.transformations),
    }
    for field_name, expected in expected_audit_fields.items():
        if audit.get(field_name) != expected:
            graph_errors.append(
                f"independent_audit.{field_name} does not match the stored hypergraph"
            )

    policy_evaluations = data.get("policy_evaluations")
    if not isinstance(policy_evaluations, list):
        graph_errors.append("policy_evaluations must be a list")
        policy_evaluations = []
    failed_policies = [
        policy.get("policy_id", "<unknown>")
        for policy in policy_evaluations
        if not isinstance(policy, dict) or policy.get("passed") is not True
    ]
    target_ancestors = hypergraph.ancestors([target_artifact_id]) if target_artifact_id in hypergraph.artifacts else set()
    non_valid_target_ancestors = sorted(
        artifact_id
        for artifact_id in target_ancestors
        if artifact_id not in hypergraph.artifacts
        or hypergraph.artifacts[artifact_id].status.value != "VALID"
    )
    conclusive_evidence_classes = {
        "CRYPTOGRAPHICALLY_BOUND",
        "DIRECTLY_OBSERVED",
        "REPRODUCED",
    }
    weak_target_artifact_evidence = sorted(
        artifact_id
        for artifact_id in target_ancestors
        if artifact_id in hypergraph.artifacts
        and hypergraph.artifacts[artifact_id].evidence_class.value
        not in conclusive_evidence_classes
    )
    target_transformations = [
        transform
        for transform in hypergraph.transformations.values()
        if any(port.artifact_id in target_ancestors for port in transform.outputs)
    ]
    weak_target_transformation_evidence = sorted(
        transform.transformation_id
        for transform in target_transformations
        if transform.evidence_class.value not in conclusive_evidence_classes
    )
    if audit.get("overall_verdict") == VerificationVerdict.VERIFIED.value:
        if (
            graph_errors
            or not acyclic
            or failed_policies
            or non_valid_target_ancestors
            or weak_target_artifact_evidence
            or weak_target_transformation_evidence
        ):
            graph_errors.append(
                "overall VERIFIED is incompatible with structural errors, failed policies, "
                "target ancestors not explicitly VALID, or target-lineage evidence that "
                "is only declared, imported, inferred, manual, or unknown"
            )

    if graph_errors:
        for error in graph_errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    print(f"[PASS] Dataset Receipt {data.get('receipt_id')} is valid.")
    print(f"       Schema: {data.get('schema_version')}")
    print(f"       Digest: {recorded_digest}")
    print(f"       Verdict: {data.get('independent_audit', {}).get('overall_verdict')}")
    print("       Scope: stored receipt + recorded hypergraph; upstream bytes not rehashed")
    return 0


def reproduce_data_receipt(receipt_path_or_dir: Path) -> int:
    """Recompute stored hypergraph structure after validating stable content.

    This is a verifier-mechanism replay over the content-identical stored receipt.
    It does not reconstruct unbundled upstream artifacts or target executions.
    """
    if validate_data_receipt(receipt_path_or_dir) != 0:
        return 1

    receipt_file = _receipt_file(receipt_path_or_dir)
    data = json.loads(receipt_file.read_text(encoding="utf-8"))
    hypergraph = ProvenanceHypergraph.from_dict(data["hypergraph"])

    start_time = time.perf_counter()
    acyclic = hypergraph.verify_acyclicity()
    completeness = hypergraph.compute_completeness()
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    print("[REPRODUCTION RESULT] Level: CONTENT_IDENTICAL")
    print("  Replay scope:       stored receipt digest + hypergraph mechanisms")
    print("  Upstream execution: NOT_RECONSTRUCTED")
    print(f"  Receipt ID:         {data.get('receipt_id')}")
    print(f"  Hypergraph Nodes:   {len(hypergraph.artifacts)}")
    print(f"  Hyperedges:         {len(hypergraph.transformations)}")
    print(f"  Acyclic Check:      {'PASSED' if acyclic else 'FAILED'}")
    print(f"  Coverage Summary:   {completeness.overall_completeness * 100:.1f}%")
    print(f"  Reproduction Time:  {elapsed_ms:.2f} ms")
    return 0 if acyclic else 1


def generate_data_receipt_markdown(receipt: VerifiableDataReceipt) -> str:
    spec = receipt.dataset_spec
    comp = receipt.completeness_metrics
    audit = receipt.independent_audit
    prov = receipt.provenance
    hg = receipt.hypergraph

    policies_md = "\n".join(
        f"- **{p.policy_name}** (`{p.policy_id}`): `{'PASSED' if p.passed else 'FAILED'}` — {p.explanation}"
        for p in receipt.policy_evaluations
    )

    artifacts_md = "\n".join(
        f"| `{a.artifact_id}` | {a.label} | `{a.artifact_type.value}` | `{a.content_digest[:16]}...` | {a.byte_size:,} B | `{a.status.value}` |"
        for a in hg.artifacts.values()
    )

    transforms_md = "\n".join(
        f"| `{t.transformation_id}` | {t.label} | `{t.transformation_type.value}` | {len(t.inputs)} in &rarr; {len(t.outputs)} out | `{t.software_provenance.get('commit_sha', 'N/A')[:8]}` |"
        for t in hg.transformations.values()
    )

    return (
        f"# VERIFIABLE Dataset Provenance Report — {receipt.receipt_id}\n\n"
        f"> **Canonical Digest:** `{receipt.canonical_digest}`  \n"
        f"> **Schema Version:** `{receipt.schema_version}`  \n"
        f"> **Target Artifact:** `{spec.target_artifact_id}`  \n"
        f"> **Audit Verdict:** `{audit.overall_verdict.value}`  \n\n"
        f"---\n\n"
        f"## 1. Dataset & Artifact Specification\n\n"
        f"- **Receipt ID:** `{receipt.receipt_id}`\n"
        f"- **Dataset Title:** {spec.title}\n"
        f"- **Description:** {spec.description}\n"
        f"- **Status:** `{spec.status}`\n"
        f"- **Falsification Condition:** {spec.falsification_condition}\n\n"
        f"---\n\n"
        f"## 2. Provenance Completeness Profile\n\n"
        f"- Source Coverage: {comp.source_coverage * 100:.1f}%\n"
        f"- Transformation Coverage: {comp.transformation_coverage * 100:.1f}%\n"
        f"- Content-Digest Declaration Coverage: {comp.content_integrity * 100:.1f}%\n"
        f"- License-Metadata Coverage: {comp.license_coverage * 100:.1f}%\n"
        f"- Contributor Coverage: {comp.contributor_coverage * 100:.1f}%\n"
        f"- Lineage Topological Depth: {comp.lineage_depth}\n"
        f"- Overall Weighted Coverage Summary: {comp.overall_completeness * 100:.1f}%\n\n"
        f"> Coverage metrics describe recorded fields. They are not trust probabilities,\n"
        f"> legal conclusions, or evidence that unbundled physical files were rehashed.\n\n"
        f"| Dimension | Metric Value | Benchmark Threshold | Status |\n"
        f"| :--- | :--- | :--- | :--- |\n"
        f"| **Source Coverage** | `{comp.source_coverage * 100:.1f}%` | >= 80% | {'PASS' if comp.source_coverage >= 0.8 else 'WARN'} |\n"
        f"| **Transformation Coverage** | `{comp.transformation_coverage * 100:.1f}%` | >= 80% | {'PASS' if comp.transformation_coverage >= 0.8 else 'WARN'} |\n"
        f"| **Content-Digest Declaration Coverage** | `{comp.content_integrity * 100:.1f}%` | 100% | {'PASS' if comp.content_integrity == 1.0 else 'WARN'} |\n"
        f"| **License-Metadata Coverage** | `{comp.license_coverage * 100:.1f}%` | 100% | {'PASS' if comp.license_coverage == 1.0 else 'WARN'} |\n"
        f"| **Contributor Coverage** | `{comp.contributor_coverage * 100:.1f}%` | >= 80% | {'PASS' if comp.contributor_coverage >= 0.8 else 'WARN'} |\n"
        f"| **Lineage Topological Depth** | `{comp.lineage_depth}` | >= 1 | VALID |\n"
        f"| **Overall Weighted Coverage Summary** | `{comp.overall_completeness * 100:.1f}%` | >= 85% | {'PASS' if comp.overall_completeness >= 0.85 else 'WARN'} |\n\n"
        f"---\n\n"
        f"## 3. Formal Invariant & Policy Verification (SAT-Gated)\n\n"
        f"{policies_md}\n\n"
    ) + f"""## 4. Hypergraph Structure ({len(hg.artifacts)} Artifacts, {len(hg.transformations)} Hyperedges)

### Artifacts
| Artifact ID | Label | Type | Content Digest (Prefix) | Size | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
{artifacts_md}

### Transformation Hyperedges
| Transformation ID | Label | Type | Topology | Commit SHA |
| :--- | :--- | :--- | :--- | :--- |
{transforms_md}

---

## 5. Independent Auditor & Trusted Computing Base (TCB)

- **Acyclicity Verified:** {'PASSED (No cycles)' if audit.acyclic_hypergraph else 'FAILED (Cycle detected)'}
- **Content-Digest Declaration Check:** {'PASSED' if audit.integrity_passed else 'FAILED'}
- **Overall Independent Verdict:** {audit.overall_verdict.value}

### TCB Declaration
```yaml
{chr(10).join(f"{k}: {v}" for k, v in audit.trusted_computing_base.items())}
```

---

## 6. Upstream Source & Environment Provenance

- **Target Repository:** {prov.portable_repository_id}
- **Git Commit SHA:** {prov.git.commit_sha}
- **Git Branch:** {prov.git.branch} (dirty: {prov.git.is_dirty})
- **Python / OS:** {prov.runtime.python_version} ({prov.runtime.platform_system} {prov.runtime.platform_release})
- **Execution Timestamp:** {prov.captured_at_utc}

---

## 7. Independent Reproduction

To independently inspect and reproduce this dataset hypergraph receipt:

```bash
verifiable data verify receipts/{receipt.receipt_id}
verifiable data trace {spec.target_artifact_id} --receipt receipts/{receipt.receipt_id}
```

*Generated by VERIFIABLE Data Runtime v0.1.0 (VSTD-DATA-0.1)*
"""
