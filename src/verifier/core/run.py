"""Terminology: JavaScript Object Notation (JSON); Boolean satisfiability problem (SAT);
Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD);
YAML Ain't Markup Language (YAML).

Generic computational run receipt capture for VSTD.

This module implements the smallest working version of the "wrap any consequential
computation and get a receipt" primitive described in the VSTD program graph.
It deliberately reuses the existing VSTD-0.1 canonicalization/digest machinery
(``verifier.core.receipt``), provenance discovery (``verifier.core.provenance``),
and reproducibility taxonomy (``verifier.core.reproducibility``) rather than
introducing a parallel schema. No new standard version is declared here — this is
an implementation living under ``schema_version = "VSTD-0.1"`` with a distinct
``receipt_kind`` discriminator (``generic_computational_run``) so existing
legacy ``VstdReceipt`` documents (SAT/derivation-shaped, without this discriminator)
and ``VstdDataReceipt`` (dataset-provenance-shaped) documents are untouched.

Design commitments (do not weaken without updating tests + docs):

1. **Claims are not flattened.** "The command exited 0", "the declared output files
   exist with these digests", "an evaluator computed this metric", "the run's inputs
   trace to a provenance root", and "an external party reported a score" are five
   different, independently falsifiable statements. They are recorded as five
   distinct fields under :class:`RunClaims`, never collapsed into one boolean.
2. **Fail closed.** A missing declared input aborts the run *before* executing the
   command (no fabricated "it probably would have worked"). A missing declared
   output after execution is recorded as ``MISSING_OUTPUT``, not silently ignored.
   Commands must be given as an argv list — no ``shell=True`` and no string
   commands are accepted, closing off the shell-indirection attack class.
3. **External evaluation is never auto-promoted.** If a manifest declares that an
   organizer/leaderboard reported a score, that is stored as an
   :class:`ExternalEvaluationEvidence` record with ``attested=False``. A supplied
   evidence reference is recorded but not dereferenced or verified by this runtime.
   Its presence never flips any locally checked claim to true.
4. **Reproduction fidelity is classified, not asserted.** Rehashing on-disk output
   artifacts (always available, side-effect free) is distinguished from re-running
   the recorded command (only performed when explicitly requested via ``rerun``).
   The generic rerun compares the declared output bytes and execution outcome, so
   it can establish only scoped ``CONTENT_IDENTICAL``; a determinism declaration
   earns no level.
"""

from __future__ import annotations

import hashlib
import json
import platform as _platform
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Optional

from verifier.core.provenance import (
    ProvenanceRecord,
    capture_provenance,
    sha256_file,
)
from verifier.core.receipt import compute_canonical_digest
from verifier.core.reproducibility import ReproducibilityLevel

RUN_SCHEMA_VERSION = "VSTD-0.1"
RUN_RECEIPT_KIND = "generic_computational_run"

_SNIPPET_LIMIT = 4000
_DEFAULT_TIMEOUT_SECONDS = 300
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _digest_if_available(path: Path, label: str, *alternatives: Path) -> str:
    for candidate in (path, *alternatives):
        try:
            return "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        except OSError:
            continue
    return f"UNAVAILABLE:{label}"


def _legacy_generic_run_binding(
    manifest: Mapping[str, Any],
    *,
    falsification_condition: str,
) -> dict[str, Any]:
    """Serialize generic assessment context into the historical wire container.

    ``layer4_binding`` was introduced by the version 1.0.0 generic-run writer,
    but none of its positive content establishes VSTD-4. Older receipts omit the
    block and retain their canonical digests. Version 1.2.0 continues to emit the
    legacy shape so declared context is not silently dropped under the frozen
    profile; a clean replacement requires an explicit later profile boundary.
    """
    raw_bounds = manifest.get("resource_bounds", {})
    if not isinstance(raw_bounds, Mapping):
        raise RunError("resource_bounds must be an object")
    bound_fields = (
        "verification_cost_bound",
        "memory_bound",
        "certificate_size_bound",
    )
    unknown_bounds = sorted(set(raw_bounds) - set(bound_fields))
    if unknown_bounds:
        raise RunError(f"resource_bounds has unknown fields: {', '.join(unknown_bounds)}")
    bounds: dict[str, int] = {}
    for name in bound_fields:
        value = raw_bounds.get(name, 0)
        if type(value) is not int or value < 0:
            raise RunError(f"resource_bounds.{name} must be a non-negative integer")
        bounds[name] = value

    raw_surface = manifest.get("refutation_surface")
    if raw_surface is not None and not isinstance(raw_surface, Mapping):
        raise RunError("refutation_surface must be an object")
    surface = dict(raw_surface or {})
    surface.setdefault("admissible_refutations", [])
    surface.setdefault("excluded_claims", ["PHYSICAL_WORLD_COMPLETENESS"])
    surface.setdefault("legacy_falsification_condition", falsification_condition)
    for name in ("admissible_refutations", "excluded_claims"):
        if not isinstance(surface[name], list) or not all(
            isinstance(item, str) for item in surface[name]
        ):
            raise RunError(f"refutation_surface.{name} must be an array of strings")
    if not isinstance(surface["legacy_falsification_condition"], str):
        raise RunError("refutation_surface.legacy_falsification_condition must be a string")

    here = Path(__file__).resolve()
    specification = here.parents[3] / "standard" / "VSTD-1.md"
    packaged_specification = here.parents[1] / "specifications" / "VSTD-1.md"
    verifier = {
        "specification_hash": _digest_if_available(
            specification, "standard/VSTD-1.md", packaged_specification
        ),
        "implementation_hash": _digest_if_available(here, "core/run.py"),
        "parser_hash": _digest_if_available(here, "core/run.py"),
        "certificate_format": "VSTD1-GENERIC-RUN",
        "format_fragment": "CAPTURE,VALIDATE,REPRODUCE",
        "dependencies": ["python-stdlib"],
        "deterministic": True,
    }
    return {
        "verifier": verifier,
        "vstd4_conformance": "NOT_EVALUATED",
        "resource_bounds": bounds,
        "prior_commitment": str(manifest.get("prior_commitment", "")),
        "refutation_surface": surface,
    }


class RunError(RuntimeError):
    """Raised for manifest or capture errors that must fail closed."""


class RunOutcome(str, Enum):
    COMPLETED = "COMPLETED"
    NONZERO_EXIT = "NONZERO_EXIT"
    MISSING_INPUT = "MISSING_INPUT"
    MISSING_OUTPUT = "MISSING_OUTPUT"
    TIMEOUT = "TIMEOUT"
    EXCEPTION = "EXCEPTION"


class DeterminismDeclaration(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    NONDETERMINISTIC = "NONDETERMINISTIC"
    UNKNOWN = "UNKNOWN"


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ArtifactRef:
    path: str
    role: str
    present: bool
    sha256: Optional[str] = None
    byte_size: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "role": self.role,
            "present": self.present,
            "sha256": self.sha256,
            "byte_size": self.byte_size,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ArtifactRef":
        return cls(
            path=d["path"],
            role=d.get("role", "unspecified"),
            present=bool(d.get("present", False)),
            sha256=d.get("sha256"),
            byte_size=d.get("byte_size"),
        )


def _hash_artifact(base_dir: Path, path_str: str, role: str) -> ArtifactRef:
    p = (base_dir / path_str)
    if not p.exists() or not p.is_file():
        return ArtifactRef(path=path_str, role=role, present=False)
    return ArtifactRef(
        path=path_str,
        role=role,
        present=True,
        sha256=sha256_file(p),
        byte_size=p.stat().st_size,
    )


@dataclass(frozen=True)
class ExecutionRecord:
    command: tuple[str, ...]
    cwd: str
    started_at_utc: str
    ended_at_utc: str
    elapsed_ms: float
    exit_code: Optional[int]
    outcome: str
    python_version: str
    platform_system: str
    determinism_declared: str
    seed_declared: Optional[str]
    stdout_sha256: str
    stderr_sha256: str
    stdout_snippet: str
    stderr_snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "cwd": self.cwd,
            "started_at_utc": self.started_at_utc,
            "ended_at_utc": self.ended_at_utc,
            "elapsed_ms": self.elapsed_ms,
            "exit_code": self.exit_code,
            "outcome": self.outcome,
            "python_version": self.python_version,
            "platform_system": self.platform_system,
            "determinism_declared": self.determinism_declared,
            "seed_declared": self.seed_declared,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_snippet": self.stdout_snippet,
            "stderr_snippet": self.stderr_snippet,
        }


@dataclass(frozen=True)
class EvaluatorClaim:
    """"An evaluator computed metric M" — distinct from "the metric is true"."""

    evaluator_name: str
    metric_name: str
    value: Any
    computed_by: str  # "bound_output_extraction" | "declared_by_manifest_author"
    verified_independently: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluator_name": self.evaluator_name,
            "metric_name": self.metric_name,
            "value": self.value,
            "computed_by": self.computed_by,
            "verified_independently": self.verified_independently,
        }


@dataclass(frozen=True)
class ExternalEvaluationEvidence:
    """Explicit, bounded slot for organizer/third-party reported results.

    Presence of this record NEVER means the runtime cryptographically or
    independently verified the external event described. ``evidence_kind`` and
    ``evidence_ref`` preserve what the manifest supplied; ``attested`` remains
    false because this capture path does not dereference or verify that evidence.
    """

    source: str
    description: str
    reported_value: Any
    evidence_kind: str  # "UNVERIFIED_ASSERTION" | "LINKED_ARTIFACT" | "SIGNED_ATTESTATION"
    evidence_ref: Optional[str]
    attested: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "description": self.description,
            "reported_value": self.reported_value,
            "evidence_kind": self.evidence_kind,
            "evidence_ref": self.evidence_ref,
            "attested": self.attested,
        }

    @classmethod
    def from_manifest(cls, d: Mapping[str, Any]) -> "ExternalEvaluationEvidence":
        evidence_kind = str(d.get("evidence_kind", "UNVERIFIED_ASSERTION")).upper()
        return cls(
            source=str(d.get("source", "unspecified")),
            description=str(d.get("description", "")),
            reported_value=d.get("reported_value"),
            evidence_kind=evidence_kind,
            evidence_ref=d.get("evidence_ref"),
            attested=False,
        )


@dataclass(frozen=True)
class ProvenanceLinkage:
    """Link from this run to a VSTD-Graph provenance hypergraph artifact.

    Answers "which exact source artifacts and transformations are recorded as
    upstream of this run" by reusing the existing Dataset Provenance Hypergraph
    runtime rather than a parallel lineage system. A linkage does not by itself
    establish causal influence.
    """

    dataset_receipt_path: str
    artifact_id: str
    found_in_hypergraph: bool
    ancestor_count: Optional[int]
    ancestor_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_receipt_path": self.dataset_receipt_path,
            "artifact_id": self.artifact_id,
            "found_in_hypergraph": self.found_in_hypergraph,
            "ancestor_count": self.ancestor_count,
            "ancestor_ids": list(self.ancestor_ids),
        }


def _resolve_provenance_linkage(base_dir: Path, root: Mapping[str, Any]) -> ProvenanceLinkage:
    from verifier.data.models import ProvenanceHypergraph

    receipt_path_str = str(root["dataset_receipt_path"])
    artifact_id = str(root["artifact_id"])
    receipt_dir = (base_dir / receipt_path_str)
    receipt_file = receipt_dir / "receipt.json" if receipt_dir.is_dir() else receipt_dir
    if not receipt_file.exists():
        return ProvenanceLinkage(
            dataset_receipt_path=receipt_path_str,
            artifact_id=artifact_id,
            found_in_hypergraph=False,
            ancestor_count=None,
            ancestor_ids=(),
        )
    data = json.loads(receipt_file.read_text(encoding="utf-8"))
    hg = ProvenanceHypergraph.from_dict(data["hypergraph"])
    found = artifact_id in hg.artifacts
    ancestors: tuple[str, ...] = ()
    if found:
        ancestors = tuple(sorted(hg.ancestors([artifact_id])))
    return ProvenanceLinkage(
        dataset_receipt_path=receipt_path_str,
        artifact_id=artifact_id,
        found_in_hypergraph=found,
        ancestor_count=len(ancestors) if found else None,
        ancestor_ids=ancestors,
    )


@dataclass
class RunClaims:
    """Distinct, non-flattened claims a run receipt may make.

    Each field is an independently falsifiable statement. They must never be
    collapsed into a single pass/fail boolean — see module docstring.
    """

    execution_completed: bool
    output_digests_recorded: bool
    all_declared_artifacts_present: Optional[bool]
    evaluator_claims: list[EvaluatorClaim]
    external_evaluation: Optional[ExternalEvaluationEvidence]

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_completed": self.execution_completed,
            "output_digests_recorded": self.output_digests_recorded,
            "all_declared_artifacts_present": self.all_declared_artifacts_present,
            "evaluator_claims": [e.to_dict() for e in self.evaluator_claims],
            "external_evaluation": self.external_evaluation.to_dict() if self.external_evaluation else None,
        }


@dataclass
class GenericRunReceipt:
    schema_version: str
    receipt_kind: str
    receipt_id: str
    claim_title: str
    claim_statement: str
    claim_scope: str
    claim_limitations: tuple[str, ...]
    falsification_condition: str
    source_state: ProvenanceRecord
    inputs: tuple[ArtifactRef, ...]
    outputs: tuple[ArtifactRef, ...]
    execution: ExecutionRecord
    claims: RunClaims
    provenance_linkage: tuple[ProvenanceLinkage, ...]
    reproducibility: dict[str, Any]
    # Historical VSTD-0.1 wire name; this is generic assessment context, not VSTD-4.
    layer4_binding: Optional[dict[str, Any]] = None
    canonical_digest: str = ""

    def get_stable_payload(self) -> dict[str, Any]:
        """Deterministic, location-independent fields used for the canonical digest.

        Excludes wall-clock timestamps, elapsed milliseconds, and human-readable
        stdout/stderr *snippets* (truncated previews) — mirroring the exclusion
        pattern already established by ``VstdReceipt.get_stable_payload``.
        The exact stdout/stderr SHA-256 hashes ARE included: they are exact
        evidence of execution content, not volatile presentation.
        """
        payload = {
            "schema_version": self.schema_version,
            "receipt_kind": self.receipt_kind,
            "receipt_id": self.receipt_id,
            "claim_title": self.claim_title,
            "claim_statement": self.claim_statement,
            "claim_scope": self.claim_scope,
            "claim_limitations": list(self.claim_limitations),
            "falsification_condition": self.falsification_condition,
            "source_state_stable": {
                "target_name": self.source_state.target_name,
                "portable_repository_id": self.source_state.portable_repository_id,
                "git_commit_sha": self.source_state.git.commit_sha,
                "git_branch": self.source_state.git.branch,
                "git_is_dirty": self.source_state.git.is_dirty,
                "git_dirty_files": list(self.source_state.git.dirty_files),
                "source_file_hashes": dict(self.source_state.source_file_hashes),
                "runtime_python_version": self.source_state.runtime.python_version,
            },
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "execution_stable": {
                "command": list(self.execution.command),
                "cwd": self.execution.cwd,
                "exit_code": self.execution.exit_code,
                "outcome": self.execution.outcome,
                "python_version": self.execution.python_version,
                "platform_system": self.execution.platform_system,
                "determinism_declared": self.execution.determinism_declared,
                "seed_declared": self.execution.seed_declared,
                "stdout_sha256": self.execution.stdout_sha256,
                "stderr_sha256": self.execution.stderr_sha256,
            },
            "claims": self.claims.to_dict(),
            "provenance_linkage": [p.to_dict() for p in self.provenance_linkage],
            "reproducibility": self.reproducibility,
        }
        if self.layer4_binding is not None:
            payload["layer4_binding"] = self.layer4_binding
        return payload

    def compute_and_set_digest(self) -> str:
        self.canonical_digest = compute_canonical_digest(self.get_stable_payload())
        return self.canonical_digest

    def verify_digest_integrity(self) -> bool:
        return compute_canonical_digest(self.get_stable_payload()) == self.canonical_digest

    def to_dict(self) -> dict[str, Any]:
        if not self.canonical_digest:
            self.compute_and_set_digest()
        payload = {
            "schema_version": self.schema_version,
            "receipt_kind": self.receipt_kind,
            "receipt_id": self.receipt_id,
            "canonical_digest": self.canonical_digest,
            "claim_title": self.claim_title,
            "claim_statement": self.claim_statement,
            "claim_scope": self.claim_scope,
            "claim_limitations": list(self.claim_limitations),
            "falsification_condition": self.falsification_condition,
            "source_state": self.source_state.to_dict(),
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "execution": self.execution.to_dict(),
            "claims": self.claims.to_dict(),
            "provenance_linkage": [p.to_dict() for p in self.provenance_linkage],
            "reproducibility": self.reproducibility,
        }
        if self.layer4_binding is not None:
            payload["layer4_binding"] = self.layer4_binding
        return payload

    def save_to_directory(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        self.compute_and_set_digest()

        receipt_path = out_dir / "receipt.json"
        receipt_path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

        # NOTE: named `receipt_manifest.json`, deliberately NOT `manifest.json` — a run
        # receipt is typically saved into the same directory as the user-authored run
        # manifest (`manifest.json`, the input to `vstd run`), and that file must
        # never be overwritten by this digest-summary file.
        manifest_hash_entry = {
            "receipt_id": self.receipt_id,
            "canonical_digest": self.canonical_digest,
            "schema_version": self.schema_version,
            "receipt_kind": self.receipt_kind,
            "files": {
                "receipt.json": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            },
        }
        (out_dir / "receipt_manifest.json").write_text(
            json.dumps(manifest_hash_entry, indent=2, sort_keys=True), encoding="utf-8"
        )

        logs_dir = out_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        log_content = (
            f"Command: {' '.join(self.execution.command)}\n"
            f"CWD: {self.execution.cwd}\n"
            f"Outcome: {self.execution.outcome}\n"
            f"Exit code: {self.execution.exit_code}\n"
            f"Started: {self.execution.started_at_utc}\n"
            f"Ended: {self.execution.ended_at_utc}\n"
            f"Elapsed: {self.execution.elapsed_ms:.2f} ms\n"
            f"--- STDOUT ---\n{self.execution.stdout_snippet}\n"
            f"--- STDERR ---\n{self.execution.stderr_snippet}\n"
        )
        (logs_dir / "execution.log").write_text(log_content, encoding="utf-8")

        (out_dir / "report.md").write_text(generate_run_receipt_markdown(self), encoding="utf-8")
        return receipt_path


def generate_run_receipt_markdown(receipt: GenericRunReceipt) -> str:
    src = receipt.source_state
    ex = receipt.execution
    c = receipt.claims

    inputs_md = "\n".join(
        f"| `{i.path}` | {i.role} | {'present' if i.present else '**MISSING**'} | `{(i.sha256 or '')[:16]}` | {i.byte_size} |"
        for i in receipt.inputs
    ) or "| _(none declared)_ | | | | |"

    outputs_md = "\n".join(
        f"| `{o.path}` | {o.role} | {'present' if o.present else '**MISSING**'} | `{(o.sha256 or '')[:16]}` | {o.byte_size} |"
        for o in receipt.outputs
    ) or "| _(none declared)_ | | | | |"

    evaluator_md = "\n".join(
        f"- **{e.evaluator_name}** / `{e.metric_name}` = `{e.value}` "
        f"(computed_by=`{e.computed_by}`, verified_independently=`{e.verified_independently}`)"
        for e in c.evaluator_claims
    ) or "_(no evaluator claims declared)_"

    if c.external_evaluation:
        ext = c.external_evaluation
        external_md = (
            f"- **Source:** {ext.source}\n"
            f"- **Description:** {ext.description}\n"
            f"- **Reported value:** `{ext.reported_value}`\n"
            f"- **Evidence kind:** `{ext.evidence_kind}`\n"
            f"- **Evidence reference:** `{ext.evidence_ref}`\n"
            f"- **Verified by this runtime:** `{ext.attested}` "
            "(the reference is recorded but not dereferenced or independently checked)\n"
        )
    else:
        external_md = "_(no external evaluation evidence declared — this run makes no claim about any external score, leaderboard, or organizer report)_"

    linkage_md = "\n".join(
        f"- `{p.artifact_id}` in `{p.dataset_receipt_path}`: "
        f"{'FOUND' if p.found_in_hypergraph else 'NOT FOUND'}"
        + (f", {p.ancestor_count} recorded ancestors" if p.found_in_hypergraph else "")
        for p in receipt.provenance_linkage
    ) or "_(no provenance roots declared)_"

    return f"""# VSTD Generic Run Receipt — {receipt.receipt_id}

> **Canonical Digest:** `{receipt.canonical_digest}`
> **Schema:** `{receipt.schema_version}` (`receipt_kind={receipt.receipt_kind}`)
> **Execution Outcome:** `{ex.outcome}`

---

## 1. Declared Claim

- **Title:** {receipt.claim_title}
- **Statement:** {receipt.claim_statement}
- **Scope:** {receipt.claim_scope}
- **Falsification condition:** {receipt.falsification_condition}

### Bounded Limitations
{chr(10).join(f"- {lim}" for lim in receipt.claim_limitations) or "- (none declared)"}

---

## 2. What Was and Was Not Checked (distinct claims — not flattened)

| Claim | Value |
| :--- | :--- |
| Execution completed (exit 0, no missing declared inputs) | `{c.execution_completed}` |
| Output digests recorded (all declared outputs hashed) | `{c.output_digests_recorded}` |
| All declared artifacts present | `{c.all_declared_artifacts_present}` |

### Evaluator Claims (local, reference-computed unless noted)
{evaluator_md}

### External Evaluation Evidence (explicit, non-authoritative slot)
{external_md}

---

## 3. Source State

- **Repository:** `{src.portable_repository_id}`
- **Git commit:** `{src.git.commit_sha}`
- **Branch:** `{src.git.branch}` (dirty: `{src.git.is_dirty}`)
- **Dirty files:** `{list(src.git.dirty_files)}`

## 4. Execution Record

- **Command:** `{' '.join(ex.command)}`
- **CWD:** `{ex.cwd}`
- **Exit code:** `{ex.exit_code}`
- **Determinism declared:** `{ex.determinism_declared}`
- **Stdout SHA-256:** `{ex.stdout_sha256}`
- **Stderr SHA-256:** `{ex.stderr_sha256}`

## 5. Declared Inputs

| Path | Role | Status | SHA-256 (prefix) | Bytes |
| :--- | :--- | :--- | :--- | :--- |
{inputs_md}

## 6. Declared Outputs

| Path | Role | Status | SHA-256 (prefix) | Bytes |
| :--- | :--- | :--- | :--- | :--- |
{outputs_md}

---

## 7. Dataset Provenance Linkage

{linkage_md}

---

## 8. Reproduction

```bash
vstd reproduce <receipt-dir>
```

Highest demonstrated reproduction fidelity: `{receipt.reproducibility.get("highest_demonstrated_level") or "NOT YET REPRODUCED"}`.
Declared supported ceiling (bundled mechanism): `{receipt.reproducibility.get("declared_ceiling")}`.

---

*Generated by VSTD Generic Run Runtime (VSTD-0.1, receipt_kind=generic_computational_run).*
"""


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    text = manifest_path.read_text(encoding="utf-8")
    if manifest_path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RunError(
                "YAML manifest support is optional; install verifier-standard[yaml] or use JSON"
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise RunError(f"Manifest at {manifest_path} must decode to a JSON/YAML object.")
    return data


def _validated_command(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    command = manifest.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(c, str) for c in command):
        raise RunError(
            "manifest 'command' must be a non-empty list of strings (argv form). "
            "String/shell commands are rejected to close off shell-indirection attacks."
        )
    return tuple(command)


def describe_run_plan(manifest: Mapping[str, Any], manifest_dir: Path) -> dict[str, Any]:
    """Return the observable execution and capture paths without executing them.

    This is a review aid, not a sandbox analysis. A subprocess may access resources
    that are not named in a manifest, so the result deliberately says that the
    command's effective access remains outside VSTD's observation boundary.
    """

    command = _validated_command(manifest)
    root = manifest_dir.resolve()

    def path_record(path_value: Any) -> dict[str, Any]:
        declared = str(path_value)
        resolved = (root / declared).resolve()
        try:
            resolved.relative_to(root)
            outside = False
        except ValueError:
            outside = True
        return {
            "declared": declared,
            "resolved": str(resolved),
            "outside_manifest_directory": outside,
        }

    def artifacts(key: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for entry in manifest.get(key, []):
            if not isinstance(entry, Mapping) or "path" not in entry:
                raise RunError(f"manifest '{key}' entries must be objects with a path")
            record = path_record(entry["path"])
            record["role"] = str(entry.get("role", key[:-1]))
            record["present_before_execution"] = Path(record["resolved"]).is_file()
            result.append(record)
        return result

    return {
        "executes_without_sandbox": True,
        "manifest_directory": str(root),
        "command": list(command),
        "cwd": path_record(manifest.get("cwd", ".")),
        "repo_dir": path_record(manifest.get("repo_dir", ".")),
        "inputs": artifacts("inputs"),
        "outputs": artifacts("outputs"),
        "observation_limit": (
            "Declared paths describe receipt capture only; they do not confine the "
            "subprocess or enumerate everything it may access."
        ),
    }


def capture_run(
    manifest: Mapping[str, Any],
    manifest_dir: Path,
    receipt_id: Optional[str] = None,
) -> GenericRunReceipt:
    """Execute the manifest-declared command and capture a computational run receipt.

    Fails closed (raises :class:`RunError`) on manifest shape errors that would
    otherwise silently under-specify the claim (non-list command, absent claim
    block). Missing input/output *files* are not raised as exceptions — they are
    recorded as a falsified claim in the receipt itself, which is the more useful
    evidentiary behavior for an auditor inspecting the artifact later.
    """
    command_tuple = _validated_command(manifest)

    claim_block = manifest.get("claim") or {}
    rid = receipt_id or claim_block.get("id") or "RUN-UNSPECIFIED"

    cwd_rel = manifest.get("cwd", ".")
    cwd = (manifest_dir / cwd_rel).resolve()

    repo_dir = (manifest_dir / manifest.get("repo_dir", ".")).resolve()

    declared_inputs = manifest.get("inputs", [])
    declared_outputs = manifest.get("outputs", [])

    input_refs = tuple(
        _hash_artifact(manifest_dir, str(i["path"]), str(i.get("role", "input")))
        for i in declared_inputs
    )
    missing_inputs = [i for i in input_refs if not i.present]

    determinism = str(manifest.get("determinism_declared", DeterminismDeclaration.UNKNOWN.value)).upper()
    seed_declared = manifest.get("seed")
    seed_str = None if seed_declared is None else str(seed_declared)

    started_at = _now_utc()
    start_perf = time.perf_counter()

    if missing_inputs:
        # Fail closed: do not execute the command against an incomplete input set.
        ended_at = _now_utc()
        execution = ExecutionRecord(
            command=command_tuple,
            cwd=str(cwd_rel),
            started_at_utc=started_at,
            ended_at_utc=ended_at,
            elapsed_ms=0.0,
            exit_code=None,
            outcome=RunOutcome.MISSING_INPUT.value,
            python_version=_platform.python_version(),
            platform_system=_platform.system(),
            determinism_declared=determinism,
            seed_declared=seed_str,
            stdout_sha256=_sha256_bytes(b""),
            stderr_sha256=_sha256_bytes(b""),
            stdout_snippet="",
            stderr_snippet=f"BLOCKED: missing declared input(s): {[i.path for i in missing_inputs]}",
        )
        output_refs: tuple[ArtifactRef, ...] = tuple(
            ArtifactRef(path=str(o["path"]), role=str(o.get("role", "output")), present=False)
            for o in declared_outputs
        )
    else:
        try:
            proc = subprocess.run(
                list(command_tuple),
                cwd=str(cwd),
                capture_output=True,
                timeout=int(manifest.get("timeout_seconds", _DEFAULT_TIMEOUT_SECONDS)),
                shell=False,
            )
            elapsed_ms = (time.perf_counter() - start_perf) * 1000.0
            ended_at = _now_utc()
            stdout_bytes, stderr_bytes = proc.stdout or b"", proc.stderr or b""
            output_refs = tuple(
                _hash_artifact(manifest_dir, str(o["path"]), str(o.get("role", "output")))
                for o in declared_outputs
            )
            missing_outputs = [o for o in output_refs if not o.present]
            if proc.returncode != 0:
                outcome = RunOutcome.NONZERO_EXIT
            elif missing_outputs:
                outcome = RunOutcome.MISSING_OUTPUT
            else:
                outcome = RunOutcome.COMPLETED
            execution = ExecutionRecord(
                command=command_tuple,
                cwd=str(cwd_rel),
                started_at_utc=started_at,
                ended_at_utc=ended_at,
                elapsed_ms=elapsed_ms,
                exit_code=proc.returncode,
                outcome=outcome.value,
                python_version=_platform.python_version(),
                platform_system=_platform.system(),
                determinism_declared=determinism,
                seed_declared=seed_str,
                stdout_sha256=_sha256_bytes(stdout_bytes),
                stderr_sha256=_sha256_bytes(stderr_bytes),
                stdout_snippet=stdout_bytes.decode("utf-8", errors="replace")[:_SNIPPET_LIMIT],
                stderr_snippet=stderr_bytes.decode("utf-8", errors="replace")[:_SNIPPET_LIMIT],
            )
        except subprocess.TimeoutExpired as exc:
            elapsed_ms = (time.perf_counter() - start_perf) * 1000.0
            execution = ExecutionRecord(
                command=command_tuple,
                cwd=str(cwd_rel),
                started_at_utc=started_at,
                ended_at_utc=_now_utc(),
                elapsed_ms=elapsed_ms,
                exit_code=None,
                outcome=RunOutcome.TIMEOUT.value,
                python_version=_platform.python_version(),
                platform_system=_platform.system(),
                determinism_declared=determinism,
                seed_declared=seed_str,
                stdout_sha256=_sha256_bytes(exc.stdout or b""),
                stderr_sha256=_sha256_bytes(exc.stderr or b""),
                stdout_snippet="",
                stderr_snippet=f"TIMEOUT after {manifest.get('timeout_seconds', _DEFAULT_TIMEOUT_SECONDS)}s",
            )
            output_refs = tuple(
                ArtifactRef(path=str(o["path"]), role=str(o.get("role", "output")), present=False)
                for o in declared_outputs
            )
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any failure must still receipt
            execution = ExecutionRecord(
                command=command_tuple,
                cwd=str(cwd_rel),
                started_at_utc=started_at,
                ended_at_utc=_now_utc(),
                elapsed_ms=(time.perf_counter() - start_perf) * 1000.0,
                exit_code=None,
                outcome=RunOutcome.EXCEPTION.value,
                python_version=_platform.python_version(),
                platform_system=_platform.system(),
                determinism_declared=determinism,
                seed_declared=seed_str,
                stdout_sha256=_sha256_bytes(b""),
                stderr_sha256=_sha256_bytes(b""),
                stdout_snippet="",
                stderr_snippet=f"EXCEPTION: {type(exc).__name__}: {exc}",
            )
            output_refs = tuple(
                ArtifactRef(path=str(o["path"]), role=str(o.get("role", "output")), present=False)
                for o in declared_outputs
            )

    execution_completed = execution.outcome == RunOutcome.COMPLETED.value
    output_digests_recorded = bool(output_refs) and all(o.present for o in output_refs)
    all_present = execution_completed and output_digests_recorded and not missing_inputs

    evaluator_claims: list[EvaluatorClaim] = []
    for ev in manifest.get("evaluator_claims", []):
        read_from = ev.get("read_from_output")
        value = ev.get("value")
        computed_by = "declared_by_manifest_author"
        verified_independently = False
        if read_from and execution_completed:
            out_path = manifest_dir / str(read_from["path"])
            pointer = str(read_from.get("json_pointer", ""))
            if out_path.exists():
                try:
                    payload = json.loads(out_path.read_text(encoding="utf-8"))
                    node: Any = payload
                    for key in [k for k in pointer.split(".") if k]:
                        node = node[key]
                    value = node
                    computed_by = "bound_output_extraction"
                    verified_independently = False
                except Exception:
                    value = None
                    computed_by = "bound_output_extraction"
                    verified_independently = False
        evaluator_claims.append(
            EvaluatorClaim(
                evaluator_name=str(ev.get("evaluator_name", "unspecified")),
                metric_name=str(ev.get("metric_name", "unspecified")),
                value=value,
                computed_by=computed_by,
                verified_independently=verified_independently,
            )
        )

    external_evaluation = None
    if manifest.get("external_evaluation"):
        external_evaluation = ExternalEvaluationEvidence.from_manifest(manifest["external_evaluation"])

    provenance_linkage = tuple(
        _resolve_provenance_linkage(manifest_dir, root) for root in manifest.get("provenance_roots", [])
    )

    key_files = [manifest_dir / str(i["path"]) for i in declared_inputs if (manifest_dir / str(i["path"])).exists()]
    source_state = capture_provenance(
        repo_dir=repo_dir,
        target_name=manifest.get("target_name", rid),
        portable_id=manifest.get("portable_repository_id", ""),
        command_executed=" ".join(command_tuple),
        key_files=key_files,
    )

    supported_levels = [ReproducibilityLevel.CONTENT_IDENTICAL.value]
    ceiling = ReproducibilityLevel.CONTENT_IDENTICAL.value

    receipt = GenericRunReceipt(
        schema_version=RUN_SCHEMA_VERSION,
        receipt_kind=RUN_RECEIPT_KIND,
        receipt_id=rid,
        claim_title=str(claim_block.get("title", "")),
        claim_statement=str(claim_block.get("statement", "")),
        claim_scope=str(claim_block.get("scope", "")),
        claim_limitations=tuple(claim_block.get("limitations", ())),
        falsification_condition=str(claim_block.get("falsification_condition", "")),
        source_state=source_state,
        inputs=input_refs,
        outputs=output_refs,
        execution=execution,
        claims=RunClaims(
            execution_completed=execution_completed,
            output_digests_recorded=output_digests_recorded,
            all_declared_artifacts_present=all_present,
            evaluator_claims=evaluator_claims,
            external_evaluation=external_evaluation,
        ),
        provenance_linkage=provenance_linkage,
        reproducibility={
            "highest_demonstrated_level": None,
            "declared_ceiling": ceiling,
            "supported_levels": supported_levels,
            "reproduction_command": "vstd reproduce <receipt-dir>",
        },
        layer4_binding=_legacy_generic_run_binding(
            manifest,
            falsification_condition=str(
                claim_block.get("falsification_condition", "")
            ),
        ),
    )
    receipt.compute_and_set_digest()
    return receipt


def _rebuild_stable_payload_from_dict(data: Mapping[str, Any]) -> dict[str, Any]:
    src = data.get("source_state", {})
    payload = {
        "schema_version": data.get("schema_version"),
        "receipt_kind": data.get("receipt_kind"),
        "receipt_id": data.get("receipt_id"),
        "claim_title": data.get("claim_title"),
        "claim_statement": data.get("claim_statement"),
        "claim_scope": data.get("claim_scope"),
        "claim_limitations": data.get("claim_limitations"),
        "falsification_condition": data.get("falsification_condition"),
        "source_state_stable": {
            "target_name": src.get("target_name"),
            "portable_repository_id": src.get("portable_repository_id"),
            "git_commit_sha": src.get("git", {}).get("commit_sha"),
            "git_branch": src.get("git", {}).get("branch"),
            "git_is_dirty": src.get("git", {}).get("is_dirty"),
            "git_dirty_files": src.get("git", {}).get("dirty_files", []),
            "source_file_hashes": src.get("source_file_hashes", {}),
            "runtime_python_version": src.get("runtime", {}).get("python_version"),
        },
        "inputs": data.get("inputs", []),
        "outputs": data.get("outputs", []),
        "execution_stable": {
            "command": data.get("execution", {}).get("command"),
            "cwd": data.get("execution", {}).get("cwd"),
            "exit_code": data.get("execution", {}).get("exit_code"),
            "outcome": data.get("execution", {}).get("outcome"),
            "python_version": data.get("execution", {}).get("python_version"),
            "platform_system": data.get("execution", {}).get("platform_system"),
            "determinism_declared": data.get("execution", {}).get("determinism_declared"),
            "seed_declared": data.get("execution", {}).get("seed_declared"),
            "stdout_sha256": data.get("execution", {}).get("stdout_sha256"),
            "stderr_sha256": data.get("execution", {}).get("stderr_sha256"),
        },
        "claims": data.get("claims", {}),
        "provenance_linkage": data.get("provenance_linkage", []),
        "reproducibility": data.get("reproducibility", {}),
    }
    if "layer4_binding" in data:
        payload["layer4_binding"] = data.get("layer4_binding")
    return payload


def _missing_fields(
    value: object,
    label: str,
    required: tuple[str, ...],
    errors: list[str],
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(f"{label} must be an object")
        return None
    missing = [name for name in required if name not in value]
    if missing:
        errors.append(f"{label} missing required fields: {', '.join(missing)}")
    return value


def _unexpected_fields(
    value: Mapping[str, Any], label: str, allowed: tuple[str, ...], errors: list[str]
) -> None:
    unexpected = sorted(set(value) - set(allowed))
    if unexpected:
        errors.append(f"{label} has unexpected fields: {', '.join(unexpected)}")


def _run_payload_errors(data: Mapping[str, Any]) -> list[str]:
    """Fail-closed structural checks for the generic-run wire profile."""

    errors: list[str] = []
    required = (
        "schema_version",
        "receipt_kind",
        "receipt_id",
        "canonical_digest",
        "claim_title",
        "claim_statement",
        "claim_scope",
        "claim_limitations",
        "falsification_condition",
        "source_state",
        "inputs",
        "outputs",
        "execution",
        "claims",
        "provenance_linkage",
        "reproducibility",
    )
    _missing_fields(data, "receipt", required, errors)
    _unexpected_fields(data, "receipt", required + ("layer4_binding",), errors)
    if data.get("schema_version") != RUN_SCHEMA_VERSION:
        errors.append(f"schema_version must be {RUN_SCHEMA_VERSION}")
    if data.get("receipt_kind") != RUN_RECEIPT_KIND:
        errors.append(f"receipt_kind must be {RUN_RECEIPT_KIND}")
    for name in (
        "receipt_id",
        "claim_title",
        "claim_statement",
        "claim_scope",
        "falsification_condition",
    ):
        if not isinstance(data.get(name), str):
            errors.append(f"{name} must be a string")
    digest = data.get("canonical_digest")
    if not isinstance(digest, str) or not _SHA256_PATTERN.fullmatch(digest):
        errors.append("canonical_digest must be 64 lowercase hexadecimal characters")
    if not isinstance(data.get("claim_limitations"), list) or not all(
        isinstance(item, str) for item in data.get("claim_limitations", [])
    ):
        errors.append("claim_limitations must be an array of strings")

    source = _missing_fields(
        data.get("source_state"),
        "source_state",
        (
            "target_name",
            "portable_repository_id",
            "local_repository_path",
            "git",
            "runtime",
            "captured_at_utc",
            "command_executed",
            "source_file_hashes",
        ),
        errors,
    )
    if source is not None:
        source_fields = (
            "target_name",
            "portable_repository_id",
            "local_repository_path",
            "git",
            "runtime",
            "captured_at_utc",
            "command_executed",
            "source_file_hashes",
        )
        _unexpected_fields(source, "source_state", source_fields, errors)
        for name in (
            "target_name",
            "portable_repository_id",
            "local_repository_path",
            "captured_at_utc",
            "command_executed",
        ):
            if not isinstance(source.get(name), str):
                errors.append(f"source_state.{name} must be a string")
        source_hashes = source.get("source_file_hashes")
        if not isinstance(source_hashes, Mapping) or not all(
            isinstance(path, str)
            and isinstance(digest, str)
            and bool(_SHA256_PATTERN.fullmatch(digest))
            for path, digest in (
                source_hashes.items() if isinstance(source_hashes, Mapping) else ()
            )
        ):
            errors.append("source_state.source_file_hashes must map paths to SHA-256 digests")
        git = _missing_fields(
            source.get("git"),
            "source_state.git",
            ("commit_sha", "branch", "is_dirty"),
            errors,
        )
        if git is not None:
            git_fields = (
                "commit_sha",
                "branch",
                "is_dirty",
                "dirty_files",
                "untracked_files",
                "remote_origin",
            )
            _unexpected_fields(git, "source_state.git", git_fields, errors)
            if not isinstance(git.get("commit_sha"), str) or not isinstance(
                git.get("branch"), str
            ):
                errors.append("source_state.git commit_sha and branch must be strings")
            if type(git.get("is_dirty")) is not bool:
                errors.append("source_state.git.is_dirty must be a boolean")
            for name in ("dirty_files", "untracked_files"):
                if name in git and (
                    not isinstance(git.get(name), list)
                    or not all(isinstance(item, str) for item in git.get(name, []))
                ):
                    errors.append(f"source_state.git.{name} must be an array of strings")
            if "remote_origin" in git and not isinstance(git.get("remote_origin"), str):
                errors.append("source_state.git.remote_origin must be a string")
        runtime = _missing_fields(
            source.get("runtime"),
            "source_state.runtime",
            ("python_version", "platform_system"),
            errors,
        )
        if runtime is not None and any(
            not isinstance(runtime.get(name), str)
            for name in ("python_version", "platform_system")
        ):
            errors.append("source_state.runtime required fields must be strings")
        if runtime is not None:
            runtime_fields = (
                "python_version",
                "python_implementation",
                "platform_system",
                "platform_release",
                "platform_machine",
                "hostname_masked",
            )
            _unexpected_fields(runtime, "source_state.runtime", runtime_fields, errors)
            for name in runtime_fields:
                if name in runtime and not isinstance(runtime.get(name), str):
                    errors.append(f"source_state.runtime.{name} must be a string")

    for collection_name in ("inputs", "outputs"):
        collection = data.get(collection_name)
        if not isinstance(collection, list):
            errors.append(f"{collection_name} must be an array")
            continue
        for index, raw in enumerate(collection):
            label = f"{collection_name}[{index}]"
            item = _missing_fields(raw, label, ("path", "role", "present", "sha256", "byte_size"), errors)
            if item is None:
                continue
            _unexpected_fields(
                item, label, ("path", "role", "present", "sha256", "byte_size"), errors
            )
            if not isinstance(item.get("path"), str) or not isinstance(item.get("role"), str):
                errors.append(f"{label}.path and .role must be strings")
            if type(item.get("present")) is not bool:
                errors.append(f"{label}.present must be a boolean")
            artifact_digest = item.get("sha256")
            if artifact_digest is not None and (
                not isinstance(artifact_digest, str)
                or not _SHA256_PATTERN.fullmatch(artifact_digest)
            ):
                errors.append(f"{label}.sha256 must be null or 64 lowercase hexadecimal characters")
            byte_size = item.get("byte_size")
            if byte_size is not None and (type(byte_size) is not int or byte_size < 0):
                errors.append(f"{label}.byte_size must be null or a non-negative integer")
            if item.get("present") is True and (artifact_digest is None or byte_size is None):
                errors.append(f"{label} is present but lacks a digest or byte size")

    execution = _missing_fields(
        data.get("execution"),
        "execution",
        (
            "command",
            "cwd",
            "started_at_utc",
            "ended_at_utc",
            "elapsed_ms",
            "exit_code",
            "outcome",
            "python_version",
            "platform_system",
            "determinism_declared",
            "seed_declared",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_snippet",
            "stderr_snippet",
        ),
        errors,
    )
    if execution is not None:
        _unexpected_fields(
            execution,
            "execution",
            (
                "command",
                "cwd",
                "started_at_utc",
                "ended_at_utc",
                "elapsed_ms",
                "exit_code",
                "outcome",
                "python_version",
                "platform_system",
                "determinism_declared",
                "seed_declared",
                "stdout_sha256",
                "stderr_sha256",
                "stdout_snippet",
                "stderr_snippet",
            ),
            errors,
        )
        command = execution.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
            errors.append("execution.command must be a non-empty array of strings")
        if execution.get("outcome") not in {member.value for member in RunOutcome}:
            errors.append("execution.outcome is not a recognized run outcome")
        if execution.get("determinism_declared") not in {
            member.value for member in DeterminismDeclaration
        }:
            errors.append("execution.determinism_declared is not recognized")
        for name in (
            "cwd",
            "started_at_utc",
            "ended_at_utc",
            "python_version",
            "platform_system",
            "stdout_snippet",
            "stderr_snippet",
        ):
            if not isinstance(execution.get(name), str):
                errors.append(f"execution.{name} must be a string")
        elapsed = execution.get("elapsed_ms")
        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or elapsed < 0:
            errors.append("execution.elapsed_ms must be a non-negative number")
        exit_code = execution.get("exit_code")
        if exit_code is not None and (type(exit_code) is not int):
            errors.append("execution.exit_code must be an integer or null")
        seed = execution.get("seed_declared")
        if seed is not None and not isinstance(seed, str):
            errors.append("execution.seed_declared must be a string or null")
        for name in ("stdout_sha256", "stderr_sha256"):
            value = execution.get(name)
            if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
                errors.append(f"execution.{name} must be 64 lowercase hexadecimal characters")

    claims = _missing_fields(
        data.get("claims"),
        "claims",
        (
            "execution_completed",
            "output_digests_recorded",
            "all_declared_artifacts_present",
            "evaluator_claims",
            "external_evaluation",
        ),
        errors,
    )
    if claims is not None:
        _unexpected_fields(
            claims,
            "claims",
            (
                "execution_completed",
                "output_digests_recorded",
                "all_declared_artifacts_present",
                "evaluator_claims",
                "external_evaluation",
            ),
            errors,
        )
        for name in ("execution_completed", "output_digests_recorded"):
            if type(claims.get(name)) is not bool:
                errors.append(f"claims.{name} must be a boolean")
        if claims.get("all_declared_artifacts_present") is not None and type(
            claims.get("all_declared_artifacts_present")
        ) is not bool:
            errors.append("claims.all_declared_artifacts_present must be a boolean or null")
        evaluator_claims = claims.get("evaluator_claims")
        if not isinstance(evaluator_claims, list):
            errors.append("claims.evaluator_claims must be an array")
        else:
            evaluator_fields = (
                "evaluator_name",
                "metric_name",
                "value",
                "computed_by",
                "verified_independently",
            )
            for index, raw in enumerate(evaluator_claims):
                label = f"claims.evaluator_claims[{index}]"
                evaluator = _missing_fields(raw, label, evaluator_fields, errors)
                if evaluator is None:
                    continue
                _unexpected_fields(evaluator, label, evaluator_fields, errors)
                if not isinstance(evaluator.get("evaluator_name"), str) or not isinstance(
                    evaluator.get("metric_name"), str
                ):
                    errors.append(f"{label} names must be strings")
                if evaluator.get("computed_by") not in {
                    "bound_output_extraction",
                    "declared_by_manifest_author",
                }:
                    errors.append(f"{label}.computed_by is not recognized")
                if evaluator.get("verified_independently") is not False:
                    errors.append(
                        f"{label}.verified_independently must be false for this runtime"
                    )
        external = claims.get("external_evaluation")
        if external is not None and not isinstance(external, Mapping):
            errors.append("claims.external_evaluation must be an object or null")
        elif isinstance(external, Mapping):
            external_fields = (
                "source",
                "description",
                "reported_value",
                "evidence_kind",
                "evidence_ref",
                "attested",
            )
            _missing_fields(external, "claims.external_evaluation", external_fields, errors)
            _unexpected_fields(
                external, "claims.external_evaluation", external_fields, errors
            )
            for name in ("source", "description", "evidence_kind"):
                if not isinstance(external.get(name), str):
                    errors.append(f"claims.external_evaluation.{name} must be a string")
            if external.get("evidence_ref") is not None and not isinstance(
                external.get("evidence_ref"), str
            ):
                errors.append("claims.external_evaluation.evidence_ref must be a string or null")
            if external.get("attested") is not False:
                errors.append("claims.external_evaluation.attested must be false for this runtime")

    linkage = data.get("provenance_linkage")
    if not isinstance(linkage, list):
        errors.append("provenance_linkage must be an array")
    else:
        linkage_fields = (
            "dataset_receipt_path",
            "artifact_id",
            "found_in_hypergraph",
            "ancestor_count",
            "ancestor_ids",
        )
        for index, raw in enumerate(linkage):
            label = f"provenance_linkage[{index}]"
            item = _missing_fields(raw, label, linkage_fields, errors)
            if item is None:
                continue
            _unexpected_fields(item, label, linkage_fields, errors)
            if not isinstance(item.get("dataset_receipt_path"), str) or not isinstance(
                item.get("artifact_id"), str
            ):
                errors.append(f"{label} paths and identifiers must be strings")
            if type(item.get("found_in_hypergraph")) is not bool:
                errors.append(f"{label}.found_in_hypergraph must be a boolean")
            count = item.get("ancestor_count")
            if count is not None and (type(count) is not int or count < 0):
                errors.append(f"{label}.ancestor_count must be a non-negative integer or null")
            if not isinstance(item.get("ancestor_ids"), list) or not all(
                isinstance(ancestor, str) for ancestor in item.get("ancestor_ids", [])
            ):
                errors.append(f"{label}.ancestor_ids must be an array of strings")
    reproduction = _missing_fields(
        data.get("reproducibility"),
        "reproducibility",
        ("highest_demonstrated_level", "declared_ceiling", "supported_levels", "reproduction_command"),
        errors,
    )
    if reproduction is not None:
        reproduction_fields = (
            "highest_demonstrated_level",
            "declared_ceiling",
            "supported_levels",
            "reproduction_command",
        )
        _unexpected_fields(reproduction, "reproducibility", reproduction_fields, errors)
        if reproduction.get("highest_demonstrated_level") is not None and not isinstance(
            reproduction.get("highest_demonstrated_level"), str
        ):
            errors.append("reproducibility.highest_demonstrated_level must be a string or null")
        if not isinstance(reproduction.get("declared_ceiling"), str) or not isinstance(
            reproduction.get("reproduction_command"), str
        ):
            errors.append("reproducibility ceiling and command must be strings")
        if not isinstance(reproduction.get("supported_levels"), list) or not all(
            isinstance(level, str) for level in reproduction.get("supported_levels", [])
        ):
            errors.append("reproducibility.supported_levels must be an array of strings")
    if "layer4_binding" in data:
        layer4 = _missing_fields(
            data.get("layer4_binding"),
            "layer4_binding",
            ("verifier", "resource_bounds", "prior_commitment", "refutation_surface"),
            errors,
        )
        if layer4 is not None:
            layer4_fields = (
                "verifier",
                "vstd4_conformance",
                "resource_bounds",
                "prior_commitment",
                "refutation_surface",
            )
            _unexpected_fields(layer4, "layer4_binding", layer4_fields, errors)
            if "vstd4_conformance" in layer4 and layer4.get(
                "vstd4_conformance"
            ) != "NOT_EVALUATED":
                errors.append("layer4_binding.vstd4_conformance must be NOT_EVALUATED")
            verifier = _missing_fields(
                layer4.get("verifier"),
                "layer4_binding.verifier",
                (
                    "specification_hash",
                    "implementation_hash",
                    "parser_hash",
                    "certificate_format",
                    "format_fragment",
                    "dependencies",
                    "deterministic",
                ),
                errors,
            )
            if verifier is not None:
                verifier_fields = (
                    "specification_hash",
                    "implementation_hash",
                    "parser_hash",
                    "certificate_format",
                    "format_fragment",
                    "dependencies",
                    "deterministic",
                )
                _unexpected_fields(
                    verifier, "layer4_binding.verifier", verifier_fields, errors
                )
                for name in (
                    "specification_hash",
                    "implementation_hash",
                    "parser_hash",
                ):
                    value = verifier.get(name)
                    unavailable_legacy_specification = (
                        name == "specification_hash"
                        and isinstance(value, str)
                        and value.startswith("UNAVAILABLE:")
                    )
                    if (
                        not unavailable_legacy_specification
                        and (
                            not isinstance(value, str)
                            or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
                        )
                    ):
                        errors.append(
                            f"layer4_binding.verifier.{name} must be a prefixed SHA-256 digest"
                        )
                for name in ("certificate_format", "format_fragment"):
                    if not isinstance(verifier.get(name), str):
                        errors.append(f"layer4_binding.verifier.{name} must be a string")
                if not isinstance(verifier.get("dependencies"), list) or not all(
                    isinstance(item, str) for item in verifier.get("dependencies", [])
                ):
                    errors.append(
                        "layer4_binding.verifier.dependencies must be an array of strings"
                    )
                if type(verifier.get("deterministic")) is not bool:
                    errors.append("layer4_binding.verifier.deterministic must be a boolean")
            bounds = _missing_fields(
                layer4.get("resource_bounds"),
                "layer4_binding.resource_bounds",
                (
                    "verification_cost_bound",
                    "memory_bound",
                    "certificate_size_bound",
                ),
                errors,
            )
            if bounds is not None:
                bound_fields = (
                    "verification_cost_bound",
                    "memory_bound",
                    "certificate_size_bound",
                )
                _unexpected_fields(
                    bounds, "layer4_binding.resource_bounds", bound_fields, errors
                )
                for name in bound_fields:
                    value = bounds.get(name)
                    if type(value) is not int or value < 0:
                        errors.append(
                            f"layer4_binding.resource_bounds.{name} must be a non-negative integer"
                        )
            if not isinstance(layer4.get("prior_commitment"), str):
                errors.append("layer4_binding.prior_commitment must be a string")
            surface = _missing_fields(
                layer4.get("refutation_surface"),
                "layer4_binding.refutation_surface",
                (
                    "admissible_refutations",
                    "excluded_claims",
                    "legacy_falsification_condition",
                ),
                errors,
            )
            if surface is not None:
                for name in ("admissible_refutations", "excluded_claims"):
                    if not isinstance(surface.get(name), list) or not all(
                        isinstance(item, str) for item in surface.get(name, [])
                    ):
                        errors.append(
                            f"layer4_binding.refutation_surface.{name} must be an array of strings"
                        )
                if not isinstance(surface.get("legacy_falsification_condition"), str):
                    errors.append(
                        "layer4_binding.refutation_surface.legacy_falsification_condition must be a string"
                    )
    return errors


def is_generic_run_receipt(data: Mapping[str, Any]) -> bool:
    return (
        data.get("schema_version") == RUN_SCHEMA_VERSION
        and data.get("receipt_kind") == RUN_RECEIPT_KIND
    )


def validate_run_receipt(receipt_path_or_dir: Path) -> int:
    receipt_file = receipt_path_or_dir / "receipt.json" if receipt_path_or_dir.is_dir() else receipt_path_or_dir
    if not receipt_file.exists():
        print(f"[FAIL] Receipt file not found: {receipt_file}")
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
    recorded_digest = data.get("canonical_digest", "")
    recomputed = compute_canonical_digest(_rebuild_stable_payload_from_dict(data))
    if recomputed != recorded_digest:
        print(f"[FAIL] Canonical digest mismatch:\n  Recorded:   {recorded_digest}\n  Recomputed: {recomputed}")
        return 1
    print(f"[INTEGRITY OK] Run receipt {data.get('receipt_id')} stable digest matches.")
    print(f"       Digest: {recorded_digest}")
    print(f"       Outcome: {data.get('execution', {}).get('outcome')}")
    return 0


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


def reproduce_run_receipt(receipt_path_or_dir: Path, rerun: bool = False) -> int:
    """Assess reproduction fidelity.

    By default this rehashes the declared output artifacts as they currently
    exist on disk relative to the receipt directory's manifest base (safe,
    side-effect free, always available). Pass ``rerun=True`` to additionally
    re-execute the recorded command and compare freshly produced outputs —
    this mutates on-disk state at the declared output paths and is therefore
    opt-in only.
    """
    receipt_dir = receipt_path_or_dir if receipt_path_or_dir.is_dir() else receipt_path_or_dir.parent
    receipt_file = receipt_dir / "receipt.json"
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
            level = (
                ReproducibilityLevel.CONTENT_IDENTICAL.value
                if outputs_match and outcomes_match
                else "NOT_DEMONSTRATED"
            )
            print(f"[REPRODUCTION RESULT - RERUN] Level: {level} (declared-output scope)")
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
    print("  Run-level reproduction: NOT_DEMONSTRATED (command was not re-executed; pass --rerun to assess it)")
    return 0


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
