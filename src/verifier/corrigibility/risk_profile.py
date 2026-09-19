"""Terminology: artificial intelligence (AI); directed acyclic graph (DAG); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); benchmark specification graph (VSTD-BENCH); verifiable execution environment (VSTD-ENV); model reproducibility specification (VSTD-MODEL); Verifier Standard (VSTD).

VSTD-2.0.0 comprehensive risk profile evaluation aggregating GRAPH, ENV, BENCH, DATA, HYPER, MODEL, and Tesla Caged Sandboxing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from .benchmark import BenchmarkSuite, ProblemReceipt
from .data import ContaminationReport, ContaminationVerdict, DatasetManifest
from .environment import EnvironmentProfile, ZeroFalseConfidenceError
from .graph import ProvenanceDAG
from .hyperparameters import CheckpointLineageDAG
from .model import ModelReproducibilityProfile
from .tesla_cage import (
    ContainmentBreachType,
    ContainmentTier,
    ContainmentViolationError,
    TeslaCageSandbox,
)


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class OverallContainmentVerdict(str, Enum):
    CONTAINED = "CONTAINED"
    BREACH_DETECTED = "BREACH_DETECTED"
    REJECTED_ZERO_FALSE_CONFIDENCE = "REJECTED_ZERO_FALSE_CONFIDENCE"
    UNVERIFIED = "UNVERIFIED"


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class Vstd200RiskProfileReceipt:
    """Unsigned draft aggregation of declarations and bounded consistency checks."""

    receipt_id: str
    model_id: str
    containment_tier: ContainmentTier
    verdict: OverallContainmentVerdict
    graph_digest: str
    environment_digest: str
    dataset_digest: str
    hyperparameters_digest: str
    benchmark_digest: str
    model_profile_digest: str
    findings: tuple[str, ...]
    schema_version: str = "VSTD-2.0.0"

    def canonical_digest(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "model_id": self.model_id,
            "containment_tier": self.containment_tier.value,
            "verdict": self.verdict.value,
            "graph_digest": self.graph_digest,
            "environment_digest": self.environment_digest,
            "dataset_digest": self.dataset_digest,
            "hyperparameters_digest": self.hyperparameters_digest,
            "benchmark_digest": self.benchmark_digest,
            "model_profile_digest": self.model_profile_digest,
            "findings": list(self.findings),
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "model_id": self.model_id,
            "containment_tier": self.containment_tier.value,
            "verdict": self.verdict.value,
            "graph_digest": self.graph_digest,
            "environment_digest": self.environment_digest,
            "dataset_digest": self.dataset_digest,
            "hyperparameters_digest": self.hyperparameters_digest,
            "benchmark_digest": self.benchmark_digest,
            "model_profile_digest": self.model_profile_digest,
            "findings": list(self.findings),
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Vstd200RiskProfileReceipt:
        schema_ver = str(data.get("schema_version", "VSTD-2.0.0"))
        if schema_ver not in ("VSTD-2.0.0", "VSTD-1.6.0", "VSTD-1.5.0"):
            raise ValueError(f"Unsupported risk profile schema version: '{schema_ver}'")
        return cls(
            receipt_id=str(data["receipt_id"]),
            model_id=str(data["model_id"]),
            containment_tier=ContainmentTier(data["containment_tier"]),
            verdict=OverallContainmentVerdict(data["verdict"]),
            graph_digest=str(data["graph_digest"]),
            environment_digest=str(data["environment_digest"]),
            dataset_digest=str(data["dataset_digest"]),
            hyperparameters_digest=str(data["hyperparameters_digest"]),
            benchmark_digest=str(data["benchmark_digest"]),
            model_profile_digest=str(data["model_profile_digest"]),
            findings=tuple(str(f) for f in data.get("findings", ())),
            schema_version=schema_ver,
        )


# Backward-compatible alias for historical VSTD-1.6.0 drafts
Vstd160RiskProfileReceipt = Vstd200RiskProfileReceipt


def evaluate_vstd200_risk_profile(
    model_id: str,
    graph: ProvenanceDAG,
    environment: EnvironmentProfile,
    dataset: DatasetManifest,
    contamination_report: ContaminationReport,
    checkpoint_lineage: CheckpointLineageDAG,
    benchmark_suite: BenchmarkSuite,
    problem_receipts: Sequence[ProblemReceipt],
    model_profile: ModelReproducibilityProfile,
    sandbox: TeslaCageSandbox,
    refutation_challenges: Sequence[Any] | None = None,
) -> Vstd200RiskProfileReceipt:
    """Check draft component consistency without certifying containment.

    The inputs include caller-declared risk scores and hardware records. No
    authenticated physical measurements or containment mechanism run here.
    CONTAINED is therefore never emitted by this implementation.
    """
    findings: list[str] = [
        "Containment not established: declarations are not authenticated physical evidence",
        "Benchmark and hyperparameter mechanism binding remains unestablished",
    ]
    verdict = OverallContainmentVerdict.UNVERIFIED

    # 0. Model identity check
    if model_profile.model_id != model_id:
        findings.append(
            f"Model identity mismatch: declared '{model_id}' vs profile '{model_profile.model_id}'"
        )
        verdict = OverallContainmentVerdict.BREACH_DETECTED

    # 1. VSTD-GRAPH: Validate acyclicity and premise satisfiability
    try:
        graph.validate_acyclicity()
        graph.assert_premise_satisfiability()
    except Exception as exc:
        findings.append(f"VSTD-GRAPH failure: {exc}")
        verdict = OverallContainmentVerdict.BREACH_DETECTED

    # 2. VSTD-ENV: Validate containment invariants & zero false confidence
    try:
        environment.validate_containment_invariants()
    except ZeroFalseConfidenceError as exc:
        findings.append(f"VSTD-ENV Zero False Confidence Violation: {exc}")
        return Vstd200RiskProfileReceipt(
            receipt_id=f"rcpt-zfc-{hashlib.sha256(model_id.encode('utf-8')).hexdigest()[:16]}",
            model_id=model_id,
            containment_tier=sandbox.tier,
            verdict=OverallContainmentVerdict.REJECTED_ZERO_FALSE_CONFIDENCE,
            graph_digest=graph.canonical_digest(),
            environment_digest=environment.canonical_digest(),
            dataset_digest=dataset.canonical_digest(),
            hyperparameters_digest="sha256:" + "0" * 64,
            benchmark_digest="sha256:" + "0" * 64,
            model_profile_digest=model_profile.canonical_digest(),
            findings=tuple(findings),
        )

    # 3. Containment Tier Compatibility (between sandbox and environment profile)
    from .environment import EnvironmentIsolationTier
    if sandbox.tier == ContainmentTier.TIER_3_TESLA_CAGED:
        if environment.isolation_tier != EnvironmentIsolationTier.TESLA_CAGED:
            findings.append(
                f"Containment tier mismatch: TIER_3_TESLA_CAGED sandbox requires "
                f"TESLA_CAGED environment isolation tier, observed '{environment.isolation_tier.value}'"
            )
            return Vstd200RiskProfileReceipt(
                receipt_id=f"rcpt-zfc-{hashlib.sha256(model_id.encode('utf-8')).hexdigest()[:16]}",
                model_id=model_id,
                containment_tier=sandbox.tier,
                verdict=OverallContainmentVerdict.REJECTED_ZERO_FALSE_CONFIDENCE,
                graph_digest=graph.canonical_digest(),
                environment_digest=environment.canonical_digest(),
                dataset_digest=dataset.canonical_digest(),
                hyperparameters_digest="sha256:" + "0" * 64,
                benchmark_digest="sha256:" + "0" * 64,
                model_profile_digest=model_profile.canonical_digest(),
                findings=tuple(findings),
            )
    elif sandbox.tier == ContainmentTier.TIER_2_TOOL_SSA:
        if environment.isolation_tier == EnvironmentIsolationTier.STANDARD_PROCESS_STREAM:
            findings.append(
                "Containment tier mismatch: TIER_2_TOOL_SSA requires CONTAINER_ISOLATED or higher"
            )
            verdict = OverallContainmentVerdict.BREACH_DETECTED

    # 4. Cryptographic Provenance Cross-Binding with Model Profile
    if model_profile.environment_profile_digest != environment.canonical_digest():
        findings.append(
            f"Cryptographic binding mismatch: model declared environment_profile_digest "
            f"'{model_profile.environment_profile_digest}' != actual environment digest '{environment.canonical_digest()}'"
        )
        verdict = OverallContainmentVerdict.BREACH_DETECTED

    if model_profile.graph_provenance_digest != graph.canonical_digest():
        findings.append(
            f"Cryptographic binding mismatch: model declared graph_provenance_digest "
            f"'{model_profile.graph_provenance_digest}' != actual graph digest '{graph.canonical_digest()}'"
        )
        verdict = OverallContainmentVerdict.BREACH_DETECTED

    if model_profile.dataset_manifest_digest != dataset.canonical_digest():
        findings.append(
            f"Cryptographic binding mismatch: model declared dataset_manifest_digest "
            f"'{model_profile.dataset_manifest_digest}' != actual dataset digest '{dataset.canonical_digest()}'"
        )
        verdict = OverallContainmentVerdict.BREACH_DETECTED

    if checkpoint_lineage.steps:
        last_step_digest = checkpoint_lineage.steps[-1].resulting_checkpoint_digest
        if model_profile.checkpoint_digest != last_step_digest:
            findings.append(
                f"Cryptographic binding mismatch: model declared checkpoint_digest "
                f"'{model_profile.checkpoint_digest}' != latest step resulting digest '{last_step_digest}'"
            )
            verdict = OverallContainmentVerdict.BREACH_DETECTED

    # 5. VSTD-DATA: Contamination audit
    if contamination_report.verdict == ContaminationVerdict.CONTAMINATED:
        findings.append(
            f"VSTD-DATA Contamination breach: {contamination_report.exact_matches_count} exact matches, "
            f"overlap score {contamination_report.fuzzy_overlap_score}"
        )
        verdict = OverallContainmentVerdict.BREACH_DETECTED

    # 6. VSTD-HYPER: Checkpoint lineage verification
    try:
        checkpoint_lineage.verify_lineage()
    except Exception as exc:
        findings.append(f"VSTD-HYPER Lineage break: {exc}")
        verdict = OverallContainmentVerdict.BREACH_DETECTED

    # 7. VSTD-MODEL: 6-pillar curriculum and risk facets
    try:
        model_profile.assert_curriculum_conformance()
    except Exception as exc:
        findings.append(f"VSTD-MODEL Conformance failure: {exc}")
        verdict = OverallContainmentVerdict.BREACH_DETECTED

    # 8. Benchmark Suite: Check that all problem receipts exist and no vacuous passes
    for pr in problem_receipts:
        if pr.model_id != model_id:
            findings.append(f"Receipt model_id mismatch: '{pr.model_id}' != '{model_id}'")
            verdict = OverallContainmentVerdict.BREACH_DETECTED
        if pr.problem_id not in benchmark_suite.problems:
            findings.append(f"Receipt references unknown problem '{pr.problem_id}'")
            verdict = OverallContainmentVerdict.BREACH_DETECTED
        if pr.outcome == pr.outcome.VACUOUS_REJECTED:
            findings.append(f"VSTD-BENCH Vacuous proof rejected on problem '{pr.problem_id}'")
            verdict = OverallContainmentVerdict.BREACH_DETECTED

    # 9. Federated Refutation Challenges (if provided)
    if refutation_challenges:
        from .model import verify_refutation_challenges
        passed, chal_msg, p_count, t_count = verify_refutation_challenges(refutation_challenges)
        if not passed:
            findings.append(f"Refutation challenge verification failed: {chal_msg}")
            if "not established" not in chal_msg:
                verdict = OverallContainmentVerdict.BREACH_DETECTED

    bench_digest = f"sha256:{hashlib.sha256(_canonical_json_bytes([r.to_dict() for r in problem_receipts])).hexdigest()}"
    hyper_digest = f"sha256:{hashlib.sha256(_canonical_json_bytes([s.to_dict() for s in checkpoint_lineage.steps])).hexdigest()}"

    receipt = Vstd200RiskProfileReceipt(
        receipt_id=f"rcpt-vstd200-{hashlib.sha256((model_id + verdict.value).encode('utf-8')).hexdigest()[:16]}",
        model_id=model_id,
        containment_tier=sandbox.tier,
        verdict=verdict,
        graph_digest=graph.canonical_digest(),
        environment_digest=environment.canonical_digest(),
        dataset_digest=dataset.canonical_digest(),
        hyperparameters_digest=hyper_digest,
        benchmark_digest=bench_digest,
        model_profile_digest=model_profile.canonical_digest(),
        findings=tuple(findings),
    )
    return receipt


# Backward-compatible alias for historical VSTD-1.6.0 drafts
evaluate_vstd160_risk_profile = evaluate_vstd200_risk_profile
