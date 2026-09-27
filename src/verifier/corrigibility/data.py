"""Terminology: identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

DATA: Bounded training/eval dataset provenance, integrity digests, and contamination boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence, Set


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class DatasetSplit(str, Enum):
    TRAIN = "TRAIN"
    VALIDATION = "VALIDATION"
    TEST = "TEST"
    BENCHMARK_EVAL = "BENCHMARK_EVAL"
    RED_TEAM = "RED_TEAM"


class ContaminationVerdict(str, Enum):
    CLEAN = "CLEAN"
    CONTAMINATED = "CONTAMINATED"
    INDETERMINATE = "INDETERMINATE"


class DatasetError(ValueError):
    """Base error for DATA operations."""


class ContaminationError(DatasetError):
    """Raised when evaluation benchmark contamination is detected in training data."""


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def compute_merkle_root(leaf_hashes: Sequence[str]) -> str:
    """Compute binary SHA-256 Merkle root over ordered leaf hashes."""
    if not leaf_hashes:
        empty_hash = hashlib.sha256(b"").hexdigest()
        return f"sha256:{empty_hash}"

    for h in leaf_hashes:
        if not _DIGEST_PATTERN.match(h):
            raise DatasetError(f"Invalid leaf hash '{h}': must be sha256 hex digest")

    current = [h.replace("sha256:", "") for h in leaf_hashes]
    while len(current) > 1:
        next_level: list[str] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            combined = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
            next_level.append(combined)
        current = next_level
    return f"sha256:{current[0]}"


@dataclass(frozen=True)
class DataShard:
    """A bounded shard of dataset records with Merkle integrity."""

    shard_id: str
    split: DatasetSplit
    record_count: int
    byte_size: int
    content_sha256: str
    records_merkle_root: str = ""

    def __post_init__(self) -> None:
        if not self.shard_id:
            raise DatasetError("shard_id cannot be empty")
        if self.record_count < 0:
            raise DatasetError("record_count must be non-negative")
        if self.byte_size < 0:
            raise DatasetError("byte_size must be non-negative")
        if not _DIGEST_PATTERN.match(self.content_sha256):
            raise DatasetError(
                f"Invalid content_sha256: '{self.content_sha256}' must be a sha256 hex digest"
            )
        if self.records_merkle_root and not _DIGEST_PATTERN.match(self.records_merkle_root):
            raise DatasetError(
                f"Invalid records_merkle_root: '{self.records_merkle_root}' must be a sha256 hex digest"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "shard_id": self.shard_id,
            "split": self.split.value,
            "record_count": self.record_count,
            "byte_size": self.byte_size,
            "content_sha256": self.content_sha256,
            "records_merkle_root": self.records_merkle_root,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DataShard:
        return cls(
            shard_id=str(data["shard_id"]),
            split=DatasetSplit(data["split"]),
            record_count=int(data["record_count"]),
            byte_size=int(data["byte_size"]),
            content_sha256=str(data["content_sha256"]),
            records_merkle_root=str(data.get("records_merkle_root", "")),
        )


@dataclass(frozen=True)
class DatasetManifest:
    """Verifiable dataset provenance and shard inventory (verifier-data-2)."""

    dataset_id: str
    shards: tuple[DataShard, ...]
    transformations: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = "verifier-data-2"

    def canonical_digest(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "dataset_id": self.dataset_id,
            "shards": [s.to_dict() for s in sorted(self.shards, key=lambda s: s.shard_id)],
            "transformations": list(self.transformations),
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dataset_id": self.dataset_id,
            "shards": [s.to_dict() for s in self.shards],
            "transformations": list(self.transformations),
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DatasetManifest:
        return cls(
            dataset_id=str(data["dataset_id"]),
            shards=tuple(DataShard.from_dict(s) for s in data.get("shards", ())),
            transformations=tuple(str(t) for t in data.get("transformations", ())),
            schema_version=str(data.get("schema_version", "verifier-data-2")),
        )


@dataclass(frozen=True)
class ContaminationReport:
    """Audit report establishing whether benchmark problems leaked into training data."""

    dataset_id: str
    benchmark_suite_id: str
    exact_matches_count: int
    fuzzy_overlap_score: float
    contaminated_problem_ids: tuple[str, ...]
    verdict: ContaminationVerdict
    report_digest: str = ""

    def canonical_digest(self) -> str:
        payload = {
            "dataset_id": self.dataset_id,
            "benchmark_suite_id": self.benchmark_suite_id,
            "exact_matches_count": self.exact_matches_count,
            "fuzzy_overlap_score": self.fuzzy_overlap_score,
            "contaminated_problem_ids": sorted(self.contaminated_problem_ids),
            "verdict": self.verdict.value,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        cdigest = self.report_digest or self.canonical_digest()
        return {
            "dataset_id": self.dataset_id,
            "benchmark_suite_id": self.benchmark_suite_id,
            "exact_matches_count": self.exact_matches_count,
            "fuzzy_overlap_score": self.fuzzy_overlap_score,
            "contaminated_problem_ids": list(self.contaminated_problem_ids),
            "verdict": self.verdict.value,
            "report_digest": cdigest,
        }


def detect_benchmark_contamination(
    dataset_id: str,
    benchmark_suite_id: str,
    training_texts: Sequence[str],
    benchmark_items: Mapping[str, str],  # problem_id -> text (problem prompt or solution)
    fuzzy_ngram_size: int = 5,
    fuzzy_threshold: float = 0.5,
) -> ContaminationReport:
    """Audit training data for contamination by benchmark problems.

    Performs exact hash collision and n-gram overlap audits.
    """
    if fuzzy_ngram_size <= 0:
        raise DatasetError("fuzzy_ngram_size must be positive")
    if not 0.0 <= fuzzy_threshold <= 1.0:
        raise DatasetError("fuzzy_threshold must be in [0.0, 1.0]")

    # 1. Exact hash matching
    training_hashes: set[str] = {
        hashlib.sha256(text.strip().encode("utf-8")).hexdigest()
        for text in training_texts
    }

    leaked_ids: list[str] = []
    exact_matches = 0

    def _tokenize(s: str) -> list[str]:
        return re.findall(r"\w+", s.lower())

    def _get_ngrams_from_tokens(tokens: list[str], n: int) -> set[tuple[str, ...]]:
        if not tokens:
            return set()
        if len(tokens) < n:
            return {tuple(tokens)}
        return {tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)}

    training_token_lists = [_tokenize(t) for t in training_texts]
    training_ngrams_cache: dict[int, set[tuple[str, ...]]] = {}

    max_fuzzy = 0.0

    for prob_id, prob_text in benchmark_items.items():
        clean_text = prob_text.strip()
        p_hash = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()
        if p_hash in training_hashes:
            exact_matches += 1
            leaked_ids.append(prob_id)
            continue

        p_tokens = _tokenize(clean_text)
        if not p_tokens:
            continue
        effective_n = min(fuzzy_ngram_size, len(p_tokens))
        if effective_n not in training_ngrams_cache:
            ngs: set[tuple[str, ...]] = set()
            for t_tokens in training_token_lists:
                ngs.update(_get_ngrams_from_tokens(t_tokens, effective_n))
            training_ngrams_cache[effective_n] = ngs

        t_ngrams = training_ngrams_cache[effective_n]
        p_ngrams = _get_ngrams_from_tokens(p_tokens, effective_n)
        if p_ngrams and t_ngrams:
            overlap = len(p_ngrams.intersection(t_ngrams))
            ratio = overlap / len(p_ngrams)
            if ratio > max_fuzzy:
                max_fuzzy = ratio
            if ratio >= fuzzy_threshold:
                leaked_ids.append(prob_id)

    verdict = (
        ContaminationVerdict.CONTAMINATED
        if (exact_matches > 0 or max_fuzzy >= fuzzy_threshold)
        else ContaminationVerdict.CLEAN
    )

    report = ContaminationReport(
        dataset_id=dataset_id,
        benchmark_suite_id=benchmark_suite_id,
        exact_matches_count=exact_matches,
        fuzzy_overlap_score=round(max_fuzzy, 4),
        contaminated_problem_ids=tuple(sorted(set(leaked_ids))),
        verdict=verdict,
    )
    return report
