"""Terminology: identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Comprehensive adversarial test suite for DATA dataset provenance and contamination boundaries.
"""

from __future__ import annotations

import hashlib
import json
import pytest

from verifier.corrigibility.data import (
    ContaminationError,
    ContaminationReport,
    ContaminationVerdict,
    DataShard,
    DatasetError,
    DatasetManifest,
    DatasetSplit,
    compute_merkle_root,
    detect_benchmark_contamination,
)


def _digest(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def test_merkle_root_computation_deterministic() -> None:
    h1 = _digest("record_1")
    h2 = _digest("record_2")
    h3 = _digest("record_3")
    h4 = _digest("record_4")

    root1 = compute_merkle_root([h1, h2, h3, h4])
    root2 = compute_merkle_root([h1, h2, h3, h4])
    assert root1 == root2
    assert root1.startswith("sha256:")

    # Permuted leaves yield different Merkle root
    root_permuted = compute_merkle_root([h2, h1, h3, h4])
    assert root_permuted != root1

    # Empty list handling
    empty_root = compute_merkle_root([])
    assert empty_root.startswith("sha256:")


def test_data_shard_creation_and_validation() -> None:
    shard = DataShard(
        shard_id="shard:train-0001",
        split=DatasetSplit.TRAIN,
        record_count=100000,
        byte_size=1024 * 1024 * 50,
        content_sha256=_digest("shard-content"),
        records_merkle_root=_digest("merkle-root"),
    )
    assert shard.shard_id == "shard:train-0001"
    assert shard.split == DatasetSplit.TRAIN

    with pytest.raises(DatasetError, match="shard_id cannot be empty"):
        DataShard("", DatasetSplit.TRAIN, 10, 100, _digest("x"))

    with pytest.raises(DatasetError, match="Invalid content_sha256"):
        DataShard("s1", DatasetSplit.TRAIN, 10, 100, "not-a-sha256")


def test_dataset_manifest_canonical_digest_and_serialization() -> None:
    s1 = DataShard("s1", DatasetSplit.TRAIN, 100, 1000, _digest("s1"))
    s2 = DataShard("s2", DatasetSplit.VALIDATION, 20, 200, _digest("s2"))

    manifest1 = DatasetManifest(
        dataset_id="dataset:fineweb-subset",
        shards=(s1, s2),
        transformations=("deduplication", "quality_filtering", "tokenization"),
    )
    manifest2 = DatasetManifest(
        dataset_id="dataset:fineweb-subset",
        shards=(s2, s1),  # Order swapped
        transformations=("deduplication", "quality_filtering", "tokenization"),
    )

    # Canonical digest must be sorted and identical
    assert manifest1.canonical_digest() == manifest2.canonical_digest()

    data = manifest1.to_dict()
    restored = DatasetManifest.from_dict(data)
    assert restored.canonical_digest() == manifest1.canonical_digest()
    assert len(restored.shards) == 2


def test_contamination_detection_clean_corpus() -> None:
    training_corpus = [
        "The quick brown fox jumps over the lazy dog.",
        "Differential geometry studies smooth manifolds and Riemannian metrics.",
        "Functional programming emphasizes pure functions and immutable data structures.",
    ]
    eval_benchmark = {
        "bench_01": "Prove that every prime number greater than 2 is odd.",
        "bench_02": "Compute the shortest path in a weighted directed acyclic graph.",
    }

    report = detect_benchmark_contamination(
        dataset_id="ds:clean-math",
        benchmark_suite_id="bench:math-eval",
        training_texts=training_corpus,
        benchmark_items=eval_benchmark,
    )

    assert report.verdict == ContaminationVerdict.CLEAN
    assert report.exact_matches_count == 0
    assert len(report.contaminated_problem_ids) == 0


def test_contamination_detection_exact_leak() -> None:
    leaked_problem_text = "Prove that there are infinitely many prime numbers using Euclid's lemma."
    training_corpus = [
        "Standard machine learning text on linear algebra.",
        leaked_problem_text,  # Leaked into training data!
        "Deep reinforcement learning for robotics.",
    ]
    eval_benchmark = {
        "bench_prime_inf": leaked_problem_text,
        "bench_other": "Show that the halting problem is undecidable.",
    }

    report = detect_benchmark_contamination(
        dataset_id="ds:leaked-math",
        benchmark_suite_id="bench:math-eval",
        training_texts=training_corpus,
        benchmark_items=eval_benchmark,
    )

    assert report.verdict == ContaminationVerdict.CONTAMINATED
    assert report.exact_matches_count == 1
    assert "bench_prime_inf" in report.contaminated_problem_ids
    assert "bench_other" not in report.contaminated_problem_ids


def test_contamination_detection_fuzzy_overlap() -> None:
    training_corpus = [
        "In number theory we know that every integer greater than one either is a prime itself or can be represented as the prime factor product.",
    ]
    eval_benchmark = {
        "bench_fund_arith": "every integer greater than one either is a prime itself or can be represented as the prime factor product uniquely up to order.",
    }

    report = detect_benchmark_contamination(
        dataset_id="ds:fuzzy-leak",
        benchmark_suite_id="bench:arithmetic",
        training_texts=training_corpus,
        benchmark_items=eval_benchmark,
        fuzzy_ngram_size=4,
        fuzzy_threshold=0.5,
    )

    assert report.verdict == ContaminationVerdict.CONTAMINATED
    assert report.fuzzy_overlap_score >= 0.5
    assert "bench_fund_arith" in report.contaminated_problem_ids


def test_contamination_detection_catches_short_token_embedded_leak() -> None:
    # 4-token benchmark problem embedded inside a longer training sentence
    training_corpus = [
        "We must always solve x plus 2 equals 4 for elementary math curricula.",
    ]
    eval_benchmark = {
        "p_short": "solve x plus 2",
    }

    report = detect_benchmark_contamination(
        dataset_id="ds:short-leak",
        benchmark_suite_id="bench:short",
        training_texts=training_corpus,
        benchmark_items=eval_benchmark,
        fuzzy_ngram_size=5,  # ngram size larger than problem token count!
        fuzzy_threshold=0.5,
    )

    assert report.verdict == ContaminationVerdict.CONTAMINATED
    assert report.fuzzy_overlap_score == 1.0
    assert "p_short" in report.contaminated_problem_ids


def test_data_shard_rejects_negative_records_and_invalid_merkle_root() -> None:
    with pytest.raises(DatasetError, match="record_count must be non-negative"):
        DataShard("s1", DatasetSplit.TRAIN, -1, 100, _digest("payload"))

    with pytest.raises(DatasetError, match="byte_size must be non-negative"):
        DataShard("s1", DatasetSplit.TRAIN, 10, -50, _digest("payload"))

    with pytest.raises(DatasetError, match="Invalid records_merkle_root"):
        DataShard("s1", DatasetSplit.TRAIN, 10, 100, _digest("payload"), records_merkle_root="not-sha256")


def test_compute_merkle_root_rejects_invalid_leaf_hashes() -> None:
    with pytest.raises(DatasetError, match="Invalid leaf hash"):
        compute_merkle_root(["sha256:invalid-hash-too-short"])
