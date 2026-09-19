"""Terminology: directed acyclic graph (DAG); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Comprehensive adversarial test suite for VSTD-HYPER hyperparameter, checkpoint lineage, and training run traceability.
"""

from __future__ import annotations

import hashlib
import json
import pytest

from verifier.corrigibility.hyperparameters import (
    CheckpointLineageBrokenError,
    CheckpointLineageDAG,
    CheckpointNode,
    HyperparameterError,
    HyperparameterManifest,
    PrecisionType,
    TrainingStepReceipt,
)


def _digest(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _sample_manifest() -> HyperparameterManifest:
    return HyperparameterManifest(
        run_id="run:pretrain-7b-v1",
        learning_rate=3e-4,
        scheduler="cosine_with_warmup",
        batch_size=2048,
        gradient_accumulation_steps=8,
        optimizer="AdamW",
        weight_decay=0.1,
        precision=PrecisionType.BF16,
        random_seed=42,
        max_grad_norm=1.0,
    )


def test_hyperparameter_manifest_canonical_digest_and_serialization() -> None:
    m1 = _sample_manifest()
    m2 = _sample_manifest()
    assert m1.canonical_digest() == m2.canonical_digest()
    assert m1.canonical_digest().startswith("sha256:")

    data = m1.to_dict()
    restored = HyperparameterManifest.from_dict(data)
    assert restored.canonical_digest() == m1.canonical_digest()
    assert restored.run_id == "run:pretrain-7b-v1"


def test_training_step_receipt_validation() -> None:
    receipt = TrainingStepReceipt(
        step_index=100,
        epoch=1,
        parent_checkpoint_digest=_digest("ckpt_step_99"),
        batch_shard_digest=_digest("shard_100"),
        loss_value=1.845,
        grad_norm=0.72,
        step_duration_ms=420.5,
        resulting_checkpoint_digest=_digest("ckpt_step_100"),
    )
    assert receipt.step_index == 100
    assert receipt.epoch == 1

    with pytest.raises(HyperparameterError, match="must be non-negative"):
        TrainingStepReceipt(
            step_index=-1,
            epoch=0,
            parent_checkpoint_digest=_digest("p"),
            batch_shard_digest=_digest("b"),
            loss_value=1.0,
            grad_norm=1.0,
            step_duration_ms=10.0,
            resulting_checkpoint_digest=_digest("r"),
        )

    with pytest.raises(HyperparameterError, match="Invalid parent_checkpoint_digest"):
        TrainingStepReceipt(
            step_index=0,
            epoch=0,
            parent_checkpoint_digest="invalid",
            batch_shard_digest=_digest("b"),
            loss_value=1.0,
            grad_norm=1.0,
            step_duration_ms=10.0,
            resulting_checkpoint_digest=_digest("r"),
        )


def test_checkpoint_lineage_unbroken_success() -> None:
    dag = CheckpointLineageDAG()

    d0 = _digest("ckpt_0")
    d1 = _digest("ckpt_1")
    d2 = _digest("ckpt_2")

    # Checkpoints
    c0 = CheckpointNode("ckpt:0", 0, d0, _digest("opt0"), _digest("hp"))
    c1 = CheckpointNode("ckpt:1", 100, d1, _digest("opt1"), _digest("hp"), parent_checkpoint_id="ckpt:0")
    c2 = CheckpointNode("ckpt:2", 200, d2, _digest("opt2"), _digest("hp"), parent_checkpoint_id="ckpt:1")

    dag.add_checkpoint(c0)
    dag.add_checkpoint(c1)
    dag.add_checkpoint(c2)

    # Step receipts linking 0 -> 1 -> 2
    s1 = TrainingStepReceipt(1, 0, d0, _digest("b1"), 2.5, 0.9, 100.0, _digest("ckpt_step_1"))
    s2 = TrainingStepReceipt(2, 0, _digest("ckpt_step_1"), _digest("b2"), 2.4, 0.8, 100.0, _digest("ckpt_step_2"))

    dag.add_step(s1)
    dag.add_step(s2)

    verified, msg = dag.verify_lineage()
    assert verified is True
    assert "cryptographically verified" in msg


def test_checkpoint_lineage_broken_on_parent_hash_mismatch() -> None:
    dag = CheckpointLineageDAG()

    d0 = _digest("ckpt_0")
    d1_actual = _digest("ckpt_step_1")
    d1_tampered = _digest("ckpt_step_1_tampered")

    s1 = TrainingStepReceipt(1, 0, d0, _digest("b1"), 2.5, 0.9, 100.0, d1_actual)
    # s2 claims parent is d1_tampered instead of d1_actual!
    s2 = TrainingStepReceipt(2, 0, d1_tampered, _digest("b2"), 2.4, 0.8, 100.0, _digest("ckpt_step_2"))

    dag.add_step(s1)
    dag.add_step(s2)

    with pytest.raises(CheckpointLineageBrokenError, match="Lineage break at step 2"):
        dag.verify_lineage()


def test_checkpoint_lineage_broken_on_non_monotonic_step_index() -> None:
    dag = CheckpointLineageDAG()

    d0 = _digest("ckpt_0")
    d1 = _digest("ckpt_1")
    d2 = _digest("ckpt_2")

    s1 = TrainingStepReceipt(10, 0, d0, _digest("b1"), 2.5, 0.9, 100.0, d1)
    # Non-monotonic: step 10 -> step 9
    s2 = TrainingStepReceipt(9, 0, d1, _digest("b2"), 2.4, 0.8, 100.0, d2)

    dag.add_step(s1)
    dag.add_step(s2)

    with pytest.raises(CheckpointLineageBrokenError, match="Non-monotonic step progression"):
        dag.verify_lineage()


def test_checkpoint_lineage_broken_on_missing_parent_checkpoint() -> None:
    dag = CheckpointLineageDAG()

    c1 = CheckpointNode(
        "ckpt:child",
        100,
        _digest("w"),
        _digest("opt"),
        _digest("hp"),
        parent_checkpoint_id="ckpt:missing-parent",
    )
    dag.add_checkpoint(c1)

    s1 = TrainingStepReceipt(1, 0, _digest("p"), _digest("b"), 2.0, 0.5, 50.0, _digest("r"))
    dag.add_step(s1)

    with pytest.raises(CheckpointLineageBrokenError, match="Missing parent checkpoint"):
        dag.verify_lineage()


def test_checkpoint_lineage_detects_mismatch_with_step_receipt_weights() -> None:
    dag = CheckpointLineageDAG()

    # Step 50 produced resulting_checkpoint_digest sha256:...50
    step_50_digest = _digest("weights_step_50_actual")
    s1 = TrainingStepReceipt(50, 1, _digest("w_prev"), _digest("b"), 1.2, 0.4, 45.0, step_50_digest)
    dag.add_step(s1)

    # Checkpoint at step 50 claims to be step 50 but contains different weights sha256:...tampered
    tampered_digest = _digest("weights_step_50_tampered")
    c1 = CheckpointNode("ckpt:50", 50, tampered_digest, _digest("opt"), _digest("hp"))
    dag.add_checkpoint(c1)

    with pytest.raises(CheckpointLineageBrokenError, match="Checkpoint digest mismatch at step 50"):
        dag.verify_lineage()
