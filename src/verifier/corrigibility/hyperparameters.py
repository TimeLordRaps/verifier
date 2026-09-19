"""Terminology: directed acyclic graph (DAG); identifier (ID); JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

VSTD-HYPER: Hyperparameter, checkpoint lineage, and training run traceability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class PrecisionType(str, Enum):
    FP32 = "FP32"
    FP16 = "FP16"
    BF16 = "BF16"
    FP8 = "FP8"


class HyperparameterError(ValueError):
    """Base error for VSTD-HYPER operations."""


class CheckpointLineageBrokenError(HyperparameterError):
    """Raised when checkpoint lineage hashes diverge or intermediate steps are missing."""


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class HyperparameterManifest:
    """Declared hyperparameter configuration for a training run."""

    run_id: str
    learning_rate: float
    scheduler: str
    batch_size: int
    gradient_accumulation_steps: int
    optimizer: str
    weight_decay: float
    precision: PrecisionType
    random_seed: int
    max_grad_norm: float = 1.0

    def canonical_digest(self) -> str:
        payload = {
            "run_id": self.run_id,
            "learning_rate": self.learning_rate,
            "scheduler": self.scheduler,
            "batch_size": self.batch_size,
            "gradient_accumulation_steps": self.gradient_accumulation_steps,
            "optimizer": self.optimizer,
            "weight_decay": self.weight_decay,
            "precision": self.precision.value,
            "random_seed": self.random_seed,
            "max_grad_norm": self.max_grad_norm,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "learning_rate": self.learning_rate,
            "scheduler": self.scheduler,
            "batch_size": self.batch_size,
            "gradient_accumulation_steps": self.gradient_accumulation_steps,
            "optimizer": self.optimizer,
            "weight_decay": self.weight_decay,
            "precision": self.precision.value,
            "random_seed": self.random_seed,
            "max_grad_norm": self.max_grad_norm,
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HyperparameterManifest:
        return cls(
            run_id=str(data["run_id"]),
            learning_rate=float(data["learning_rate"]),
            scheduler=str(data["scheduler"]),
            batch_size=int(data["batch_size"]),
            gradient_accumulation_steps=int(data["gradient_accumulation_steps"]),
            optimizer=str(data["optimizer"]),
            weight_decay=float(data["weight_decay"]),
            precision=PrecisionType(data["precision"]),
            random_seed=int(data["random_seed"]),
            max_grad_norm=float(data.get("max_grad_norm", 1.0)),
        )


@dataclass(frozen=True)
class TrainingStepReceipt:
    """Cryptographically bound receipt for an individual gradient step."""

    step_index: int
    epoch: int
    parent_checkpoint_digest: str
    batch_shard_digest: str
    loss_value: float
    grad_norm: float
    step_duration_ms: float
    resulting_checkpoint_digest: str

    def __post_init__(self) -> None:
        if self.step_index < 0 or self.epoch < 0:
            raise HyperparameterError("step_index and epoch must be non-negative integers")
        if not _DIGEST_PATTERN.match(self.parent_checkpoint_digest):
            raise HyperparameterError(
                f"Invalid parent_checkpoint_digest: '{self.parent_checkpoint_digest}'"
            )
        if not _DIGEST_PATTERN.match(self.batch_shard_digest):
            raise HyperparameterError(
                f"Invalid batch_shard_digest: '{self.batch_shard_digest}'"
            )
        if not _DIGEST_PATTERN.match(self.resulting_checkpoint_digest):
            raise HyperparameterError(
                f"Invalid resulting_checkpoint_digest: '{self.resulting_checkpoint_digest}'"
            )

    def canonical_digest(self) -> str:
        payload = {
            "step_index": self.step_index,
            "epoch": self.epoch,
            "parent_checkpoint_digest": self.parent_checkpoint_digest,
            "batch_shard_digest": self.batch_shard_digest,
            "loss_value": self.loss_value,
            "grad_norm": self.grad_norm,
            "step_duration_ms": self.step_duration_ms,
            "resulting_checkpoint_digest": self.resulting_checkpoint_digest,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_index": self.step_index,
            "epoch": self.epoch,
            "parent_checkpoint_digest": self.parent_checkpoint_digest,
            "batch_shard_digest": self.batch_shard_digest,
            "loss_value": self.loss_value,
            "grad_norm": self.grad_norm,
            "step_duration_ms": self.step_duration_ms,
            "resulting_checkpoint_digest": self.resulting_checkpoint_digest,
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TrainingStepReceipt:
        return cls(
            step_index=int(data["step_index"]),
            epoch=int(data["epoch"]),
            parent_checkpoint_digest=str(data["parent_checkpoint_digest"]),
            batch_shard_digest=str(data["batch_shard_digest"]),
            loss_value=float(data["loss_value"]),
            grad_norm=float(data["grad_norm"]),
            step_duration_ms=float(data["step_duration_ms"]),
            resulting_checkpoint_digest=str(data["resulting_checkpoint_digest"]),
        )


@dataclass(frozen=True)
class CheckpointNode:
    """Checkpoint metadata node in the training lineage."""

    checkpoint_id: str
    step_index: int
    weights_digest: str
    optimizer_state_digest: str
    hyperparameters_digest: str
    parent_checkpoint_id: str = ""

    def __post_init__(self) -> None:
        if not self.checkpoint_id:
            raise HyperparameterError("checkpoint_id cannot be empty")
        if not _DIGEST_PATTERN.match(self.weights_digest):
            raise HyperparameterError(f"Invalid weights_digest: '{self.weights_digest}'")
        if not _DIGEST_PATTERN.match(self.optimizer_state_digest):
            raise HyperparameterError(
                f"Invalid optimizer_state_digest: '{self.optimizer_state_digest}'"
            )
        if not _DIGEST_PATTERN.match(self.hyperparameters_digest):
            raise HyperparameterError(
                f"Invalid hyperparameters_digest: '{self.hyperparameters_digest}'"
            )

    def canonical_digest(self) -> str:
        payload = {
            "checkpoint_id": self.checkpoint_id,
            "step_index": self.step_index,
            "weights_digest": self.weights_digest,
            "optimizer_state_digest": self.optimizer_state_digest,
            "hyperparameters_digest": self.hyperparameters_digest,
            "parent_checkpoint_id": self.parent_checkpoint_id,
        }
        digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
        return f"sha256:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "step_index": self.step_index,
            "weights_digest": self.weights_digest,
            "optimizer_state_digest": self.optimizer_state_digest,
            "hyperparameters_digest": self.hyperparameters_digest,
            "parent_checkpoint_id": self.parent_checkpoint_id,
            "canonical_digest": self.canonical_digest(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CheckpointNode:
        return cls(
            checkpoint_id=str(data["checkpoint_id"]),
            step_index=int(data["step_index"]),
            weights_digest=str(data["weights_digest"]),
            optimizer_state_digest=str(data["optimizer_state_digest"]),
            hyperparameters_digest=str(data["hyperparameters_digest"]),
            parent_checkpoint_id=str(data.get("parent_checkpoint_id", "")),
        )


class CheckpointLineageDAG:
    """Cryptographic lineage tracker across model checkpoints and gradient receipts."""

    def __init__(self) -> None:
        self._checkpoints: dict[str, CheckpointNode] = {}
        self._steps: list[TrainingStepReceipt] = []

    def add_checkpoint(self, ckpt: CheckpointNode) -> None:
        if ckpt.checkpoint_id in self._checkpoints:
            raise HyperparameterError(f"Duplicate checkpoint_id: '{ckpt.checkpoint_id}'")
        self._checkpoints[ckpt.checkpoint_id] = ckpt

    def add_step(self, step: TrainingStepReceipt) -> None:
        self._steps.append(step)

    @property
    def checkpoints(self) -> Mapping[str, CheckpointNode]:
        return dict(self._checkpoints)

    @property
    def steps(self) -> Sequence[TrainingStepReceipt]:
        return tuple(self._steps)

    def verify_lineage(self) -> tuple[bool, str]:
        """Verify unbroken cryptographic parent hash binding and monotonic step progression."""
        if not self._steps:
            return False, "Empty step sequence: no gradient steps to verify"

        for i in range(len(self._steps)):
            curr = self._steps[i]
            if i > 0:
                prev = self._steps[i - 1]
                # Step index monotonicity check in sequence
                if curr.step_index <= prev.step_index:
                    raise CheckpointLineageBrokenError(
                        f"Non-monotonic step progression: step {curr.step_index} <= previous {prev.step_index}"
                    )
                if curr.epoch < prev.epoch:
                    raise CheckpointLineageBrokenError(
                        f"Non-monotonic epoch progression: epoch {curr.epoch} < previous {prev.epoch}"
                    )
                # Strict parent hash binding check
                if curr.parent_checkpoint_digest != prev.resulting_checkpoint_digest:
                    raise CheckpointLineageBrokenError(
                        f"Lineage break at step {curr.step_index}: parent hash '{curr.parent_checkpoint_digest}' "
                        f"does not match previous step result '{prev.resulting_checkpoint_digest}'"
                    )

        # Checkpoint node hierarchy check
        for ckpt_id, ckpt in self._checkpoints.items():
            if ckpt.parent_checkpoint_id:
                if ckpt.parent_checkpoint_id not in self._checkpoints:
                    raise CheckpointLineageBrokenError(
                        f"Missing parent checkpoint '{ckpt.parent_checkpoint_id}' for '{ckpt_id}'"
                    )
                parent_ckpt = self._checkpoints[ckpt.parent_checkpoint_id]
                if ckpt.step_index <= parent_ckpt.step_index:
                    raise CheckpointLineageBrokenError(
                        f"Step index inversion: checkpoint '{ckpt_id}' (step {ckpt.step_index}) "
                        f"<= parent '{parent_ckpt.checkpoint_id}' (step {parent_ckpt.step_index})"
                    )

        # Cross-reference checkpoint nodes with step receipts at matching step indices
        steps_by_index = {step.step_index: step for step in self._steps}
        for ckpt_id, ckpt in self._checkpoints.items():
            if ckpt.step_index in steps_by_index:
                matching_step = steps_by_index[ckpt.step_index]
                if ckpt.weights_digest != matching_step.resulting_checkpoint_digest:
                    raise CheckpointLineageBrokenError(
                        f"Checkpoint digest mismatch at step {ckpt.step_index}: checkpoint '{ckpt_id}' "
                        f"weights digest '{ckpt.weights_digest}' does not match step receipt "
                        f"resulting digest '{matching_step.resulting_checkpoint_digest}'"
                    )

        return True, "Checkpoint lineage cryptographically verified and unbroken"
