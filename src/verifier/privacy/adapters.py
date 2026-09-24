"""Standardized privacy framework meta-adapters for Level 6 disclosure bounds.

Acronyms:
    differential privacy (DP);
    JavaScript Object Notation (JSON);
    Secure Hash Algorithm 256-bit (SHA-256);
    Verifier Standard (VSTD).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any

from .models import ObserverParty, TransparencyCommitment


class BudgetExhaustedError(ValueError):
    """Raised when cumulative differential privacy budget exceeds the declared limit."""


@dataclass
class DifferentialPrivacyBudget:
    """Tracks and bounds cumulative privacy budget exhaustion across emissions.

    Differential privacy models information leakage as a depletable resource
    governed by parameters (epsilon, delta). Each emission consumes a declared
    slice, and exceeding the total bound locks the emission interface.
    """

    max_epsilon: float
    max_delta: float
    consumed_epsilon: float = 0.0
    consumed_delta: float = 0.0
    emissions_count: int = 0

    def consume(self, epsilon: float, delta: float = 0.0) -> dict[str, Any]:
        """Attempt to consume budget for an emission; fails closed if exhausted."""
        if epsilon < 0.0 or delta < 0.0:
            raise ValueError(f"Negative privacy budget parameter: eps={epsilon}, delta={delta}")
        new_eps = self.consumed_epsilon + epsilon
        new_delta = self.consumed_delta + delta
        if new_eps > self.max_epsilon or new_delta > self.max_delta:
            raise BudgetExhaustedError(
                f"Differential privacy budget exhausted: requested (+{epsilon}, +{delta}), "
                f"cumulative would be ({new_eps:.4f}, {new_delta:.6f}) > limit ({self.max_epsilon}, {self.max_delta})"
            )
        self.consumed_epsilon = new_eps
        self.consumed_delta = new_delta
        self.emissions_count += 1
        return {
            "consumed_epsilon": self.consumed_epsilon,
            "consumed_delta": self.consumed_delta,
            "remaining_epsilon": max(0.0, self.max_epsilon - self.consumed_epsilon),
            "remaining_delta": max(0.0, self.max_delta - self.consumed_delta),
            "emissions_count": self.emissions_count,
        }


@dataclass(frozen=True)
class ContextualTransmissionNorm:
    """Nissenbaum's Contextual Integrity transmission norm 5-tuple."""

    sender: str
    recipient: str
    subject: str
    information_type: str
    transmission_principle: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class ContextualIntegrityEvaluator:
    """Evaluates whether an emission conforms to Contextual Integrity transmission norms.

    Privacy is defined not as absolute confidentiality, but as adherence to
    context-relative informational norms.
    """

    ALLOWED_PRINCIPLES = {
        "audit_only",
        "confidential",
        "non_relaying",
        "single_use",
        "consent_governed",
    }

    def __init__(self, admitted_norms: tuple[ContextualTransmissionNorm, ...] | None = None) -> None:
        self.admitted_norms = () if admitted_norms is None else admitted_norms

    def evaluate(
        self,
        sender: str,
        recipient: ObserverParty,
        subject: str,
        information_type: str,
        requested_principle: str,
    ) -> tuple[bool, str]:
        """Verify whether the requested transmission conforms to an admitted norm."""
        if requested_principle not in self.ALLOWED_PRINCIPLES:
            return False, f"Unknown transmission principle: {requested_principle!r}"

        # If explicit norms are configured, verify match
        if self.admitted_norms:
            match = any(
                norm.sender == sender
                and (norm.recipient == recipient.role or norm.recipient == recipient.actor_id or norm.recipient == "*")
                and (norm.subject == subject or norm.subject == "*")
                and (norm.information_type == information_type or norm.information_type == "*")
                and (norm.transmission_principle == requested_principle or norm.transmission_principle == "*")
                for norm in self.admitted_norms
            )
            if not match:
                return (
                    False,
                    f"No matching contextual transmission norm for ({sender} -> {recipient.role}, {subject}, {information_type}, {requested_principle})",
                )

        # Principle-specific role verification
        if requested_principle == "audit_only" and recipient.role.lower() not in {"auditor", "verifier_admin", "compliance_officer", "inspector"}:
            return False, f"Principle 'audit_only' requires auditor role, got {recipient.role!r}"

        return True, ""


class SelectiveMerkleDisclosure:
    """Merkle tree leaf disclosure preserving cryptographic root integrity.

    Transparently commits to every field of an object. When a field is redacted
    for privacy, its value is replaced with its leaf digest, allowing an observer
    to verify the global root without learning the private leaf value.
    """

    @staticmethod
    def _leaf_hash(key: str, value: Any) -> str:
        payload = json.dumps({"k": key, "v": value}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def compute_root(cls, fields: dict[str, Any]) -> str:
        """Compute Merkle-like root commitment across dictionary fields."""
        if not fields:
            return hashlib.sha256(b"empty").hexdigest()
        leaf_hashes = sorted(cls._leaf_hash(k, v) for k, v in fields.items())
        combined = ":".join(leaf_hashes)
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    @classmethod
    def disclose_selectively(
        cls,
        fields: dict[str, Any],
        disclosed_keys: set[str],
    ) -> tuple[dict[str, Any], tuple[TransparencyCommitment, ...], str]:
        """Produce selectively disclosed fields and transparency commitments."""
        root_digest = cls.compute_root(fields)
        emitted: dict[str, Any] = {}
        commitments: list[TransparencyCommitment] = []

        for k, v in fields.items():
            if k in disclosed_keys:
                emitted[k] = v
            else:
                leaf = cls._leaf_hash(k, v)
                commitments.append(
                    TransparencyCommitment(
                        field_name=k,
                        schema_type=type(v).__name__,
                        commitment_digest=leaf,
                        algorithm="sha256",
                    )
                )
                emitted[f"__withheld_{k}__"] = {
                    "commitment": leaf,
                    "schema_type": type(v).__name__,
                }

        return emitted, tuple(commitments), root_digest


class SafeHarborPartition:
    """Attribute-based de-identification partitioning."""

    DIRECT_IDENTIFIER_KEYS = {
        "name", "email", "phone", "ssn", "ip_address", "actor_secret", "private_key",
        "genesis_secret", "salt", "passphrase"
    }

    @classmethod
    def partition(cls, data: dict[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
        """Partition data by suppressing direct identifiers."""
        disclosed: dict[str, Any] = {}
        withheld: list[str] = []
        for k, v in data.items():
            if k.lower() in cls.DIRECT_IDENTIFIER_KEYS:
                withheld.append(k)
            else:
                disclosed[k] = v
        return disclosed, tuple(withheld)
