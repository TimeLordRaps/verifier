"""Experimental level 6 disclosure helpers; normative conformance remains UNKNOWN.

These functions match caller-supplied policy and observer declarations. They do
not authenticate parties, establish consent, or prove general composition safety.
Digest commitments are not hiding or zero-knowledge proofs. Use the native domain
rechecker separately to establish the unchanged certificate's bounded result.

Acronyms:
    differential privacy (DP);
    JavaScript Object Notation (JSON);
    Secure Hash Algorithm 256-bit (SHA-256);
    Verifier Standard (VSTD);
    zero-identity/zero-knowledge (ZIZK).
"""

from __future__ import annotations

from .adapters import (
    BudgetExhaustedError,
    ContextualIntegrityEvaluator,
    ContextualTransmissionNorm,
    DifferentialPrivacyBudget,
    SafeHarborPartition,
    SelectiveMerkleDisclosure,
)
from .composition import CompositionDeltaEvaluator
from .engine import EmissionEvaluator, EmissionRefusalError
from .independence import MalformedRedactionError, assert_verdict_independence
from .models import (
    DisclosureBound,
    DisclosureSurface,
    EmissionContext,
    EmissionResult,
    ObserverParty,
    RedactionRecord,
    TransparencyCommitment,
)

__all__ = [
    "BudgetExhaustedError",
    "CompositionDeltaEvaluator",
    "ContextualIntegrityEvaluator",
    "ContextualTransmissionNorm",
    "DifferentialPrivacyBudget",
    "DisclosureBound",
    "DisclosureSurface",
    "EmissionContext",
    "EmissionEvaluator",
    "EmissionRefusalError",
    "EmissionResult",
    "MalformedRedactionError",
    "ObserverParty",
    "RedactionRecord",
    "SafeHarborPartition",
    "SelectiveMerkleDisclosure",
    "TransparencyCommitment",
    "assert_verdict_independence",
]
