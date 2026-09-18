"""Terminology: JavaScript Object Notation (JSON); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD); zero-identity/zero-knowledge (ZIZK).

Zero-identity cryptographic tokens and offline evaluation for Verifier Standard (VSTD)."""

from __future__ import annotations

from verifier.identity.invariants import (
    IDENTITY_VERDICTS,
    PROHIBITED_INFERENCES,
    PROPERTY_STATUSES,
    IdentityVerdict,
    PropertyStatus,
)
from verifier.identity.tokens import (
    ActorBinding,
    AgingToken,
    BirthToken,
    LifetimeToken,
    advance_aging_accumulator,
    canonical_token_bytes,
    compute_birth_commitment,
)
from verifier.identity.evaluator import (
    IdentityEvaluation,
    evaluate_identity,
)
from verifier.identity.audit import (
    audit_actor_slippage,
    AdversarialAuditReport,
)

__all__ = [
    "IDENTITY_VERDICTS",
    "PROHIBITED_INFERENCES",
    "PROPERTY_STATUSES",
    "IdentityVerdict",
    "PropertyStatus",
    "ActorBinding",
    "AgingToken",
    "BirthToken",
    "LifetimeToken",
    "advance_aging_accumulator",
    "canonical_token_bytes",
    "compute_birth_commitment",
    "IdentityEvaluation",
    "evaluate_identity",
    "audit_actor_slippage",
    "AdversarialAuditReport",
]
