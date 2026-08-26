"""Terminology: Boolean satisfiability problem (SAT); Verifier Standard (VSTD).

Reproducibility taxonomy and verification comparison levels.

Defines the formal gradient of reproducibility for computational and formal claims.
"""

from __future__ import annotations

from enum import Enum


class ReproducibilityLevel(str, Enum):
    """Monotone levels of reproduction fidelity."""

    BITWISE_IDENTICAL = "BITWISE_IDENTICAL"
    """Exact byte-for-byte identity of all generated artifacts, receipts, and hashes."""

    CONTENT_IDENTICAL = "CONTENT_IDENTICAL"
    """Canonical representation of mathematical and logical verification payload matches exactly,
    ignoring volatile runtime fields (execution timestamps, elapsed wall-clock ms, hostnames)."""

    EVIDENCE_EQUIVALENT = "EVIDENCE_EQUIVALENT"
    """All checks, SAT assignments, invariant bounds, and derivation graphs evaluate to the same
    truth values and proof certificates, though internal trace order or solver step counts may differ."""

    RESULT_EQUIVALENT = "RESULT_EQUIVALENT"
    """High-level verification verdict (VERIFIED/FALSIFIED) and primary output metrics agree within
    declared error tolerance, but internal intermediate proof structures may differ."""

    SEMANTIC_REPRODUCTION = "SEMANTIC_REPRODUCTION"
    """The proposition is sustained under a separately implemented translation or solver.

    This level does not establish distinct actors.
    """


def compare_reproduction_level(
    original_canonical_digest: str,
    reproduced_canonical_digest: str,
    original_verdict: str,
    reproduced_verdict: str,
    original_evidence_hash: str | None = None,
    reproduced_evidence_hash: str | None = None,
    original_raw_bytes: bytes | None = None,
    reproduced_raw_bytes: bytes | None = None,
) -> ReproducibilityLevel | None:
    """Return the strongest level earned by the supplied comparison evidence.

    ``None`` means that these inputs do not establish a taxonomy level.  A
    matching verdict without matching primary metrics cannot establish result
    equivalence, and a verdict mismatch cannot establish semantic reproduction.
    """
    if original_raw_bytes is not None and reproduced_raw_bytes is not None:
        if original_raw_bytes == reproduced_raw_bytes:
            return ReproducibilityLevel.BITWISE_IDENTICAL

    if original_canonical_digest == reproduced_canonical_digest:
        return ReproducibilityLevel.CONTENT_IDENTICAL

    if (
        original_verdict == reproduced_verdict
        and original_evidence_hash is not None
        and original_evidence_hash == reproduced_evidence_hash
    ):
        return ReproducibilityLevel.EVIDENCE_EQUIVALENT

    return None
