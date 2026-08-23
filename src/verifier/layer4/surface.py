"""Rung 4.10 -- the explicit refutation surface.

VSTD-2 defines the *claim* surface. VSTD-4 defines the *refutation* surface of
that claim surface. This is where the two layers compose, and it is the rung
that turns "someone could theoretically challenge this" into a list: here are
the predicates they may challenge, the coordinates on which each applies, and
the evidence that would overturn the verdict.

It replaces ``GenericRunReceipt.falsification_condition`` -- today a free-prose
English sentence sealed inside a canonical digest, where no checker can read it
and no challenger can be told they have satisfied it.

The invariant this rung serves:

> **No portable certificate without an explicit falsifier.**

which is enforced literally: a surface with an empty ``admissible`` list is
refused. A claim nobody is permitted to refute is not a strong claim, it is an
unfalsifiable one, and layer 4 exists to say so out loud.

``excluded_claims`` is the other half, and it is not a disclaimer. It gives
``PHYSICAL_WORLD_COMPLETENESS`` a permanent machine-readable home: ordinary
VSTD evidence has no observation boundary that enumerates all physical
execution worldwide.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Sequence

from ..core.certificate import ClaimCoordinate, canonical_digest


class RefutationType(str, Enum):
    """Kinds of counterevidence a claim may declare itself open to."""

    METRIC_RECOMPUTATION_MISMATCH = "metric_recomputation_mismatch"
    EVIDENCE_HASH_MISMATCH = "evidence_hash_mismatch"
    UNDECLARED_DEPENDENCY = "undeclared_dependency"
    INVALID_EXECUTION_RECEIPT = "invalid_execution_receipt"
    CERTIFICATE_VERIFICATION_FAILURE = "certificate_verification_failure"
    GROUNDING_MISMATCH = "grounding_mismatch"
    PRECOMMITMENT_VIOLATION = "precommitment_violation"
    AVAILABILITY_FAILURE = "availability_failure"
    ANCHOR_FORK = "anchor_fork"


PHYSICAL_WORLD_COMPLETENESS = "physical_world_completeness"
"""The ordinary-profile exclusion. See ``LADDER.md`` §4.3: no implemented
observation boundary enumerates all physical execution worldwide."""


@dataclass(frozen=True)
class AdmissibleRefutation:
    """One way this claim may be overturned, stated precisely enough to attempt."""

    refutation_type: RefutationType
    applies_to: tuple[str, ...]
    """Coordinate parameters the refutation ranges over. Empty means the whole claim."""

    overturning_evidence: str
    """What a challenger must produce. Not a hint -- the acceptance condition."""

    resulting_status: str = "REVOKED"
    """Where the claim lands if the challenge is confirmed."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "refutation_type": self.refutation_type.value,
            "applies_to": list(self.applies_to),
            "overturning_evidence": self.overturning_evidence,
            "resulting_status": self.resulting_status,
        }


@dataclass(frozen=True)
class ExcludedClaim:
    """Something this verdict is explicitly *not* evidence for."""

    claim_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"claim_id": self.claim_id, "reason": self.reason}


@dataclass(frozen=True)
class SurfaceCheck:
    accepted: bool
    details: str

    def to_dict(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "details": self.details}


@dataclass(frozen=True)
class RefutationSurface:
    coordinate: ClaimCoordinate
    admissible: tuple[AdmissibleRefutation, ...]
    excluded: tuple[ExcludedClaim, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "coordinate": self.coordinate.to_dict(),
            "admissible_refutations": [item.to_dict() for item in self.admissible],
            "excluded_claims": [item.to_dict() for item in self.excluded],
        }

    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def admits(self, refutation_type: RefutationType) -> Optional[AdmissibleRefutation]:
        for item in self.admissible:
            if item.refutation_type is refutation_type:
                return item
        return None

    def excludes(self, claim_id: str) -> Optional[ExcludedClaim]:
        for item in self.excluded:
            if item.claim_id == claim_id:
                return item
        return None

    def validate(self) -> SurfaceCheck:
        if not self.admissible:
            return SurfaceCheck(
                False,
                "surface declares no admissible refutation; a claim no one is "
                "permitted to refute is unfalsifiable, which is a rung 4.10 violation",
            )

        seen: set[RefutationType] = set()
        for refutation in self.admissible:
            if refutation.refutation_type in seen:
                return SurfaceCheck(
                    False,
                    f"refutation type {refutation.refutation_type.value!r} is declared twice",
                )
            seen.add(refutation.refutation_type)
            if not refutation.overturning_evidence.strip():
                return SurfaceCheck(
                    False,
                    f"refutation {refutation.refutation_type.value!r} states no overturning "
                    "evidence, so no challenger can tell whether they have met it",
                )
            unknown = [
                name
                for name in refutation.applies_to
                if name not in self.coordinate.parameters
            ]
            if unknown:
                return SurfaceCheck(
                    False,
                    f"refutation {refutation.refutation_type.value!r} ranges over coordinate "
                    f"parameters that do not exist: {sorted(unknown)}",
                )

        excluded_ids: set[str] = set()
        for exclusion in self.excluded:
            if exclusion.claim_id in excluded_ids:
                return SurfaceCheck(
                    False, f"claim {exclusion.claim_id!r} is excluded twice"
                )
            excluded_ids.add(exclusion.claim_id)
            if not exclusion.reason.strip():
                return SurfaceCheck(
                    False, f"exclusion of {exclusion.claim_id!r} states no reason"
                )

        return SurfaceCheck(
            True,
            f"{len(self.admissible)} admissible refutations, "
            f"{len(self.excluded)} excluded claims",
        )


def default_exclusions() -> tuple[ExcludedClaim, ...]:
    """The exclusion every VSTD claim carries, whether or not it says so."""
    return (
        ExcludedClaim(
            PHYSICAL_WORLD_COMPLETENESS,
            "ordinary VSTD evidence does not enumerate all physical execution "
            "worldwide; the claim is outside the declared observation boundary. "
            "A finite, explicitly enumerated world requires its own checked "
            "completeness mechanism and cannot be widened beyond that coordinate.",
        ),
    )


def surface_from_types(
    coordinate: ClaimCoordinate,
    types: Sequence[RefutationType],
    *,
    overturning_evidence: str,
    include_default_exclusions: bool = True,
) -> RefutationSurface:
    """Convenience constructor for the common case of whole-claim refutations."""
    return RefutationSurface(
        coordinate=coordinate,
        admissible=tuple(
            AdmissibleRefutation(item, (), overturning_evidence) for item in types
        ),
        excluded=default_exclusions() if include_default_exclusions else (),
    )
