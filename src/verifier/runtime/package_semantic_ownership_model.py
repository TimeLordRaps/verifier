"""Immutable records and normalization for package semantic ownership declarations.

This data-only module lets independently reviewed catalog partitions share one
constructor without importing the aggregate catalog or creating import cycles.
Construction normalizes ordering only; it does not validate paths, kinds,
reasons, evidence, admission, or conformance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class RootRoleDecision:
    """Evidence-backed applicability for a retained root kind.

    Retained roots are not structural specializations.  Keeping this decision
    separate prevents a mixed-role source owner from bypassing that root's
    typed operand layout while still carrying its higher-tier obligations.
    """

    kind: str
    status: Literal["APPLIES", "DOES_NOT_APPLY"]
    reason: str


@dataclass(frozen=True)
class SemanticOwnershipSpec:
    """One path-disjoint package object proposed for manifest ownership."""

    object_id: str
    primary_kind: str
    specializations: tuple[str, ...]
    owned_paths: tuple[str, ...]
    representation_role: str
    necessity_reason: str
    consequence_boundary: str
    operands: tuple[tuple[str, tuple[str, ...]], ...] = ()
    root_role_decisions: tuple[RootRoleDecision, ...] = ()


def root_role_decision(
    kind: str,
    status: Literal["APPLIES", "DOES_NOT_APPLY"],
    reason: str,
) -> RootRoleDecision:
    """Construct one deterministic retained-root applicability decision."""
    return RootRoleDecision(kind=kind, status=status, reason=reason)


def ownership_spec(
    object_id: str,
    primary_kind: str,
    paths: tuple[str, ...],
    role: str,
    reason: str,
    boundary: str,
    *specializations: str,
    operands: tuple[tuple[str, tuple[str, ...]], ...] = (),
    root_role_decisions: tuple[RootRoleDecision, ...] = (),
) -> SemanticOwnershipSpec:
    """Normalize one declaration without asserting that its claims are true."""
    return SemanticOwnershipSpec(
        object_id=object_id,
        primary_kind=primary_kind,
        specializations=tuple(sorted(specializations)),
        owned_paths=tuple(sorted(paths)),
        representation_role=role,
        necessity_reason=reason,
        consequence_boundary=boundary,
        operands=tuple(
            sorted((name, tuple(sorted(targets))) for name, targets in operands)
        ),
        root_role_decisions=tuple(
            sorted(root_role_decisions, key=lambda decision: decision.kind)
        ),
    )


__all__ = [
    "RootRoleDecision",
    "SemanticOwnershipSpec",
    "ownership_spec",
    "root_role_decision",
]
