"""Terminology: Verifier Standard (VSTD).

Rung 4.14 -- refutability closure, and the handoff out of layer 4.

``A`` is VSTD-4 and ``B`` is VSTD-4 does **not** make ``C = f(A, B)`` VSTD-4.
Refutability is not preserved by arbitrary transformation, and assuming it is
is how a pipeline ends up with an impeccably-certified output that no one can
attack, because every challenge bounces between the two inputs and the step
that combined them with nobody responsible for any of it.

A :class:`RefutabilityClosure` fixes that by declaring, in advance, where each
possible challenge to the output lands: on an input, on the transformation, or
on the composition itself. A challenger reading it knows what to attack.

This rung is simultaneously three things, which is why it sits at the top:

* the top of layer 4;
* the precondition for VSTD-Graph condition 4 -- edges carry evidence, not just
  nodes, because a graph is only as verified as its edges;
* the entry gate to VSTD-5. An external witness can only corroborate a claim
  whose refutability composes, so ``vstd4_depth(claim) == 14`` is the gate.

:meth:`RefutabilityClosure.closed_depth` is the load-bearing computation: the
output is capped at the *minimum* depth across its inputs and its transformation.
Not the average, and emphatically not the maximum -- an unevidenced edge between
two layer-5 artifacts does not yield a layer-5 collection.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from ..core.certificate import canonical_digest
from .surface import RefutationSurface, RefutationType


class Locus(str, Enum):
    """Where a challenge to the output actually lands."""

    INPUT = "INPUT"
    """An input claim is wrong. The challenge forwards to that input's own surface."""

    TRANSFORMATION = "TRANSFORMATION"
    """The step itself is wrong -- ``f`` did not do what its certificate says."""

    COMPOSITION = "COMPOSITION"
    """Every input is sound and ``f`` ran correctly, and the output still does not
    follow. The interesting case, and the one an unclosed pipeline loses entirely."""


@dataclass(frozen=True)
class InputBinding:
    input_id: str
    certificate_digest: str
    depth: int
    """``vstd4_depth`` of this input, computed by :mod:`verifier.core.depth`."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_id": self.input_id,
            "certificate_digest": self.certificate_digest,
            "depth": self.depth,
        }


@dataclass(frozen=True)
class RefutationMapping:
    """One output refutation, localized."""

    output_refutation: RefutationType
    locus: Locus
    localizes_to: str
    input_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "output_refutation": self.output_refutation.value,
            "locus": self.locus.value,
            "localizes_to": self.localizes_to,
            "input_id": self.input_id,
        }


@dataclass(frozen=True)
class ClosureCheck:
    accepted: bool
    closed_depth: int
    details: str
    unmapped: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "closed_depth": self.closed_depth,
            "details": self.details,
            "unmapped": list(self.unmapped),
        }


@dataclass(frozen=True)
class RefutabilityClosure:
    closure_id: str
    inputs: tuple[InputBinding, ...]
    transformation_certificate: str
    transformation_depth: int
    output_claim: str
    output_surface: RefutationSurface
    mappings: tuple[RefutationMapping, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "closure_id": self.closure_id,
            "inputs": [item.to_dict() for item in self.inputs],
            "transformation_certificate": self.transformation_certificate,
            "transformation_depth": self.transformation_depth,
            "output_claim": self.output_claim,
            "output_surface": self.output_surface.to_dict(),
            "mappings": [item.to_dict() for item in self.mappings],
        }

    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def closed_depth(self) -> int:
        """The output's ceiling: the weakest link, inputs and edge alike."""
        return min(
            [self.transformation_depth] + [item.depth for item in self.inputs],
            default=0,
        )

    def localize(self, refutation_type: RefutationType) -> Optional[RefutationMapping]:
        for mapping in self.mappings:
            if mapping.output_refutation is refutation_type:
                return mapping
        return None

    def validate(self) -> ClosureCheck:
        depth = self.closed_depth()

        if not self.inputs:
            return ClosureCheck(
                False, depth, "closure declares no inputs; there is nothing being composed"
            )
        if not self.transformation_certificate.strip():
            return ClosureCheck(
                False,
                depth,
                "closure declares no transformation certificate; an unevidenced edge "
                "between verified nodes does not yield a verified output",
            )

        surface = self.output_surface.validate()
        if not surface.accepted:
            return ClosureCheck(False, depth, f"output surface rejected: {surface.details}")

        known = {item.input_id for item in self.inputs}
        if len(known) != len(self.inputs):
            return ClosureCheck(False, depth, "closure declares the same input twice")

        seen: set[RefutationType] = set()
        for mapping in self.mappings:
            if mapping.output_refutation in seen:
                return ClosureCheck(
                    False,
                    depth,
                    f"refutation {mapping.output_refutation.value!r} is mapped twice; a "
                    "challenge that lands in two places lands nowhere",
                )
            seen.add(mapping.output_refutation)
            if mapping.locus is Locus.INPUT and mapping.input_id not in known:
                return ClosureCheck(
                    False,
                    depth,
                    f"refutation {mapping.output_refutation.value!r} localizes to input "
                    f"{mapping.input_id!r}, which is not bound by this closure",
                )
            if mapping.locus is not Locus.INPUT and mapping.input_id:
                return ClosureCheck(
                    False,
                    depth,
                    f"refutation {mapping.output_refutation.value!r} has locus "
                    f"{mapping.locus.value} but still names an input",
                )
            if not mapping.localizes_to.strip():
                return ClosureCheck(
                    False,
                    depth,
                    f"refutation {mapping.output_refutation.value!r} names no target; "
                    "a challenger is told where to aim or the mapping is decoration",
                )

        unmapped = tuple(
            sorted(
                item.refutation_type.value
                for item in self.output_surface.admissible
                if item.refutation_type not in seen
            )
        )
        if unmapped:
            return ClosureCheck(
                False,
                depth,
                "the output surface admits refutations the closure cannot localize: "
                + ", ".join(unmapped),
                unmapped,
            )

        return ClosureCheck(
            True,
            depth,
            f"closure over {len(self.inputs)} input(s) is complete; output is capped "
            f"at vstd4_depth {depth}",
        )


def cap_output_depth(closure: RefutabilityClosure, claimed_depth: int) -> ClosureCheck:
    """Refuse an output claiming more layer-4 depth than its closure supports.

    This is rung 4.13 acting across a transformation rather than across time,
    and it is the specific check VSTD-Graph condition 4 calls into.
    """
    check = closure.validate()
    if not check.accepted:
        return check
    if claimed_depth > check.closed_depth:
        return ClosureCheck(
            False,
            check.closed_depth,
            f"output claims vstd4_depth {claimed_depth} but its closure supports only "
            f"{check.closed_depth}; refutability does not increase under composition",
        )
    return ClosureCheck(
        True,
        check.closed_depth,
        f"output depth {claimed_depth} is within the closure's ceiling of {check.closed_depth}",
    )
