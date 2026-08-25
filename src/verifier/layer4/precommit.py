"""Terminology: International Organization for Standardization (ISO);
Coordinated Universal Time (UTC); Verifier Standard (VSTD).

Rung 4.11 -- the precommitment envelope.

Committing only the claim is not enough, and the gap is not subtle. A declarant
can honestly precommit *"my system achieves X"* and then, after looking at the
data, pick the friendliest evaluator, the friendliest evidence subset, the
friendliest stopping point, or the friendliest compute budget. Every individual
step is defensible. The result is a claim that was selected rather than tested.

So the envelope covers every verdict-material degree of freedom, and the rule
is stated in the strongest form that is still checkable:

> A declarant MUST NOT select any verdict-material degree of freedom after
> observing the evidence produced by that degree of freedom.

Two independent checks enforce it, and they catch different cheats.
:func:`audit_selections` compares what was *used* against what was *committed* --
that catches substitution. The temporal comparison catches the subtler case
where the committed value was left open, or committed late: a choice timestamped
after the evidence it produced was observed is a violation even when nothing was
substituted, because the choice was informed by its own outcome.

VSTD-3 §11 already anchors *continuity* through ``AnchorProvider``. This module
anchors *claim content* with the same pattern and no new trust root:
:class:`PrecommitmentLedger` rejects forks exactly as ``LocalAnchorProvider``
does -- one envelope id may hold one envelope, and a second differing envelope
under the same id is an equivocation, not an update.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Optional, Sequence

from ..core.certificate import canonical_digest
from ..hardware.anchors import AnchorProvider
from ..hardware.models import ContinuityAnchor


class PrecommitmentError(RuntimeError):
    """Raised on equivocation. Deliberately mirrors ``AnchorError``."""


class DegreeOfFreedom(str, Enum):
    """Every choice that can move a verdict. Commit all of them or commit none."""

    CLAIM = "claim"
    CLAIM_COORDINATE = "claim_coordinate"
    EVALUATION_POLICY = "evaluation_policy"
    ADMISSIBLE_EVIDENCE_CLASSES = "admissible_evidence_classes"
    EVIDENCE_SELECTION_RULE = "evidence_selection_rule"
    VERIFIER_IDENTITY = "verifier_identity"
    RANDOMNESS_POLICY = "randomness_policy"
    RESOURCE_BUDGET = "resource_budget"
    STOPPING_CONDITION = "stopping_condition"
    DISCLOSURE_POLICY = "disclosure_policy"


REQUIRED_DEGREES: frozenset[DegreeOfFreedom] = frozenset(DegreeOfFreedom)
"""All ten. A partial envelope is the failure mode this rung exists to close --
whichever degree is left uncommitted is precisely the one that will be chosen
after the fact."""


@dataclass(frozen=True)
class Commitment:
    """One degree of freedom, pinned before the evidence existed.

    ``value`` is a canonical value or its digest; the envelope never needs the
    plaintext, which is what lets rung 4.11 coexist with rung 4.9.
    """

    degree: DegreeOfFreedom
    value: str
    committed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "degree": self.degree.value,
            "value": self.value,
            "committed_at": self.committed_at,
        }


@dataclass(frozen=True)
class EnvelopeCheck:
    accepted: bool
    details: str
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "details": self.details, "missing": list(self.missing)}


@dataclass(frozen=True)
class PrecommitmentEnvelope:
    envelope_id: str
    commitments: tuple[Commitment, ...]
    anchor_reference: str = ""
    """Identifier of the external continuity anchor witnessing this envelope, if any.
    Empty means the envelope is self-anchored and is therefore only as trustworthy
    as the declarant's own append-only log."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "anchor_reference": self.anchor_reference,
            "commitments": [
                item.to_dict()
                for item in sorted(self.commitments, key=lambda c: c.degree.value)
            ],
        }

    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    def content_digest(self) -> str:
        """Digest anchored before an anchor reference exists.

        Excluding ``anchor_reference`` avoids a self-referential commitment. The
        full :meth:`digest` still binds the returned reference after anchoring.
        """
        return canonical_digest(
            {
                "envelope_id": self.envelope_id,
                "commitments": [
                    item.to_dict()
                    for item in sorted(
                        self.commitments, key=lambda commitment: commitment.degree.value
                    )
                ],
            }
        )

    def anchor(
        self, provider: AnchorProvider, *, anchored_at: str
    ) -> "PrecommitmentEnvelope":
        """Anchor claim content through the existing VSTD-3 provider interface."""
        anchor = provider.anchor_content(
            f"precommitment:{self.envelope_id}",
            self.content_digest(),
            epoch=0,
            sequence=0,
            anchored_at=anchored_at,
        )
        return replace(self, anchor_reference=anchor.anchor_id)

    def verify_anchor(
        self, provider: AnchorProvider, anchor: ContinuityAnchor
    ) -> bool:
        return (
            bool(self.anchor_reference)
            and self.anchor_reference == anchor.anchor_id
            and anchor.device_identity_id == f"precommitment:{self.envelope_id}"
            and anchor.rolling_root == self.content_digest()
            and provider.verify(anchor)
        )

    def value_of(self, degree: DegreeOfFreedom) -> Optional[str]:
        for item in self.commitments:
            if item.degree is degree:
                return item.value
        return None

    def committed_at(self, degree: DegreeOfFreedom) -> Optional[str]:
        for item in self.commitments:
            if item.degree is degree:
                return item.committed_at
        return None

    def validate(self) -> EnvelopeCheck:
        seen: set[DegreeOfFreedom] = set()
        for item in self.commitments:
            if item.degree in seen:
                return EnvelopeCheck(
                    False, f"degree of freedom {item.degree.value!r} is committed twice"
                )
            seen.add(item.degree)
            if not item.value.strip():
                return EnvelopeCheck(
                    False, f"degree of freedom {item.degree.value!r} is committed to nothing"
                )
            if not item.committed_at.strip():
                return EnvelopeCheck(
                    False, f"commitment for {item.degree.value!r} carries no timestamp"
                )

        missing = tuple(sorted(item.value for item in REQUIRED_DEGREES - seen))
        if missing:
            return EnvelopeCheck(
                False,
                "envelope leaves verdict-material degrees of freedom uncommitted: "
                + ", ".join(missing),
                missing,
            )
        return EnvelopeCheck(True, f"all {len(REQUIRED_DEGREES)} degrees of freedom committed")


@dataclass(frozen=True)
class ObservedSelection:
    """What was actually used, and when the choice was made."""

    degree: DegreeOfFreedom
    value: str
    selected_at: str
    evidence_observed_at: str = ""
    """When the declarant first saw evidence produced by this degree of freedom.
    Empty means no evidence had been observed, which is the honest ordering."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "degree": self.degree.value,
            "value": self.value,
            "selected_at": self.selected_at,
            "evidence_observed_at": self.evidence_observed_at,
        }


@dataclass(frozen=True)
class PrecommitmentViolation:
    degree: DegreeOfFreedom
    kind: str
    details: str

    def to_dict(self) -> dict[str, Any]:
        return {"degree": self.degree.value, "kind": self.kind, "details": self.details}


@dataclass(frozen=True)
class PrecommitmentAudit:
    accepted: bool
    envelope_digest: str
    violations: tuple[PrecommitmentViolation, ...]
    checked: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "envelope_digest": self.envelope_digest,
            "checked": self.checked,
            "violations": [item.to_dict() for item in self.violations],
        }


def audit_selections(
    envelope: PrecommitmentEnvelope,
    selections: Sequence[ObservedSelection],
) -> PrecommitmentAudit:
    """Check what was used against what was committed, on both axes."""
    violations: list[PrecommitmentViolation] = []

    structure = envelope.validate()
    if not structure.accepted:
        violations.append(
            PrecommitmentViolation(DegreeOfFreedom.CLAIM, "malformed_envelope", structure.details)
        )

    seen: set[DegreeOfFreedom] = set()
    for selection in selections:
        if selection.degree in seen:
            violations.append(
                PrecommitmentViolation(
                    selection.degree,
                    "duplicate_selection",
                    f"{selection.degree.value!r} is reported as selected more than once",
                )
            )
            continue
        seen.add(selection.degree)

        committed = envelope.value_of(selection.degree)
        if committed is None:
            violations.append(
                PrecommitmentViolation(
                    selection.degree,
                    "uncommitted_selection",
                    f"{selection.degree.value!r} was used but never committed",
                )
            )
            continue
        if committed != selection.value:
            violations.append(
                PrecommitmentViolation(
                    selection.degree,
                    "substitution",
                    f"{selection.degree.value!r} was committed to {committed!r} "
                    f"but {selection.value!r} was used",
                )
            )

        # Timestamps are compared lexicographically, which is exact for the
        # normalized UTC ISO-8601 form this project uses throughout.
        observed = selection.evidence_observed_at
        if observed and selection.selected_at > observed:
            violations.append(
                PrecommitmentViolation(
                    selection.degree,
                    "post_hoc_selection",
                    f"{selection.degree.value!r} was selected at {selection.selected_at} "
                    f"after its own evidence was observed at {observed}",
                )
            )
        committed_at = envelope.committed_at(selection.degree)
        if observed and committed_at and committed_at > observed:
            violations.append(
                PrecommitmentViolation(
                    selection.degree,
                    "post_hoc_commitment",
                    f"{selection.degree.value!r} was committed at {committed_at}, "
                    f"after its own evidence was observed at {observed}",
                )
            )

    return PrecommitmentAudit(
        not violations, envelope.digest(), tuple(violations), len(selections)
    )


class PrecommitmentLedger:
    """Append-only envelope store with fork rejection.

    The same shape as ``LocalAnchorProvider``: one envelope id holds one
    envelope. Recording a second, differing envelope under an id already taken
    is showing two faces of the same commitment to two observers, and it raises
    rather than overwriting.
    """

    def __init__(self) -> None:
        self._envelopes: dict[str, PrecommitmentEnvelope] = {}

    def record(self, envelope: PrecommitmentEnvelope) -> PrecommitmentEnvelope:
        existing = self._envelopes.get(envelope.envelope_id)
        if existing is not None and existing.digest() != envelope.digest():
            raise PrecommitmentError(f"precommitment fork for {envelope.envelope_id}")
        self._envelopes[envelope.envelope_id] = envelope
        return envelope

    def get(self, envelope_id: str) -> Optional[PrecommitmentEnvelope]:
        return self._envelopes.get(envelope_id)

    def __len__(self) -> int:
        return len(self._envelopes)
