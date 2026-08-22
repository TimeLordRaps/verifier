"""Rung 4.8 -- the availability ladder.

A hash is not availability. ``proof_sha256 = abc123…`` that nobody can obtain is
cryptographically bound and completely uncheckable, and a verdict resting on it
is exactly as portable as the declarant's willingness to answer email.

    IDENTIFIED -> AVAILABLE -> PORTABLE -> SELF_CONTAINED

The levels are monotone in the same sense as
:class:`verifiable.core.reproducibility.ReproducibilityLevel`, whose shape this
mirrors deliberately: an artifact at a level satisfies every level below it.

> All verdict-critical artifacts MUST either accompany the certificate or be
> retrievable through content-addressed references satisfying a declared
> retention policy.

The consequence that gives the rung teeth is at the bottom of this module:
:func:`assess_bundle` returns the *minimum* over verdict-critical artifacts, so
one unobtainable byte-range caps the whole claim. That is rung 4.13 acting
through rung 4.8 -- weakening evidence cannot leave a verdict where it was.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Sequence


class AvailabilityLevel(str, Enum):
    """Monotone levels of artifact obtainability."""

    IDENTIFIED = "IDENTIFIED"
    """A content address exists. Nothing asserts that the bytes can be fetched."""

    AVAILABLE = "AVAILABLE"
    """Retrievable now from a declared locator, under a declared retention policy."""

    PORTABLE = "PORTABLE"
    """Retrievable by an outside party with no credential, account, or relationship
    with the declarant, and with the retrieval procedure itself declared."""

    SELF_CONTAINED = "SELF_CONTAINED"
    """The bytes accompany the certificate. Nothing needs to be fetched at all."""


_ORDER: tuple[AvailabilityLevel, ...] = (
    AvailabilityLevel.IDENTIFIED,
    AvailabilityLevel.AVAILABLE,
    AvailabilityLevel.PORTABLE,
    AvailabilityLevel.SELF_CONTAINED,
)

_RANK: dict[AvailabilityLevel, int] = {level: index for index, level in enumerate(_ORDER)}


def rank(level: AvailabilityLevel) -> int:
    return _RANK[level]


def weakest(levels: Sequence[AvailabilityLevel]) -> AvailabilityLevel:
    """The floor. An empty sequence has nothing to obtain, hence nothing obtainable."""
    if not levels:
        return AvailabilityLevel.IDENTIFIED
    return min(levels, key=rank)


@dataclass(frozen=True)
class RetentionPolicy:
    """What the declarant commits to about how long the bytes stay fetchable."""

    horizon: str
    """ISO-8601 instant or duration through which retrieval is committed."""

    custodian: str
    """Who is committed. ``"declarant"`` is the weakest honest answer."""

    replicas: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"horizon": self.horizon, "custodian": self.custodian, "replicas": self.replicas}


@dataclass(frozen=True)
class ArtifactAvailability:
    """One verdict-critical artifact and how obtainable it actually is.

    The level is **derived**, never taken on the declarant's word -- see
    :meth:`assess`. A record may state a level, and if the stated level exceeds
    the derived one the record is refused rather than believed.
    """

    artifact_id: str
    content_address: str
    verdict_critical: bool = True
    embedded_bytes: Optional[bytes] = None
    locator: str = ""
    anonymous_access: bool = False
    retrieval_procedure: str = ""
    retention: Optional[RetentionPolicy] = None
    declared_level: Optional[AvailabilityLevel] = None

    def assess(self) -> AvailabilityLevel:
        if self.embedded_bytes is not None:
            return AvailabilityLevel.SELF_CONTAINED
        if not self.locator or self.retention is None:
            return AvailabilityLevel.IDENTIFIED
        if self.anonymous_access and self.retrieval_procedure:
            return AvailabilityLevel.PORTABLE
        return AvailabilityLevel.AVAILABLE

    def overstated(self) -> bool:
        """True when the record claims more availability than its fields support."""
        if self.declared_level is None:
            return False
        return rank(self.declared_level) > rank(self.assess())

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "content_address": self.content_address,
            "verdict_critical": self.verdict_critical,
            "embedded": self.embedded_bytes is not None,
            "locator": self.locator,
            "anonymous_access": self.anonymous_access,
            "retrieval_procedure": self.retrieval_procedure,
            "retention": None if self.retention is None else self.retention.to_dict(),
            "declared_level": None if self.declared_level is None else self.declared_level.value,
            "assessed_level": self.assess().value,
        }


@dataclass(frozen=True)
class AvailabilityAssessment:
    level: AvailabilityLevel
    accepted: bool
    limiting_artifacts: tuple[str, ...]
    details: str
    artifacts: tuple[ArtifactAvailability, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "accepted": self.accepted,
            "limiting_artifacts": list(self.limiting_artifacts),
            "details": self.details,
            "artifacts": [item.to_dict() for item in self.artifacts],
        }


def assess_bundle(
    artifacts: Sequence[ArtifactAvailability],
    *,
    required: AvailabilityLevel = AvailabilityLevel.AVAILABLE,
) -> AvailabilityAssessment:
    """Assess a certificate's evidence bundle. The bundle is its weakest member.

    Averaging here would be a category error: an outside party checking a claim
    needs *every* verdict-critical artifact, so the one they cannot get decides
    the outcome.
    """
    critical = [item for item in artifacts if item.verdict_critical]

    overstated = [item.artifact_id for item in artifacts if item.overstated()]
    if overstated:
        return AvailabilityAssessment(
            AvailabilityLevel.IDENTIFIED,
            False,
            tuple(overstated),
            "availability is overstated for: " + ", ".join(overstated),
            tuple(artifacts),
        )

    if not critical:
        return AvailabilityAssessment(
            AvailabilityLevel.IDENTIFIED,
            False,
            (),
            "no artifact is marked verdict-critical; a claim with no critical "
            "evidence has nothing for an outside party to obtain",
            tuple(artifacts),
        )

    levels = [item.assess() for item in critical]
    floor = weakest(levels)
    limiting = tuple(
        item.artifact_id for item, level in zip(critical, levels) if level is floor
    )
    accepted = rank(floor) >= rank(required)
    return AvailabilityAssessment(
        floor,
        accepted,
        limiting,
        (
            f"bundle is {floor.value}; {len(critical)} verdict-critical artifacts, "
            f"limited by {', '.join(limiting)}"
            if not accepted
            else f"bundle is {floor.value} across {len(critical)} verdict-critical artifacts"
        ),
        tuple(artifacts),
    )
