"""Terminology: identifier (ID); International Organization for Standardization (ISO);
Verifier Standard (VSTD).

Rung 4.8 -- the availability ladder.

A hash is not availability. ``proof_sha256 = abc123…`` that nobody can obtain is
cryptographically bound and completely uncheckable, and a verdict resting on it
is exactly as portable as the declarant's willingness to answer email.

    IDENTIFIED -> AVAILABLE -> PORTABLE -> SELF_CONTAINED

The levels are monotone in the same sense as
:class:`verifier.core.reproducibility.ReproducibilityLevel`, whose shape this
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

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence


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

    def valid(self) -> bool:
        return (
            isinstance(self.horizon, str)
            and bool(self.horizon.strip())
            and isinstance(self.custodian, str)
            and bool(self.custodian.strip())
            and type(self.replicas) is int
            and self.replicas > 0
        )

    def to_dict(self) -> dict[str, Any]:
        return {"horizon": self.horizon, "custodian": self.custodian, "replicas": self.replicas}


def _sha256_address(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


@dataclass(frozen=True)
class RetrievalObservation:
    """Bytes actually observed through a declared locator.

    This is a trust-root-scoped observation, not proof of independent retrieval. The
    availability checker validates that the observed bytes, artifact ID, and locator are
    bound to the availability record. A locator or retention promise without this
    observed-byte binding remains only ``IDENTIFIED``.
    """

    artifact_id: str
    locator: str
    observed_at: str
    observer: str
    retrieved_bytes: bytes = field(repr=False)

    def matches(self, artifact: "ArtifactAvailability") -> bool:
        return (
            self.artifact_id == artifact.artifact_id
            and isinstance(self.observed_at, str)
            and bool(self.observed_at.strip())
            and isinstance(self.observer, str)
            and bool(self.observer.strip())
            and isinstance(self.locator, str)
            and bool(self.locator.strip())
            and self.locator == artifact.locator
            and _sha256_address(self.retrieved_bytes) == artifact.content_address
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "locator": self.locator,
            "observed_at": self.observed_at,
            "observer": self.observer,
            "observed_content_address": _sha256_address(self.retrieved_bytes),
        }


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

    def assess(
        self, observation: Optional[RetrievalObservation] = None
    ) -> AvailabilityLevel:
        if self.embedded_bytes is not None:
            if _sha256_address(self.embedded_bytes) == self.content_address:
                return AvailabilityLevel.SELF_CONTAINED
            return AvailabilityLevel.IDENTIFIED
        if (
            not isinstance(self.locator, str)
            or not self.locator.strip()
            or self.retention is None
            or not self.retention.valid()
            or observation is None
            or not observation.matches(self)
        ):
            return AvailabilityLevel.IDENTIFIED
        if (
            self.anonymous_access
            and isinstance(self.retrieval_procedure, str)
            and self.retrieval_procedure.strip()
        ):
            return AvailabilityLevel.PORTABLE
        return AvailabilityLevel.AVAILABLE

    def overstated(
        self, observation: Optional[RetrievalObservation] = None
    ) -> bool:
        """True when the record claims more availability than its fields support."""
        if self.declared_level is None:
            return False
        return rank(self.declared_level) > rank(self.assess(observation))

    def to_dict(
        self, observation: Optional[RetrievalObservation] = None
    ) -> dict[str, Any]:
        result = {
            "artifact_id": self.artifact_id,
            "content_address": self.content_address,
            "verdict_critical": self.verdict_critical,
            "embedded": self.embedded_bytes is not None,
            "locator": self.locator,
            "anonymous_access": self.anonymous_access,
            "retrieval_procedure": self.retrieval_procedure,
            "retention": None if self.retention is None else self.retention.to_dict(),
            "declared_level": None if self.declared_level is None else self.declared_level.value,
            "assessed_level": self.assess(observation).value,
        }
        if observation is not None:
            result["retrieval_observation"] = observation.to_dict()
        return result


@dataclass(frozen=True)
class AvailabilityAssessment:
    level: AvailabilityLevel
    accepted: bool
    limiting_artifacts: tuple[str, ...]
    details: str
    artifacts: tuple[ArtifactAvailability, ...] = field(default_factory=tuple)
    observations: tuple[RetrievalObservation, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        observed = {item.artifact_id: item for item in self.observations}
        return {
            "level": self.level.value,
            "accepted": self.accepted,
            "limiting_artifacts": list(self.limiting_artifacts),
            "details": self.details,
            "artifacts": [
                item.to_dict(observed.get(item.artifact_id)) for item in self.artifacts
            ],
        }


def assess_bundle(
    artifacts: Sequence[ArtifactAvailability],
    *,
    required: AvailabilityLevel = AvailabilityLevel.AVAILABLE,
    observations: Optional[Mapping[str, RetrievalObservation]] = None,
) -> AvailabilityAssessment:
    """Assess a certificate's evidence bundle. The bundle is its weakest member.

    Averaging here would be a category error: an outside party checking a claim
    needs *every* verdict-critical artifact, so the one they cannot get decides
    the outcome.
    """
    critical = [item for item in artifacts if item.verdict_critical]

    observed = {} if observations is None else observations
    used_observations = tuple(
        observed[item.artifact_id]
        for item in artifacts
        if item.artifact_id in observed
    )
    overstated = [
        item.artifact_id
        for item in artifacts
        if item.overstated(observed.get(item.artifact_id))
    ]
    if overstated:
        return AvailabilityAssessment(
            AvailabilityLevel.IDENTIFIED,
            False,
            tuple(overstated),
            "availability is overstated for: " + ", ".join(overstated),
            tuple(artifacts),
            used_observations,
        )

    if not critical:
        return AvailabilityAssessment(
            AvailabilityLevel.IDENTIFIED,
            False,
            (),
            "no artifact is marked verdict-critical; a claim with no critical "
            "evidence has nothing for an outside party to obtain",
            tuple(artifacts),
            used_observations,
        )

    levels = [item.assess(observed.get(item.artifact_id)) for item in critical]
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
        used_observations,
    )
