"""Terminology: Verifier Standard (VSTD).

Rung 4.12 -- the challenge protocol.

The Refutability coordinate must define what happens when someone says *this verdict is wrong*,
even though nobody has yet. A challenge mechanism that exists but does not move
verdict state is item 7 on the challenge-theater list, and until now this
repository was on that list: ``ArtifactStatus.CHALLENGED`` has existed in
``verifier.data.models`` with **no producer anywhere in the tree**. This module
produces challenge-ledger claim state only; it is not an adapter that mutates or
binds that state into a VSTD-Graph artifact.

The state machine::

    VALID ──credible challenge──▶ CHALLENGED ──confirmed refutation──▶ REVOKED
                                       └──challenge disproven──▶ VALID

``REVOKED`` is terminal. That is rung 4.13 expressed in the transition table
rather than in prose: a confirmed refutation may not be undone by later filings,
because a verdict that can climb back out of revocation on the declarant's own
say-so never degraded at all.

**The implementation constraint the diagram hides.** Status is a *function over
an append-only record set*, never a mutable field. Anything else makes 4.12
contradict 4.3 -- you cannot mutate a status that is sealed inside the committed
digest ``C``. The house pattern already exists: VSTD-Graph-1 §5 blast radius "does
not silently mutate historical artifact nodes," it creates additive records.
:class:`ChallengeLedger` follows it, and :meth:`ChallengeLedger.status` recomputes
from the records every time.

The split with profile 5 is clean and worth stating, because it is the whole
reason this rung sits at 4 and not at 5:

* **VSTD-4:** is the claim structurally challengeable? Testable alone, with a
  synthetic challenger.
* **VSTD-5:** did somebody independent actually challenge or corroborate it?
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from ..core.certificate import canonical_digest
from ..data.models import ArtifactStatus
from .surface import RefutationSurface, RefutationType


class ChallengeError(RuntimeError):
    pass


class ChallengeOutcome(str, Enum):
    ACCEPTED = "ACCEPTED"
    """The counterevidence stands. The claim degrades to ``resulting_status``."""

    REJECTED = "REJECTED"
    """The challenge was disproven. The claim returns to ``VALID``."""

    UNRESOLVED = "UNRESOLVED"
    """Credible but not adjudicated. The claim stays ``CHALLENGED`` -- fail-closed,
    because an open credible challenge is not evidence of validity."""


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    target_claim_id: str
    target_certificate_id: str
    challenged_predicate: str
    challenge_type: RefutationType
    counterevidence: str
    filed_at: str
    challenge_certificate: str = ""
    """Digest of the challenger's own ``DecisionCertificate``, if they produced one.
    A challenge carrying one is checkable by the same kernel as the claim it
    attacks, which is rung 4.14 acting on the adversary's side of the table."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "target_claim_id": self.target_claim_id,
            "target_certificate_id": self.target_certificate_id,
            "challenged_predicate": self.challenged_predicate,
            "challenge_type": self.challenge_type.value,
            "counterevidence": self.counterevidence,
            "filed_at": self.filed_at,
            "challenge_certificate": self.challenge_certificate,
        }

    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass(frozen=True)
class Adjudication:
    challenge_id: str
    outcome: ChallengeOutcome
    rationale: str
    adjudicated_at: str
    adjudication_certificate: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "outcome": self.outcome.value,
            "rationale": self.rationale,
            "adjudicated_at": self.adjudicated_at,
            "adjudication_certificate": self.adjudication_certificate,
        }


@dataclass(frozen=True)
class Admission:
    """Whether a filing is in scope. Inadmissible is not the same as disproven."""

    admitted: bool
    details: str
    resulting_status: str = ArtifactStatus.REVOKED.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted": self.admitted,
            "details": self.details,
            "resulting_status": self.resulting_status,
        }


@dataclass(frozen=True)
class ChallengeRecord:
    """One append-only entry. Records are never edited and never removed."""

    sequence: int
    kind: str
    claim_id: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "claim_id": self.claim_id,
            "payload": self.payload,
        }


@dataclass(frozen=True)
class ClaimStatus:
    status: ArtifactStatus
    open_challenges: tuple[str, ...]
    confirmed_challenges: tuple[str, ...]
    details: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "open_challenges": list(self.open_challenges),
            "confirmed_challenges": list(self.confirmed_challenges),
            "details": self.details,
        }


def admissibility(challenge: Challenge, surface: RefutationSurface) -> Admission:
    """Check a filing against the refutation surface the claim published.

    This is where ``excluded_claims`` does real work rather than serving as a
    disclaimer: a challenge aimed at something the claim explicitly disclaimed
    is refused, and the refusal quotes the exclusion's stated reason.
    """
    excluded = surface.excludes(challenge.challenged_predicate)
    if excluded is not None:
        return Admission(
            False,
            f"predicate {challenge.challenged_predicate!r} is an excluded claim: "
            f"{excluded.reason}",
        )

    admissible = surface.admits(challenge.challenge_type)
    if admissible is None:
        return Admission(
            False,
            f"refutation type {challenge.challenge_type.value!r} is not on this "
            "claim's declared refutation surface",
        )

    if not challenge.counterevidence.strip():
        return Admission(
            False,
            f"challenge cites no counterevidence; the surface requires: "
            f"{admissible.overturning_evidence}",
        )

    return Admission(
        True,
        f"admissible under {admissible.refutation_type.value!r}",
        admissible.resulting_status,
    )


DEGRADATION_ORDER: tuple[ArtifactStatus, ...] = (
    ArtifactStatus.VALID,
    ArtifactStatus.UNKNOWN,
    ArtifactStatus.CHALLENGED,
    ArtifactStatus.STALE,
    ArtifactStatus.SUPERSEDED,
    ArtifactStatus.REVOKED,
)
"""Increasing severity. Rung 4.13 needs a total order to take a minimum over."""


def most_degraded(statuses) -> ArtifactStatus:
    worst = ArtifactStatus.VALID
    for status in statuses:
        if DEGRADATION_ORDER.index(status) > DEGRADATION_ORDER.index(worst):
            worst = status
    return worst


class ChallengeLedger:
    """Append-only record set. Status is derived from it, never stored in it."""

    def __init__(self) -> None:
        self._records: list[ChallengeRecord] = []
        self._challenges: dict[str, Challenge] = {}
        self._resulting: dict[str, str] = {}

    # -- writes: append only ------------------------------------------------

    def file(self, challenge: Challenge, surface: RefutationSurface) -> Admission:
        if challenge.challenge_id in self._challenges:
            raise ChallengeError(f"challenge {challenge.challenge_id} is already filed")

        verdict = admissibility(challenge, surface)
        self._challenges[challenge.challenge_id] = challenge
        self._resulting[challenge.challenge_id] = verdict.resulting_status
        self._append(
            "FILED" if verdict.admitted else "REFUSED",
            challenge.target_claim_id,
            {"challenge": challenge.to_dict(), "admission": verdict.to_dict()},
        )
        return verdict

    def adjudicate(self, adjudication: Adjudication) -> ChallengeRecord:
        challenge = self._challenges.get(adjudication.challenge_id)
        if challenge is None:
            raise ChallengeError(f"no such challenge {adjudication.challenge_id}")
        for record in self._records:
            if (
                record.kind == "ADJUDICATED"
                and record.payload["adjudication"]["challenge_id"] == adjudication.challenge_id
            ):
                raise ChallengeError(
                    f"challenge {adjudication.challenge_id} is already adjudicated; "
                    "the record set is append-only and an adjudication is final"
                )
        return self._append(
            "ADJUDICATED",
            challenge.target_claim_id,
            {"adjudication": adjudication.to_dict()},
        )

    def _append(self, kind: str, claim_id: str, payload: dict[str, Any]) -> ChallengeRecord:
        record = ChallengeRecord(len(self._records), kind, claim_id, payload)
        self._records.append(record)
        return record

    # -- reads: everything derived -----------------------------------------

    def records(self, claim_id: Optional[str] = None) -> tuple[ChallengeRecord, ...]:
        if claim_id is None:
            return tuple(self._records)
        return tuple(record for record in self._records if record.claim_id == claim_id)

    def status(self, claim_id: str) -> ClaimStatus:
        """Recompute the claim's status from the whole record set.

        Deliberately recomputed rather than cached. A cached status is a mutable
        field wearing a method, and the point of this rung is that no such field
        exists.
        """
        filed: dict[str, Challenge] = {}
        outcomes: dict[str, ChallengeOutcome] = {}

        for record in self._records:
            if record.claim_id != claim_id:
                continue
            if record.kind == "FILED":
                data = record.payload["challenge"]
                filed[data["challenge_id"]] = self._challenges[data["challenge_id"]]
            elif record.kind == "ADJUDICATED":
                data = record.payload["adjudication"]
                if data["challenge_id"] in filed:
                    outcomes[data["challenge_id"]] = ChallengeOutcome(data["outcome"])

        confirmed = tuple(
            sorted(cid for cid, outcome in outcomes.items() if outcome is ChallengeOutcome.ACCEPTED)
        )
        open_ids = tuple(
            sorted(
                cid
                for cid in filed
                if outcomes.get(cid) in (None, ChallengeOutcome.UNRESOLVED)
            )
        )

        if confirmed:
            # Terminal by construction. Rung 4.13: a verdict that can climb back
            # out of revocation never degraded in the first place. Where several
            # refutations land, the most degrading one decides -- taking any
            # other would let a claim launder a revocation behind a milder
            # confirmed challenge.
            status = most_degraded(
                ArtifactStatus(self._resulting.get(cid, ArtifactStatus.REVOKED.value))
                for cid in confirmed
            )
            return ClaimStatus(
                status,
                open_ids,
                confirmed,
                f"{len(confirmed)} confirmed refutation(s); status is terminal",
            )
        if open_ids:
            return ClaimStatus(
                ArtifactStatus.CHALLENGED,
                open_ids,
                (),
                f"{len(open_ids)} open credible challenge(s); an unadjudicated "
                "challenge is not evidence of validity",
            )
        if filed:
            return ClaimStatus(
                ArtifactStatus.VALID,
                (),
                (),
                f"all {len(filed)} challenge(s) adjudicated and disproven",
            )
        return ClaimStatus(ArtifactStatus.VALID, (), (), "no challenges filed")

    def __len__(self) -> int:
        return len(self._records)
