"""Terminology: Request for Comments (RFC); Verifier Standard (VSTD); zero-identity/zero-knowledge (ZIZK).

Normative invariants, verdicts, and prohibited inferences for zero-identity actor verification."""

from __future__ import annotations

from typing import Final, Literal

PropertyStatus = Literal[
    "SUPPORTED",
    "ATTESTED",
    "ASSUMED",
    "UNKNOWN",
    "CONFLICTED",
    "REFUTED",
    "UNSUPPORTED_BY_DESIGN",
]

PROPERTY_STATUSES: Final[tuple[PropertyStatus, ...]] = (
    "SUPPORTED",
    "ATTESTED",
    "ASSUMED",
    "UNKNOWN",
    "CONFLICTED",
    "REFUTED",
    "UNSUPPORTED_BY_DESIGN",
)

IdentityVerdict = Literal[
    "ACCEPTED_BOUNDED",
    "UNKNOWN",
    "CONFLICTED",
    "REJECTED",
]

IDENTITY_VERDICTS: Final[tuple[IdentityVerdict, ...]] = (
    "ACCEPTED_BOUNDED",
    "UNKNOWN",
    "CONFLICTED",
    "REJECTED",
)

PROHIBITED_INFERENCES: Final[tuple[str, ...]] = (
    "Absent civil identity implies anonymity or unlinkability.",
    "A pseudonym implies a distinct actor.",
    "A shared pseudonym implies a single actor.",
    "Two distinct pseudonyms imply two independent actors.",
    "A verified signature implies authorization.",
    "A grant implies that the authority is currently active.",
    "Absent revocation evidence implies active authority.",
    "Absent uniqueness evidence implies Sybil resistance.",
    "Hashing, redaction, encryption, omission, or pseudonymity alone implies zero identity.",
    "Disclosure minimization preserves the original claim boundary.",
    "Missing evidence implies safety.",
    "A signer is the author of the claim.",
    "A relayed, delegated, or aggregated claim is first-party authorship.",
    "An absent authorship role means degree zero.",
    "A recorded ancestry chain establishes that authority survived every hop.",
    "Actor standing, tenure, or token validity implies verification correctness.",
)

PRIME_INVARIANT: Final[str] = (
    "An actor identity NEVER upgrades a computational verdict. "
    "Receipt verdicts (VERIFIED, FALSIFIED, UNKNOWN, REJECTED) depend strictly upon "
    "the inspected artifact, trace, bounds, and checker kernel."
)
