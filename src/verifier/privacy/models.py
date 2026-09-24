"""Data models for Level 6 disclosure bounds, declarative privacy, and provable transparency.

Acronyms:
    application programming interface (API);
    Concise Binary Object Representation (CBOR);
    JavaScript Object Notation (JSON);
    Verifier Standard (VSTD);
    zero-identity/zero-knowledge (ZIZK).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any


@dataclass(frozen=True)
class ObserverParty:
    """An observer entity identified as a party rather than a channel (obligation 6.3).

    Channels can be relayed, duplicated, or forwarded; parties are accountable
    entities bound to verified credentials, actor identity, and declared purpose.
    """

    actor_id: str
    role: str
    purpose: str
    credentials: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TransparencyCommitment:
    """A tamper-evident cryptographic commitment to a withheld private coordinate (obligation 6.1).

    Provable transparency requires that withholding a field is not silent omission.
    The existence and schema of the withheld data are transparently committed.
    """

    field_name: str
    schema_type: str
    commitment_digest: str
    algorithm: str = "sha256"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DisclosureSurface:
    """Enumeration of what a certificate emits versus withholds (obligation 6.1).

    Partitions emitted coordinates from withheld private state (e.g. raw records,
    genesis secrets, salts, or unrevealed commitments).
    """

    object_name: str
    disclosed_fields: tuple[str, ...]
    withheld_fields: tuple[str, ...]
    commitments: tuple[TransparencyCommitment, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_name": self.object_name,
            "disclosed_fields": list(self.disclosed_fields),
            "withheld_fields": list(self.withheld_fields),
            "commitments": [c.to_dict() for c in self.commitments],
        }


@dataclass(frozen=True)
class DisclosureBound:
    """A declared admission predicate governing an emitted field (obligation 6.2).

    A field emitted without an explicit bound is not admissible. Absence of a
    bound fails closed and is never read as an open or public bound.
    """

    bound_id: str
    field_name: str
    admitted_observers: tuple[str, ...] = ()
    admitted_roles: tuple[str, ...] = ()
    conditions: tuple[tuple[str, str], ...] = ()

    def permits(self, observer: ObserverParty) -> bool:
        """Evaluate whether this bound admits the given observer party."""
        if not self.admitted_observers and not self.admitted_roles:
            return False
        if self.admitted_observers and observer.actor_id in self.admitted_observers:
            return True
        if self.admitted_roles and observer.role in self.admitted_roles:
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "bound_id": self.bound_id,
            "field_name": self.field_name,
            "admitted_observers": list(self.admitted_observers),
            "admitted_roles": list(self.admitted_roles),
            "conditions": dict(self.conditions),
        }


@dataclass(frozen=True)
class EmissionContext:
    """Dynamic context captured at certificate emission time (obligation 6.4).

    Bounds are evaluated dynamically at each emission rather than settled once
    at certification.
    """

    observer: ObserverParty
    timestamp: str
    co_emitted_certificates: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "observer": self.observer.to_dict(),
            "timestamp": self.timestamp,
            "co_emitted_count": len(self.co_emitted_certificates),
        }


@dataclass(frozen=True)
class RedactionRecord:
    """Audit record capturing an authorized redaction event."""

    field_name: str
    bound_id: str
    commitment_digest: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EmissionResult:
    """The result of an emission-time evaluation over a domain certificate."""

    emitted_certificate: dict[str, Any]
    redacted_fields: tuple[str, ...]
    transparency_commitments: tuple[TransparencyCommitment, ...]
    receipt: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "emitted_certificate": self.emitted_certificate,
            "redacted_fields": list(self.redacted_fields),
            "transparency_commitments": [c.to_dict() for c in self.transparency_commitments],
            "receipt": self.receipt,
        }
