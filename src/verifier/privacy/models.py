"""Data models for experimental level 6 disclosure bounds and digest records.

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


def _string_sequence(value: Any) -> bool:
    """Admission sets are sequences of exact strings, never substring containers."""
    return type(value) in (tuple, list) and all(type(item) is str for item in value)


@dataclass(frozen=True)
class ObserverParty:
    """An observer entity identified as a party rather than a channel (obligation 6.3).

    Values are supplied by the caller. This record does not authenticate identity,
    roles, purpose, or credentials; a trusted observer model must establish them.
    """

    actor_id: str
    role: str
    purpose: str
    credentials: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TransparencyCommitment:
    """A digest binding a withheld coordinate (obligation 6.1 helper).

    Provable transparency requires that withholding a field is not silent omission.
    The existence and schema of the withheld data are recorded. An unsalted digest
    is not hiding: an observer can guess low-entropy values and compare digests.
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
        """Match a caller-established party and every declared condition.

        Supported condition keys are actor_id, role, purpose (exact strings), and
        credential (membership). Unsupported predicates deny admission, never
        disappear. These matches are not authentication or consent verification.
        """
        if not isinstance(observer, ObserverParty) or not all(
            type(value) is str for value in (observer.actor_id, observer.role, observer.purpose)
        ):
            return False
        if not all(_string_sequence(value) for value in (
            self.admitted_observers, self.admitted_roles, observer.credentials,
        )) or type(self.conditions) not in (tuple, list):
            return False
        admitted = (observer.actor_id in self.admitted_observers
                    or observer.role in self.admitted_roles)
        if not admitted:
            return False
        values = {"actor_id": observer.actor_id, "role": observer.role,
                  "purpose": observer.purpose}
        for condition in self.conditions:
            if not isinstance(condition, (tuple, list)) or len(condition) != 2:
                return False
            key, expected = condition
            if not isinstance(key, str) or not isinstance(expected, str):
                return False
            if key == "credential":
                if expected not in observer.credentials:
                    return False
            elif key not in values or values[key] != expected:
                return False
        return True

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
