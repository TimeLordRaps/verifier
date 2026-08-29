"""Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD).

Evidence-bound execution for meta-verifier mechanisms.

Serialized claims are inputs, never verdicts.  :class:`VerificationSession`
resolves every content-addressed evidence item, checks its bytes, selects the
exact registered mechanism implementation, enforces the declared input bounds,
and runs that mechanism again.  A caller cannot promote a declaration by
putting ``PASS`` in a field because no such field exists on
:class:`BoundProposition`.

The session establishes only the exact proposition a mechanism checks under its
named trust roots and bounds.  Registration does not make a mechanism correct,
independent, or authoritative; it makes the executable coordinate explicit and
prevents a different declared digest from substituting after the proposition was
bound. Built-in mechanisms derive that digest from their exact module bytes. An
external mechanism remains responsible for truthfully deriving its advertised
implementation digest; the session cannot infer arbitrary plugin source identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import base64
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping, Protocol, Sequence

from .certificate import canonical_digest


_DIGEST = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")


class EvidenceBindingError(ValueError):
    """An evidence binding is malformed or cannot be resolved exactly."""


class MechanismOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EvidenceBounds:
    """Resource ceilings enforced before invoking a domain mechanism."""

    max_evidence_items: int
    max_evidence_bytes: int

    def __post_init__(self) -> None:
        if self.max_evidence_items < 0 or self.max_evidence_bytes < 0:
            raise EvidenceBindingError("evidence bounds cannot be negative")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_evidence_items": self.max_evidence_items,
            "max_evidence_bytes": self.max_evidence_bytes,
        }


@dataclass(frozen=True)
class BoundProposition:
    """Exact proposition, evidence, mechanism, trust-root, and bound binding."""

    subject_id: str
    predicate: str
    expected: Any
    mechanism_id: str
    mechanism_digest: str
    evidence_refs: tuple[str, ...]
    trust_roots: tuple[str, ...]
    bounds: EvidenceBounds
    parameters: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.subject_id or not self.predicate or not self.mechanism_id:
            raise EvidenceBindingError(
                "subject_id, predicate, and mechanism_id must not be empty"
            )
        if not _DIGEST.fullmatch(self.mechanism_digest):
            raise EvidenceBindingError("mechanism_digest must be a SHA-256 digest")
        if not self.evidence_refs:
            raise EvidenceBindingError("a bound proposition needs evidence")
        normalized = tuple(_normalize_ref(item) for item in self.evidence_refs)
        if len(set(normalized)) != len(normalized):
            raise EvidenceBindingError(
                "duplicate evidence references do not create additional support"
            )
        if not self.trust_roots or any(not item for item in self.trust_roots):
            raise EvidenceBindingError("at least one explicit trust root is required")
        object.__setattr__(self, "evidence_refs", normalized)
        object.__setattr__(self, "trust_roots", tuple(sorted(set(self.trust_roots))))
        object.__setattr__(self, "parameters", dict(sorted(self.parameters.items())))

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "predicate": self.predicate,
            "expected": self.expected,
            "mechanism_id": self.mechanism_id,
            "mechanism_digest": _normalize_ref(self.mechanism_digest),
            "evidence_refs": list(self.evidence_refs),
            "trust_roots": list(self.trust_roots),
            "bounds": self.bounds.to_dict(),
            "parameters": dict(self.parameters),
        }

    def digest(self) -> str:
        return canonical_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BoundProposition":
        bounds = data["bounds"]
        return cls(
            subject_id=str(data["subject_id"]),
            predicate=str(data["predicate"]),
            expected=data["expected"],
            mechanism_id=str(data["mechanism_id"]),
            mechanism_digest=str(data["mechanism_digest"]),
            evidence_refs=tuple(str(item) for item in data["evidence_refs"]),
            trust_roots=tuple(str(item) for item in data["trust_roots"]),
            bounds=EvidenceBounds(
                int(bounds["max_evidence_items"]),
                int(bounds["max_evidence_bytes"]),
            ),
            parameters={str(key): str(value) for key, value in data.get("parameters", {}).items()},
        )


@dataclass(frozen=True)
class MechanismDecision:
    """One bounded mechanism result plus its exact observations."""

    outcome: MechanismOutcome
    details: str
    observations: Mapping[str, Any] = field(default_factory=dict)


class VerificationMechanism(Protocol):
    """Executable domain mechanism selected by an exact implementation digest."""

    mechanism_id: str
    mechanism_digest: str

    def evaluate(
        self, binding: BoundProposition, evidence: Sequence[bytes]
    ) -> MechanismDecision:
        """Evaluate only ``binding`` using the already digest-checked evidence."""


@dataclass(frozen=True)
class EvaluatedProposition:
    """Result of executing a mechanism, not a caller-serializable verdict field."""

    binding_digest: str
    outcome: MechanismOutcome
    mechanism_id: str
    mechanism_digest: str
    evidence_refs: tuple[str, ...]
    trust_roots: tuple[str, ...]
    observed_evidence_bytes: int
    details: str
    observations: Mapping[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.outcome is MechanismOutcome.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_digest": self.binding_digest,
            "outcome": self.outcome.value,
            "mechanism_id": self.mechanism_id,
            "mechanism_digest": _normalize_ref(self.mechanism_digest),
            "evidence_refs": list(self.evidence_refs),
            "trust_roots": list(self.trust_roots),
            "observed_evidence_bytes": self.observed_evidence_bytes,
            "details": self.details,
            "observations": dict(self.observations),
        }


def _normalize_ref(reference: str) -> str:
    matched = _DIGEST.fullmatch(reference)
    if matched is None:
        raise EvidenceBindingError(f"not a SHA-256 evidence reference: {reference!r}")
    return "sha256:" + matched.group(1)


def implementation_file_digest(path: str) -> str:
    """Return the SHA-256 coordinate of exact mechanism module bytes."""
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


class EvidenceStore:
    """In-memory content-addressed evidence store with collision/fork refusal."""

    def __init__(self) -> None:
        self._payloads: dict[str, bytes] = {}

    def add(self, payload: bytes) -> str:
        if not isinstance(payload, bytes):
            raise TypeError("evidence payload must be bytes")
        reference = "sha256:" + hashlib.sha256(payload).hexdigest()
        existing = self._payloads.get(reference)
        if existing is not None and existing != payload:
            raise EvidenceBindingError(f"evidence digest collision at {reference}")
        self._payloads[reference] = payload
        return reference

    def resolve(self, reference: str) -> bytes:
        normalized = _normalize_ref(reference)
        try:
            payload = self._payloads[normalized]
        except KeyError as exc:
            raise EvidenceBindingError(f"evidence is unavailable: {normalized}") from exc
        observed = "sha256:" + hashlib.sha256(payload).hexdigest()
        if observed != normalized:
            raise EvidenceBindingError(
                f"evidence bytes do not match their reference: {normalized}"
            )
        return payload

    def export_base64(self, references: Sequence[str]) -> dict[str, str]:
        """Export exact evidence bytes for portable, offline mechanism replay."""
        return {
            _normalize_ref(reference): base64.b64encode(self.resolve(reference)).decode("ascii")
            for reference in references
        }

    def import_base64(self, payloads: Mapping[str, str]) -> None:
        """Import a portable bundle and refuse every reference/byte mismatch."""
        for reference, encoded in payloads.items():
            try:
                payload = base64.b64decode(encoded, validate=True)
            except Exception as exc:
                raise EvidenceBindingError(
                    f"invalid base64 evidence payload for {reference}"
                ) from exc
            observed = self.add(payload)
            if observed != _normalize_ref(reference):
                raise EvidenceBindingError(
                    f"embedded evidence does not match reference {reference}"
                )

    def __contains__(self, reference: object) -> bool:
        if not isinstance(reference, str):
            return False
        try:
            return _normalize_ref(reference) in self._payloads
        except EvidenceBindingError:
            return False


class VerificationSession:
    """Resolve evidence and rerun only explicitly registered mechanisms."""

    def __init__(self, evidence: EvidenceStore) -> None:
        self.evidence = evidence
        self._mechanisms: dict[str, VerificationMechanism] = {}

    def register(self, mechanism: VerificationMechanism) -> None:
        if not mechanism.mechanism_id:
            raise EvidenceBindingError("mechanism_id must not be empty")
        digest = _normalize_ref(mechanism.mechanism_digest)
        previous = self._mechanisms.get(mechanism.mechanism_id)
        if previous is not None and _normalize_ref(previous.mechanism_digest) != digest:
            raise EvidenceBindingError(
                f"mechanism substitution refused for {mechanism.mechanism_id}"
            )
        self._mechanisms[mechanism.mechanism_id] = mechanism

    def evaluate(self, binding: BoundProposition) -> EvaluatedProposition:
        mechanism = self._mechanisms.get(binding.mechanism_id)
        if mechanism is None:
            return self._unknown(binding, "bound mechanism is not registered", 0)
        if _normalize_ref(mechanism.mechanism_digest) != _normalize_ref(
            binding.mechanism_digest
        ):
            return self._unknown(binding, "registered mechanism digest does not match", 0)

        if len(binding.evidence_refs) > binding.bounds.max_evidence_items:
            return self._unknown(binding, "evidence item bound exceeded", 0)
        try:
            payloads = tuple(self.evidence.resolve(item) for item in binding.evidence_refs)
        except EvidenceBindingError as exc:
            return self._unknown(binding, str(exc), 0)
        observed_bytes = sum(len(item) for item in payloads)
        if observed_bytes > binding.bounds.max_evidence_bytes:
            return self._unknown(binding, "evidence byte bound exceeded", observed_bytes)

        try:
            decision = mechanism.evaluate(binding, payloads)
        except Exception as exc:  # A mechanism crash is uncertainty, not a pass.
            return self._unknown(
                binding,
                f"mechanism execution failed: {type(exc).__name__}: {exc}",
                observed_bytes,
            )
        if not isinstance(decision, MechanismDecision):
            return self._unknown(
                binding, "mechanism returned an invalid decision object", observed_bytes
            )
        return EvaluatedProposition(
            binding.digest(),
            decision.outcome,
            binding.mechanism_id,
            _normalize_ref(binding.mechanism_digest),
            binding.evidence_refs,
            binding.trust_roots,
            observed_bytes,
            decision.details,
            dict(decision.observations),
        )

    @staticmethod
    def _unknown(
        binding: BoundProposition, details: str, observed_bytes: int
    ) -> EvaluatedProposition:
        return EvaluatedProposition(
            binding.digest(),
            MechanismOutcome.UNKNOWN,
            binding.mechanism_id,
            _normalize_ref(binding.mechanism_digest),
            binding.evidence_refs,
            binding.trust_roots,
            observed_bytes,
            details,
        )


class BytesDigestMechanism:
    """Built-in mechanism for the exact proposition ``bytes.sha256 == expected``."""

    mechanism_id = "vstd.bytes.sha256"
    mechanism_digest = implementation_file_digest(__file__)

    def evaluate(
        self, binding: BoundProposition, evidence: Sequence[bytes]
    ) -> MechanismDecision:
        if binding.predicate != "bytes.sha256" or len(evidence) != 1:
            return MechanismDecision(
                MechanismOutcome.UNKNOWN,
                "this mechanism checks one bytes.sha256 proposition",
            )
        observed = "sha256:" + hashlib.sha256(evidence[0]).hexdigest()
        expected = _normalize_ref(str(binding.expected))
        outcome = MechanismOutcome.PASS if observed == expected else MechanismOutcome.FAIL
        return MechanismDecision(
            outcome,
            f"observed {observed}; expected {expected}",
            {"observed_digest": observed},
        )


__all__ = [
    "BoundProposition",
    "BytesDigestMechanism",
    "EvidenceBindingError",
    "EvidenceBounds",
    "EvidenceStore",
    "EvaluatedProposition",
    "MechanismDecision",
    "MechanismOutcome",
    "VerificationMechanism",
    "VerificationSession",
    "implementation_file_digest",
]
