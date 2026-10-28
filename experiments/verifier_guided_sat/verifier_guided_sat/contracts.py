"""Typed, non-wire contracts for verifier objects and bounded outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .canonical import canonical_digest


class NativeVerdict(str, Enum):
    """Outcome reported by the wrapped native verifier."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


class RouteVerdict(str, Enum):
    """Outcome of one bounded route, never the whole domain problem."""

    SAT_ACCEPTED = "SAT_ACCEPTED"
    SAT_REJECTED = "SAT_REJECTED"
    ROUTE_UNSAT = "ROUTE_UNSAT"
    ROUTE_UNKNOWN = "ROUTE_UNKNOWN"
    MALFORMED = "MALFORMED"


@dataclass(frozen=True)
class VerifierObjectContract:
    """Observable interface and claim boundary for one external verifier object."""

    identifier: str
    domain: str
    source_commit: str
    source_digest: str
    instance_schema: str
    witness_schema: str
    invocation: str
    deterministic: bool
    configuration: dict[str, Any]
    resource_limits: dict[str, Any]
    result_semantics: dict[str, str]
    diagnostics: str
    candidate_canonicalization: str
    verification_cost: str
    trust_roots: tuple[str, ...]
    acceptance_proves: str
    rejection_proves: str
    neither_proves: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "domain": self.domain,
            "source_commit": self.source_commit,
            "source_digest": self.source_digest,
            "instance_schema": self.instance_schema,
            "witness_schema": self.witness_schema,
            "invocation": self.invocation,
            "deterministic": self.deterministic,
            "configuration": dict(self.configuration),
            "resource_limits": dict(self.resource_limits),
            "result_semantics": dict(self.result_semantics),
            "diagnostics": self.diagnostics,
            "candidate_canonicalization": self.candidate_canonicalization,
            "verification_cost": self.verification_cost,
            "trust_roots": list(self.trust_roots),
            "acceptance_proves": self.acceptance_proves,
            "rejection_proves": self.rejection_proves,
            "neither_proves": list(self.neither_proves),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass(frozen=True)
class VerificationObservation:
    """Direct observation from a native verifier invocation."""

    verdict: NativeVerdict
    elapsed_ns: int
    diagnostics: tuple[str, ...]
    instance_digest: str
    candidate_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "elapsed_ns": self.elapsed_ns,
            "diagnostics": list(self.diagnostics),
            "instance_digest": self.instance_digest,
            "candidate_digest": self.candidate_digest,
        }
