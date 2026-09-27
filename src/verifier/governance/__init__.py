"""Bounded level 8 governance admission; not execution or legal authority.

Verifier Standard (VSTD) receipts use canonical JavaScript Object Notation (JSON),
Secure Hash Algorithm 256-bit (SHA-256), and hash-based message authentication code
(HMAC). This symmetric mechanism authenticates evidence only relative to separately
provisioned secret roots; any holder of those keys can create that evidence.
Timestamps are integer Unix seconds in Coordinated Universal Time (UTC).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import hmac
import re
from typing import Any, Mapping

from verifier.core.certificate import canonical_bytes, canonical_digest


class GovernanceVerdict(str, Enum):
    PASS = "PASS"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


def _text(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 512


def _instant(value: Any) -> bool:
    return type(value) is int and value >= 0


def _hex(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


@dataclass(frozen=True)
class GovernanceContext:
    object_name: str
    artifact_digest: str
    operation: str
    actor_id: str
    observer_id: str
    purpose: str
    timestamp: int
    jurisdiction: str
    invocation_id: str


@dataclass(frozen=True)
class GovernancePrincipal:
    actor_id: str
    key_id: str
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not _text(self.actor_id) or not _text(self.key_id):
            raise ValueError("principal identifiers must be bounded nonempty strings")
        if not isinstance(self.key, bytes) or len(self.key) < 32:
            raise ValueError("trusted principal key must contain at least 32 bytes")


@dataclass(frozen=True)
class GovernancePolicy:
    """Trusted operator input, never reconstructed from candidate evidence.

    Provision high-entropy keys independently. Their minimum length is a shape
    check, not an entropy proof. Jurisdictions are exact policy scopes, not legal
    conclusions. A policy update must change its revision and retained terms.
    """

    policy_id: str
    revision: int
    object_names: tuple[str, ...]
    operations: tuple[str, ...]
    jurisdictions: tuple[str, ...]
    principals: tuple[GovernancePrincipal, ...]
    quorum: int
    veto_actors: tuple[str, ...]
    status_key_id: str
    status_key: bytes = field(repr=False)
    effective_from: int
    effective_until: int
    max_status_age: int
    appeal_route: str = ""

    def __post_init__(self) -> None:
        if not _text(self.policy_id) or not _text(self.status_key_id):
            raise ValueError("policy and status identifiers must be bounded nonempty strings")
        if not _instant(self.revision) or self.revision == 0:
            raise ValueError("policy revision must be a positive integer")
        for values in (self.object_names, self.operations, self.jurisdictions):
            if not isinstance(values, tuple) or not values or not all(_text(x) for x in values) or len(set(values)) != len(values):
                raise ValueError("policy scopes must be distinct nonempty string tuples")
        if not isinstance(self.principals, tuple) or not self.principals or not all(isinstance(p, GovernancePrincipal) for p in self.principals):
            raise ValueError("policy principals must be a nonempty tuple")
        for values in ([p.actor_id for p in self.principals], [p.key_id for p in self.principals], [p.key for p in self.principals]):
            if len(set(values)) != len(values):
                raise ValueError("quorum principals must have distinct actors, key identifiers, and keys")
        if type(self.quorum) is not int or not 1 <= self.quorum <= len(self.principals):
            raise ValueError("quorum must be achievable and positive")
        if not isinstance(self.veto_actors, tuple) or len(set(self.veto_actors)) != len(self.veto_actors) or not set(self.veto_actors) <= {p.actor_id for p in self.principals}:
            raise ValueError("veto actors must be distinct configured principals")
        if not isinstance(self.status_key, bytes) or len(self.status_key) < 32 or self.status_key in {p.key for p in self.principals} or self.status_key_id in {p.key_id for p in self.principals}:
            raise ValueError("status root must be distinct from voting roots and contain at least 32 bytes")
        if not all(_instant(x) for x in (self.effective_from, self.effective_until, self.max_status_age)) or self.effective_until <= self.effective_from:
            raise ValueError("policy time bounds must be nonempty integer intervals")
        if not isinstance(self.appeal_route, str) or len(self.appeal_route) > 512:
            raise ValueError("appeal route must be a bounded string")


def policy_digest(policy: GovernancePolicy) -> str:
    """Hash public policy terms; this digest supplies no trust or secret root."""
    public = asdict(policy)
    public.pop("status_key")
    public["principals"] = [{"actor_id": p.actor_id, "key_id": p.key_id} for p in policy.principals]
    return canonical_digest(public)


@dataclass(frozen=True)
class GovernanceEvaluation:
    verdict: GovernanceVerdict
    receipt: dict[str, Any]


_DECISION_FIELDS = {"schema", "decision_id", "policy_digest", "binding", "actor_id", "key_id", "decision", "issued_at", "expires_at", "signature"}
_STATUS_FIELDS = {"schema", "policy_digest", "key_id", "observed_at", "expires_at", "revoked_decisions", "revoked_actors", "consumed_invocations", "signature"}


def _signature_valid(record: Mapping[str, Any], key: bytes) -> bool:
    signature = record.get("signature")
    if not _hex(signature):
        return False
    try:
        message = canonical_bytes({k: v for k, v in record.items() if k != "signature"})
    except (TypeError, ValueError, OverflowError):
        return False
    return hmac.compare_digest(hmac.new(key, message, hashlib.sha256).hexdigest(), signature)


def evaluate_governance(
    context: GovernanceContext,
    decisions: tuple[dict[str, Any], ...],
    *,
    policy: GovernancePolicy | None,
    status: dict[str, Any] | None,
    evaluation_time: int | None,
    computational_verdict: str = "UNKNOWN",
) -> GovernanceEvaluation:
    """Recompute exact-action admission against independent current roots.

    The trusted caller supplies current policy, evaluation time, and the signed
    status snapshot from its authority channel. Candidate evidence supplies none
    of those roots. A passing receipt is not an execution permit: the caller must
    separately enforce privacy, consent, and atomic invocation consumption.
    """
    checks: list[dict[str, str]] = []
    approvals: set[str] = set()

    def mark(verdict: GovernanceVerdict, code: str) -> None:
        checks.append({"verdict": verdict.value, "code": code})

    binding = asdict(context)
    digest = policy_digest(policy) if policy is not None else None

    def finish() -> GovernanceEvaluation:
        values = {row["verdict"] for row in checks}
        verdict = (GovernanceVerdict.REJECTED if "REJECTED" in values else
                   GovernanceVerdict.UNKNOWN if "UNKNOWN" in values else GovernanceVerdict.PASS)
        try:
            evidence_digest = canonical_digest({"decisions": decisions, "status": status})
        except (TypeError, ValueError, OverflowError):
            evidence_digest = None
        return GovernanceEvaluation(verdict, {
            "schema": "verifier-governance-evaluation-1", "mechanism": "governance-hmac-sha256-1",
            "binding": binding, "evaluation_time": evaluation_time, "policy_digest": digest,
            "policy_id": policy.policy_id if policy else None, "policy_revision": policy.revision if policy else None,
            "evidence_digest": evidence_digest, "verdict": verdict.value, "checks": checks,
            "approving_actors": sorted(approvals), "computational_verdict": computational_verdict,
            "privacy": "NOT_EVALUATED", "consent": "NOT_EVALUATED", "enforcement": "UNKNOWN",
            "appeal_route": policy.appeal_route if policy else None,
        })

    if not all(_text(value) for key, value in binding.items() if key != "timestamp") or not _hex(context.artifact_digest) or not _instant(context.timestamp):
        mark(GovernanceVerdict.REJECTED, "MALFORMED_CONTEXT")
        return finish()
    if evaluation_time is None:
        mark(GovernanceVerdict.UNKNOWN, "TRUSTED_CLOCK_UNAVAILABLE")
    elif not _instant(evaluation_time):
        mark(GovernanceVerdict.REJECTED, "MALFORMED_TRUSTED_CLOCK")
        return finish()
    if evaluation_time is not None and context.timestamp != evaluation_time:
        mark(GovernanceVerdict.REJECTED, "ACTION_CLOCK_MISMATCH")
    if policy is None:
        mark(GovernanceVerdict.UNKNOWN, "TRUSTED_POLICY_UNAVAILABLE")
        return finish()
    if evaluation_time is not None and not policy.effective_from <= evaluation_time < policy.effective_until:
        mark(GovernanceVerdict.REJECTED, "POLICY_NOT_EFFECTIVE")
    if context.object_name not in policy.object_names or context.operation not in policy.operations or context.jurisdiction not in policy.jurisdictions:
        mark(GovernanceVerdict.REJECTED, "OUTSIDE_POLICY_SCOPE")
    if not isinstance(decisions, tuple) or len(decisions) > 256:
        mark(GovernanceVerdict.REJECTED, "MALFORMED_DECISION_INVENTORY")
        return finish()
    principals = {p.actor_id: p for p in policy.principals}
    seen_actors: set[str] = set()
    seen_ids: set[str] = set()
    for decision in decisions:
        if not isinstance(decision, dict) or set(decision) != _DECISION_FIELDS or decision.get("schema") != "verifier-governance-decision-1":
            mark(GovernanceVerdict.REJECTED, "MALFORMED_DECISION")
            continue
        actor = decision["actor_id"]
        decision_id = decision["decision_id"]
        if not _text(actor) or not _text(decision_id) or not _text(decision["key_id"]):
            mark(GovernanceVerdict.REJECTED, "MALFORMED_DECISION_IDENTIFIERS")
            continue
        if actor in seen_actors or decision_id in seen_ids:
            mark(GovernanceVerdict.REJECTED, "DUPLICATE_DECISION_OR_ACTOR")
        seen_actors.add(actor)
        seen_ids.add(decision_id)
        principal = principals.get(actor)
        if principal is None or decision["key_id"] != principal.key_id:
            mark(GovernanceVerdict.REJECTED, "UNAUTHORIZED_DECISION_MAKER")
            continue
        if not _signature_valid(decision, principal.key):
            mark(GovernanceVerdict.REJECTED, "DECISION_SIGNATURE_INVALID")
            continue
        if decision["policy_digest"] != digest or canonical_bytes(decision["binding"]) != canonical_bytes(binding):
            mark(GovernanceVerdict.REJECTED, "DECISION_BINDING_MISMATCH")
        start, end = decision["issued_at"], decision["expires_at"]
        if not _instant(start) or not _instant(end) or end <= start or evaluation_time is not None and not start <= evaluation_time < end:
            mark(GovernanceVerdict.REJECTED, "DECISION_NOT_EFFECTIVE")
        vote = decision["decision"]
        if vote == "APPROVE":
            approvals.add(actor)
        elif vote == "DENY" or vote == "VETO" and actor in policy.veto_actors:
            mark(GovernanceVerdict.REJECTED, "EXPLICIT_DENIAL_OR_VETO")
        else:
            mark(GovernanceVerdict.REJECTED, "INVALID_DECISION_KIND")
    if len(approvals) < policy.quorum:
        mark(GovernanceVerdict.UNKNOWN, "QUORUM_NOT_ESTABLISHED")
    if status is None:
        mark(GovernanceVerdict.UNKNOWN, "STATUS_UNAVAILABLE")
        return finish()
    if not isinstance(status, dict) or set(status) != _STATUS_FIELDS or status.get("schema") != "verifier-governance-status-1":
        mark(GovernanceVerdict.REJECTED, "MALFORMED_STATUS")
        return finish()
    if status["key_id"] != policy.status_key_id or status["policy_digest"] != digest:
        mark(GovernanceVerdict.REJECTED, "STATUS_ROOT_OR_POLICY_MISMATCH")
    if not _signature_valid(status, policy.status_key):
        mark(GovernanceVerdict.REJECTED, "STATUS_SIGNATURE_INVALID")
        return finish()
    observed, expires = status["observed_at"], status["expires_at"]
    if not _instant(observed) or not _instant(expires) or expires <= observed:
        mark(GovernanceVerdict.REJECTED, "MALFORMED_STATUS_INTERVAL")
    elif evaluation_time is not None and (not observed <= evaluation_time < expires or evaluation_time - observed > policy.max_status_age):
        mark(GovernanceVerdict.UNKNOWN, "STATUS_NOT_CURRENT")
    for name in ("revoked_decisions", "revoked_actors", "consumed_invocations"):
        values = status[name]
        if not isinstance(values, list) or len(values) > 10000 or not all(_text(x) for x in values) or len(set(values)) != len(values):
            mark(GovernanceVerdict.REJECTED, "MALFORMED_STATUS_INVENTORY")
            return finish()
    if seen_ids.intersection(status["revoked_decisions"]) or seen_actors.intersection(status["revoked_actors"]):
        mark(GovernanceVerdict.REJECTED, "REVOKED_AUTHORITY_OR_DECISION")
    if context.invocation_id in status["consumed_invocations"]:
        mark(GovernanceVerdict.REJECTED, "KNOWN_INVOCATION_REPLAY")
    if not checks:
        mark(GovernanceVerdict.PASS, "EXACT_ACTION_ADMISSION_ESTABLISHED")
    return finish()


def recheck_governance(
    receipt: dict[str, Any], context: GovernanceContext, decisions: tuple[dict[str, Any], ...],
    *, policy: GovernancePolicy | None, status: dict[str, Any] | None,
    evaluation_time: int | None, computational_verdict: str = "UNKNOWN",
) -> bool:
    """Recompute receipt bytes using independently supplied roots and inputs."""
    reproduced = evaluate_governance(context, decisions, policy=policy, status=status,
                                    evaluation_time=evaluation_time,
                                    computational_verdict=computational_verdict)
    try:
        return hmac.compare_digest(canonical_bytes(receipt), canonical_bytes(reproduced.receipt))
    except (TypeError, ValueError, OverflowError):
        return False


__all__ = ["GovernanceContext", "GovernancePrincipal", "GovernancePolicy", "GovernanceVerdict",
           "GovernanceEvaluation", "evaluate_governance", "policy_digest", "recheck_governance"]
