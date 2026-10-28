"""Source-bound, in-memory POLICY enforcement for Verifier Standard (VSTD).

Terminology: hash-based message authentication code (HMAC); Secure Hash Algorithm
256-bit (SHA-256); JavaScript Object Notation (JSON); Verifier Standard (VSTD).

A policy is a versioned rule set over named actions. Its content is bound to a
decision authority by an HMAC over canonical JSON, so an authority signs the exact
policy digest rather than a name. Each request names one declared enforcement point,
one action, one target and a set of consequence roles (AGENT, FINANCIAL, MODEL,
PHYSICAL, POLICY). Roles accumulate: every role must be allowed by an applicable rule
on its own, so a POLICY label never exempts a financial or physical consequence.
Anything not positively allowed is refused. An evaluation that raises returns
UNAVAILABLE, which is never treated as ALLOWED.

Every ``enforce`` call whose ledger argument is a Ledger appends exactly one receipt to a
hash-chained ledger, including refusals of a non-PolicyVersion policy or a
non-EnforcementRequest input; fields that cannot be represented read UNREPRESENTED. The
ledger is a new tuple per decision, so a refused or unavailable decision cannot partially
mutate earlier receipts. Each receipt commits to the selected decision authority's
trust-root identity and key fingerprint and to a commitment over every supplied trust
root. That commitment is not signer identity, key custody or trust-root truth. A decision
needs a declared current-revision pointer, verified by its authority; whether that pointer
is published or current is not established here. The report binds the digests of this
module and of the decision engine it consumes, and it replays byte-for-byte from the same
policy, requests and trust roots.

Boundary: this module observes only calls made through ``enforce``. It does not observe
downstream execution, trust-root custody, signer identity, publication of revisions, or the
truth of the facts behind decision evidence. Unsupplied effects are UNKNOWN. Time is a
logical epoch that the caller supplies, not a wall clock. Revision 1 of this mechanism is
in-process; it establishes no external enforcement.

The auxiliary route checks at the end of this module are local field evidence. They never execute
the central catalog checking mechanism and never establish route conformance.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, fields
import hashlib
import hmac
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from verifier.data import policy as policy_source_module
from verifier.data.policy import PolicyDecisionEvidence, check_policy_decision
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest

ADAPTER = "verifier-policy-enforcement-1"
SEMANTIC_VERSION = "verifier-policy-enforcement-semantics-1"
REPORT_SCHEMA = "verifier-policy-enforcement-report-1"
CLAIM = (
    "For the supplied policy, grants, exceptions, current-revision declaration and requests, each "
    "decision is ALLOWED only when every consequence role is positively allowed by an applicable rule "
    "under verified, unexpired authority and a verified current-revision declaration; every other path "
    "is REFUSED or UNAVAILABLE. Publication and currentness of the declaration are not established."
)
BOUNDARY = (
    "In-process mechanism over caller-supplied trust roots and logical time. Observes only calls "
    "made through enforce; not downstream execution, key custody, signer identity, external "
    "enforcement, or the truth of facts behind decision evidence. Receipts are hash-chained, not "
    "signed: a party that rewrites a whole chain is not detected here."
)

ENFORCEMENT_POINTS = ("ADMISSION", "EXECUTION", "RELEASE", "PERSISTENCE")
ROLES = ("AGENT", "FINANCIAL", "MODEL", "PHYSICAL", "POLICY")
ALLOW = "ALLOW"
DENY = "DENY"
ALLOWED = "ALLOWED"
REFUSED = "REFUSED"
UNAVAILABLE = "UNAVAILABLE"
GENESIS = "sha256:" + "0" * 64
# Receipt fields that carry no value: an unselected trust root, an unrepresentable input, or a receipt
# whose digest could not be computed. A receipt holding UNSEALED fails verify_chain by construction.
NONE = "NONE"
UNREPRESENTED = "UNREPRESENTED"
UNSEALED = "UNSEALED"

_FIELD_DISPOSITIONS = {
    "scope": (
        "PARTIAL",
        "Auxiliary checks refuse actions outside the closed scope tuple before any rule is consulted. "
        "Central audit: PARTIAL; complete scope coverage and repository adoption are not established.",
    ),
    "decision_inputs": (
        "PARTIAL",
        "Auxiliary checks bind each receipt to the canonical digest of its request, including grants, "
        "exceptions and evidence. Central audit: PARTIAL; the declared input set is not fully adjudicated.",
    ),
    "defaults": (
        "PARTIAL",
        "Auxiliary checks refuse a role with no applicable rule as NO_MATCHING_RULE, and the default effect "
        "is fixed to DENY. Central audit: PARTIAL; the default is not fully adjudicated.",
    ),
    "precedence": (
        "PARTIAL",
        "Auxiliary checks exercise higher-priority ALLOW and DENY and equal-priority PRECEDENCE_CONFLICT. "
        "Central audit: PARTIAL; the declared precedence meaning is not fully adjudicated here.",
    ),
    "exceptions": (
        "PARTIAL",
        "Auxiliary checks exercise an in-window waiver of a DENY rule and an expired waiver. "
        "Central audit: PARTIAL; the declared exception meaning is not fully adjudicated here.",
    ),
    "authority": (
        "BOUNDARY",
        "Auxiliary checks HMAC-verify grants against caller-supplied trust roots, including bit-flipped and "
        "unknown-authority grants. Key custody, signer identity and trust-root truth are outside the "
        "established boundary. Central audit: BOUNDARY_EXCLUDED.",
    ),
    "activation": (
        "BOUNDARY",
        "Auxiliary checks evaluate the active window against the caller's logical epoch, not a wall clock. "
        "Central audit: BOUNDARY_EXCLUDED.",
    ),
    "revisions": (
        "PARTIAL",
        "Auxiliary checks refuse stale request revisions and grants bound to a prior revision. Central "
        "audit: PARTIAL; publication and currentness of the declared revision remain unestablished.",
    ),
    "decision_evidence": (
        "PARTIAL",
        "Auxiliary checks recheck evidence through check_policy_decision and require it to match the policy "
        "and target. The truth of the underlying facts is not established. Central audit: PARTIAL.",
    ),
    "enforcement_points": (
        "BOUNDARY",
        "Auxiliary checks observe only calls made through enforce; whether downstream execution routes "
        "through a declared point is not observed. Central audit: BOUNDARY_EXCLUDED.",
    ),
    "bypass_handling": (
        "PARTIAL",
        "detect_bypass reports supplied effects that lack an allowed receipt for the same point, action and "
        "target. Central audit: PARTIAL; unsupplied effects and downstream bypasses are not detected.",
    ),
    "unavailable_behavior": (
        "PARTIAL",
        "Auxiliary checks map an evaluator exception to UNAVAILABLE, never to ALLOWED. Central audit: "
        "PARTIAL; external and downstream unavailable paths are not established.",
    ),
}

_DISPOSITION_REASON_SHA256 = {
    "scope": "222ea5ccd3d208df4d0c6134d5ae5786f1f3d494b9d214e751c809cc5ec8dae4",
    "decision_inputs": "50f26f6acf4a186e8fa701f574ec8e8f9b9eb4695fdeb6b26ed7c0e80dbdfc5c",
    "defaults": "71f3757a951820650e30e006c45277fcd1af280db35e78f13db8b13b0dbc468b",
    "precedence": "a40a58d0dff911e31442a358b303a89f28c7d6a995baf50af67e21398be48bc2",
    "exceptions": "7ec7dd30e9a4009d5fb6e63e5e4a56488e189695454f0bd4e3049a22fe8b8f7f",
    "authority": "409737ecb33b206adccf40bee4441bdfa2048036e3bbc008c08488794f9d9416",
    "activation": "d9faf4e054057d929611807d66ca6254de8b4c90e80596f13c7a7835b6013254",
    "revisions": "2408eefc4607a6ddff266c4a9458ef8e217230b02cd4242dea23c950514f358b",
    "decision_evidence": "989cd027d24c1795aeea16dccfde143810bfc3d0a8b777748435581143237f3e",
    "enforcement_points": "90db89e5e1390cf1d97fcf73af3ba335304f829c87ac87b0c92a9a89e87028b3",
    "bypass_handling": "eb8f301d6bf6cf1d8b96c0c2f437225c2f17f5c5107e9bfcee9cda1d9b34c385",
    "unavailable_behavior": "c4ea3111d82bc2fff00fe44f15fa715f9966a7f5dd647a1374236ba56e8c01fe",
}



class PolicyDefinitionError(ValueError):
    """A policy, grant, exception or request has a form this mechanism refuses to interpret."""


class PolicyBypassDetected(RuntimeError):
    """At least one claimed effect has no allowed enforcement receipt for its exact fields."""

    def __init__(self, findings: tuple["BypassFinding", ...]) -> None:
        super().__init__(f"{len(findings)} effect(s) without an allowed enforcement receipt")
        self.findings = findings


def _closed(value: Any, names: frozenset, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != names:
        raise PolicyDefinitionError(f"{name} must have exactly the fields " + ", ".join(sorted(names)))
    return value


def _text(value: Any, name: str) -> str:
    if type(value) is not str or not value:
        raise PolicyDefinitionError(f"{name} must be a non-empty string")
    return value


def _integer(value: Any, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PolicyDefinitionError(f"{name} must be an integer of at least {minimum}")
    return value


def _flag(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise PolicyDefinitionError(f"{name} must be a boolean")
    return value


def _texts(values: Any, name: str, allowed: Optional[tuple] = None) -> tuple:
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise PolicyDefinitionError(f"{name} must be a sequence of strings")
    items = tuple(_text(item, name) for item in values)
    if allowed is not None and any(item not in allowed for item in items):
        raise PolicyDefinitionError(f"{name} contains a value outside {', '.join(allowed)}")
    return items


def _sign(key: bytes, payload: Mapping[str, Any]) -> str:
    return hmac.new(key, canonical_bytes(payload), hashlib.sha256).hexdigest()


def _verify(key: bytes, payload: Mapping[str, Any], mac: Any) -> bool:
    if type(mac) is not str or not mac.isascii():
        return False
    return hmac.compare_digest(_sign(key, payload), mac)


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class Rule:
    """One rule over exact actions and consequence roles; higher priority decides first."""

    rule_id: str
    priority: int
    effect: str
    actions: tuple[str, ...]
    roles: tuple[str, ...]
    requires_policy_evidence: bool = False

    def __post_init__(self) -> None:
        _text(self.rule_id, "rule_id")
        _integer(self.priority, "priority", -(10**9))
        if self.effect not in (ALLOW, DENY):
            raise PolicyDefinitionError("rule effect must be ALLOW or DENY")
        object.__setattr__(self, "actions", _texts(self.actions, "rule actions"))
        object.__setattr__(self, "roles", _texts(self.roles, "rule roles", ROLES))
        if not self.actions or not self.roles:
            raise PolicyDefinitionError("a rule must name at least one action and one role")
        _flag(self.requires_policy_evidence, "requires_policy_evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "priority": self.priority,
            "effect": self.effect,
            "actions": list(self.actions),
            "roles": list(self.roles),
            "requires_policy_evidence": self.requires_policy_evidence,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Rule":
        names = frozenset(item.name for item in fields(cls))
        return cls(**dict(_closed(value, names, "rule")))


@dataclass(frozen=True)
class PolicyVersion:
    """A revisioned policy. Its digest is what decision authorities sign.

    ``active_from``/``active_until`` are logical epochs; ``active_until`` of None is open.
    ``decision_policy_id`` names the one decision-engine policy whose evidence may
    satisfy an evidence-bound rule; None means no evidence can be linked.
    ``max_exception_lifetime`` bounds every waiver's ``expires_at - not_before``.
    """

    policy_id: str
    revision: int
    scope: tuple[str, ...]
    rules: tuple[Rule, ...]
    enforcement_points: tuple[str, ...]
    active_from: int
    active_until: Optional[int]
    decision_policy_id: Optional[str]
    max_exception_lifetime: int
    default_effect: str = DENY

    def __post_init__(self) -> None:
        _text(self.policy_id, "policy_id")
        _integer(self.revision, "revision", 1)
        if self.default_effect != DENY:
            raise PolicyDefinitionError("the default effect must be DENY; an allow default is not a policy")
        scope = _texts(self.scope, "scope")
        if not scope:
            raise PolicyDefinitionError("scope must name at least one action")
        object.__setattr__(self, "scope", scope)
        rules = tuple(self.rules)
        if not all(isinstance(item, Rule) for item in rules):
            raise PolicyDefinitionError("rules must be Rule values")
        identifiers = [item.rule_id for item in rules]
        if len(set(identifiers)) != len(identifiers):
            raise PolicyDefinitionError("rule identifiers must be unique")
        for item in rules:
            if not set(item.actions) <= set(scope):
                raise PolicyDefinitionError(f"rule {item.rule_id} names an action outside the scope")
        object.__setattr__(self, "rules", rules)
        points = _texts(self.enforcement_points, "enforcement_points", ENFORCEMENT_POINTS)
        if not points:
            raise PolicyDefinitionError("a policy must declare at least one enforcement point")
        object.__setattr__(self, "enforcement_points", points)
        _integer(self.active_from, "active_from")
        if self.active_until is not None:
            _integer(self.active_until, "active_until")
            if self.active_until <= self.active_from:
                raise PolicyDefinitionError("active_until must follow active_from")
        if self.decision_policy_id is not None:
            _text(self.decision_policy_id, "decision_policy_id")
        _integer(self.max_exception_lifetime, "max_exception_lifetime", 1)

    @property
    def digest(self) -> str:
        return value_digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "revision": self.revision,
            "scope": list(self.scope),
            "rules": [item.to_dict() for item in self.rules],
            "enforcement_points": list(self.enforcement_points),
            "active_from": self.active_from,
            "active_until": self.active_until,
            "decision_policy_id": self.decision_policy_id,
            "max_exception_lifetime": self.max_exception_lifetime,
            "default_effect": self.default_effect,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PolicyVersion":
        names = frozenset(item.name for item in fields(cls))
        checked = dict(_closed(value, names, "policy"))
        if type(checked["rules"]) is not list:
            raise PolicyDefinitionError("policy rules must be a list")
        checked["rules"] = tuple(Rule.from_dict(item) for item in checked["rules"])
        return cls(**checked)


@dataclass(frozen=True)
class Authorization:
    """An authority's HMAC grant over one exact policy revision and digest.

    ``may_decide`` lets the authority make this policy binding in force. ``may_except``
    lets it sign exceptions. ``actions`` is the ceiling for exceptions it may grant.
    """

    authority_id: str
    policy_id: str
    revision: int
    policy_digest: str
    may_decide: bool
    may_except: bool
    actions: tuple[str, ...]
    mac: str

    def __post_init__(self) -> None:
        _text(self.authority_id, "authority_id")
        _text(self.policy_id, "policy_id")
        _integer(self.revision, "revision", 1)
        _text(self.policy_digest, "policy_digest")
        _flag(self.may_decide, "may_decide")
        _flag(self.may_except, "may_except")
        object.__setattr__(self, "actions", _texts(self.actions, "actions"))
        _text(self.mac, "mac")

    def payload(self) -> dict[str, Any]:
        return {key: value for key, value in self.to_dict().items() if key != "mac"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id,
            "policy_id": self.policy_id,
            "revision": self.revision,
            "policy_digest": self.policy_digest,
            "may_decide": self.may_decide,
            "may_except": self.may_except,
            "actions": list(self.actions),
            "mac": self.mac,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Authorization":
        names = frozenset(item.name for item in fields(cls))
        return cls(**dict(_closed(value, names, "authorization")))


@dataclass(frozen=True)
class PolicyException:
    """A signed waiver of one DENY rule for one action and target, within a bounded window."""

    exception_id: str
    policy_id: str
    revision: int
    policy_digest: str
    rule_id: str
    action: str
    target: str
    granted_by: str
    not_before: int
    expires_at: int
    mac: str

    def __post_init__(self) -> None:
        for name in ("exception_id", "policy_id", "policy_digest", "rule_id", "action", "target",
                     "granted_by", "mac"):
            _text(getattr(self, name), name)
        _integer(self.revision, "revision", 1)
        _integer(self.not_before, "not_before")
        _integer(self.expires_at, "expires_at")

    def payload(self) -> dict[str, Any]:
        return {key: value for key, value in self.to_dict().items() if key != "mac"}

    def to_dict(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}


@dataclass(frozen=True)
class CurrentRevision:
    """An authority's HMAC declaration of which revision and digest of a policy is current."""

    policy_id: str
    revision: int
    policy_digest: str
    authority_id: str
    mac: str

    def payload(self) -> dict[str, Any]:
        return {key: value for key, value in self.to_dict().items() if key != "mac"}

    def to_dict(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}


def issue_current_revision(
    key: bytes, *, policy_id: str, revision: int, policy_digest: str, authority_id: str
) -> CurrentRevision:
    """Sign one declaration of the current revision and digest of ``policy_id``."""
    fields_ = {
        "policy_id": policy_id,
        "revision": revision,
        "policy_digest": policy_digest,
        "authority_id": authority_id,
    }
    return CurrentRevision(**fields_, mac=_sign(key, fields_))


@dataclass(frozen=True)
class EnforcementRequest:
    """One request at one declared enforcement point. Roles are canonicalized to a sorted set."""

    request_id: str
    policy_id: str
    revision: int
    point: str
    action: str
    target: str
    roles: tuple[str, ...]
    now: int
    authorizations: tuple[Authorization, ...] = ()
    exceptions: tuple[PolicyException, ...] = ()
    decision_evidence: Optional[PolicyDecisionEvidence] = None
    current_revision: Optional[CurrentRevision] = None

    def __post_init__(self) -> None:
        for name in ("request_id", "policy_id", "action", "target"):
            _text(getattr(self, name), name)
        _integer(self.revision, "revision", 1)
        if self.point not in ENFORCEMENT_POINTS:
            raise PolicyDefinitionError("point must be a declared enforcement point")
        roles = _texts(self.roles, "roles", ROLES)
        if not roles:
            raise PolicyDefinitionError("a request must name at least one consequence role")
        object.__setattr__(self, "roles", tuple(sorted(set(roles))))
        _integer(self.now, "now")
        object.__setattr__(self, "authorizations", tuple(self.authorizations))
        object.__setattr__(self, "exceptions", tuple(self.exceptions))
        if not all(isinstance(item, Authorization) for item in self.authorizations):
            raise PolicyDefinitionError("authorizations must be Authorization values")
        if not all(isinstance(item, PolicyException) for item in self.exceptions):
            raise PolicyDefinitionError("exceptions must be PolicyException values")
        if self.decision_evidence is not None and not isinstance(self.decision_evidence, PolicyDecisionEvidence):
            raise PolicyDefinitionError("decision_evidence must be PolicyDecisionEvidence or None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "policy_id": self.policy_id,
            "revision": self.revision,
            "point": self.point,
            "action": self.action,
            "target": self.target,
            "roles": list(self.roles),
            "now": self.now,
            "authorizations": [item.to_dict() for item in self.authorizations],
            "exceptions": [item.to_dict() for item in self.exceptions],
            "decision_evidence": None if self.decision_evidence is None else self.decision_evidence.to_dict(),
            "current_revision": None if self.current_revision is None else self.current_revision.to_dict(),
        }


@dataclass(frozen=True)
class Receipt:
    """One sealed decision. ``digest`` commits to every other field and to ``previous_digest``."""

    sequence: int
    request_id: str
    request_digest: str
    point: str
    policy_id: str
    revision: int
    policy_digest: str
    action: str
    target: str
    roles: tuple[str, ...]
    outcome: str
    reasons: tuple[str, ...]
    role_dispositions: tuple[tuple[str, str, str], ...]
    exception_dispositions: tuple[tuple[str, str], ...]
    evidence_digest: Optional[str]
    trust_root_id: str
    trust_root_digest: str
    trust_roots_digest: str
    previous_digest: str
    digest: str

    def body(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self) if item.name != "digest"}

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "digest": self.digest}


@dataclass(frozen=True)
class Ledger:
    """An append-only, hash-chained sequence of receipts."""

    receipts: tuple[Receipt, ...] = ()

    @property
    def digest(self) -> str:
        return self.receipts[-1].digest if self.receipts else GENESIS


def empty_ledger() -> Ledger:
    return Ledger()


def verify_chain(ledger: Ledger) -> bool:
    """True only when every receipt recomputes its digest and links to its predecessor."""
    previous = GENESIS
    for index, item in enumerate(ledger.receipts):
        if item.sequence != index or item.previous_digest != previous:
            return False
        if value_digest(item.body()) != item.digest:
            return False
        previous = item.digest
    return True


@dataclass(frozen=True)
class EffectClaim:
    """An effect someone reports as executed. It must be backed by an allowed receipt."""

    request_id: str
    point: str
    action: str
    target: str
    request_digest: Optional[str] = None


@dataclass(frozen=True)
class BypassFinding:
    request_id: str
    point: str
    action: str
    target: str
    reason: str


@dataclass(frozen=True)
class _Verdict:
    outcome: str
    reasons: tuple[str, ...]
    role_dispositions: tuple[tuple[str, str, str], ...] = ()
    exception_dispositions: tuple[tuple[str, str], ...] = ()
    evidence_digest: Optional[str] = None
    trust_root_id: str = NONE
    trust_root_digest: str = NONE


def _key_fingerprint(key: Any) -> str:
    """SHA-256 of the raw trust-root key bytes. Keys must be high entropy; fixture keys are public constants."""
    if type(key) is not bytes:
        return "NON_BYTES:" + type(key).__name__
    return "sha256:" + hashlib.sha256(key).hexdigest()


def _trust_roots_digest(trust_roots: Any) -> str:
    """Commitment to every supplied trust root: SHA-256 of compact JSON for sorted [authority, fingerprint] pairs.

    Total over arbitrary input: an unrepresentable mapping reads UNREPRESENTED, never an exception.
    """
    if not isinstance(trust_roots, Mapping):
        return UNREPRESENTED
    try:
        pairs = sorted(
            [authority if type(authority) is str else "NON_STRING:" + type(authority).__name__,
             _key_fingerprint(key)]
            for authority, key in trust_roots.items()
        )
    except Exception:  # an unreadable mapping is recorded as unrepresentable, not raised
        return UNREPRESENTED
    text = json.dumps(pairs, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def issue_authorization(
    key: bytes,
    policy: PolicyVersion,
    authority_id: str,
    *,
    may_decide: bool = True,
    may_except: bool = False,
    actions: Iterable[str] = (),
) -> Authorization:
    """Sign one authority grant over the exact current digest of ``policy``."""
    fields_ = {
        "authority_id": authority_id,
        "policy_id": policy.policy_id,
        "revision": policy.revision,
        "policy_digest": policy.digest,
        "may_decide": may_decide,
        "may_except": may_except,
        "actions": list(actions),
    }
    return Authorization(**fields_, mac=_sign(key, fields_))


def issue_exception(
    key: bytes,
    policy: PolicyVersion,
    *,
    exception_id: str,
    rule_id: str,
    action: str,
    target: str,
    granted_by: str,
    not_before: int,
    expires_at: int,
) -> PolicyException:
    """Sign one waiver of a DENY rule under the exact current digest of ``policy``."""
    fields_ = {
        "exception_id": exception_id,
        "policy_id": policy.policy_id,
        "revision": policy.revision,
        "policy_digest": policy.digest,
        "rule_id": rule_id,
        "action": action,
        "target": target,
        "granted_by": granted_by,
        "not_before": not_before,
        "expires_at": expires_at,
    }
    return PolicyException(**fields_, mac=_sign(key, fields_))


def _refuse(*reasons: str) -> _Verdict:
    return _Verdict(REFUSED, tuple(reasons))


def _verified_grant(authorization: Authorization, trust: Mapping[str, bytes]) -> bool:
    key = trust.get(authorization.authority_id)
    return key is not None and _verify(key, authorization.payload(), authorization.mac)


def _find_decision_authority(
    policy: PolicyVersion, request: EnforcementRequest, trust: Mapping[str, bytes]
) -> tuple[Optional[Authorization], tuple[str, ...]]:
    """The first grant that verifies and binds this exact policy, plus every rejection reason seen."""
    reasons: list[str] = []
    for grant in request.authorizations:
        if not _verified_grant(grant, trust):
            reasons.append("UNVERIFIED_AUTHORITY")
        elif grant.policy_id != policy.policy_id:
            reasons.append("AUTHORIZATION_POLICY_MISMATCH")
        elif grant.revision != policy.revision:
            reasons.append("AUTHORIZATION_REVISION_MISMATCH")
        elif grant.policy_digest != policy.digest:
            reasons.append("POLICY_DIGEST_MISMATCH")
        elif not grant.may_decide:
            reasons.append("NOT_DECISION_AUTHORITY")
        else:
            return grant, tuple(reasons)
    return None, tuple(reasons)


def _exception_refusal(
    policy: PolicyVersion, request: EnforcementRequest, exception: PolicyException, trust: Mapping[str, bytes]
) -> Optional[str]:
    key = trust.get(exception.granted_by)
    if key is None or not _verify(key, exception.payload(), exception.mac):
        return "UNVERIFIED_EXCEPTION"
    if exception.policy_id != policy.policy_id:
        return "EXCEPTION_OVERREACH:WRONG_POLICY"
    if exception.revision != policy.revision:
        return "STALE_REVISION"
    if exception.policy_digest != policy.digest:
        return "POLICY_DIGEST_MISMATCH"
    grant = next(
        (item for item in request.authorizations
         if item.authority_id == exception.granted_by and _verified_grant(item, trust)),
        None,
    )
    if grant is None or not grant.may_except:
        return "EXCEPTION_OVERREACH:NOT_EXCEPTION_AUTHORITY"
    if exception.action not in grant.actions:
        return "EXCEPTION_OVERREACH:ACTION_BEYOND_GRANT"
    lifetime = exception.expires_at - exception.not_before
    if lifetime <= 0 or lifetime > policy.max_exception_lifetime:
        return "EXCEPTION_OVERREACH:LIFETIME_BOUND"
    rule = next((item for item in policy.rules if item.rule_id == exception.rule_id), None)
    if rule is None:
        return "EXCEPTION_OVERREACH:UNKNOWN_RULE"
    if rule.effect != DENY:
        return "EXCEPTION_OVERREACH:NOT_A_DENY_RULE"
    return None


def _exception_window(exception: PolicyException, request: EnforcementRequest) -> str:
    if request.action != exception.action or request.target != exception.target:
        return "NON_MATCHING"
    if request.now < exception.not_before:
        return "NOT_YET_ACTIVE"
    if request.now >= exception.expires_at:
        return "EXPIRED"
    return "APPLIED"


def _evaluate_exceptions(
    policy: PolicyVersion, request: EnforcementRequest, trust: Mapping[str, bytes]
) -> tuple[frozenset, tuple[tuple[str, str], ...], tuple[str, ...]]:
    seen: set[str] = set()
    waived: set[str] = set()
    dispositions: list[tuple[str, str]] = []
    refusals: list[str] = []
    for exception in sorted(request.exceptions, key=lambda item: item.exception_id):
        if exception.exception_id in seen:
            refusals.append("DUPLICATE_EXCEPTION")
            continue
        seen.add(exception.exception_id)
        refusal = _exception_refusal(policy, request, exception, trust)
        if refusal is not None:
            refusals.append(refusal)
            continue
        window = _exception_window(exception, request)
        dispositions.append((exception.exception_id, window))
        if window == "APPLIED":
            waived.add(exception.rule_id)
    return frozenset(waived), tuple(dispositions), tuple(refusals)


def _evidence_failure(policy: PolicyVersion, target: str, evidence: PolicyDecisionEvidence) -> Optional[str]:
    if evidence.policy_id != policy.decision_policy_id:
        return "EVIDENCE_MISMATCH:POLICY"
    if evidence.target_artifact_id != target:
        return "EVIDENCE_MISMATCH:TARGET"
    if evidence.passed is not True:
        return "EVIDENCE_REJECTED:NOT_PASSED"
    if not check_policy_decision(evidence):
        return "EVIDENCE_REJECTED:RECHECK_FAILED"
    return None


def _decide_role(
    policy: PolicyVersion, request: EnforcementRequest, role: str, waived: frozenset
) -> tuple[str, str, str]:
    applicable = [
        item for item in policy.rules
        if request.action in item.actions and role in item.roles and item.rule_id not in waived
    ]
    if not applicable:
        return role, DENY, "NO_MATCHING_RULE"
    top = max(item.priority for item in applicable)
    deciding = [item for item in applicable if item.priority == top]
    effects = {item.effect for item in deciding}
    identifiers = ",".join(sorted(item.rule_id for item in deciding))
    if len(effects) > 1:
        return role, DENY, "PRECEDENCE_CONFLICT"
    if effects == {DENY}:
        return role, DENY, f"DENIED_BY_RULE:{identifiers}"
    if any(item.requires_policy_evidence for item in deciding) and request.decision_evidence is None:
        return role, DENY, "EVIDENCE_MISSING"
    return role, ALLOW, f"ALLOWED_BY_RULE:{identifiers}"


def _current_revision_failure(
    policy: PolicyVersion, request: EnforcementRequest, trust: Mapping[str, bytes]
) -> Optional[str]:
    """Why the declared current-revision pointer does not establish this policy as current, or None.

    Only a pointer that verifies under a trust root and names this exact policy id, revision and digest
    is accepted. A newer declared revision is SUPERSEDED. Publication and currentness are not established.
    """
    pointer = request.current_revision
    if pointer is None:
        return "CURRENT_REVISION_UNDECLARED"
    key = trust.get(pointer.authority_id)
    if key is None or not _verify(key, pointer.payload(), pointer.mac):
        return "UNVERIFIED_CURRENT_REVISION"
    if pointer.policy_id != policy.policy_id:
        return "CURRENT_REVISION_MISMATCH:POLICY"
    if pointer.revision > policy.revision:
        return "SUPERSEDED_REVISION"
    if pointer.revision != policy.revision:
        return "CURRENT_REVISION_MISMATCH:REVISION"
    if pointer.policy_digest != policy.digest:
        return "CURRENT_REVISION_MISMATCH:DIGEST"
    return None


def _decide(policy: PolicyVersion, request: EnforcementRequest, trust: Mapping[str, bytes]) -> _Verdict:
    """Refusals before a decision authority is selected name no trust root; later verdicts name the selected one."""
    if request.policy_id != policy.policy_id:
        return _refuse("POLICY_ID_MISMATCH")
    if request.point not in policy.enforcement_points:
        return _refuse("POINT_NOT_DECLARED")
    if request.revision != policy.revision:
        return _refuse("STALE_REVISION")
    pointer_failure = _current_revision_failure(policy, request, trust)
    if pointer_failure is not None:
        return _refuse(pointer_failure)
    grant, rejections = _find_decision_authority(policy, request, trust)
    if grant is None:
        return _refuse(*rejections, "NO_DECISION_AUTHORITY")
    verdict = _decide_under_authority(policy, request, trust)
    return dataclasses.replace(
        verdict,
        trust_root_id=grant.authority_id,
        trust_root_digest=_key_fingerprint(trust[grant.authority_id]),
    )


def _decide_under_authority(policy: PolicyVersion, request: EnforcementRequest, trust: Mapping[str, bytes]) -> _Verdict:
    if request.now < policy.active_from or (policy.active_until is not None and request.now >= policy.active_until):
        return _refuse("POLICY_INACTIVE")
    if request.action not in policy.scope:
        return _refuse("OUT_OF_SCOPE")
    waived, exception_dispositions, exception_refusals = _evaluate_exceptions(policy, request, trust)
    if exception_refusals:
        return _Verdict(REFUSED, exception_refusals, exception_dispositions=exception_dispositions)
    evidence_digest: Optional[str] = None
    evidence = request.decision_evidence
    if evidence is not None:
        failure = _evidence_failure(policy, request.target, evidence)
        if failure is not None:
            return _Verdict(REFUSED, (failure,), exception_dispositions=exception_dispositions)
        evidence_digest = value_digest(evidence.to_dict())
    roles = tuple(_decide_role(policy, request, role, waived) for role in request.roles)
    if all(decision == ALLOW for _, decision, _ in roles):
        return _Verdict(ALLOWED, ("ALL_ROLES_ALLOWED",), roles, exception_dispositions, evidence_digest)
    reasons = tuple(dict.fromkeys(reason for _, decision, reason in roles if decision == DENY))
    return _Verdict(REFUSED, reasons, roles, exception_dispositions, evidence_digest)


def enforce(
    ledger: Ledger,
    policy: PolicyVersion,
    request: EnforcementRequest,
    trust_roots: Mapping[str, bytes],
) -> tuple[Ledger, Receipt]:
    """Decide one request and return the ledger extended by exactly one receipt.

    Only a ``ledger`` that is not a Ledger raises, because nothing can be recorded. Any other input
    yields one receipt: a non-PolicyVersion policy or non-EnforcementRequest input is REFUSED, and any
    evaluator or digest fault is UNAVAILABLE, never ALLOWED. The caller's ledger is never modified.
    A receipt whose digest cannot be computed holds UNSEALED, so the chain fails verification.
    """
    if not isinstance(ledger, Ledger):
        raise TypeError("ledger must be a Ledger, because a decision must be recorded in one")
    subject = _subject(policy, request)
    verdict = _guarded_verdict(ledger, policy, request, trust_roots, subject)
    draft = {
        "sequence": len(ledger.receipts),
        **subject,
        "outcome": verdict.outcome,
        "reasons": verdict.reasons,
        "role_dispositions": verdict.role_dispositions,
        "exception_dispositions": verdict.exception_dispositions,
        "evidence_digest": verdict.evidence_digest,
        "trust_root_id": verdict.trust_root_id,
        "trust_root_digest": verdict.trust_root_digest,
        "trust_roots_digest": _trust_roots_digest(trust_roots),
        "previous_digest": ledger.digest,
    }
    sealed = Receipt(**draft, digest=_seal(draft))
    return Ledger(ledger.receipts + (sealed,)), sealed


def _subject(policy: Any, request: Any) -> dict[str, Any]:
    """Receipt fields naming the policy and request. Total: anything unrepresentable reads UNREPRESENTED."""
    subject: dict[str, Any] = {
        "request_id": UNREPRESENTED,
        "request_digest": UNREPRESENTED,
        "point": UNREPRESENTED,
        "policy_id": UNREPRESENTED,
        "revision": 0,
        "policy_digest": UNREPRESENTED,
        "action": UNREPRESENTED,
        "target": UNREPRESENTED,
        "roles": (),
    }
    if isinstance(policy, PolicyVersion):
        subject.update(policy_id=policy.policy_id, revision=policy.revision)
    if isinstance(request, EnforcementRequest):
        subject.update(
            request_id=request.request_id,
            point=request.point,
            action=request.action,
            target=request.target,
            roles=request.roles,
        )
    return subject


def _guarded_verdict(
    ledger: Ledger, policy: Any, request: Any, trust_roots: Mapping[str, bytes], subject: dict[str, Any]
) -> _Verdict:
    """The verdict for one call. Fills the digest fields of ``subject``; every fault becomes UNAVAILABLE."""
    try:  # fail closed: any evaluator or digest fault is UNAVAILABLE, never ALLOWED
        if not isinstance(policy, PolicyVersion):
            return _refuse("POLICY_NOT_POLICY_VERSION")
        subject["policy_digest"] = policy.digest
        if not isinstance(request, EnforcementRequest):
            return _refuse("REQUEST_NOT_ENFORCEMENT_REQUEST")
        subject["request_digest"] = value_digest(request.to_dict())
        if request.request_id in {item.request_id for item in ledger.receipts}:
            return _refuse("REPLAY_DETECTED")
        verdict = _decide(policy, request, dict(trust_roots))
        if type(verdict) is not _Verdict or verdict.outcome not in (ALLOWED, REFUSED):
            raise TypeError("evaluator returned no verdict")
        return verdict
    except Exception as error:
        return _Verdict(UNAVAILABLE, (f"EVALUATOR_UNAVAILABLE:{type(error).__name__}",))


def _seal(draft: Mapping[str, Any]) -> str:
    try:
        return value_digest(dict(draft))
    except Exception:  # an unsealable receipt is recorded as UNSEALED, which fails the chain check
        return UNSEALED


def run_sequence(
    policy: PolicyVersion, requests: Iterable[EnforcementRequest], trust_roots: Mapping[str, bytes]
) -> Ledger:
    ledger = empty_ledger()
    for request in requests:
        ledger, _ = enforce(ledger, policy, request, trust_roots)
    return ledger


def detect_bypass(ledger: Ledger, effects: Iterable[EffectClaim]) -> tuple[BypassFinding, ...]:
    """Report each claimed effect that lacks an allowed receipt with identical point, action and target."""
    findings: list[BypassFinding] = []
    for effect in effects:
        related = [item for item in ledger.receipts if item.request_id == effect.request_id]
        allowed = [item for item in related if item.outcome == ALLOWED]
        same_fields = [
            item for item in allowed
            if item.point == effect.point and item.action == effect.action and item.target == effect.target
        ]
        if any(effect.request_digest is None or item.request_digest == effect.request_digest for item in same_fields):
            continue
        if not related:
            reason = "NO_ENFORCEMENT_RECEIPT"
        elif same_fields:
            reason = "REQUEST_DIGEST_MISMATCH"
        elif allowed:
            reason = "MISMATCHED_RECEIPT"
        else:
            reason = "ENFORCEMENT_NOT_ALLOWED"
        findings.append(BypassFinding(effect.request_id, effect.point, effect.action, effect.target, reason))
    return tuple(findings)


def assert_no_bypass(ledger: Ledger, effects: Iterable[EffectClaim]) -> None:
    findings = detect_bypass(ledger, effects)
    if findings:
        raise PolicyBypassDetected(findings)


def _declared(field: str) -> tuple[Any, Any]:
    """The self-declared (status, reason) of one field; (None, None) when the entry is malformed."""
    entry = _FIELD_DISPOSITIONS.get(field)
    return entry if type(entry) is tuple and len(entry) == 2 else (None, None)


def _digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _disposition_refusals(audit: Mapping[str, str]) -> list[str]:
    """Fail-closed comparison of the self-declared dispositions with central audit statuses.

    A field refuses when its declaration is absent, malformed, outside the status vocabulary, different
    from its audited status, or when its reason text no longer matches the pinned digest.
    """
    refusals: list[str] = []
    for field in sorted(audit):
        if field not in _FIELD_DISPOSITIONS:
            refusals.append("DISPOSITION_MISSING:" + field)
            continue
        status, reason = _declared(field)
        if type(status) is not str or status not in _DECLARED_TO_AUDIT:
            refusals.append("DISPOSITION_STATUS_INVALID:" + field)
        elif _DECLARED_TO_AUDIT[status] != audit[field]:
            refusals.append("DISPOSITION_DISAGREES_WITH_AUDIT:" + field)
        if type(reason) is not str or _digest_text(reason) != _DISPOSITION_REASON_SHA256.get(field):
            refusals.append("DISPOSITION_REASON_DRIFT:" + field)
    return refusals


def _disposition_set_refusals(audit: Mapping[str, str]) -> list[str]:
    extra = sorted(set(_FIELD_DISPOSITIONS) ^ set(audit))
    return ["DISPOSITION_SET_MISMATCH:" + ",".join(extra)] if extra else []


def _flat_audit_snapshot() -> dict[str, str]:
    return {field: status for fields in _AUDITED_FIELDS.values() for field, status in fields.items()}


def _live_audit_refusals() -> list[str]:
    """Drift between the frozen field snapshot and the live central audit. Any drift keeps a report off PASS."""
    try:
        live = {obligation: _central_field_audit(obligation) for obligation in _AUDITED_FIELDS}
    except Exception as error:  # an unreadable central audit is UNKNOWN, never a silent snapshot PASS
        return ["CENTRAL_AUDIT_UNAVAILABLE:" + type(error).__name__]
    return [
        "CENTRAL_FIELD_AUDIT_DRIFT:" + obligation
        for obligation in _AUDITED_FIELDS
        if live[obligation] != _AUDITED_FIELDS[obligation]
    ]


def build_report(
    policy: PolicyVersion, ledger: Ledger, effects: Iterable[EffectClaim] = ()
) -> dict[str, Any]:
    """An auxiliary verifier-style report bound to this module's and the decision engine's exact bytes.

    auxiliary_verdict PASS: the chain verifies, no evaluation was unavailable, no supplied effect lacks an
    allowed receipt, the self-declared dispositions match the frozen snapshot, and the live central audit
    matches that snapshot. A REFUSED decision is a correct enforcement result and remains PASS. Effects
    that were not supplied stay UNKNOWN in ``effect_coverage`` whatever the verdict. FAIL: a supplied
    effect bypassed enforcement, the chain is broken, or the self-declaration diverges. UNKNOWN: an
    evaluator was unavailable, or the live central audit drifted from the snapshot.
    This report is never route conformance: route_conformance is always NOT_ESTABLISHED.
    """
    supplied = tuple(effects)
    findings = detect_bypass(ledger, supplied)
    audit = _flat_audit_snapshot()
    refusals = _disposition_refusals(audit) + _disposition_set_refusals(audit)
    chain = verify_chain(ledger)
    if not chain:
        refusals.append("LEDGER_CHAIN_INVALID")
    live_refusals = _live_audit_refusals()
    unavailable = any(item.outcome == UNAVAILABLE for item in ledger.receipts)
    verdict = FAIL if findings or refusals else (UNKNOWN if unavailable or live_refusals else PASS)
    return {
        "schema": REPORT_SCHEMA,
        "adapter": ADAPTER,
        "semantic_version": SEMANTIC_VERSION,
        "claim": CLAIM,
        "boundary": BOUNDARY,
        "source_binding": {
            "enforcement_module_sha256": _file_digest(Path(__file__)),
            "policy_module_sha256": _file_digest(Path(policy_source_module.__file__)),
        },
        "policy": {
            "policy_id": policy.policy_id,
            "revision": policy.revision,
            "digest": policy.digest,
        },
        "chain_verified": chain,
        "ledger_digest": ledger.digest,
        "receipts": [item.to_dict() for item in ledger.receipts],
        "bypass_findings": [dataclasses.asdict(item) for item in findings],
        "effect_coverage": {
            "supplied_effects": len(supplied),
            "unsupplied_effects": UNKNOWN,
            "statement": "Bypass findings cover only the supplied effects; any other executed effect is UNKNOWN.",
        },
        "live_audit_refusals": live_refusals,
        "field_dispositions": {
            name: {
                "auxiliary_status": _declared(name)[0],
                "exact_limit": _declared(name)[1],
                "central_audit_snapshot_status": audit.get(name),
            }
            for name in sorted(set(_FIELD_DISPOSITIONS) | set(audit))
        },
        "declaration_refusals": refusals,
        "auxiliary_verdict": verdict,
        "route_conformance": NOT_ESTABLISHED,
    }


def report_bytes(report: Mapping[str, Any]) -> bytes:
    return canonical_bytes(report)


def replay_matches(
    data: bytes,
    policy: PolicyVersion,
    requests: Iterable[EnforcementRequest],
    trust_roots: Mapping[str, bytes],
    effects: Iterable[EffectClaim] = (),
) -> bool:
    """True only when re-running the same inputs reproduces ``data`` byte-for-byte."""
    ledger = run_sequence(policy, requests, trust_roots)
    return report_bytes(build_report(policy, ledger, effects)) == data


# --- Auxiliary route checks over the existing POLICY 0.x coordinates ------------------------
# Everything in this section is local field evidence. Its PASS is never route conformance, and it
# never executes the central catalog checking mechanism.

AUXILIARY_ADAPTER = "verifier-policy-enforcement-auxiliary-1"
AUXILIARY_REPORT_SCHEMA = "verifier-policy-enforcement-auxiliary-report-1"
PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
VERDICTS = (PASS, FAIL, UNKNOWN)

# The exact POLICY coordinates already present in the central package catalog. Tier t selects
# the POLICY-0.t declaration obligation whose fields these checks adjudicate. No coordinate is
# invented here, and central_route_rows() refuses any drift in this set.
ROUTE_COORDINATES = (
    "POLICY-1.1", "POLICY-1.2", "POLICY-1.3",
    "POLICY-2.1", "POLICY-2.2", "POLICY-2.3",
    "POLICY-3.1", "POLICY-3.2", "POLICY-3.3",
)
SOURCE_ROUTE_COORDINATES = ("POLICY-1.90", "POLICY-2.90", "POLICY-3.90")
# Hash the complete semantic binding rather than trusting coordinate presence. In particular,
# the retained .3 routes are a separate checking mechanism from the provenance .1/.2 routes,
# while .90 rows remain source-boundary routes and are never auxiliary execution targets.
_ROUTE_BINDING_FIELDS = (
    "coordinate", "tier", "object_kind", "obligation_id", "reason", "exact_claim",
    "proposition_digest", "checking_mechanism", "adapter",
)
_ROUTE_BINDING_DIGESTS = {
    "POLICY-1.1": "sha256:9b9cdcdd8bf42fda16564e9db764b5e2c6a861a827dacecd2ed85ba607beee53",
    "POLICY-1.2": "sha256:52b4c590d0b5305281f6faa666407efad5670e816859bc5d7cbc895892c1fd98",
    "POLICY-1.3": "sha256:3c658ab43dbe9f256603537e95ee320ef126ff372b51ce684ea819cd56f99a02",
    "POLICY-2.1": "sha256:2eb9b7f4cf26f564081246b1a4c15cd6bf60de1698bbd764322a55a56398f952",
    "POLICY-2.2": "sha256:ae47792f9767ad3985eab3283d2a4a90a77ec968efe82fe80e898e470173a963",
    "POLICY-2.3": "sha256:dd2a296a58cf8eaa9e83eedf970e345fe58f589d4fc55174973fc64c0cb367a2",
    "POLICY-3.1": "sha256:ea58ad52617c4f5f8f305a95efa62a4bf60555065f83859c2796010e1d084355",
    "POLICY-3.2": "sha256:67037b2cca306d19f01b1cee97936f11abeb5768ccf11f2983b53bcc175e6fe2",
    "POLICY-3.3": "sha256:859967ec8745367c78b0ed7a54a49b557b18af25802049202507fba91b206d53",
}
_SOURCE_ROUTE_BINDING_DIGESTS = {
    "POLICY-1.90": "sha256:27be0f828eccfdeb135c33981a4c7f8cab32570fa439b18edb9e21ab0f68efad",
    "POLICY-2.90": "sha256:6957339caed822638d61b473d40caeb1527fbe0ae08debed04662a9cfbf237e2",
    "POLICY-3.90": "sha256:36b79403d20070837edf39d08327c29c61baee8c39bf8b1204d4d81992920d13",
}
_DECLARATION_BY_TIER = {
    1: "POLICY-0.1-rules-and-precedence",
    2: "POLICY-0.2-authority-and-exceptions",
    3: "POLICY-0.3-enforcement-and-decisions",
}
# Snapshot of the central field audit (package_contract_profiles._DECLARATION_FIELD_STATUS_GROUPS).
# central_route_rows() re-reads the live audit and refuses any difference from this snapshot.
# The module's own _FIELD_DISPOSITIONS never close a field: they are checked against this snapshot.
_AUDITED_FIELDS = {
    "POLICY-0.1-rules-and-precedence": {
        "scope": "PARTIAL", "decision_inputs": "PARTIAL", "defaults": "PARTIAL", "precedence": "PARTIAL",
    },
    "POLICY-0.2-authority-and-exceptions": {
        "exceptions": "PARTIAL", "authority": "BOUNDARY_EXCLUDED", "activation": "BOUNDARY_EXCLUDED",
        "revisions": "PARTIAL",
    },
    "POLICY-0.3-enforcement-and-decisions": {
        "decision_evidence": "PARTIAL", "enforcement_points": "BOUNDARY_EXCLUDED",
        "bypass_handling": "PARTIAL", "unavailable_behavior": "PARTIAL",
    },
}
_DECLARED_TO_AUDIT = {"MECHANIZED": "MECHANIZED", "PARTIAL": "PARTIAL", "MISSING": "MISSING",
                      "BOUNDARY": "BOUNDARY_EXCLUDED"}
# Exclusions the central catalog records for every POLICY obligation.
_CATALOG_EXCLUSIONS = ("legal authority", "complete downstream enforcement", "external policy adoption")
# Boundaries that stay UNKNOWN in every auxiliary report, whatever the local checks return.
EXTERNAL_BOUNDARIES = (
    "legal authority",
    "complete downstream enforcement",
    "external policy adoption",
    "key custody",
    "signer identity",
    "truth of facts behind decision evidence",
)
AUXILIARY_EXCLUSIONS = _CATALOG_EXCLUSIONS + (
    "route conformance: an auxiliary PASS is local field evidence only",
    "execution of the catalog checking mechanism verifier.runtime.provenance_policy_execution.evaluate",
    "closure of POLICY 0.x fields (every field remains PARTIAL or BOUNDARY_EXCLUDED)",
    "key custody and signer identity (fixture trust roots are public constants)",
    "external enforcement and downstream execution routing",
    "the truth of facts behind decision evidence",
)
AUXILIARY_BOUNDARY = (
    "Fresh in-process execution of this module's enforcement field checks over fixed fixture policies, "
    "trust roots and logical time, bound to current bytes of this module and of data/policy.py. "
    "Auxiliary only: a PASS neither executes the central catalog checking mechanism, nor is route "
    "conformance, nor closes the obligation. Catalog presence is never conformance."
)

_ROUTE_TRUST = {"authority:decider": b"d" * 32, "authority:exceptor": b"e" * 32, "authority:clerk": b"c" * 32}
_ROUTE_TARGET = "artifact:route-target"
_ROUTE_OTHER_TARGET = "artifact:route-other"
_ROUTE_NOW = 100
_ROUTE_SCOPE = ("publish", "transfer", "release")
_ROUTE_RULES = (
    Rule("ALLOW-PUBLISH", 1, ALLOW, ("publish",), ("POLICY", "MODEL")),
    Rule("ALLOW-TRANSFER", 1, ALLOW, ("transfer",), ("POLICY",)),
)


@dataclass(frozen=True)
class AuxiliaryObservation:
    """A caller's claim about one auxiliary check. Only fresh execution can make its verdict PASS."""

    coordinate: str
    catalog_proposition_digest: str
    adapter_proposition_digest: str
    enforcement_module_sha256: str
    policy_module_sha256: str
    auxiliary_verdict: str
    ledger: Ledger


@dataclass(frozen=True)
class _RouteRun:
    auxiliary_verdict: str
    reason: str
    report: dict[str, Any]
    ledger: Ledger
    adapter_proposition_digest: str
    source_binding: dict[str, str]


def _source_binding() -> dict[str, str]:
    enforcement = Path(__file__)
    decision_policy = Path(policy_source_module.__file__)
    return {
        "enforcement_module_sha256": _file_digest(enforcement),
        "policy_module_sha256": _file_digest(decision_policy),
    }


def _repository_state(path: Path) -> str:
    """Git status of one bound file, reported beside its bytes. It never blesses the file.

    Read-only: --no-optional-locks keeps git from refreshing the index. Any failure is UNKNOWN.
    """
    try:
        completed = subprocess.run(
            ["git", "--no-optional-locks", "status", "--porcelain", "--", path.name],
            cwd=path.parent, capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"
    if completed.returncode != 0:
        return "UNKNOWN"
    return "DIRTY_NOT_BLESSED" if completed.stdout.strip() else "CLEAN_NOT_BLESSED"


def _central_field_audit(obligation: str) -> dict[str, str]:
    """The live central field statuses of one POLICY obligation, read from the central audit."""
    from verifier.runtime.package_contract_profiles import _DECLARATION_FIELD_STATUS_GROUPS, _FIELD_STATUS_NAMES

    groups = _DECLARATION_FIELD_STATUS_GROUPS[obligation]
    return {field: _FIELD_STATUS_NAMES[code] for code, names in groups.items() for field in names}


def _route_policy(rules=_ROUTE_RULES, *, revision=1, decision_policy_id=None, active_from=0, active_until=None):
    return PolicyVersion(
        policy_id="policy:route-fixture", revision=revision, scope=_ROUTE_SCOPE, rules=tuple(rules),
        enforcement_points=("EXECUTION", "RELEASE"), active_from=active_from, active_until=active_until,
        decision_policy_id=decision_policy_id, max_exception_lifetime=50,
    )


def _route_grant(policy, authority="authority:decider", *, key=None, may_decide=True, may_except=False,
                 actions=_ROUTE_SCOPE):
    return issue_authorization(
        _ROUTE_TRUST[authority] if key is None else key, policy, authority,
        may_decide=may_decide, may_except=may_except, actions=actions,
    )


_ROUTE_DEFAULT = object()


def _route_pointer(policy, authority="authority:decider"):
    """The current-revision declaration of ``policy`` as its decider signs it."""
    return issue_current_revision(
        _ROUTE_TRUST[authority], policy_id=policy.policy_id, revision=policy.revision,
        policy_digest=policy.digest, authority_id=authority,
    )


def _route_request(policy, tag, *, action="publish", roles=("POLICY",), point="RELEASE", target=_ROUTE_TARGET,
                   now=_ROUTE_NOW, grants=None, exceptions=(), evidence=None, revision=None, current=_ROUTE_DEFAULT):
    return EnforcementRequest(
        request_id=tag, policy_id=policy.policy_id, revision=policy.revision if revision is None else revision,
        point=point, action=action, target=target, roles=roles, now=now,
        authorizations=(_route_grant(policy),) if grants is None else grants,
        exceptions=exceptions, decision_evidence=evidence,
        current_revision=_route_pointer(policy) if current is _ROUTE_DEFAULT else current,
    )


def _financial(rules, tag, **overrides):
    policy = _route_policy(rules)
    return policy, _route_request(policy, tag, action="transfer", roles=("FINANCIAL",), **overrides)


def _windowed(tag, **window):
    policy = _route_policy(**window)
    return policy, _route_request(policy, tag)


def _fin_rules(allow_priority, deny_priority):
    return (
        Rule("ALLOW-FIN", allow_priority, ALLOW, ("transfer",), ("FINANCIAL",)),
        Rule("DENY-FIN", deny_priority, DENY, ("transfer",), ("FINANCIAL",)),
    )


def _evidence_policy(decision_policy_id):
    return _route_policy(
        (Rule("ALLOW-RELEASE", 1, ALLOW, ("release",), ("POLICY",), True),),
        decision_policy_id=decision_policy_id,
    )


def _route_evidence(revoked: bool) -> Any:
    """Real decision evidence from the installed decision engine over a fixed two-artifact lineage."""
    from verifier.data.models import (
        ArtifactNode, ArtifactStatus, ArtifactType, HyperedgePort, ProvenanceHypergraph, RightsSpec,
        TransformationHyperedge, TransformationType,
    )
    from verifier.data.policy import ProvenancePolicyVerifier

    ancestor = "artifact:route-ancestor"
    graph = ProvenanceHypergraph()
    graph.add_rights(RightsSpec("rights:route-ancestor", "MIT"))
    graph.add_rights(RightsSpec("rights:route-target", "MIT"))
    graph.add_artifact(ArtifactNode(
        artifact_id=ancestor, label=ancestor, artifact_type=ArtifactType.RAW_SOURCE_FILE,
        content_digest="0" * 64, status=ArtifactStatus.REVOKED if revoked else ArtifactStatus.VALID,
        rights_id="rights:route-ancestor",
    ))
    graph.add_artifact(ArtifactNode(
        artifact_id=_ROUTE_TARGET, label=_ROUTE_TARGET, artifact_type=ArtifactType.RAW_SOURCE_FILE,
        content_digest="1" * 64, status=ArtifactStatus.VALID, rights_id="rights:route-target",
    ))
    graph.add_transformation(TransformationHyperedge(
        transformation_id="transform:route-derive", label="derive target from ancestor",
        transformation_type=TransformationType.EVALUATION, inputs=(HyperedgePort(ancestor, "INPUT"),),
        outputs=(HyperedgePort(_ROUTE_TARGET, "OUTPUT"),), software_provenance={}, parameters={},
        execution_environment={},
    ))
    return ProvenancePolicyVerifier.verify_no_revoked_ancestors(graph, _ROUTE_TARGET).decision_evidence()


def _flip_last_hex(text: str) -> str:
    return text[:-1] + ("0" if text[-1] != "0" else "1")


def _observe_receipt(receipt: Receipt, *tokens: str) -> str:
    """Outcome followed by each token that appears among the receipt's reasons or window dispositions."""
    seen = set(receipt.reasons) | {window for _, window in receipt.exception_dispositions}
    return "|".join([receipt.outcome, *(token if token in seen else "-" for token in tokens)])


def _case(field, name, outcome, tokens, make, trust=_ROUTE_TRUST):
    """One fresh field check. ``make(tag)`` builds the policy and request; the expectation is fixed here."""
    expected = "|".join([outcome, *tokens])

    def run(ledger: Ledger, tag: str) -> tuple[Ledger, str]:
        policy, request = make(tag)
        ledger, receipt = enforce(ledger, policy, request, trust)
        return ledger, _observe_receipt(receipt, *tokens)

    return (field, name, expected, run)


def _digest_case(ledger: Ledger, tag: str) -> tuple[Ledger, str]:
    policy = _route_policy()
    first = _route_request(policy, tag + ":first")
    second = _route_request(policy, tag + ":second", target=_ROUTE_OTHER_TARGET)
    ledger, first_receipt = enforce(ledger, policy, first, _ROUTE_TRUST)
    ledger, second_receipt = enforce(ledger, policy, second, _ROUTE_TRUST)
    bound = (
        first_receipt.request_digest == value_digest(first.to_dict())
        and second_receipt.request_digest == value_digest(second.to_dict())
        and first_receipt.request_digest != second_receipt.request_digest
    )
    return ledger, "DIGEST_BOUND" if bound else "DIGEST_UNBOUND"


def _bypass_case(ledger: Ledger, tag: str) -> tuple[Ledger, str]:
    policy = _route_policy()
    ledger, _ = enforce(ledger, policy, _route_request(policy, tag + ":allowed"), _ROUTE_TRUST)
    ledger, _ = enforce(
        ledger, policy, _route_request(policy, tag + ":refused", action="destroy"), _ROUTE_TRUST
    )
    claims = (
        EffectClaim(tag + ":allowed", "RELEASE", "publish", _ROUTE_TARGET),
        EffectClaim(tag + ":allowed", "RELEASE", "publish", _ROUTE_OTHER_TARGET),
        EffectClaim(tag + ":ghost", "RELEASE", "publish", _ROUTE_TARGET),
        EffectClaim(tag + ":refused", "RELEASE", "destroy", _ROUTE_TARGET),
    )
    return ledger, "|".join(finding.reason for finding in detect_bypass(ledger, claims))


def _tier_one_cases():
    """POLICY-0.1: scope, decision inputs, defaults and precedence."""
    base = _route_policy()
    return (
        _case("scope", "action_outside_scope_refused", REFUSED, ("OUT_OF_SCOPE",),
              lambda tag: (base, _route_request(base, tag, action="destroy"))),
        ("decision_inputs", "receipt_digest_binds_request", "DIGEST_BOUND", _digest_case),
        _case("defaults", "role_without_rule_refused", REFUSED, ("NO_MATCHING_RULE",),
              lambda tag: (base, _route_request(base, tag, action="transfer", roles=("FINANCIAL",)))),
        _case("precedence", "higher_priority_deny_wins", REFUSED, ("DENIED_BY_RULE:DENY-FIN",),
              lambda tag: _financial(_fin_rules(1, 10), tag)),
        _case("precedence", "higher_priority_allow_wins", ALLOWED, ("ALL_ROLES_ALLOWED",),
              lambda tag: _financial(_fin_rules(10, 1), tag)),
        _case("precedence", "equal_priority_conflict_refused", REFUSED, ("PRECEDENCE_CONFLICT",),
              lambda tag: _financial(_fin_rules(5, 5), tag)),
    )


def _tier_two_cases():
    """POLICY-0.2: exceptions, authority, activation and revisions."""
    base = _route_policy()
    fin = _route_policy(_fin_rules(1, 10))
    waiver = issue_exception(
        _ROUTE_TRUST["authority:exceptor"], fin, exception_id="exc-route", rule_id="DENY-FIN",
        action="transfer", target=_ROUTE_TARGET, granted_by="authority:exceptor", not_before=60, expires_at=110,
    )
    exceptor = _route_grant(fin, "authority:exceptor", may_decide=False, may_except=True, actions=("transfer",))
    decider = _route_grant(fin)
    bound_grant = _route_grant(base)
    stranger = _route_grant(base, "authority:stranger", key=b"s" * 32)
    clerk = _route_grant(base, "authority:clerk", may_decide=False)
    prior_policy = _route_policy(revision=1)
    current_policy = _route_policy(revision=2)
    return (
        _case("exceptions", "no_waiver_leaves_deny_in_force", REFUSED, ("DENIED_BY_RULE:DENY-FIN",),
              lambda tag: _financial(_fin_rules(1, 10), tag)),
        _case("exceptions", "in_window_waiver_applied", ALLOWED, ("ALL_ROLES_ALLOWED", "APPLIED"),
              lambda tag: _financial(_fin_rules(1, 10), tag, grants=(decider, exceptor), exceptions=(waiver,))),
        _case("exceptions", "expired_waiver_not_applied", REFUSED, ("DENIED_BY_RULE:DENY-FIN", "EXPIRED"),
              lambda tag: _financial(_fin_rules(1, 10), tag, now=200, grants=(decider, exceptor),
                                     exceptions=(waiver,))),
        _case("authority", "decider_grant_positive_control", ALLOWED, ("ALL_ROLES_ALLOWED",),
              lambda tag: (base, _route_request(base, tag, grants=(bound_grant,)))),
        _case("authority", "bit_flipped_grant_unverified", REFUSED, ("UNVERIFIED_AUTHORITY", "NO_DECISION_AUTHORITY"),
              lambda tag: (base, _route_request(base, tag, grants=(
                  dataclasses.replace(bound_grant, mac=_flip_last_hex(bound_grant.mac)),)))),
        _case("authority", "unknown_authority_unverified", REFUSED, ("UNVERIFIED_AUTHORITY", "NO_DECISION_AUTHORITY"),
              lambda tag: (base, _route_request(base, tag, grants=(stranger,)))),
        _case("authority", "validly_signed_clerk_not_decider", REFUSED,
              ("NOT_DECISION_AUTHORITY", "NO_DECISION_AUTHORITY"),
              lambda tag: (base, _route_request(base, tag, grants=(clerk,)))),
        _case("activation", "before_active_window_refused", REFUSED, ("POLICY_INACTIVE",),
              lambda tag: _windowed(tag, active_from=200)),
        _case("activation", "after_active_window_refused", REFUSED, ("POLICY_INACTIVE",),
              lambda tag: _windowed(tag, active_until=50)),
        _case("activation", "inside_active_window_allowed", ALLOWED, ("ALL_ROLES_ALLOWED",),
              lambda tag: _windowed(tag, active_until=200)),
        _case("revisions", "stale_request_revision_refused", REFUSED, ("STALE_REVISION",),
              lambda tag: (base, _route_request(base, tag, revision=2))),
        _case("revisions", "grant_for_prior_revision_refused", REFUSED,
              ("AUTHORIZATION_REVISION_MISMATCH", "NO_DECISION_AUTHORITY"),
              lambda tag: (current_policy, _route_request(current_policy, tag, grants=(_route_grant(prior_policy),)))),
        _case("revisions", "current_revision_grant_allowed", ALLOWED, ("ALL_ROLES_ALLOWED",),
              lambda tag: (current_policy, _route_request(current_policy, tag))),
    )


def _tier_three_cases():
    """POLICY-0.3: decision evidence, enforcement points, bypass handling and unavailable behavior."""
    base = _route_policy()
    passing = _route_evidence(revoked=False)
    failing = _route_evidence(revoked=True)
    passing_policy = _evidence_policy(passing.policy_id)
    failing_policy = _evidence_policy(failing.policy_id)
    return (
        _case("decision_evidence", "real_passing_evidence_authorizes", ALLOWED, ("ALL_ROLES_ALLOWED",),
              lambda tag: (passing_policy, _route_request(passing_policy, tag, action="release", evidence=passing))),
        _case("decision_evidence", "missing_evidence_refused", REFUSED, ("EVIDENCE_MISSING",),
              lambda tag: (passing_policy, _route_request(passing_policy, tag, action="release"))),
        _case("decision_evidence", "evidence_for_other_target_refused", REFUSED, ("EVIDENCE_MISMATCH:TARGET",),
              lambda tag: (passing_policy, _route_request(passing_policy, tag, action="release",
                                                          target=_ROUTE_OTHER_TARGET, evidence=passing))),
        _case("decision_evidence", "failing_evidence_refused", REFUSED, ("EVIDENCE_REJECTED:NOT_PASSED",),
              lambda tag: (failing_policy, _route_request(failing_policy, tag, action="release", evidence=failing))),
        _case("enforcement_points", "undeclared_point_refused", REFUSED, ("POINT_NOT_DECLARED",),
              lambda tag: (base, _route_request(base, tag, point="ADMISSION"))),
        _case("enforcement_points", "declared_point_allowed", ALLOWED, ("ALL_ROLES_ALLOWED",),
              lambda tag: (base, _route_request(base, tag, point="EXECUTION"))),
        ("bypass_handling", "unbacked_or_mismatched_effects_reported", "MISMATCHED_RECEIPT|NO_ENFORCEMENT_RECEIPT|"
         "ENFORCEMENT_NOT_ALLOWED", _bypass_case),
        _case("unavailable_behavior", "unavailable_trust_root_never_allowed", UNAVAILABLE,
              ("EVALUATOR_UNAVAILABLE:TypeError",),
              lambda tag: (base, _route_request(base, tag)), trust={"authority:decider": "not-bytes"}),
    )


_CASES_BY_OBLIGATION = {
    _DECLARATION_BY_TIER[1]: _tier_one_cases,
    _DECLARATION_BY_TIER[2]: _tier_two_cases,
    _DECLARATION_BY_TIER[3]: _tier_three_cases,
}


def central_route_rows() -> tuple[dict[str, Any], ...]:
    """The existing POLICY route rows, copied from the central package catalog.

    Rows are NOT_EXECUTED: presence in the central catalog is never conformance, and this function runs
    no checking mechanism. Raises PolicyDefinitionError when the central route set, any route row, or
    the live central field audit differs from what this module adjudicates.
    """
    from verifier.runtime.added_kind_behavioral_routes import policy_catalog
    from verifier.runtime.manifest_gate import obligation_catalog

    try:
        central = obligation_catalog()
        retained = {row["coordinate"]: row for row in policy_catalog()}
        live_audits = {obligation: _central_field_audit(obligation) for obligation in _AUDITED_FIELDS}
    except Exception as error:  # an unreadable central source is UNKNOWN for every route, never a crash
        raise PolicyDefinitionError("CENTRAL_CATALOG_UNAVAILABLE:" + type(error).__name__) from error
    for obligation, live in live_audits.items():
        if live != _AUDITED_FIELDS[obligation]:
            raise PolicyDefinitionError("CENTRAL_FIELD_AUDIT_DRIFT:" + obligation)
    rows = [row for row in central if row.get("coordinate") in ROUTE_COORDINATES]
    if sorted(row["coordinate"] for row in rows) != sorted(ROUTE_COORDINATES):
        raise PolicyDefinitionError("the central catalog does not carry the exact POLICY route set")
    source_rows = [row for row in central if row.get("coordinate") in SOURCE_ROUTE_COORDINATES]
    if sorted(row["coordinate"] for row in source_rows) != sorted(SOURCE_ROUTE_COORDINATES):
        raise PolicyDefinitionError("the central catalog does not carry the exact POLICY source-boundary route set")
    for row in (*rows, *source_rows):
        coordinate = row["coordinate"]
        expected = (_ROUTE_BINDING_DIGESTS.get(coordinate)
                    or _SOURCE_ROUTE_BINDING_DIGESTS.get(coordinate))
        binding = value_digest({field: row.get(field) for field in _ROUTE_BINDING_FIELDS})
        if binding != expected:
            raise PolicyDefinitionError("POLICY route binding drift: " + coordinate)
    retained_coordinates = {coordinate for coordinate in ROUTE_COORDINATES if coordinate.endswith(".3")}
    if set(retained) != retained_coordinates:
        raise PolicyDefinitionError("retained POLICY route set drift")
    for row in rows:
        coordinate = row["coordinate"]
        if coordinate in retained_coordinates and row != retained[coordinate]:
            raise PolicyDefinitionError("POLICY route binding drift: " + coordinate)
    entries = []
    for row in sorted(rows, key=lambda item: ROUTE_COORDINATES.index(item["coordinate"])):
        coordinate = row["coordinate"]
        tier = int(coordinate.split("-", 1)[1].split(".", 1)[0])
        if row.get("object_kind") != "POLICY" or row.get("tier") != tier:
            raise PolicyDefinitionError("POLICY route row does not match its coordinate tier: " + coordinate)
        entries.append({
            "coordinate": coordinate,
            "tier": tier,
            "obligation_id": _DECLARATION_BY_TIER[tier],
            "route_obligation_id": _text(row.get("obligation_id"), "route obligation_id"),
            "catalog_proposition_digest": _text(row.get("proposition_digest"), "proposition_digest"),
            "catalog_checking_mechanism": _text(row.get("checking_mechanism"), "checking_mechanism"),
            "catalog_adapter": _text(row.get("adapter"), "adapter"),
            "adapter": AUXILIARY_ADAPTER,
            "execution_status": "NOT_EXECUTED",
            "route_conformance": NOT_ESTABLISHED,
        })
    return tuple(entries)


def _execute(entry: Mapping[str, Any]) -> _RouteRun:
    """Run every field check for one route afresh.

    A divergent self-declaration is FAIL. A raised check is UNKNOWN. Neither path can yield PASS.
    """
    coordinate = entry["coordinate"]
    obligation = entry["obligation_id"]
    audit = _AUDITED_FIELDS[obligation]
    cases = _CASES_BY_OBLIGATION[obligation]()
    source = _source_binding()
    adapter_digest = value_digest({
        "coordinate": coordinate,
        "obligation_id": obligation,
        "cases": [[field, name, expected] for field, name, expected, _ in cases],
    })
    declaration_refusals = _disposition_refusals(audit)
    ledger = empty_ledger()
    checks: list[dict[str, Any]] = []
    raised: list[str] = []
    for field, name, expected, run in cases:
        try:
            ledger, observed = run(ledger, f"{coordinate}:{field}:{name}")
        except Exception as error:  # an evaluator fault leaves the route UNKNOWN, never PASS
            observed = f"RAISED:{type(error).__name__}"
            raised.append(name)
        checks.append({
            "field": field, "case": name, "expected": expected, "observed": observed,
            "passed": observed == expected,
        })
    chain = verify_chain(ledger)
    failed = [item["case"] for item in checks if not item["passed"]]
    if declaration_refusals:
        verdict, reason = FAIL, "DECLARATION_DIVERGED:" + ",".join(declaration_refusals)
    elif raised:
        verdict, reason = UNKNOWN, "FIELD_CHECKS_RAISED:" + ",".join(raised)
    elif failed or not chain:
        verdict = FAIL
        reason = "FIELD_CHECKS_DIVERGED:" + ",".join(failed) if failed else "LEDGER_CHAIN_INVALID"
    else:
        verdict = PASS
        reason = f"auxiliary: {len(checks)} fresh field checks matched; not route conformance; obligation not closed"
    fields = []
    for field, audited in audit.items():
        declared = _declared(field)[0]
        fields.append({
            "field": field,
            "audited_status": audited,
            "module_declared_status": declared,
            "agrees_with_audit": (type(declared) is str and _DECLARED_TO_AUDIT.get(declared) == audited),
            "checks": sum(item["field"] == field for item in checks),
        })
    report = {
        "schema": AUXILIARY_REPORT_SCHEMA,
        "adapter": AUXILIARY_ADAPTER,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate,
        "tier": entry["tier"],
        "obligation_id": obligation,
        "catalog_proposition_digest": entry["catalog_proposition_digest"],
        "adapter_proposition_digest": adapter_digest,
        "catalog_checking_mechanism": entry["catalog_checking_mechanism"],
        "catalog_checking_mechanism_executed": False,
        "source_binding": source,
        "policy_module_repository_state": _repository_state(Path(policy_source_module.__file__)),
        "source_blessing": NOT_ESTABLISHED,
        "fields": fields,
        "declaration_refusals": declaration_refusals,
        "checks": checks,
        "ledger_digest": ledger.digest,
        "chain_verified": chain,
        "auxiliary_verdict": verdict,
        "reason": reason,
        "route_conformance": NOT_ESTABLISHED,
        "obligation_closure": NOT_ESTABLISHED,
        "unclosed_fields": [row["field"] + "=" + row["audited_status"] for row in fields
                            if row["audited_status"] != "MECHANIZED"],
        "external_boundaries": {name: UNKNOWN for name in EXTERNAL_BOUNDARIES},
        "not_established": list(AUXILIARY_EXCLUSIONS),
        "boundary": AUXILIARY_BOUNDARY,
    }
    return _RouteRun(verdict, reason, report, ledger, adapter_digest, source)


def _unknown_report(coordinate: Any, reason: str) -> dict[str, Any]:
    return {
        "schema": AUXILIARY_REPORT_SCHEMA,
        "adapter": AUXILIARY_ADAPTER,
        "coordinate": coordinate,
        "auxiliary_verdict": UNKNOWN,
        "reason": reason,
        "route_conformance": NOT_ESTABLISHED,
        "boundary": AUXILIARY_BOUNDARY,
    }


def _route_entry(coordinate: Any) -> dict[str, Any]:
    if coordinate not in ROUTE_COORDINATES:
        raise PolicyDefinitionError("UNKNOWN_ROUTE:" + repr(coordinate))
    entries = [entry for entry in central_route_rows() if entry["coordinate"] == coordinate]
    if len(entries) != 1:
        raise PolicyDefinitionError("ROUTE_CATALOG_ENTRY_NOT_UNIQUE:" + coordinate)
    return entries[0]


def auxiliary_evaluate(coordinate: str) -> dict[str, Any]:
    """Fresh auxiliary execution of one POLICY route. Its PASS is never route conformance."""
    try:
        entry = _route_entry(coordinate)
    except PolicyDefinitionError as error:
        return _unknown_report(coordinate, str(error))
    return _execute(entry).report


def auxiliary_evaluate_all() -> dict[str, Any]:
    """Fresh auxiliary execution of every POLICY route; PASS only when all nine pass afresh.

    The aggregate is still auxiliary: it never states route conformance or obligation closure.
    """
    try:
        entries = {entry["coordinate"]: entry for entry in central_route_rows()}
    except PolicyDefinitionError as error:
        return {"schema": AUXILIARY_REPORT_SCHEMA, "adapter": AUXILIARY_ADAPTER, "auxiliary_verdict": UNKNOWN,
                "reason": str(error), "routes": [], "route_conformance": NOT_ESTABLISHED,
                "obligation_closure": NOT_ESTABLISHED, "boundary": AUXILIARY_BOUNDARY}
    reports = [_execute(entries[coordinate]).report for coordinate in ROUTE_COORDINATES]
    verdicts = [report["auxiliary_verdict"] for report in reports]
    verdict = FAIL if FAIL in verdicts else (UNKNOWN if UNKNOWN in verdicts else PASS)
    return {
        "schema": AUXILIARY_REPORT_SCHEMA,
        "adapter": AUXILIARY_ADAPTER,
        "auxiliary_verdict": verdict,
        "routes": reports,
        "route_conformance": NOT_ESTABLISHED,
        "obligation_closure": NOT_ESTABLISHED,
        "boundary": AUXILIARY_BOUNDARY,
    }


def _observation(entry: Mapping[str, Any], run: _RouteRun) -> AuxiliaryObservation:
    return AuxiliaryObservation(
        coordinate=entry["coordinate"],
        catalog_proposition_digest=entry["catalog_proposition_digest"],
        adapter_proposition_digest=run.adapter_proposition_digest,
        enforcement_module_sha256=run.source_binding["enforcement_module_sha256"],
        policy_module_sha256=run.source_binding["policy_module_sha256"],
        auxiliary_verdict=run.auxiliary_verdict,
        ledger=run.ledger,
    )


def auxiliary_observe(coordinate: str) -> AuxiliaryObservation:
    """An auxiliary observation: the verdict and ledger of a fresh execution of one route."""
    entry = _route_entry(coordinate)
    return _observation(entry, _execute(entry))


def auxiliary_observe_all() -> tuple[AuxiliaryObservation, ...]:
    """Auxiliary observations of every route, from one catalog read and one fresh execution each."""
    entries = {entry["coordinate"]: entry for entry in central_route_rows()}
    return tuple(_observation(entries[coordinate], _execute(entries[coordinate]))
                 for coordinate in ROUTE_COORDINATES)


def _compare_observation(observation: AuxiliaryObservation, entry: Mapping[str, Any], run: _RouteRun) -> list[str]:
    coordinate = entry["coordinate"]
    refusals: list[str] = []
    if type(observation.ledger) is not Ledger:
        return ["LEDGER_TYPE_INVALID:" + coordinate]
    if observation.auxiliary_verdict not in VERDICTS:
        refusals.append("UNRECOGNIZED_STATUS:" + coordinate)
    if observation.catalog_proposition_digest != entry["catalog_proposition_digest"]:
        refusals.append("PROPOSITION_DIGEST_MISMATCH:" + coordinate)
    if observation.adapter_proposition_digest != run.adapter_proposition_digest:
        refusals.append("ADAPTER_PROPOSITION_MISMATCH:" + coordinate)
    source = run.source_binding
    if (observation.enforcement_module_sha256, observation.policy_module_sha256) != (
        source["enforcement_module_sha256"], source["policy_module_sha256"]
    ):
        refusals.append("SOURCE_DRIFT:" + coordinate)
    if not verify_chain(observation.ledger):
        refusals.append("LEDGER_CHAIN_INVALID:" + coordinate)
    elif observation.ledger != run.ledger:
        refusals.append("LEDGER_NOT_FRESH:" + coordinate)
    if observation.auxiliary_verdict == PASS and run.auxiliary_verdict != PASS:
        refusals.append("FORGED_PASS:" + coordinate)
    elif observation.auxiliary_verdict in VERDICTS and observation.auxiliary_verdict != run.auxiliary_verdict:
        refusals.append("STATUS_MISMATCH:" + coordinate)
    return refusals


def auxiliary_check_observations(observations: Iterable[Any]) -> dict[str, Any]:
    """Reconcile auxiliary observations against fresh execution of every route.

    Refuses missing, duplicate, unknown or aliased routes, unrecognised status words, digests or
    source bytes that differ from current ones, ledgers that fail the chain or differ from fresh
    execution, and any PASS that fresh execution does not reproduce. Overall PASS needs all nine
    routes to pass afresh and exactly one matching observation for each. It is never route conformance.
    """
    try:
        entries = {entry["coordinate"]: entry for entry in central_route_rows()}
    except PolicyDefinitionError as error:
        return {"schema": AUXILIARY_REPORT_SCHEMA, "adapter": AUXILIARY_ADAPTER, "auxiliary_verdict": UNKNOWN,
                "refusals": [str(error)], "route_conformance": NOT_ESTABLISHED,
                "obligation_closure": NOT_ESTABLISHED, "boundary": AUXILIARY_BOUNDARY}
    runs = {coordinate: _execute(entries[coordinate]) for coordinate in ROUTE_COORDINATES}
    grouped: dict[str, list[Any]] = {coordinate: [] for coordinate in ROUTE_COORDINATES}
    refusals: list[str] = []
    for item in observations:
        if type(item) is not AuxiliaryObservation:
            refusals.append("OBSERVATION_TYPE_INVALID")
        elif type(item.coordinate) is not str or item.coordinate not in grouped:
            refusals.append("UNKNOWN_ROUTE:" + repr(item.coordinate))
        else:
            grouped[item.coordinate].append(item)
    for coordinate in ROUTE_COORDINATES:
        matches = grouped[coordinate]
        if not matches:
            refusals.append("MISSING_OBSERVATION:" + coordinate)
        elif len(matches) > 1:
            refusals.append("DUPLICATE_OBSERVATION:" + coordinate)
        else:
            refusals.extend(_compare_observation(matches[0], entries[coordinate], runs[coordinate]))
    fresh = {coordinate: runs[coordinate].auxiliary_verdict for coordinate in ROUTE_COORDINATES}
    if FAIL in fresh.values():
        verdict = FAIL
    elif refusals or UNKNOWN in fresh.values():
        verdict = UNKNOWN
    else:
        verdict = PASS
    return {
        "schema": AUXILIARY_REPORT_SCHEMA,
        "adapter": AUXILIARY_ADAPTER,
        "auxiliary_verdict": verdict,
        "fresh_auxiliary_verdicts": fresh,
        "refusals": refusals,
        "route_conformance": NOT_ESTABLISHED,
        "obligation_closure": NOT_ESTABLISHED,
        "boundary": AUXILIARY_BOUNDARY,
    }
