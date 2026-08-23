#!/usr/bin/env python3
"""Experimental evaluator for the ZIZK-VSTD bounded identity disclosure profile.

Discharges nothing on the VSTD ladder. This module is experimental scaffolding for
the terminology and safety question recorded in ``SEMANTIC_MODEL.md``: it decides
which identity-adjacent properties a bounded disclosure record can support, and it
fails closed everywhere else.

The evaluator never verifies a signature, a revocation list, or a proof. It consumes
*asserted* evidence coordinates and decides what may be concluded from them. Any
cryptographic verification happens outside this module and enters here as evidence.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

MODEL_FILE = Path(__file__).resolve().parent / "model" / "zero_identity_model.json"

SUPPORTED = "SUPPORTED"
ATTESTED = "ATTESTED"
ASSUMED = "ASSUMED"
UNKNOWN = "UNKNOWN"
CONFLICTED = "CONFLICTED"
REFUTED = "REFUTED"
UNSUPPORTED_BY_DESIGN = "UNSUPPORTED_BY_DESIGN"

ACCEPTED_BOUNDED = "ACCEPTED_BOUNDED"
REJECTED = "REJECTED"

VERDICT_PRECEDENCE = (REJECTED, CONFLICTED, UNKNOWN, ACCEPTED_BOUNDED)

REQUIRED_TRUST_ROOT_COORDINATES = (
    "actor.key_binding.trust_root",
    "authorization.issuer",
    "revocation.source",
)


def load_model() -> dict[str, Any]:
    """Return the experimental machine-readable model."""

    return json.loads(MODEL_FILE.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Evaluation:
    """Result of evaluating one bounded disclosure record."""

    verdict: str
    properties: dict[str, str]
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "properties": dict(self.properties),
            "reasons": list(self.reasons),
        }


def _get(record: dict[str, Any], dotted: str) -> Any:
    node: Any = record
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _conflicted(record: dict[str, Any], prop: str) -> bool:
    for entry in record.get("conflicts", []) or []:
        if entry.get("property") == prop:
            return True
    return False


def _evaluate_civil_identity(record: dict[str, Any], reasons: list[str]) -> str:
    if _conflicted(record, "civil_identity"):
        reasons.append("civil_identity: conflicting evidence retained as CONFLICTED")
        return CONFLICTED
    disclosed = _get(record, "actor.civil_identity")
    if disclosed not in (None, "withheld"):
        reasons.append("civil_identity: a disclosed value is outside this profile")
        return CONFLICTED
    reasons.append(
        "civil_identity: withheld by profile; absence is neither anonymity nor unlinkability"
    )
    return UNSUPPORTED_BY_DESIGN


def _evaluate_authentication(record: dict[str, Any], reasons: list[str]) -> str:
    if _conflicted(record, "authentication"):
        reasons.append("authentication: conflicting evidence retained as CONFLICTED")
        return CONFLICTED
    binding = _get(record, "actor.key_binding")
    if not isinstance(binding, dict):
        reasons.append("authentication: no key binding coordinate")
        return UNKNOWN
    if binding.get("key_compromised_during_interval") is True:
        reasons.append("authentication: signing key reported compromised for the interval")
        return REFUTED
    verified = binding.get("signature_verified")
    if verified is False:
        reasons.append("authentication: asserted signature verification failed")
        return REFUTED
    if verified is not True:
        reasons.append("authentication: signature verification result absent")
        return UNKNOWN
    root = binding.get("trust_root")
    if root not in (record.get("trust_roots") or []):
        reasons.append("authentication: key trust root is not among the declared trust roots")
        return UNKNOWN
    return SUPPORTED


def _evaluate_authority_active(record: dict[str, Any], reasons: list[str]) -> str:
    if _conflicted(record, "authority_active"):
        reasons.append("authority_active: conflicting evidence retained as CONFLICTED")
        return CONFLICTED
    grant = record.get("authorization")
    revocation = record.get("revocation")
    if not isinstance(grant, dict):
        reasons.append("authority_active: no authorization grant to evaluate")
        return UNKNOWN
    if not isinstance(revocation, dict) or not revocation.get("source"):
        reasons.append("authority_active: no revocation source; absence is not liveness")
        return UNKNOWN
    state = revocation.get("state")
    if state == "revoked":
        reasons.append("authority_active: authority is revoked")
        return REFUTED
    if state != "active":
        reasons.append("authority_active: revocation state is not asserted active")
        return UNKNOWN
    evaluated_at = record.get("evaluated_at")
    not_before = grant.get("not_before")
    not_after = grant.get("not_after")
    if not (evaluated_at and not_before and not_after):
        reasons.append("authority_active: validity window or evaluation instant absent")
        return UNKNOWN
    if not (not_before <= evaluated_at <= not_after):
        reasons.append("authority_active: evaluation instant is outside the validity window")
        return REFUTED
    if not revocation.get("checked_at"):
        reasons.append("authority_active: revocation check instant absent")
        return UNKNOWN
    return SUPPORTED


def _evaluate_authorization(
    record: dict[str, Any], authentication: str, authority: str, reasons: list[str]
) -> str:
    if _conflicted(record, "authorization"):
        reasons.append("authorization: conflicting evidence retained as CONFLICTED")
        return CONFLICTED
    grant = record.get("authorization")
    if not isinstance(grant, dict) or not grant.get("grant_id"):
        reasons.append("authorization: no grant coordinate; missing authorization stays UNKNOWN")
        return UNKNOWN
    if authority == REFUTED:
        reasons.append("authorization: refuted because the authority is not active")
        return REFUTED
    if authentication == REFUTED:
        reasons.append("authorization: refuted because authentication is refuted")
        return REFUTED
    if authentication != SUPPORTED or authority != SUPPORTED:
        reasons.append("authorization: preconditions are not both SUPPORTED")
        return UNKNOWN
    scope = grant.get("scope") or []
    claim_scope = record.get("claim_scope")
    if not claim_scope:
        reasons.append("authorization: record declares no claim scope to cover")
        return UNKNOWN
    if claim_scope not in scope:
        reasons.append("authorization: grant scope does not cover the claim scope")
        return REFUTED
    return SUPPORTED


def _evaluate_freshness(record: dict[str, Any], reasons: list[str]) -> str:
    freshness = record.get("freshness") or {}
    if not freshness.get("required"):
        reasons.append("freshness: not required by this record; replay is not excluded")
        return UNKNOWN
    nonce = freshness.get("nonce")
    if not nonce or not freshness.get("challenge_source"):
        reasons.append("freshness: required but the challenge coordinate is absent; fails closed")
        return REFUTED
    if nonce in (freshness.get("previously_observed_nonces") or []):
        reasons.append("freshness: challenge value was previously observed; replay detected")
        return REFUTED
    return SUPPORTED


def _evaluate_uniqueness(record: dict[str, Any], reasons: list[str]) -> str:
    if _conflicted(record, "uniqueness"):
        reasons.append("uniqueness: conflicting evidence retained as CONFLICTED")
        return CONFLICTED
    evidence = record.get("uniqueness_evidence") or []
    if not [entry for entry in evidence if entry.get("attested_by")]:
        reasons.append(
            "uniqueness: no attested mechanism; absence does not imply Sybil resistance"
        )
        return UNKNOWN
    return ATTESTED


def _evaluate_independence(record: dict[str, Any], reasons: list[str]) -> str:
    if _conflicted(record, "verifier_independence"):
        reasons.append("verifier_independence: conflicting evidence retained as CONFLICTED")
        return CONFLICTED
    peers = record.get("peer_receipts") or []
    if not peers:
        reasons.append("verifier_independence: no peer receipt to compare; independence UNKNOWN")
        return UNKNOWN
    own = _get(record, "actor.pseudonym")
    for peer in peers:
        if peer.get("pseudonym") == own:
            reasons.append(
                "verifier_independence: peer shares this pseudonymous coordinate; not independent"
            )
            return REFUTED
    evidence = record.get("independence_evidence") or []
    attested = [
        entry
        for entry in evidence
        if entry.get("attested_by") and entry.get("distinct_trust_root")
    ]
    if not attested:
        reasons.append(
            "verifier_independence: distinct pseudonyms are not evidence of distinct actors"
        )
        return UNKNOWN
    return ATTESTED


def _evaluate_unlinkability(record: dict[str, Any], reasons: list[str]) -> str:
    request = record.get("disclosure_minimization") or {}
    if not request:
        reasons.append("unlinkability: not requested")
        return UNKNOWN
    if not request.get("declared_assumptions"):
        reasons.append("unlinkability: requested without declared assumptions")
        return UNKNOWN
    reasons.append(
        "unlinkability: ASSUMED under declared assumptions only; this model cannot observe "
        "the correlation surface available to an adversary"
    )
    return ASSUMED


def _evaluate_accountability(record: dict[str, Any], reasons: list[str]) -> str:
    if not record.get("escalation_authority"):
        reasons.append("accountability: no escalation authority bound to the pseudonym")
        return UNKNOWN
    return ATTESTED


def _evaluate_recovery(record: dict[str, Any], reasons: list[str]) -> str:
    recovery = record.get("recovery") or {}
    if not recovery.get("mechanism"):
        reasons.append("recovery: no credential-loss recovery mechanism declared")
        return UNKNOWN
    return ATTESTED


def _apply_minimization(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the record with every withheld coordinate actually removed.

    Minimization is enforced rather than trusted: a coordinate the actor asked to
    withhold is deleted before evaluation, so a removed trust root really does make
    the dependent property unevaluable instead of quietly remaining available.
    """

    request = record.get("disclosure_minimization") or {}
    withheld = request.get("withheld_coordinates") or []
    if not withheld:
        return record
    reduced = copy.deepcopy(record)
    for dotted in withheld:
        parts = dotted.split(".")
        node: Any = reduced
        for part in parts[:-1]:
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if isinstance(node, dict):
            node.pop(parts[-1], None)
    return reduced


def _check_structural_rejections(record: dict[str, Any], reasons: list[str]) -> list[str]:
    """Return the reasons that make a record unevaluable, that is, REJECTED outright."""

    fatal: list[str] = []
    request = record.get("disclosure_minimization") or {}
    withheld = set(request.get("withheld_coordinates") or [])
    for coordinate in REQUIRED_TRUST_ROOT_COORDINATES:
        if coordinate in withheld:
            fatal.append(
                f"minimization removed required trust-root coordinate {coordinate}; "
                "an unlinkability request does not erase trust roots"
            )
    before = request.get("claim_boundary_before")
    after = request.get("claim_boundary_after")
    if before is not None and after is not None:
        before_set = set(before if isinstance(before, list) else [before])
        after_set = set(after if isinstance(after, list) else [after])
        if not after_set <= before_set:
            fatal.append(
                "minimization widened the claim boundary; minimization may only narrow it"
            )
    reasons.extend(fatal)
    return fatal


def evaluate(record: dict[str, Any]) -> Evaluation:
    """Evaluate one bounded disclosure record, failing closed on missing coordinates."""

    reasons: list[str] = []
    record = _apply_minimization(record)
    fatal = _check_structural_rejections(record, reasons)

    properties: dict[str, str] = {}
    properties["civil_identity"] = _evaluate_civil_identity(record, reasons)
    properties["authentication"] = _evaluate_authentication(record, reasons)
    properties["authority_active"] = _evaluate_authority_active(record, reasons)
    properties["authorization"] = _evaluate_authorization(
        record, properties["authentication"], properties["authority_active"], reasons
    )
    properties["freshness"] = _evaluate_freshness(record, reasons)
    properties["uniqueness"] = _evaluate_uniqueness(record, reasons)
    properties["verifier_independence"] = _evaluate_independence(record, reasons)
    properties["unlinkability"] = _evaluate_unlinkability(record, reasons)
    properties["accountability"] = _evaluate_accountability(record, reasons)
    properties["recovery"] = _evaluate_recovery(record, reasons)

    if fatal:
        return Evaluation(REJECTED, properties, reasons)

    values = set(properties.values())
    if REFUTED in values:
        verdict = REJECTED
    elif CONFLICTED in values:
        verdict = CONFLICTED
    elif properties["authorization"] == SUPPORTED and properties["authentication"] == SUPPORTED:
        verdict = ACCEPTED_BOUNDED
    else:
        verdict = UNKNOWN

    unmet = [
        name
        for name in (record.get("claimed_properties") or [])
        if properties.get(name, UNKNOWN) not in (SUPPORTED, ATTESTED)
    ]
    if unmet and verdict == ACCEPTED_BOUNDED:
        reasons.append(
            "verdict: claimed properties "
            + ", ".join(sorted(unmet))
            + " are not supported; the record stays UNKNOWN rather than widening"
        )
        verdict = UNKNOWN
    return Evaluation(verdict, properties, reasons)


def evaluate_file(path: Path) -> Evaluation:
    """Evaluate the ``record`` object stored in a fixture file."""

    fixture = json.loads(Path(path).read_text(encoding="utf-8"))
    return evaluate(fixture["record"])


def main(argv: list[str] | None = None) -> int:
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: evaluate.py FIXTURE [FIXTURE ...]")
        return 2
    for raw in args:
        result = evaluate_file(Path(raw))
        print(json.dumps({"fixture": raw, **result.to_dict()}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
