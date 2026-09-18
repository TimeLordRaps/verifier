"""Terminology: JavaScript Object Notation (JSON); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD); zero-identity/zero-knowledge (ZIZK).

Offline evaluator for zero-identity actor tokens and bounded claims."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any

from verifier.identity.invariants import (
    IdentityVerdict,
    PropertyStatus,
)


@dataclass(frozen=True)
class IdentityEvaluation:
    verdict: IdentityVerdict
    properties: dict[str, PropertyStatus]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "properties": dict(self.properties),
            "reasons": list(self.reasons),
        }


def _parse_iso(ts: str) -> datetime | None:
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def evaluate_identity(
    record: dict[str, Any],
    *,
    evaluation_time_iso: str | None = None,
    accepted_trust_roots: set[str] | None = None,
) -> IdentityEvaluation:
    """Evaluate an actor identity record offline, strictly failing closed on missing coordinates."""
    reasons: list[str] = []
    properties: dict[str, PropertyStatus] = {}

    # 1. Civil Identity: Always explicitly withheld / unsupported by design
    properties["civil_identity"] = "UNSUPPORTED_BY_DESIGN"

    # 2. Authentication: requires valid signature over canonical bytes by declared key
    actor_info = record.get("actor") or {}
    key_binding = actor_info.get("key_binding") or {}
    key_id = key_binding.get("key_id")
    sig_verified = key_binding.get("signature_verified")
    trust_root = key_binding.get("trust_root")

    if not key_id or not sig_verified:
        properties["authentication"] = "UNKNOWN"
        reasons.append("authentication: key_binding or signature_verified coordinate is missing")
    elif sig_verified is not True:
        properties["authentication"] = "REFUTED"
        reasons.append("authentication: signature verification failed")
    else:
        properties["authentication"] = "SUPPORTED"

    # 3. Trust root acceptance
    declared_roots = set(record.get("trust_roots") or [])
    if trust_root and accepted_trust_roots is not None:
        if trust_root not in accepted_trust_roots:
            properties["authentication"] = "UNKNOWN"
            reasons.append(f"authentication: key trust root {trust_root} is not accepted by verifier")

    # 4. Authority Active / Freshness / Expiry
    auth_grant = record.get("authorization") or {}
    not_before_str = auth_grant.get("not_before")
    not_after_str = auth_grant.get("not_after")

    now = _parse_iso(evaluation_time_iso) if evaluation_time_iso else datetime.now(timezone.utc)
    not_before = _parse_iso(not_before_str) if not_before_str else None
    not_after = _parse_iso(not_after_str) if not_after_str else None

    revocation = record.get("revocation") or {}
    revocation_state = revocation.get("state")

    if revocation_state == "REVOKED":
        properties["authority_active"] = "REFUTED"
        reasons.append("authority_active: grant is explicitly marked REVOKED")
    elif not not_before or not not_after:
        properties["authority_active"] = "UNKNOWN"
        reasons.append("authority_active: temporal validity window coordinates missing")
    elif now is not None and not_before is not None and not_after is not None:
        if now < not_before:
            properties["authority_active"] = "REFUTED"
            reasons.append("authority_active: grant is not yet active (evaluation precedes not_before)")
        elif now > not_after:
            properties["authority_active"] = "REFUTED"
            reasons.append("authority_active: grant has expired (evaluation succeeds not_after)")
        elif revocation_state != "ACTIVE":
            properties["authority_active"] = "UNKNOWN"
            reasons.append("authority_active: active revocation proof missing")
        else:
            properties["authority_active"] = "SUPPORTED"
    else:
        properties["authority_active"] = "UNKNOWN"

    # 5. Authorization: Scope containment and delegation constraints
    requested_scope = record.get("requested_scope")
    permitted_scopes = set(auth_grant.get("permitted_scopes") or [])

    if properties["authentication"] != "SUPPORTED":
        properties["authorization"] = "UNKNOWN"
        reasons.append("authorization: cannot authorize without verified authentication")
    elif properties["authority_active"] == "REFUTED":
        properties["authorization"] = "REFUTED"
        reasons.append("authorization: cannot authorize with refuted authority liveness")
    elif properties["authority_active"] != "SUPPORTED":
        properties["authorization"] = "UNKNOWN"
        reasons.append("authorization: active authority not proven")
    elif not requested_scope:
        properties["authorization"] = "UNKNOWN"
        reasons.append("authorization: requested_scope coordinate missing")
    elif requested_scope not in permitted_scopes:
        properties["authorization"] = "REFUTED"
        reasons.append(f"authorization: requested scope {requested_scope} outside permitted_scopes {permitted_scopes}")
    else:
        # Check delegation widening
        parent_grant = record.get("parent_grant") or {}
        parent_scopes = set(parent_grant.get("permitted_scopes") or [])
        if parent_grant and not permitted_scopes.issubset(parent_scopes):
            properties["authorization"] = "REFUTED"
            reasons.append("authorization: delegation widens scope beyond parent grant")
        else:
            properties["authorization"] = "SUPPORTED"

    # 6. Aging / Tenure Accumulator Proof
    aging = record.get("aging") or {}
    accumulated_epochs = aging.get("accumulated_epochs")
    required_tenure = record.get("required_tenure_epochs")
    if required_tenure is not None:
        if accumulated_epochs is None:
            properties["tenure_aging"] = "UNKNOWN"
            reasons.append("tenure_aging: required tenure declared but aging accumulator missing")
        elif accumulated_epochs < required_tenure:
            properties["tenure_aging"] = "REFUTED"
            reasons.append(f"tenure_aging: accumulated epochs {accumulated_epochs} below required {required_tenure}")
        elif aging.get("revocation_status") != "ACTIVE":
            properties["tenure_aging"] = "REFUTED"
            reasons.append("tenure_aging: aging token revocation status is not ACTIVE")
        else:
            properties["tenure_aging"] = "SUPPORTED"
    else:
        properties["tenure_aging"] = "SUPPORTED" if accumulated_epochs is not None else "UNKNOWN"

    # 7. Verifier Independence
    peer_records = record.get("co_verifiers") or []
    if peer_records:
        all_keys = {key_id}
        has_duplicate = False
        for peer in peer_records:
            peer_key = peer.get("key_id")
            if peer_key in all_keys:
                has_duplicate = True
                break
            if peer_key:
                all_keys.add(peer_key)
        if has_duplicate:
            properties["verifier_independence"] = "REFUTED"
            reasons.append("verifier_independence: co-verifiers share identical signing key coordinate")
        else:
            properties["verifier_independence"] = "ATTESTED"
    else:
        properties["verifier_independence"] = "UNKNOWN"

    # 8. Prime Invariant Check: Computational Verdict Isolation
    # If the record attempts to assert a computational verdict based on actor identity, reject it.
    if record.get("upgrade_verdict_via_identity") is True:
        properties["authorization"] = "REFUTED"
        reasons.append("prime_invariant: attempting to upgrade computational verdict via identity is strictly prohibited")

    # Aggregate overall verdict
    values = set(properties.values())
    if "REFUTED" in values:
        verdict = "REJECTED"
    elif "CONFLICTED" in values:
        verdict = "CONFLICTED"
    elif properties.get("authorization") == "SUPPORTED" and properties.get("authentication") == "SUPPORTED":
        # Check that tenure_aging is not UNKNOWN if requested
        if required_tenure is not None and properties.get("tenure_aging") != "SUPPORTED":
            verdict = "UNKNOWN"
        else:
            verdict = "ACCEPTED_BOUNDED"
    else:
        verdict = "UNKNOWN"

    return IdentityEvaluation(
        verdict=verdict,
        properties=properties,
        reasons=tuple(reasons),
    )
