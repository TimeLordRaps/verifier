"""Compose bounded privacy, consent and governance admission for one certificate.

Verifier Standard (VSTD) computational checks and operation permissions remain
separate. This function performs no publication, network call or atomic invocation
consumption. Secure Hash Algorithm 256-bit (SHA-256) binds the canonical JavaScript
Object Notation (JSON) certificate bytes. Caller-supplied policy and observer facts
must come through an independently trusted operator channel.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import re
from typing import Any

from verifier import recheck_domain_certificate
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.consent import ConsentContext, ConsentPolicy, evaluate_consent
from verifier.governance import GovernanceContext, GovernancePolicy, evaluate_governance
from verifier.privacy import (
    DisclosureBound, DisclosureSurface, EmissionContext, EmissionEvaluator, EmissionRefusalError,
)


def evaluate_controlled_emission(
    certificate: dict[str, Any], action: GovernanceContext, *,
    certificate_policy: dict[str, Any], privacy_surface: DisclosureSurface,
    privacy_bounds: tuple[DisclosureBound, ...], privacy_context: EmissionContext,
    consent_policy: ConsentPolicy | None, consent_grants: tuple[dict[str, Any], ...],
    consent_revocation: dict[str, Any] | None, governance_policy: GovernancePolicy | None,
    governance_decisions: tuple[dict[str, Any], ...], governance_status: dict[str, Any] | None,
    evaluation_time: int | None,
) -> dict[str, Any]:
    """Recompute every gate and emit only when all bounded checks pass.

The consent grant binds the seven shared context coordinates. Governance also
binds jurisdiction and invocation identifier. A continuing consent grant is not
a one-time redemption token. Artifact identity here is the lowercase hexadecimal
SHA-256 of the whole canonical certificate, including its own certificate digest;
it is deliberately distinct from an evidence/artifact digest inside that certificate.
Receipts are private operator audit material until separately disclosure-reviewed.
"""
    statuses: list[str] = []
    checks: dict[str, Any] = {}
    emitted = None
    source = deepcopy(certificate)

    def finish() -> dict[str, Any]:
        verdict = "REJECTED" if "REJECTED" in statuses else "UNKNOWN" if "UNKNOWN" in statuses else "PASS"
        receipt = {
            "schema_version": "verifier-controlled-emission-1", "action": asdict(action),
            "evaluation_time": evaluation_time, "admission": verdict, "checks": checks,
            "computational_result": deepcopy(source.get("result")) if isinstance(source, dict) else None,
            "computational_result_basis": "REPRODUCED" if checks.get("computational_recheck", {}).get("status") == "PASS" else "SUBMITTED_UNVERIFIED",
            "normative_level_6_7_8_conformance": "UNKNOWN", "external_execution": "NOT_PERFORMED",
            "atomic_invocation_consumption": "NOT_PERFORMED",
        }
        receipt["receipt_digest"] = canonical_digest(receipt)
        return {"admission": verdict, "emitted_certificate": emitted if verdict == "PASS" else None,
                "receipt": receipt}

    try:
        actual_digest = hashlib.sha256(canonical_bytes(source)).hexdigest()
        domain = source["request"]["domain"]
        if (source.get("schema_version") != "verifier-domain-certification-1"
                or action.artifact_digest != actual_digest or action.object_name != domain
                or privacy_surface.object_name != domain):
            raise ValueError("artifact scope")
    except (KeyError, TypeError, ValueError, OverflowError):
        statuses.append("REJECTED"); checks["binding"] = "ARTIFACT_BINDING_REJECTED"
        return finish()

    # The exact canonical certificate is authorized, so its embedded request is
    # already bound by the action digest. Native replay still checks all evidence.
    native = recheck_domain_certificate(source, expected_request=source["request"], policy=certificate_policy)
    checks["computational_recheck"] = native
    if native.get("status") != "PASS":
        statuses.append("UNKNOWN" if native.get("status") == "UNKNOWN" else "REJECTED")
        return finish()

    common = {key: value for key, value in asdict(action).items() if key not in {"jurisdiction", "invocation_id"}}
    consent = evaluate_consent(ConsentContext(**common), consent_grants, policy=consent_policy,
        revocation=consent_revocation, evaluation_time=evaluation_time,
        computational_verdict=source["result"]["status"])
    governance = evaluate_governance(action, governance_decisions, policy=governance_policy,
        status=governance_status, evaluation_time=evaluation_time,
        computational_verdict=source["result"]["status"])
    statuses.extend((consent.verdict.value, governance.verdict.value))
    checks.update(consent=consent.receipt, governance=governance.receipt)

    observer = privacy_context.observer
    try:
        timestamp = privacy_context.timestamp
        # Integral-second context only: reject precision the parser would truncate,
        # including fractional timezone offsets, before any time conversion.
        if not isinstance(timestamp, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.0+)?(?:Z|[+-][0-9]{2}:[0-9]{2})", timestamp
        ):
            raise ValueError("privacy timestamp must identify an exact integral second")
        # Python 3.10 rejects seven or more fractional digits even when they
        # are all zero. The full match above has already excluded nonzero
        # fractions, so remove only that redundant integral-second spelling.
        integral_timestamp = re.sub(
            r"\.0+(?=(?:Z|[+-][0-9]{2}:[0-9]{2})$)", "", timestamp
        )
        instant = datetime.fromisoformat(integral_timestamp.replace("Z", "+00:00"))
        delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
        exact_seconds = delta.days * 86400 + delta.seconds
        if (delta.microseconds != 0 or exact_seconds != action.timestamp
                or observer.actor_id != action.observer_id or observer.purpose != action.purpose):
            raise ValueError("privacy context")
        privacy = EmissionEvaluator().evaluate_emission(source, privacy_surface, privacy_bounds, privacy_context)
        if privacy.emitted_certificate != source:
            raise ValueError("canonical certificate must remain unchanged")
        checks["privacy"] = privacy.receipt
        statuses.append("PASS")
        emitted = privacy.emitted_certificate
    except (ValueError, TypeError, OverflowError, EmissionRefusalError):
        statuses.append("REJECTED")
        checks["privacy"] = {"admission": "REJECTED", "reason": "DISCLOSURE_OR_CONTEXT_REFUSED"}
    return finish()
