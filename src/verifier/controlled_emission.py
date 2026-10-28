"""Compose bounded privacy, consent and governance admission for one certificate.

Verifier Standard (VSTD) computational checks and operation permissions remain
separate. This function performs no publication, network call or atomic invocation
consumption. Secure Hash Algorithm 256-bit (SHA-256) binds the canonical JavaScript
Object Notation (JSON) certificate bytes. Caller-supplied policy and observer facts
must come through an independently trusted operator channel. Unicode Transformation
Format, 8-bit (UTF-8) bytes are charged during bounded input capture. The current
Simulation (SIM) and HYPER routes retain their separately versioned meanings.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, fields
from datetime import datetime, timezone
import hashlib
import math
from pathlib import Path
import re
from typing import Any

from verifier import recheck_domain_certificate
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.receipt import strict_json_loads
from verifier.consent import ConsentContext, ConsentKey, ConsentPolicy, evaluate_consent
from verifier.domains.certification import MAX_BYTES as _DOMAIN_CERTIFICATE_MAX_BYTES
from verifier.domains.contracts import object_grounding, hyper_closure
from verifier.governance import (
    GovernanceContext, GovernancePolicy, GovernancePrincipal, evaluate_governance,
)
from verifier.privacy import (
    DisclosureBound, DisclosureSurface, EmissionContext, EmissionEvaluator, EmissionRefusalError,
    ObserverParty, TransparencyCommitment,
)
from verifier.privacy.current_certificate_emission import (
    CurrentCertificateEmission, evaluate_current_certificate_emission,
    recheck_current_certificate_emission,
)
from verifier.privacy.models import EmissionResult


_MAX_CAPTURE_NODES = 150000  # Certificate, consent, and governance inventories together.
_MAX_CAPTURE_DEPTH = 80  # Includes the aggregate tuple and bundled-record wrappers.
_MAX_CAPTURE_ITEMS = 10000
_MAX_CAPTURE_BYTES = 4 * _DOMAIN_CERTIFICATE_MAX_BYTES  # 16 mebibyte certificate plus authority inventories.
_RECORD_TYPES = (
    GovernanceContext, GovernancePolicy, GovernancePrincipal, ConsentContext,
    ConsentPolicy, ConsentKey, DisclosureSurface, DisclosureBound,
    EmissionContext, ObserverParty, TransparencyCommitment,
)


class _InputCaptureRefused(ValueError):
    """The aggregate input cannot be frozen within finite plain-data bounds."""


class _CaptureBudget:
    __slots__ = ("nodes", "byte_count")

    def __init__(self) -> None:
        self.nodes = 0
        self.byte_count = 0


def _capture_inputs(value: Any, budget: _CaptureBudget, *,
                    record_types: tuple[type, ...] = _RECORD_TYPES) -> Any:
    """Freeze exact bundled records and plain evidence before invoking any gate.

    The returned graph alone supplies later gate calls and the aggregate receipt.
    This bounds local capture; it does not make concurrent host mutation atomic.
    """
    def charge(size: int) -> None:
        budget.byte_count += size
        if budget.byte_count > _MAX_CAPTURE_BYTES:
            raise _InputCaptureRefused("controlled emission input byte bound exhausted")

    def charge_text(value: str) -> None:
        # Every code point takes at least one UTF-8 byte; refuse before encoding
        # when even that lower bound exceeds the remaining aggregate budget.
        if len(value) > _MAX_CAPTURE_BYTES - budget.byte_count:
            raise _InputCaptureRefused("controlled emission input text bound exhausted")
        try:
            for offset in range(0, len(value), 4096):
                charge(len(value[offset:offset + 4096].encode("utf-8")))
        except UnicodeEncodeError as exc:
            raise _InputCaptureRefused("controlled emission text is not UTF-8") from exc

    def copy(item: Any, depth: int) -> Any:
        budget.nodes += 1
        if budget.nodes > _MAX_CAPTURE_NODES or depth > _MAX_CAPTURE_DEPTH:
            raise _InputCaptureRefused("controlled emission input structural bound exhausted")
        kind = type(item)
        if kind is dict:
            if len(item) > _MAX_CAPTURE_ITEMS:
                raise _InputCaptureRefused("controlled emission object bound exhausted")
            entries = tuple(item.items())
            if len(entries) != len(item):
                raise _InputCaptureRefused("controlled emission object changed during capture")
            captured: dict[str, Any] = {}
            for name, child in entries:
                if type(name) is not str or len(name) > 512:
                    raise _InputCaptureRefused("controlled emission object key is invalid")
                charge_text(name)
                captured[name] = copy(child, depth + 1)
            return captured
        if kind is list or kind is tuple:
            if len(item) > _MAX_CAPTURE_ITEMS:
                raise _InputCaptureRefused("controlled emission array bound exhausted")
            values = tuple(item)
            if len(values) != len(item):
                raise _InputCaptureRefused("controlled emission array changed during capture")
            copied = [copy(child, depth + 1) for child in values]
            return copied if kind is list else tuple(copied)
        if any(kind is selected_type for selected_type in record_types):
            selected = {field.name: copy(getattr(item, field.name), depth + 1)
                        for field in fields(kind)}
            try:
                return kind(**selected)
            except (TypeError, ValueError) as exc:
                raise _InputCaptureRefused("controlled emission record is invalid") from exc
        if kind is str:
            charge_text(item)
            return item
        if kind is bytes:
            charge(len(item))
            return item
        if kind is int:
            if item.bit_length() > 4096:
                raise _InputCaptureRefused("controlled emission integer bound exhausted")
            return item
        if kind is float and math.isfinite(item):
            return item
        if item is None or kind is bool:
            return item
        raise _InputCaptureRefused("controlled emission inputs require plain finite data")

    try:
        return copy(value, 0)
    except (RuntimeError, RecursionError) as exc:
        raise _InputCaptureRefused("controlled emission input changed or cycled during capture") from exc


def evaluate_controlled_emission(
    certificate: dict[str, Any], action: GovernanceContext, *,
    certificate_policy: dict[str, Any], privacy_surface: DisclosureSurface,
    privacy_bounds: tuple[DisclosureBound, ...], privacy_context: EmissionContext,
    consent_policy: ConsentPolicy | None, consent_grants: tuple[dict[str, Any], ...],
    consent_revocation: dict[str, Any] | None, governance_policy: GovernancePolicy | None,
    governance_decisions: tuple[dict[str, Any], ...], governance_status: dict[str, Any] | None,
    evaluation_time: int | None,
) -> dict[str, Any]:
    """Recompute the retained legacy gates; emit only on aggregate admission.

The consent grant binds the seven shared context coordinates. Governance also
binds jurisdiction and invocation identifier. A continuing consent grant is not
a one-time redemption token. Artifact identity here is the lowercase hexadecimal
SHA-256 of the whole canonical certificate, including its own certificate digest;
it is deliberately distinct from an evidence/artifact digest inside that certificate.
Receipts are private operator audit material until separately disclosure-reviewed.
"""
    return _evaluate_controlled_emission(
        certificate, action,
        certificate_policy=certificate_policy,
        privacy_surface=privacy_surface,
        privacy_bounds=privacy_bounds,
        privacy_context=privacy_context,
        consent_policy=consent_policy,
        consent_grants=consent_grants,
        consent_revocation=consent_revocation,
        governance_policy=governance_policy,
        governance_decisions=governance_decisions,
        governance_status=governance_status,
        evaluation_time=evaluation_time,
    )


def evaluate_controlled_current_emission(
    certificate_bytes: bytes, action: GovernanceContext, *,
    semantic_version: str, objective: str, represented_kind: str,
    expected_request: dict[str, Any], certificate_policy: dict[str, Any],
    privacy_surface: DisclosureSurface, privacy_bounds: tuple[DisclosureBound, ...],
    privacy_context: EmissionContext, consent_policy: ConsentPolicy | None,
    consent_grants: tuple[dict[str, Any], ...], consent_revocation: dict[str, Any] | None,
    governance_policy: GovernancePolicy | None, governance_decisions: tuple[dict[str, Any], ...],
    governance_status: dict[str, Any] | None, evaluation_time: int | None,
    admitted_computational_statuses: tuple[str, ...] = ("PASS",),
) -> dict[str, Any]:
    """Join exact current SIM-5.1/HYPER-4.1 bytes to the same admission contract.

    Select route, request, outcome policy and authority externally. Native FAIL
    or UNKNOWN never becomes computational PASS, even when explicitly admitted
    for disclosure. No other current route, transmission or consumption is added.
    """
    selection = (
        semantic_version, objective, represented_kind, expected_request,
        admitted_computational_statuses,
    )
    return _evaluate_controlled_emission(
        certificate_bytes, action,
        certificate_policy=certificate_policy,
        privacy_surface=privacy_surface,
        privacy_bounds=privacy_bounds,
        privacy_context=privacy_context,
        consent_policy=consent_policy,
        consent_grants=consent_grants,
        consent_revocation=consent_revocation,
        governance_policy=governance_policy,
        governance_decisions=governance_decisions,
        governance_status=governance_status,
        evaluation_time=evaluation_time,
        current_selection=selection,
    )


def _evaluate_controlled_emission(
    certificate: Any, action: GovernanceContext, *,
    certificate_policy: dict[str, Any], privacy_surface: DisclosureSurface,
    privacy_bounds: tuple[DisclosureBound, ...], privacy_context: EmissionContext,
    consent_policy: ConsentPolicy | None, consent_grants: tuple[dict[str, Any], ...],
    consent_revocation: dict[str, Any] | None, governance_policy: GovernancePolicy | None,
    governance_decisions: tuple[dict[str, Any], ...], governance_status: dict[str, Any] | None,
    evaluation_time: int | None, current_selection: tuple[Any, ...] | None = None,
) -> dict[str, Any]:
    """One capture, consent, governance, clock and emission flow for both versions."""
    if type(action) is not GovernanceContext:
        raise _InputCaptureRefused("controlled emission action must be a plain context")
    capture_budget = _CaptureBudget()
    action = _capture_inputs(action, capture_budget)
    supplied_evaluation_time = evaluation_time
    evaluation_time = None
    statuses: list[str] = []
    checks: dict[str, Any] = {}
    emitted = None
    source: Any = None
    current = current_selection is not None
    selection_binding: dict[str, Any] = {}
    current_disclosure: dict[str, Any] | None = None
    current_privacy_receipt: dict[str, Any] | None = None

    def finish() -> dict[str, Any]:
        verdict = "REJECTED" if "REJECTED" in statuses else "UNKNOWN" if "UNKNOWN" in statuses else "PASS"
        receipt = {
            "schema_version": ("verifier-controlled-current-emission-1" if current
                               else "verifier-controlled-emission-1"), "action": asdict(action),
            "evaluation_time": evaluation_time, "admission": verdict, "checks": checks,
            "computational_result": deepcopy(source.get("result")) if isinstance(source, dict) else None,
            "computational_result_basis": "REPRODUCED" if checks.get("computational_recheck", {}).get("status") == "PASS" else "SUBMITTED_UNVERIFIED",
            "normative_level_6_7_8_conformance": "UNKNOWN", "external_execution": "NOT_PERFORMED",
            "atomic_invocation_consumption": "NOT_PERFORMED",
        }
        if current:
            receipt["selection_binding"] = deepcopy(selection_binding)
        receipt["receipt_digest"] = canonical_digest(receipt)
        return {"admission": verdict,
                ("emitted_certificate_bytes" if current else "emitted_certificate"):
                    emitted if verdict == "PASS" else None,
                "receipt": receipt}

    try:
        evaluation_time = _capture_inputs(supplied_evaluation_time, capture_budget)
        (source, certificate_policy, privacy_surface, privacy_bounds, privacy_context,
         consent_policy, consent_grants, consent_revocation, governance_policy,
         governance_decisions, governance_status, current_selection) = _capture_inputs((
            certificate, certificate_policy, privacy_surface, privacy_bounds, privacy_context,
            consent_policy, consent_grants, consent_revocation, governance_policy,
            governance_decisions, governance_status, current_selection,
        ), capture_budget)
    except _InputCaptureRefused:
        statuses.append("REJECTED"); checks["binding"] = "INPUT_CAPTURE_REJECTED"
        return finish()

    try:
        if current:
            (semantic_version, objective, domain, expected_request, admitted_statuses) = current_selection
            routes = {"SIM": object_grounding, "HYPER": hyper_closure}
            if (type(domain) is not str or domain not in routes
                    or type(semantic_version) is not str or type(objective) is not str
                    or semantic_version != routes[domain].SEMANTIC_VERSION
                    or objective != routes[domain].COORDINATE
                    or type(expected_request) is not dict
                    or expected_request.get("semantic_version") != semantic_version
                    or expected_request.get("coordinate") != objective
                    or type(admitted_statuses) is not tuple or not admitted_statuses
                    or any(type(status) is not str or status not in ("PASS", "FAIL", "UNKNOWN")
                           for status in admitted_statuses)
                    or len(set(admitted_statuses)) != len(admitted_statuses)
                    or type(source) is not bytes or len(source) > _DOMAIN_CERTIFICATE_MAX_BYTES):
                raise ValueError("unsupported current selection")
            authorized_bytes = source
            source = None
            selection_binding = {
                "semantic_version": semantic_version, "objective": objective, "represented_kind": domain,
                "certificate_sha256": "sha256:" + hashlib.sha256(authorized_bytes).hexdigest(),
                "request_sha256": "sha256:" + canonical_digest(expected_request),
                "policy_sha256": "sha256:" + canonical_digest(certificate_policy),
                "admitted_computational_statuses": admitted_statuses,
            }
        else:
            authorized_bytes = canonical_bytes(source)
            domain = source["request"]["domain"]
            if source.get("schema_version") != "verifier-domain-certification-1":
                raise ValueError("unsupported legacy certificate")
        actual_digest = hashlib.sha256(authorized_bytes).hexdigest()
        if (action.artifact_digest != actual_digest or action.object_name != domain
                or privacy_surface.object_name != domain):
            raise ValueError("artifact scope")
    except (KeyError, TypeError, ValueError, OverflowError):
        statuses.append("REJECTED"); checks["binding"] = "ARTIFACT_BINDING_REJECTED"
        return finish()

    if current:
        try:
            selection_binding["controlled_emission_source_sha256"] = (
                "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
            bridge = evaluate_current_certificate_emission(authorized_bytes, kind=domain,
                expected_request=expected_request, policy=certificate_policy,
                surface=privacy_surface, bounds=privacy_bounds, context=privacy_context)
            if type(bridge) is not CurrentCertificateEmission:
                raise ValueError("unsupported current bridge result")
            bridge = _capture_inputs(bridge, _CaptureBudget(),
                record_types=_RECORD_TYPES + (CurrentCertificateEmission, EmissionResult))
            if not recheck_current_certificate_emission(bridge, authorized_bytes, kind=domain,
                    expected_request=expected_request, policy=certificate_policy,
                    surface=privacy_surface, bounds=privacy_bounds, context=privacy_context):
                raise ValueError("current bridge result did not independently reproduce")
            output_budget = _CaptureBudget()
            source, native_result, current_disclosure, current_privacy_receipt = _capture_inputs((
                strict_json_loads(authorized_bytes.decode("utf-8")), bridge.native_result,
                bridge.privacy_result.emitted_certificate, bridge.privacy_result.receipt), output_budget)
            if (type(source) is not dict or canonical_bytes(source) != authorized_bytes
                    or canonical_bytes(current_disclosure) != authorized_bytes
                    or type(bridge.computational_status) is not str
                    or bridge.computational_status not in ("PASS", "FAIL", "UNKNOWN")
                    or native_result.get("status") != bridge.computational_status
                    or source.get("result", {}).get("status") != bridge.computational_status):
                raise ValueError("current bridge changed exact result or bytes")
            if bridge.replay_status != "REPRODUCED":
                statuses.append("UNKNOWN")
                checks["computational_recheck"] = {"status": "UNKNOWN", "replay_status": "UNAVAILABLE"}
                return finish()
            native = {"status": "PASS", "replay_status": "REPRODUCED",
                      "computational_status": bridge.computational_status, "native_result": native_result}
            selection_binding["bridge_source_sha256"] = bridge.selection_binding["bridge_source_sha256"]
            outcome = ("PASS" if bridge.computational_status in admitted_statuses else
                       "UNKNOWN" if bridge.computational_status == "UNKNOWN" else "REJECTED")
            statuses.append(outcome)
            checks["computational_outcome"] = {"status": outcome, "admitted_statuses": admitted_statuses}
        except OSError:
            statuses.append("UNKNOWN"); checks["computational_recheck"] = {"status": "UNKNOWN"}
            return finish()
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            statuses.append("REJECTED"); checks["computational_recheck"] = {"status": "REJECTED"}
            return finish()
    else:
        # The legacy embedded request is already bound by the exact action digest.
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
        privacy = (None if current else EmissionEvaluator().evaluate_emission(
            source, privacy_surface, privacy_bounds, privacy_context))
        # Capture plain bounded output before encoding. The original immutable
        # bytes remain authoritative even if a later gate mutates its source.
        emitted_snapshot = _capture_inputs(
            current_disclosure if current else privacy.emitted_certificate, _CaptureBudget())
        if canonical_bytes(emitted_snapshot) != authorized_bytes:
            raise ValueError("canonical certificate must remain unchanged")
        checks["privacy"] = current_privacy_receipt if current else privacy.receipt
        statuses.append("PASS")
        emitted = authorized_bytes if current else emitted_snapshot
    except (ValueError, TypeError, OverflowError, EmissionRefusalError):
        statuses.append("REJECTED")
        checks["privacy"] = {"admission": "REJECTED", "reason": "DISCLOSURE_OR_CONTEXT_REFUSED"}
    return finish()


def recheck_controlled_current_emission(result: dict[str, Any], **selection: Any) -> bool:
    """Recompute with external selection and compare the exact local wire result.

    This is receipt replay, never one-time consumption or a publication token.
    Capture the carried result before any gate so its callbacks cannot alter it.
    """
    try:
        carried = _capture_inputs(result, _CaptureBudget())
        if (type(carried) is not dict or set(carried) != {
                "admission", "emitted_certificate_bytes", "receipt"}
                or type(carried["receipt"]) is not dict
                or type(carried["admission"]) is not str
                or (carried["emitted_certificate_bytes"] is not None
                    and type(carried["emitted_certificate_bytes"]) is not bytes)):
            return False
        expected = evaluate_controlled_current_emission(**selection)
        return (carried["admission"] == expected["admission"]
                and carried["emitted_certificate_bytes"] == expected["emitted_certificate_bytes"]
                and canonical_bytes(carried["receipt"]) == canonical_bytes(expected["receipt"]))
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError, OSError):
        return False
