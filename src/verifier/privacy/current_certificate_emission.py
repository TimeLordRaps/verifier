"""Local full-current-certificate emission eligibility, without authority transfer.

Verifier Standard (VSTD); Simulation (SIM); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit
(UTF-8). Byte ceilings count encoded bytes; node/depth counts are dimensionless.

This bridge neither authenticates an observer nor establishes consent, governance,
privacy conformance, external execution, or permission to transmit retained data.
Those decisions belong to the independently supplied controlled-emission gates.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from hashlib import sha256
import math
from pathlib import Path
import struct
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import hyper_closure, object_grounding

from .composition import CompositionDeltaEvaluator
from .engine import EmissionEvaluator, EmissionRefusalError
from .models import (
    DisclosureBound, DisclosureSurface, EmissionContext, EmissionResult,
    ObserverParty, TransparencyCommitment,
)


class CurrentCertificateEmissionRefusal(ValueError):
    """A current certificate cannot be emitted under this local selection."""


_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_MAX_SELECTION_NODES = 50_000
_MAX_SELECTION_DEPTH = 64
_MAX_SELECTION_TEXT_BYTES = 1024 * 1024
_MAX_COLLECTION_ITEMS = 50_000
_MAX_INTEGER_BITS = 4096
_RECORDS = (DisclosureBound, DisclosureSurface, EmissionContext,
            ObserverParty, TransparencyCommitment)
_ROUTES = {
    "SIM": (object_grounding.CERTIFICATE_VERSION,
            object_grounding.recheck_current_object_certificate),
    "HYPER": (hyper_closure.CERTIFICATE_VERSION,
              hyper_closure.recheck_hyper_closure_certificate),
}


@dataclass(frozen=True)
class CurrentCertificateEmission:
    """Local replay and disclosure result; never an external authorization token."""

    kind: str
    emitted_certificate_bytes: bytes
    replay_status: str
    computational_status: str
    native_result: dict[str, Any]
    privacy_result: EmissionResult
    selection_binding: dict[str, str]


def _capture_selection(value: Any, *, max_text_bytes: int = _MAX_SELECTION_TEXT_BYTES,
                       max_nodes: int = _MAX_SELECTION_NODES) -> Any:
    """Bound and copy exact plain selections before callbacks or serialization."""
    nodes = text_bytes = 0
    active: set[int] = set()

    def copy(item: Any, depth: int) -> Any:
        nonlocal nodes, text_bytes
        nodes += 1
        if nodes > max_nodes or depth > _MAX_SELECTION_DEPTH:
            raise CurrentCertificateEmissionRefusal("selection structural bound exhausted")
        kind = type(item)
        if item is None or kind is bool:
            return item
        if kind is int:
            if item.bit_length() > _MAX_INTEGER_BITS:
                raise CurrentCertificateEmissionRefusal("selection integer bound exhausted")
            return item
        if kind is float:
            if not math.isfinite(item):
                raise CurrentCertificateEmissionRefusal("selection is nonfinite")
            return item
        if kind is str:
            if len(item) > max_text_bytes - text_bytes:
                raise CurrentCertificateEmissionRefusal("selection text bound exhausted")
            text_bytes += len(item.encode("utf-8"))
            if text_bytes > max_text_bytes:
                raise CurrentCertificateEmissionRefusal("selection text bound exhausted")
            return item
        if kind not in (dict, list, tuple) + _RECORDS:
            raise CurrentCertificateEmissionRefusal("selection requires exact plain values")
        identity = id(item)
        if identity in active:
            raise CurrentCertificateEmissionRefusal("selection is cyclic")
        active.add(identity)
        try:
            if kind is dict:
                if len(item) > _MAX_COLLECTION_ITEMS:
                    raise CurrentCertificateEmissionRefusal("selection collection bound exhausted")
                copied = {}
                for key, child in item.items():
                    if type(key) is not str:
                        raise CurrentCertificateEmissionRefusal("selection keys must be plain text")
                    if len(key) > max_text_bytes - text_bytes:
                        raise CurrentCertificateEmissionRefusal("selection text bound exhausted")
                    text_bytes += len(key.encode("utf-8"))
                    if text_bytes > max_text_bytes:
                        raise CurrentCertificateEmissionRefusal("selection text bound exhausted")
                    copied[key] = copy(child, depth + 1)
                return copied
            if kind in (list, tuple):
                if len(item) > _MAX_COLLECTION_ITEMS:
                    raise CurrentCertificateEmissionRefusal("selection collection bound exhausted")
                return kind(copy(child, depth + 1) for child in item)
            return kind(**{field.name: copy(getattr(item, field.name), depth + 1)
                           for field in fields(kind)})
        finally:
            active.remove(identity)

    try:
        return copy(value, 0)
    except (UnicodeError, RuntimeError, RecursionError) as exc:
        raise CurrentCertificateEmissionRefusal("selection cannot be captured") from exc


def _sha256_json(value: Any) -> str:
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


def _bridge_source_digest() -> str:
    """Bind local bridge source bytes, without claiming code authenticity."""
    return "sha256:" + sha256(Path(__file__).read_bytes()).hexdigest()


def _screen_selected_kind_composition(kind: str, context: EmissionContext) -> None:
    """Apply the bundled pair screen using the externally selected primary kind.

    The generic helper cannot derive SIM/HYPER from these current requests. This
    extra screen uses its same listed rules, but still proves no general safety.
    """
    co_emitted = context.co_emitted_certificates
    if type(co_emitted) not in (tuple, list):
        raise CurrentCertificateEmissionRefusal("composition inputs must be plain records")
    for other in co_emitted:
        if type(other) is not dict:
            raise CurrentCertificateEmissionRefusal("composition inputs must be plain records")
        nested_request = other.get("request")
        if nested_request is not None and type(nested_request) is not dict:
            raise CurrentCertificateEmissionRefusal("composition object scope is unknown")
        label = (other.get("object_name") or other.get("domain") or other.get("object")
                 or (nested_request or {}).get("domain"))
        if type(label) is not str or not label.strip():
            raise CurrentCertificateEmissionRefusal("composition object scope is unknown")
    admissible, _reason, _details = CompositionDeltaEvaluator().evaluate_composition_delta(
        {"object_name": kind}, co_emitted, context.observer)
    if type(admissible) is not bool or not admissible:
        raise CurrentCertificateEmissionRefusal("composition pair screen refused emission")


def _capture_carried_result(value: CurrentCertificateEmission) -> tuple[Any, ...]:
    """Treat a carried result as untrusted data, never as a callback-bearing object."""
    if (type(value) is not CurrentCertificateEmission
            or type(value.kind) is not str or value.kind not in _ROUTES
            or type(value.replay_status) is not str or value.replay_status != "REPRODUCED"
            or type(value.computational_status) is not str
            or value.computational_status not in ("PASS", "FAIL", "UNKNOWN")
            or type(value.emitted_certificate_bytes) is not bytes
            or len(value.emitted_certificate_bytes) > _MAX_CERTIFICATE_BYTES
            or type(value.native_result) is not dict
            or type(value.privacy_result) is not EmissionResult
            or type(value.privacy_result.emitted_certificate) is not dict
            or type(value.privacy_result.receipt) is not dict
            or type(value.selection_binding) is not dict):
        raise CurrentCertificateEmissionRefusal("carried result has unsupported types")
    native = _capture_selection(
        value.native_result, max_text_bytes=_MAX_CERTIFICATE_BYTES, max_nodes=250_000)
    privacy = _capture_selection(
        (value.privacy_result.emitted_certificate,
         value.privacy_result.redacted_fields,
         value.privacy_result.transparency_commitments,
         value.privacy_result.receipt),
        max_text_bytes=2 * _MAX_CERTIFICATE_BYTES + _MAX_SELECTION_TEXT_BYTES,
        max_nodes=250_000)
    binding = _capture_selection(value.selection_binding)
    return (value.kind, value.emitted_certificate_bytes, value.replay_status,
            value.computational_status, native, privacy, binding)


def _exact_plain_equal(left: Any, right: Any) -> bool:
    """Compare captured plain values without Python numeric coercion or hooks."""
    kind = type(left)
    if kind is not type(right):
        return False
    if kind is dict:
        return (left.keys() == right.keys()
                and all(_exact_plain_equal(left[key], right[key]) for key in left))
    if kind in (tuple, list):
        return (len(left) == len(right)
                and all(_exact_plain_equal(a, b) for a, b in zip(left, right)))
    if kind in _RECORDS:
        return all(_exact_plain_equal(getattr(left, field.name), getattr(right, field.name))
                   for field in fields(kind))
    if kind is float:
        return struct.pack(">d", left) == struct.pack(">d", right)
    # _capture_carried_result has admitted only exact built-in scalars here.
    return left == right


def evaluate_current_certificate_emission(
    certificate_bytes: bytes, *, kind: str, expected_request: dict[str, Any],
    policy: dict[str, Any], surface: DisclosureSurface,
    bounds: tuple[DisclosureBound, ...], context: EmissionContext,
) -> CurrentCertificateEmission:
    """Replay the exact native certificate before and after full-field assessment.

    All selectors are external arguments. A faithfully replayed native FAIL or
    UNKNOWN is retained as that computational result, never promoted to PASS.
    Replay status REPRODUCED states only that local re-execution matched.
    """
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > _MAX_CERTIFICATE_BYTES:
        raise CurrentCertificateEmissionRefusal("certificate byte bound or type differs")
    if type(kind) is not str or kind not in _ROUTES:
        raise CurrentCertificateEmissionRefusal("unsupported external certificate kind")
    if type(expected_request) is not dict or type(policy) is not dict:
        raise CurrentCertificateEmissionRefusal("request and policy must be external plain records")
    if (type(surface) is not DisclosureSurface or type(bounds) not in (tuple, list)
            or type(context) is not EmissionContext):
        raise CurrentCertificateEmissionRefusal("unsupported disclosure selection")
    # One bounded capture; subsequent caller mutation cannot change this invocation.
    request, selected_policy, selected_surface, selected_bounds, selected_context = (
        _capture_selection((expected_request, policy, surface, bounds, context))
    )
    schema, recheck = _ROUTES[kind]
    try:
        before = recheck(certificate_bytes, expected_request=request, policy=selected_policy)
        certificate = strict_json_loads(certificate_bytes.decode("utf-8"))
        if type(certificate) is not dict or certificate.get("schema_version") != schema:
            raise CurrentCertificateEmissionRefusal("certificate differs from selected kind")
        if selected_surface.object_name != kind:
            raise CurrentCertificateEmissionRefusal("disclosure object differs from selected kind")
        if type(selected_context.timestamp) is not str:
            raise CurrentCertificateEmissionRefusal("disclosure timestamp must be plain text")
        _screen_selected_kind_composition(kind, selected_context)
        assessed = EmissionEvaluator().evaluate_emission(
            certificate, selected_surface, selected_bounds, selected_context)
        if (assessed.redacted_fields or canonical_bytes(assessed.emitted_certificate) != certificate_bytes):
            raise CurrentCertificateEmissionRefusal("current certificate must emit exact full bytes")
        after = recheck(certificate_bytes, expected_request=request, policy=selected_policy)
        if (type(before) is not dict or type(after) is not dict
                or before != after or type(after.get("status")) is not str
                or after["status"] not in ("PASS", "FAIL", "UNKNOWN")):
            raise CurrentCertificateEmissionRefusal("native replay result is unstable or unsupported")
        if assessed.receipt.get("certificate_validation") != "NOT_CHECKED":
            raise CurrentCertificateEmissionRefusal("generic privacy receipt changed scope")
        binding = {
            "certificate_sha256": "sha256:" + sha256(certificate_bytes).hexdigest(),
            "request_sha256": _sha256_json(request),
            "policy_sha256": _sha256_json(selected_policy),
            "bridge_source_sha256": _bridge_source_digest(),
        }
        return CurrentCertificateEmission(
            kind=kind, emitted_certificate_bytes=certificate_bytes,
            replay_status="REPRODUCED", computational_status=after["status"],
            native_result=after, privacy_result=assessed, selection_binding=binding,
        )
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError,
            UnicodeError, OSError, EmissionRefusalError) as exc:
        if isinstance(exc, CurrentCertificateEmissionRefusal):
            raise
        raise CurrentCertificateEmissionRefusal("current certificate emission refused") from exc


def recheck_current_certificate_emission(
    result: CurrentCertificateEmission, certificate_bytes: bytes, *, kind: str,
    expected_request: dict[str, Any], policy: dict[str, Any],
    surface: DisclosureSurface, bounds: tuple[DisclosureBound, ...],
    context: EmissionContext,
) -> bool:
    """Recompute under external selection; compare complete local result."""
    try:
        carried = _capture_carried_result(result)
        expected = evaluate_current_certificate_emission(
            certificate_bytes, kind=kind, expected_request=expected_request,
            policy=policy, surface=surface, bounds=bounds, context=context)
        return _exact_plain_equal(carried, _capture_carried_result(expected))
    except (CurrentCertificateEmissionRefusal, ValueError, TypeError, OverflowError,
            RecursionError, UnicodeError, AttributeError, OSError):
        return False


__all__ = ["CurrentCertificateEmission", "CurrentCertificateEmissionRefusal",
           "evaluate_current_certificate_emission", "recheck_current_certificate_emission"]
