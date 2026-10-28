"""Current TIME-3.1: strictly increasing retained instants on one declared clock.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Instants are integer microseconds on one declared
clock. Counts and checking budgets are dimensionless. The parent replays one
exact TIME-2.1 child and refutes equal adjacent instants that the child admits;
it proves no causal arrow, clock skew bound or wall-clock truth.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, time_order


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "TIME-3.1"
REQUEST_VERSION = "verifier-current-time-strict-request-1"
POLICY_VERSION = "verifier-current-time-strict-policy-1"
CERTIFICATE_VERSION = "verifier-current-time-strict-certificate-1"
EVIDENCE_VERSION = "verifier-current-time-strict-evidence-1"
MECHANISM_ID = "verifier.current-time.retained-strict-order.1"
SCOPE = "selected_strict_declared_clock_order"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class TimeStrictError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "TIME", "scope": SCOPE,
        "proposition": (
            "The independently selected exact TIME-2.1 child replays PASS, "
            "and every consecutive pair of its retained sample instants on "
            "the one declared clock is strictly increasing, so no two retained "
            "samples share an instant."),
        "prerequisites": [
            "exact separately selected TIME-2.1 request, policy and retained "
            "certificate; child replay PASS; finite checker limits"],
        "exclusions": [
            "causal arrow preservation or any EVENT-to-TIME binding",
            "physical clock skew, clock identity, calibration or wall-clock truth",
            "any relation between clocks",
            "minimum spacing or resolution between instants",
            "whole TIME statics tier or object-profile conformance",
            "privacy, consent, governance and security"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class TimeStrictDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, TimeStrictError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, TimeStrictError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module,
               common_module, retained_selection, time_order)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_TIME_ORDER.md",
                 "CURRENT_TIME_STRICT.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=TimeStrictError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def time_strict_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest",
        "child_request_digest", "child_policy_digest",
        "child_certificate_digest", "evidence_ref", "policy_digest", "limits"},
        "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "TIME")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise TimeStrictError("selected strict declared-clock objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise TimeStrictError("bounded TIME subject required")
    for field in ("object_digest", "collection_digest",
                  "child_request_digest", "child_policy_digest",
                  "child_certificate_digest", "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, TimeStrictError)
    return selected


def time_strict_request(*, subject_id: str, object_digest: str,
        collection_digest: str, child_request_digest: str,
        child_policy_digest: str, child_certificate_digest: str,
        evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise TimeStrictError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "TIME",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "child_request_digest": child_request_digest,
        "child_policy_digest": child_policy_digest,
        "child_certificate_digest": child_certificate_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_b64(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise Refuted(label + " must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted(label + " is noncanonical base64")
    return decoded


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "child_request", "child_policy",
                         "child_certificate"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained strict-order evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        child_request = value["child_request"]
        child_policy = value["child_policy"]
        if ("sha256:" + canonical_digest(child_request)
                != request["child_request_digest"]
                or "sha256:" + canonical_digest(child_policy)
                != request["child_policy_digest"]):
            raise Refuted("selected child request or policy differs")
        if (type(child_request) is not dict
                or child_request.get("subject_id") != request["subject_id"]
                or child_request.get("object_digest") != request["object_digest"]
                or child_request.get("collection_digest") != request["collection_digest"]
                or child_request.get("semantic_version") != time_order.SEMANTIC_VERSION
                or child_request.get("coordinate") != time_order.COORDINATE
                or child_request.get("object_kind") != "TIME"):
            raise Refuted("child is not selected TIME-2.1 subject")
        child_certificate = _decode_b64(value["child_certificate"], "child certificate")
        if len(child_certificate) > time_order._MAX_CERTIFICATE_BYTES:
            raise Unavailable("child certificate bound exhausted")
        if ("sha256:" + hashlib.sha256(child_certificate).hexdigest()
                != request["child_certificate_digest"]):
            raise Refuted("selected child certificate differs")
        try:
            child_result = time_order.recheck_time_order_certificate(
                child_certificate, expected_request=child_request,
                policy=child_policy)
        except time_order.TimeOrderError as exc:
            raise Refuted("selected TIME-2.1 child does not replay") from exc
        if child_result["status"] == "UNKNOWN":
            raise Unavailable("selected TIME-2.1 child remains UNKNOWN")
        if child_result["status"] != "PASS":
            raise Refuted("selected TIME-2.1 child did not pass")
        child = strict_json_loads(child_certificate.decode("utf-8"))
        child_payloads = child["evidence_payloads"]
        child_data = _decode_b64(child_payloads[child_request["evidence_ref"]],
                                 "child retained evidence")
        retained = strict_json_loads(child_data.decode("utf-8"))
        samples = retained["inputs"]["samples"]
        if len(samples) > limits["max_items"]:
            raise Unavailable("retained sample bound exhausted")
        for earlier, later in zip(samples, samples[1:]):
            budget.tick()
            if not earlier["at_us"] < later["at_us"]:
                raise Refuted("declared clock instants are not strictly increasing")
        return MechanismDecision(MechanismOutcome.PASS,
            "selected retained instants strictly increase on one declared clock",
            {"samples": len(samples), "pairs": len(samples) - 1,
             "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _TimeStrictMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound TIME strict-order proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected strict-order bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise TimeStrictError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_TimeStrictMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "TIME", "scope": SCOPE,
        "strict_declared_order": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "causal_arrow": "NOT_ESTABLISHED",
        "clock_skew": "NOT_ESTABLISHED",
        "clock_identity": "NOT_ESTABLISHED",
        "clock_calibration": "NOT_ESTABLISHED",
        "wall_clock_truth": "NOT_ESTABLISHED",
        "cross_clock_relation": "NOT_ESTABLISHED",
        "minimum_spacing": "NOT_ESTABLISHED",
        "whole_time_statics": "NOT_ESTABLISHED",
        "privacy": "NOT_ESTABLISHED",
        "consent": "NOT_ESTABLISHED",
        "governance": "NOT_ESTABLISHED",
        "security": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise TimeStrictError("certificate byte bound exhausted")
    return encoded


def build_time_strict_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise TimeStrictError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise TimeStrictError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_time_strict_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise TimeStrictError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise TimeStrictError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise TimeStrictError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise TimeStrictError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, TimeStrictError):
            raise
        raise TimeStrictError("invalid retained TIME strict-order certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "TimeStrictDescriptor",
           "TimeStrictError", "registration", "time_strict_policy",
           "time_strict_request", "build_time_strict_certificate",
           "recheck_time_strict_certificate"]
