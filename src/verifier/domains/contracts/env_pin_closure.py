"""Replay finite selected resolver trace closure against pinned ENV inventory.

Verifier Standard (VSTD); verifiable execution environment (ENV); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Counts are
dimensionless and byte ceilings measure bytes. Retained resolution rows are
not live resolver telemetry or evidence of exhaustive host observation.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import env_checks, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "ENV-4.1"
REQUEST_VERSION = "verifier-current-env-pin-closure-request-1"
POLICY_VERSION = "verifier-current-env-pin-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-env-pin-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-env-pin-closure-evidence-1"
MECHANISM_ID = "verifier.current-env.selected-pin-closure.1"
SCOPE = "finite_selected_resolution_trace_with_exact_pinned_inventory"
_CEILINGS = {
    "max_operations": 200000,
    "max_items": 4096,
    "max_evidence_bytes": 6 * 1024 * 1024,
    "max_child_certificate_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_MAX_CHILD_SELECTION_BYTES = 512 * 1024
_MAX_SELECTION_BYTES = 128 * 1024
_MAX_RESOLUTIONS = 256


class EnvPinClosureError(ValueError):
    """Malformed external selection, policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "ENV",
        "scope": SCOPE,
        "proposition": (
            "For one externally selected finite resolver trace, every retained "
            "resolution targets the exact selected pinned ENV inventory entry "
            "and digest, with a replayed ENV-1.2 byte-inventory prerequisite."
        ),
        "prerequisites": [
            "externally selected finite pins, required resolution keys and targets, "
            "ENV-1.2 request, policy and retained certificate for the same ENV and collection",
        ],
        "exclusions": [
            "whether the selected trace includes every resolution of a real execution",
            "collector authenticity or actual runtime resolution",
            "host, network or build closure, physical isolation or authority",
            "whole closure tier, object profile or polished issuance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class EnvPinClosureDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection, env_checks,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in (
        "NAMESPACE_OBJECTS.md", "CURRENT_ENV_CHECKS.md",
        "CURRENT_ENV_PIN_CLOSURE.md",
    ):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=EnvPinClosureError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def env_pin_closure_policy(*, trust_roots: list[str],
                           max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES,
                           ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _name(value: Any) -> str:
    if (type(value) is not str or not value.strip() or len(value) > 256
            or not value.isprintable()):
        raise EnvPinClosureError("bounded printable resolution name required")
    return value


def _pins(value: Any) -> dict[str, str]:
    if type(value) is not dict or not 1 <= len(value) <= _MAX_RESOLUTIONS:
        raise EnvPinClosureError("nonempty finite selected pin set required")
    selected: dict[str, str] = {}
    for name, commitment in value.items():
        selected[_name(name)] = retained_selection.commitment(
            commitment, EnvPinClosureError,
        )
    if "@entry" in selected:
        raise EnvPinClosureError("entrypoint sentinel cannot be a pinned file")
    if len(canonical_bytes(selected)) > _MAX_SELECTION_BYTES:
        raise EnvPinClosureError("selected pins byte bound exhausted")
    return selected


def _required(value: Any, pins: dict[str, str]) -> list[dict[str, str]]:
    if type(value) is not list or not 1 <= len(value) <= _MAX_RESOLUTIONS:
        raise EnvPinClosureError("nonempty finite selected resolver trace required")
    selected: list[dict[str, str]] = []
    identifiers: set[str] = set()
    for row in value:
        item = retained_selection.record(
            row, {"id", "requester", "specifier", "target"},
            "selected resolution", EnvPinClosureError,
        )
        for field in item:
            item[field] = _name(item[field])
        if item["id"] in identifiers:
            raise EnvPinClosureError("duplicate selected resolution identifier")
        if item["requester"] != "@entry" and item["requester"] not in pins:
            raise EnvPinClosureError("selected requester is not pinned")
        if item["target"] not in pins:
            raise EnvPinClosureError("selected target is not pinned")
        identifiers.add(item["id"])
        selected.append(item)
    if len(canonical_bytes(selected)) > _MAX_SELECTION_BYTES:
        raise EnvPinClosureError("selected resolver trace byte bound exhausted")
    return selected


def _child_selection(request: Any, policy: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(request) is not dict or type(policy) is not dict:
        raise EnvPinClosureError("selected ENV-1.2 request and policy must be plain")
    try:
        budget = common_module.Budget(16384, 4096)
        common_module.inspect_structure(request, budget)
        common_module.inspect_structure(policy, budget)
        if len(canonical_bytes(request)) + len(canonical_bytes(policy)) > _MAX_CHILD_SELECTION_BYTES:
            raise EnvPinClosureError("selected ENV-1.2 selection byte bound exhausted")
        child_request = env_checks._request(request)
        child_policy = env_checks._policy(policy)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError,
            Unavailable) as exc:
        if isinstance(exc, EnvPinClosureError):
            raise
        raise EnvPinClosureError("invalid selected ENV-1.2 prerequisite") from exc
    if (child_request["check"] != "closure"
            or child_request["coordinate"] != "ENV-1.2"
            or child_request["object_kind"] != "ENV"
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise EnvPinClosureError("selected ENV-1.2 prerequisite differs")
    return child_request, child_policy


def _request(value: Any) -> dict[str, Any]:
    request = retained_selection.record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits", "pins", "required_resolutions",
        "closure_certificate_digest", "closure_request", "closure_policy",
    }, "request", EnvPinClosureError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "ENV"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise EnvPinClosureError("selected ENV pin-closure objective differs")
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise EnvPinClosureError("bounded ENV subject identifier required")
    for key in ("object_digest", "collection_digest", "evidence_ref",
                "policy_digest", "closure_certificate_digest"):
        retained_selection.commitment(request[key], EnvPinClosureError)
    request["pins"] = _pins(request["pins"])
    request["required_resolutions"] = _required(
        request["required_resolutions"], request["pins"],
    )
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, EnvPinClosureError,
    )
    child_request, child_policy = _child_selection(
        request["closure_request"], request["closure_policy"],
    )
    if (child_request["subject_id"] != request["subject_id"]
            or child_request["object_digest"] != request["object_digest"]
            or child_request["collection_digest"] != request["collection_digest"]):
        raise EnvPinClosureError("selected ENV-1.2 subject or collection differs")
    request["closure_request"], request["closure_policy"] = child_request, child_policy
    return request


def env_pin_closure_request(*, subject_id: str, object_digest: str,
                            collection_digest: str, evidence_ref: str,
                            pins: dict[str, str],
                            required_resolutions: list[dict[str, str]],
                            closure_certificate_digest: str,
                            closure_request: dict[str, Any],
                            closure_policy: dict[str, Any],
                            policy: dict[str, Any],
                            limits: dict[str, int] | None = None,
                            ) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise EnvPinClosureError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "ENV", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}, "pins": pins,
        "required_resolutions": required_resolutions,
        "closure_certificate_digest": closure_certificate_digest,
        "closure_request": closure_request, "closure_policy": closure_policy,
    })


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **retained_selection.parameters(request),
        "pins_digest": "sha256:" + canonical_digest(request["pins"]),
        "required_resolutions_digest": "sha256:" + canonical_digest(request["required_resolutions"]),
        "closure_certificate_digest": request["closure_certificate_digest"],
        "closure_selection_digest": "sha256:" + canonical_digest({
            "request": request["closure_request"], "policy": request["closure_policy"],
        }),
    }


def _child_bytes(encoded: Any, *, maximum: int) -> bytes:
    if type(encoded) is not str:
        raise Refuted("retained ENV-1.2 encoding must be text")
    if not encoded:
        raise Unavailable("selected retained ENV-1.2 certificate absent")
    if len(encoded) > (maximum + 2) // 3 * 4 + 4:
        raise Unavailable("selected retained ENV-1.2 encoded bound exhausted")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        raise Refuted("retained ENV-1.2 encoding malformed") from None
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise Refuted("retained ENV-1.2 encoding noncanonical")
    if len(raw) > maximum:
        raise Unavailable("selected retained ENV-1.2 byte bound exhausted")
    return raw


def _child_evidence(certificate: bytes, expected_ref: str) -> dict[str, Any]:
    envelope = strict_json_loads(certificate.decode("utf-8"))
    payloads = envelope["evidence_payloads"]
    if type(payloads) is not dict or set(payloads) != {expected_ref}:
        raise Refuted("selected ENV-1.2 retained collection absent")
    store = EvidenceStore()
    store.import_base64(payloads)
    return strict_json_loads(store.resolve(expected_ref).decode("utf-8"))


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "closure_certificate_b64", "observations"},
            "evidence", EnvPinClosureError,
        )
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained ENV pin-closure evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        # Selected parent rows are independently refutable even when the
        # retained child certificate or one observation is unavailable.
        observations = value["observations"]
        if observations is not None and (type(observations) is not list
                                         or len(observations) > _MAX_RESOLUTIONS):
            raise Refuted("bounded retained resolver observations required")
        observed: dict[str, dict[str, str]] = {}
        for row in observations or []:
            item = retained_selection.record(
                row, {"id", "target", "digest"}, "resolver observation",
                EnvPinClosureError,
            )
            if type(item["id"]) is not str or item["id"] in observed:
                raise Refuted("duplicate or malformed resolver observation")
            if type(item["target"]) is not str or type(item["digest"]) is not str:
                raise Refuted("resolver target or digest malformed")
            observed[item["id"]] = item
        required = {row["id"]: row for row in request["required_resolutions"]}
        if set(observed) - set(required):
            raise Refuted("unselected resolver observation retained")
        missing_observations = set(required) - set(observed)
        for identifier, row in observed.items():
            selection = required[identifier]
            budget.tick(len(canonical_bytes(row)) + len(canonical_bytes(selection)))
            if row["target"] != selection["target"]:
                raise Refuted("retained resolution target differs from selection")
            if row["target"] not in request["pins"]:
                raise Refuted("retained resolution targets unpinned path")
            if row["digest"] != request["pins"][row["target"]]:
                raise Refuted("retained resolution digest differs from pin")
        child_bytes = _child_bytes(
            value["closure_certificate_b64"],
            maximum=limits["max_child_certificate_bytes"],
        )
        if "sha256:" + hashlib.sha256(child_bytes).hexdigest() != request["closure_certificate_digest"]:
            raise Refuted("retained ENV-1.2 bytes differ from external selection")
        try:
            child = env_checks.recheck_env_checks_certificate(
                child_bytes, expected_request=request["closure_request"],
                policy=request["closure_policy"],
            )
        except env_checks.EnvChecksError as exc:
            raise Refuted("selected ENV-1.2 certificate did not reproduce") from exc
        outcome = child["status"]
        if outcome not in ("PASS", "FAIL", "UNKNOWN"):
            raise Refuted("selected ENV-1.2 result is unsupported")
        if outcome != "PASS":
            return MechanismDecision(
                MechanismOutcome(outcome), "selected ENV-1.2 inventory did not pass",
            )
        child_evidence = _child_evidence(
            child_bytes, request["closure_request"]["evidence_ref"],
        )
        common_module.inspect_structure(child_evidence, budget)
        rows = child_evidence["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        matches = [row for row in rows if row["object_id"] == request["subject_id"]]
        if len(matches) != 1:
            raise Refuted("retained ENV subject absent or duplicate")
        subject = NamespaceObject.create(**matches[0])
        if subject.kind.value != "ENV" or subject.digest != request["object_digest"]:
            raise Refuted("retained ENV subject differs from external selection")
        inventory = subject.payload.get("files")
        if type(inventory) is not dict:
            raise Refuted("retained ENV software inventory absent")
        budget.tick(len(canonical_bytes(inventory)) + len(canonical_bytes(request["pins"])))
        if canonical_bytes(inventory) != canonical_bytes(request["pins"]):
            raise Refuted("selected pins differ from rehashed ENV inventory")
        if observations is None:
            raise Unavailable("selected resolver observations absent")
        if missing_observations:
            raise Unavailable("selected resolver observation missing")
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected finite resolver trace stays inside rehashed pins",
            {"resolutions_checked": len(required), "inventory_prerequisite": "REPLAYED_LOCAL"},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _EnvPinClosureMechanism:
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
                                     "bound ENV pin-closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained ENV pin-closure bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise EnvPinClosureError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_EnvPinClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ENV", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "closure_tier_conformance": "NOT_ESTABLISHED",
        "live_resolution_completeness": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise EnvPinClosureError("pin-closure certificate byte bound exhausted")
    return encoded


def build_env_pin_closure_certificate(request: dict[str, Any],
                                      evidence_bytes: bytes | None, *,
                                      policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise EnvPinClosureError("immutable bounded pin-closure evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise EnvPinClosureError("pin-closure evidence differs from selected reference")
    return _build(selected, admitted, store)


def recheck_env_pin_closure_certificate(certificate_bytes: bytes, *,
                                        expected_request: dict[str, Any],
                                        policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise EnvPinClosureError("bounded immutable pin-closure certificate required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"},
            "certificate", EnvPinClosureError,
        )
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise EnvPinClosureError("canonical pin-closure certificate version differs")
        if value["request"] != selected:
            raise EnvPinClosureError("pin-closure certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(item) is not str for item in payloads.values())):
            raise EnvPinClosureError("retained pin-closure evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise EnvPinClosureError("pin-closure certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, EnvPinClosureError):
            raise
        raise EnvPinClosureError("invalid retained pin-closure certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "SCOPE", "EnvPinClosureDescriptor", "EnvPinClosureError", "registration",
    "mechanism_digest", "env_pin_closure_policy", "env_pin_closure_request",
    "build_env_pin_closure_certificate", "recheck_env_pin_closure_certificate",
]
