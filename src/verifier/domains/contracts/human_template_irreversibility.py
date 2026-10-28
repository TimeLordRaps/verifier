"""Versioned current HUMAN declared biometric-template irreversibility certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Event positions are dimensionless order indices;
event and object counts are dimensionless; byte ceilings count encoded bytes.

The check reads one retained, DECLARED humanness-assertion event log. It never
establishes that anyone is a person, that a template was captured, breached or
revoked in the world, or that a declared breach was real. Kind is read from the
typed namespace record, never from an identifier or label such as ``human:``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
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


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "HUMAN-2.5"
REQUEST_VERSION = "verifier-current-human-template-irreversibility-request-1"
POLICY_VERSION = "verifier-current-human-template-irreversibility-policy-1"
CERTIFICATE_VERSION = "verifier-current-human-template-irreversibility-certificate-1"
EVIDENCE_VERSION = "verifier-current-human-template-irreversibility-evidence-1"
MECHANISM_ID = "verifier.current-human.template-irreversibility.1"
SCOPE = "retained_declared_biometric_template_event_log"

#: The exact HUMAN-2.5 requirement text of DOMAIN_OBLIGATIONS.md.
ROW = ("A compromised biometric template does not rotate: revocation withdraws the "
       "binding and never restores the secrecy of the trait, so a breach is declared "
       "as permanent rather than as remediated.")
#: Exact text of prerequisite HUMAN-2.4 and its own prerequisite HUMAN-2.1, also selected.
PREREQUISITE_ROWS = {
    "HUMAN-2.1": ("Enrollment into the humanness assertion is declared as an event "
                  "with its evidence class and its instrument."),
    "HUMAN-2.4": ("Revocation on compromise withdraws the assertion from the position "
                  "in the order at which it takes effect."),
}
#: HUMAN-1.2 names these four evidence classes; a template log admits only the first.
EVIDENCE_CLASSES = frozenset({"biometric", "hardware-attested", "in-person", "social-graph"})
_EVENT_FIELDS = {
    "enrollment": frozenset({"position", "event", "template_id", "evidence_class", "instrument"}),
    "reverification": frozenset({"position", "event", "template_id"}),
    "compromise": frozenset({"position", "event", "template_id", "breach"}),
    "revocation": frozenset({"position", "event", "template_id", "effective_position"}),
}
#: Row words for what a breached template never undergoes; admitted only to be refuted.
RESTORATIVE_EVENTS = frozenset({"rotation", "restoration", "rebinding", "remediation"})
_EXCLUDED_FIELDS = (
    "personhood", "liveness", "biometric_accuracy", "presentation_attack_resistance",
    "injection_attack_resistance", "uniqueness_claim", "death", "authority",
    "consent", "privacy",
)
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_POSITION = 2**53 - 1
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_events": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class HumanTemplateIrreversibilityError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "HUMAN",
        "scope": SCOPE,
        "obligation_row": ROW,
        "prerequisite_rows": dict(PREREQUISITE_ROWS),
        "proposition": (
            "The externally selected exact HUMAN namespace record occurs, by typed "
            "kind, in the selected finite typed collection, which passes namespace "
            "composition; the externally selected retained declared event log rehashes "
            "exactly and its positions strictly increase; every template is enrolled "
            "once, before any other event names it, and every enrollment declares the "
            "biometric evidence class and a nonempty instrument; every compromise "
            "declares its breach permanent rather than remediated; every revocation "
            "follows a declared compromise of its template, occurs at most once for it "
            "and declares an effective position no earlier than its own position; after "
            "a template's declared breach no later event other than that revocation "
            "names the template, so any later enrollment uses a distinct template; and "
            "no rotation, restoration, rebinding or remediation event occurs."
        ),
        "prerequisites": [
            "independently selected exact HUMAN record, collection, retained declared "
            "event-log bytes, installed policy and finite checker limits"
        ],
        "exclusions": [
            "personhood, liveness, biometric accuracy, or that any template, capture, breach or revocation occurred",
            "presentation or injection attack resistance, uniqueness and death as a fact",
            "events absent from the retained log, or the declared order matching wall-clock order",
            "re-verification, evidence aging and death dynamics (HUMAN-2.2, HUMAN-2.3, HUMAN-2.6)",
            "whole HUMAN dynamics tier or object-profile conformance",
            "authority, consent, privacy, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class HumanTemplateIrreversibilityDescriptor:
    """Native public route metadata for one declared template-log proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != set(fields)):
        raise HumanTemplateIrreversibilityError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise HumanTemplateIrreversibilityError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_HUMAN_TEMPLATE_IRREVERSIBILITY.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {
        "schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes",
    }, "policy")
    if (type(policy["schema_version"]) is not str
            or type(policy["mechanism_id"]) is not str
            or policy["schema_version"] != POLICY_VERSION
            or policy["mechanism_id"] != MECHANISM_ID):
        raise HumanTemplateIrreversibilityError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise HumanTemplateIrreversibilityError("policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise HumanTemplateIrreversibilityError("bounded sorted unique trust-root labels required")
    size = policy["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise HumanTemplateIrreversibilityError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def human_template_irreversibility_policy(
        *, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling
           for key, ceiling in _CEILINGS.items()):
        raise HumanTemplateIrreversibilityError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "events_digest", "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "HUMAN"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise HumanTemplateIrreversibilityError("selected template irreversibility objective differs")
    for field in ("object_digest", "collection_digest", "events_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise HumanTemplateIrreversibilityError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def human_template_irreversibility_request(
        *, subject_id: str, object_digest: str, collection_digest: str,
        events_digest: str, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise HumanTemplateIrreversibilityError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "HUMAN", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "events_digest": events_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def _position(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_POSITION:
        raise Refuted("bounded integer " + label + " required")
    return value


def _template_log(inputs: Any, request: dict[str, Any],
                  budget: common_module.Budget) -> dict[str, Any]:
    retained = _record(inputs, {"events"}, "template log inputs")
    rows = retained["events"]
    if type(rows) is not list:
        raise Refuted("retained events must be an array")
    if len(rows) > request["limits"]["max_events"]:
        raise Unavailable("selected event bound exhausted")
    events_digest = "sha256:" + canonical_digest(rows)
    if events_digest != request["events_digest"]:
        raise Refuted("retained event log differs from external selection")
    enrolled: dict[str, int] = {}
    breached: dict[str, int] = {}
    revoked: dict[str, int] = {}
    previous: int | None = None
    for row in rows:
        budget.tick()
        if type(row) is not dict or type(row.get("event")) is not str:
            raise Refuted("each retained event declares its event kind")
        kind = row["event"]
        if kind in RESTORATIVE_EVENTS:
            fields = frozenset({"position", "event", "template_id"})
        elif kind in _EVENT_FIELDS:
            fields = _EVENT_FIELDS[kind]
        else:
            raise Refuted("event kind is outside the selected template-log vocabulary")
        event = _record(row, fields, kind + " event")
        position = _position(event["position"], "event position")
        if previous is not None and position <= previous:
            raise Refuted("event positions must strictly increase")
        previous = position
        template = event["template_id"]
        if not _text(template):
            raise Refuted("bounded template identifier required")
        if kind in RESTORATIVE_EVENTS:
            raise Refuted(
                f"{kind} event at position {position} names template {template}; a breach "
                "is declared permanent and a restorative event is never admitted")
        if template in breached and kind != "revocation":
            raise Refuted(
                f"{kind} event at position {position} names template {template} after its "
                f"breach at position {breached[template]}; the binding is never restored")
        if kind == "enrollment":
            if template in enrolled:
                raise Refuted(f"template {template} is enrolled more than once")
            if event["evidence_class"] is None:
                raise Refuted(f"enrollment at position {position} does not declare its evidence class")
            if type(event["evidence_class"]) is not str or event["evidence_class"] not in EVIDENCE_CLASSES:
                raise Refuted(f"enrollment at position {position} declares an unsupported evidence class")
            if event["evidence_class"] != "biometric":
                raise Refuted(f"template enrollment at position {position} must declare the biometric evidence class")
            if not _text(event["instrument"]):
                raise Refuted(f"enrollment at position {position} does not declare its instrument")
            enrolled[template] = position
            continue
        if template not in enrolled:
            raise Refuted(f"{kind} event at position {position} names template {template} before its enrollment")
        if kind == "compromise":
            if event["breach"] != "permanent":
                raise Refuted(
                    f"compromise at position {position} declares its breach as "
                    f"{event['breach']!r} rather than as permanent")
            breached[template] = position
        elif kind == "revocation":
            if template not in breached:
                raise Refuted(
                    f"revocation at position {position} follows no declared compromise of template {template}")
            if template in revoked:
                raise Refuted(f"template {template} is revoked more than once")
            effective = _position(event["effective_position"], "effective position")
            if effective < position:
                raise Refuted(
                    f"revocation at position {position} declares a retroactive effective "
                    f"position {effective}")
            revoked[template] = effective
    return {
        "events_digest": events_digest, "event_count": len(rows),
        "templates": sorted(enrolled), "breached_templates": sorted(breached),
        "revoked_templates": sorted(revoked),
    }


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        raw = strict_json_loads(data.decode("utf-8"))
        if type(raw) is dict and set(raw) == {"schema_version", "objects"}:
            if raw["schema_version"] != EVIDENCE_VERSION or canonical_bytes(raw) != data:
                raise Refuted("retained evidence version or canonical bytes differ")
            raise Unavailable("retained template event log absent")
        value = _record(raw, {"schema_version", "objects", "inputs"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            selected = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "HUMAN"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained typed HUMAN subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        if value["inputs"] is None:
            raise Unavailable("retained template event log absent")
        result = _template_log(value["inputs"], request, budget)
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected declared biometric template log keeps every breach permanent",
            {"template_log": result, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **{key: request[key] for key in (
            "semantic_version", "proposition_digest", "object_kind",
            "object_digest", "collection_digest", "events_digest", "policy_digest",
        )},
        "limits_digest": "sha256:" + canonical_digest(request["limits"]),
    }


class _HumanTemplateIrreversibilityMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound template irreversibility proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained template-log evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise HumanTemplateIrreversibilityError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_HumanTemplateIrreversibilityMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "HUMAN", "scope": SCOPE,
        "template_irreversibility": "PASS" if evaluation.outcome is MechanismOutcome.PASS
        else "NOT_ESTABLISHED",
        **{field: "NOT_ESTABLISHED" for field in _EXCLUDED_FIELDS},
        "human_dynamics_tier_conformance": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise HumanTemplateIrreversibilityError("certificate byte bound exhausted")
    return encoded


def build_human_template_irreversibility_certificate(
        request: dict[str, Any], evidence_bytes: bytes | None,
        *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise HumanTemplateIrreversibilityError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise HumanTemplateIrreversibilityError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_human_template_irreversibility_certificate(
        certificate_bytes: bytes, *, expected_request: dict[str, Any],
        policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise HumanTemplateIrreversibilityError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise HumanTemplateIrreversibilityError("canonical certificate version differs")
        if value["request"] != selected:
            raise HumanTemplateIrreversibilityError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise HumanTemplateIrreversibilityError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise HumanTemplateIrreversibilityError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, HumanTemplateIrreversibilityError):
            raise
        raise HumanTemplateIrreversibilityError("invalid retained template-log certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "ROW", "PREREQUISITE_ROWS", "EVIDENCE_CLASSES",
    "RESTORATIVE_EVENTS", "HumanTemplateIrreversibilityDescriptor",
    "HumanTemplateIrreversibilityError", "registration",
    "human_template_irreversibility_policy", "human_template_irreversibility_request",
    "build_human_template_irreversibility_certificate",
    "recheck_human_template_irreversibility_certificate",
]
