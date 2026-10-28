"""Current OWNER-2.6: ordered replay of a selected retained holding.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions and term bounds are dimensionless
integers in the declared order. Counts and checking budgets are
dimensionless. Replaying declared events establishes no legal title, lien,
authority, consent or personhood. A holder's kind is read from typed ACTOR
records, never from an identifier or label prefix.
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
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "OWNER-2.6"
REQUEST_VERSION = "verifier-current-owner-replay-request-1"
POLICY_VERSION = "verifier-current-owner-replay-policy-1"
CERTIFICATE_VERSION = "verifier-current-owner-replay-certificate-1"
EVIDENCE_VERSION = "verifier-current-owner-replay-evidence-1"
MECHANISM_ID = "verifier.current-owner.retained-ordered-replay.1"
SCOPE = "selected_retained_ordered_holding_replay"
PAYLOAD_SCOPE = "retained-ordered-holding-replay"
LIMB_KINDS = frozenset({"right", "discharge_duty", "answering_duty"})
_CEILINGS = {"max_objects": 256, "max_operations": 100000,
             "max_composition_operations": 100000, "max_items": 4096,
             "max_events": 1024, "max_grants": 1024, "max_instruments": 1024,
             "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024,
             "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_MAX_POSITION = 2**53 - 1
_MAX_LABEL = 256
_GRANT = {"object", "holder", "limb", "kind", "term"}
_CONVEYANCE = {"position", "event", "instrument_digest", "object", "from", "to", "limbs"}
_REVOCATION = {"position", "event", "instrument_digest", "object", "holder", "limbs"}


class OwnerReplayError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "OWNER", "scope": SCOPE,
        "proposition": (
            "For the externally selected exact OWNER record, its finite typed "
            "collection and its committed retained replay inputs: every holder "
            "resolves to an ACTOR record bound by the OWNER actor operand and "
            "every held object to its object operand; the origin and every "
            "declared event carry an instrument whose SHA-256 digest matches "
            "retained instrument bytes; declared positions strictly increase "
            "from the origin and no lapse is declared as an event; each "
            "transfer conveys only limbs the transferor holds at its position "
            "and removes them from the transferor; each delegation conveys "
            "only limbs the delegator holds at its position and leaves the "
            "delegator's holding intact; each revocation withdraws exactly the "
            "limbs it names, each held at its position; a term ends by the "
            "declared order alone; and replaying the events from the origin in "
            "the declared order reproduces the retained current holding "
            "exactly, by held object, holder, limb, limb kind and term, at the "
            "declared evaluation position."),
        "prerequisites": [
            "OWNER-2.1 through OWNER-2.5 as represented here: events declared "
            "with bound instruments and positions, transfer conveyance, "
            "delegation bound, revocation effect and lapse by the clock",
            "independently selected exact OWNER record, collection, retained "
            "replay inputs, installed policy and finite checker limits"],
        "exclusions": [
            "legal title, liens, encumbrances or any law of property",
            "authority of an instrument's issuer, admissibility at issue time "
            "or a holder's power to act",
            "consent, personhood, or that a HUMAN record names a natural person",
            "the holder's own ACTOR certificate and the held object's own certificate",
            "translation from an instrument's own clock: terms are read in "
            "positions of the declared order",
            "a conveyance that changes a conveyed limb's term, and merging a "
            "conveyed limb into one the recipient already holds (UNKNOWN)",
            "OWNER statics, including declared-shared limbs; OWNER closure",
            "whole OWNER dynamics tier or object-profile conformance",
            "privacy, governance, security, spending or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class OwnerReplayDescriptor:
    """Native public route metadata for one retained replay proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, OwnerReplayError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, OwnerReplayError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_OWNER_REPLAY.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=OwnerReplayError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def owner_replay_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "inputs_digest",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "OWNER")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise OwnerReplayError("selected OWNER replay objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > _MAX_LABEL):
        raise OwnerReplayError("bounded OWNER subject required")
    for field in ("object_digest", "collection_digest", "inputs_digest",
                  "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, OwnerReplayError)
    return selected


def owner_replay_request(*, subject_id: str, object_digest: str,
        collection_digest: str, inputs_digest: str, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise OwnerReplayError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "OWNER",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "inputs_digest": inputs_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _row(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != fields):
        raise Refuted(label + " fields differ")
    return value


def _label(value: Any, what: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > _MAX_LABEL:
        raise Refuted(what + " requires a bounded label")
    return value


def _position(value: Any, what: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_POSITION:
        raise Refuted(what + " requires a plain integer position")
    return value


def _term(value: Any) -> dict[str, Any]:
    if type(value) is dict and set(value) == {"start", "end"}:
        start = _position(value["start"], "term start")
        end = _position(value["end"], "term end")
        if end <= start:
            raise Refuted("a term must end after it starts")
        return {"start": start, "end": end}
    if (type(value) is dict and set(value) == {"start", "non_expiring"}
            and value["non_expiring"] is True):
        return {"start": _position(value["start"], "term start"), "non_expiring": True}
    raise Refuted("a term requires a start and an end, or a declared non-expiry")


def _ended(term: dict[str, Any], position: int) -> bool:
    return "end" in term and term["end"] <= position


def _held(term: dict[str, Any], position: int) -> bool:
    return term["start"] <= position and not _ended(term, position)


def _decode_b64(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise Refuted(label + " must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted(label + " is noncanonical base64")
    return decoded


def _limbs(value: Any) -> list[str]:
    if (type(value) is not list or not value
            or any(type(limb) is not str for limb in value)
            or value != sorted(set(value))):
        raise Refuted("named limbs must be a nonempty sorted unique list")
    return [_label(limb, "limb") for limb in value]


class _Scope:
    """Holders and held objects the selected OWNER record binds by type."""

    def __init__(self, objects: list[NamespaceObject], subject: NamespaceObject,
                 budget: common_module.Budget) -> None:
        by_id = {item.object_id: item for item in objects}
        operands = dict(subject.operands)
        self.actors: set[str] = set()
        pending = list(operands["actor"])
        while pending:
            budget.tick()
            item = by_id[pending.pop()]
            if item.kind is ObjectKind.GRAPH:
                pending.extend(dict(item.operands)["members"])
            elif item.kind is ObjectKind.ACTOR:
                self.actors.add(item.object_id)
        self.objects = set(operands["object"])

    def holder(self, value: Any) -> str:
        if _label(value, "holder") not in self.actors:
            raise Refuted("holder does not resolve to an ACTOR record bound by the "
                          "selected OWNER actor operand; a label or identifier "
                          "prefix is not a typed record")
        return value

    def held_object(self, value: Any) -> str:
        if _label(value, "held object") not in self.objects:
            raise Refuted("held object is not bound by the selected OWNER object operand")
        return value


def _grant(value: Any, scope: _Scope) -> tuple[tuple[str, str, str], dict[str, Any]]:
    row = _row(value, _GRANT, "holding row")
    key = (scope.held_object(row["object"]), scope.holder(row["holder"]),
           _label(row["limb"], "limb"))
    if type(row["kind"]) is not str or row["kind"] not in LIMB_KINDS:
        raise Refuted("limb kind must be a right, discharge-duty or answering-duty")
    return key, {"kind": row["kind"], "term": _term(row["term"])}


def _grants(rows: Any, scope: _Scope, limits: dict[str, int],
            budget: common_module.Budget, label: str) -> dict[tuple[str, str, str], dict[str, Any]]:
    if type(rows) is not list:
        raise Refuted(label + " requires a list")
    if len(rows) > limits["max_grants"]:
        raise Unavailable(label + " grant bound exhausted")
    table: dict[tuple[str, str, str], dict[str, Any]] = {}
    for value in rows:
        budget.tick()
        key, grant = _grant(value, scope)
        if key in table:
            raise Refuted(label + " repeats a limb for one holder and object")
        table[key] = grant
    return table


def _rows(table: dict[tuple[str, str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"object": key[0], "holder": key[1], "limb": key[2],
             "kind": grant["kind"], "term": grant["term"]}
            for key, grant in sorted(table.items())]


def _replay(inputs: Any, scope: _Scope, request: dict[str, Any],
            budget: common_module.Budget) -> MechanismDecision:
    limits = request["limits"]
    data = _row(inputs, {"instruments", "origin", "events",
                         "evaluation_position", "current_holding"}, "replay inputs")
    instruments = data["instruments"]
    if type(instruments) is not list or any(type(row) is not str for row in instruments):
        raise Refuted("retained instruments require a list of base64 text")
    if len(instruments) > limits["max_instruments"]:
        raise Unavailable("retained instrument bound exhausted")
    if instruments != sorted(set(instruments)):
        raise Refuted("retained instruments must be sorted and unique")
    bound = set()
    for row in instruments:
        budget.tick()
        bound.add("sha256:" + hashlib.sha256(
            _decode_b64(row, "retained instrument")).hexdigest())
    origin = _row(data["origin"], {"position", "instrument_digest", "grants"}, "origin")
    if origin["instrument_digest"] not in bound:
        raise Refuted("origin instrument is not bound to retained instrument bytes")
    last = _position(origin["position"], "origin")
    table = _grants(origin["grants"], scope, limits, budget, "origin")
    events = data["events"]
    if type(events) is not list:
        raise Refuted("declared events require a list")
    if len(events) > limits["max_events"]:
        raise Unavailable("declared event bound exhausted")
    for value in events:
        budget.tick()
        if type(value) is dict and value.get("event") == "lapse":
            raise Refuted("a lapse is the clock's doing, distinguished from "
                          "revocation, and is never a declared event")
        kind = value.get("event") if type(value) is dict else None
        if kind in ("transfer", "delegation"):
            event = _row(value, _CONVEYANCE, kind + " event")
        elif kind == "revocation":
            event = _row(value, _REVOCATION, "revocation event")
        else:
            raise Refuted("declared event must be a transfer, delegation or revocation")
        position = _position(event["position"], "declared event")
        if position <= last:
            raise Refuted("declared event positions must strictly increase from the origin")
        last = position
        if event["instrument_digest"] not in bound:
            raise Refuted("declared event instrument is not bound to retained instrument bytes")
        obj = scope.held_object(event["object"])
        limbs = _limbs(event["limbs"])
        budget.tick(len(limbs))
        for key in [key for key, grant in table.items() if _ended(grant["term"], position)]:
            del table[key]
        if kind == "revocation":
            holder = scope.holder(event["holder"])
            for limb in limbs:
                key = (obj, holder, limb)
                if key not in table or not _held(table[key]["term"], position):
                    raise Refuted("revocation names a limb its holder does not hold at "
                                  "that position, so it cannot withdraw exactly the named limbs")
                del table[key]
            continue
        source = scope.holder(event["from"])
        target = scope.holder(event["to"])
        if source == target:
            raise Refuted(kind + " requires two distinct holders")
        for limb in limbs:
            key = (obj, source, limb)
            if key not in table or not _held(table[key]["term"], position):
                raise Refuted(kind + " conveys a limb the conveying holder does not hold "
                              "at that position")
        for limb in limbs:
            if (obj, target, limb) in table:
                raise Unavailable("conveyance into a limb the recipient already holds is "
                                  "outside this bounded representation")
        for limb in limbs:
            table[(obj, target, limb)] = dict(table[(obj, source, limb)])
            if kind == "transfer":
                del table[(obj, source, limb)]
    evaluation = _position(data["evaluation_position"], "evaluation")
    if evaluation < last:
        raise Refuted("evaluation position precedes a declared event")
    replayed = _rows({key: grant for key, grant in table.items()
                      if _held(grant["term"], evaluation)})
    retained = _rows(_grants(data["current_holding"], scope, limits, budget,
                             "retained current holding"))
    budget.tick(len(replayed) + len(retained))
    if canonical_bytes(replayed) != canonical_bytes(retained):
        replayed_keys = {canonical_bytes(row) for row in replayed}
        retained_keys = {canonical_bytes(row) for row in retained}
        return MechanismDecision(MechanismOutcome.FAIL,
            "replaying the declared events does not reproduce the retained current holding",
            {"replayed_not_retained": [strict_json_loads(row.decode("utf-8"))
                                       for row in sorted(replayed_keys - retained_keys)],
             "retained_not_replayed": [strict_json_loads(row.decode("utf-8"))
                                       for row in sorted(retained_keys - replayed_keys)]})
    return MechanismDecision(MechanismOutcome.PASS,
        "declared events replayed from the origin reproduce the retained current holding",
        {"events": len(events), "origin_grants": len(origin["grants"]),
         "current_holding_rows": len(replayed), "evaluation_position": evaluation,
         "operations": budget.used})


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _row(strict_json_loads(data.decode("utf-8")),
                     {"schema_version", "objects", "inputs"}, "evidence")
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
            item = NamespaceObject.create(**_row(
                row, {"object_id", "kind", "payload", "operands"}, "namespace record"))
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [item for item in objects if item.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind is not ObjectKind.OWNER
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained OWNER subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value),
                                     composition.reason)
        subject = matches[0]
        payload = _row(subject.payload, {"scope", "inputs_digest"}, "OWNER payload")
        if payload["scope"] != PAYLOAD_SCOPE:
            raise Refuted("unsupported selected OWNER replay scope")
        if value["inputs"] is None:
            raise Unavailable("retained replay inputs absent")
        observed = "sha256:" + canonical_digest(value["inputs"])
        if observed != payload["inputs_digest"] or observed != request["inputs_digest"]:
            raise Refuted("retained replay inputs differ from the OWNER record or selection")
        return _replay(value["inputs"], _Scope(objects, subject, budget), request, budget)
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _OwnerReplayMechanism:
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
                                     "bound OWNER replay proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained replay bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise OwnerReplayError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_OwnerReplayMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "OWNER", "scope": SCOPE,
        "ordered_replay": ("PASS" if evaluation.outcome == MechanismOutcome.PASS
                           else "NOT_ESTABLISHED"),
        "holder_actor_certificate": "NOT_ESTABLISHED",
        "instrument_issuing_authority": "NOT_ESTABLISHED",
        "legal_title": "NOT_ESTABLISHED",
        "liens": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED",
        "consent": "NOT_ESTABLISHED",
        "personhood": "NOT_ESTABLISHED",
        "whole_owner_dynamics_tier": "NOT_ESTABLISHED",
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
        raise OwnerReplayError("certificate byte bound exhausted")
    return encoded


def build_owner_replay_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise OwnerReplayError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise OwnerReplayError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_owner_replay_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise OwnerReplayError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise OwnerReplayError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise OwnerReplayError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise OwnerReplayError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, OwnerReplayError):
            raise
        raise OwnerReplayError("invalid retained OWNER replay certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "OwnerReplayDescriptor",
           "OwnerReplayError", "registration", "owner_replay_policy",
           "owner_replay_request", "build_owner_replay_certificate",
           "recheck_owner_replay_certificate"]
