"""Current OWNER-4.3: fork detection over a selected retained chain of holdings.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions are dimensionless integers in the
declared order and a holding's first and last positions are inclusive.
Counts and checking budgets are dimensionless. A fork is reported, never
resolved: no holding is named the winner. This checker computes no chain
closure result, no admissibility at issue time and no accountability floor,
and establishes no legal title, lien, authority, consent or personhood. A
holder's kind is read from typed ACTOR records, never from an identifier or
label prefix.
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
COORDINATE = "OWNER-4.3"
REQUEST_VERSION = "verifier-current-owner-forks-request-1"
POLICY_VERSION = "verifier-current-owner-forks-policy-1"
CERTIFICATE_VERSION = "verifier-current-owner-forks-certificate-1"
EVIDENCE_VERSION = "verifier-current-owner-forks-evidence-1"
MECHANISM_ID = "verifier.current-owner.retained-fork-detection.1"
SCOPE = "selected_retained_holding_fork_detection"
PAYLOAD_SCOPE = "retained-holding-chain-forks"
LIMB_KINDS = frozenset({"right", "discharge_duty", "answering_duty"})
_CEILINGS = {"max_objects": 256, "max_operations": 100000,
             "max_composition_operations": 100000, "max_items": 4096,
             "max_holdings": 1024, "max_chains": 256, "max_instruments": 256,
             "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024,
             "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_MAX_POSITION = 2**53 - 1
_MAX_LABEL = 256


class OwnerForksError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "OWNER", "scope": SCOPE,
        "proposition": (
            "For the externally selected exact OWNER record, its finite typed "
            "collection and its committed retained holdings and chains: every "
            "holder resolves to an ACTOR record bound by the OWNER actor "
            "operand and every held object to its object operand; as the "
            "stated prerequisites, each selected chain begins at a declared "
            "origin whose instrument's SHA-256 digest matches retained "
            "instrument bytes, and every position from that origin to the "
            "chain's head is covered by exactly one of the chain's holdings; "
            "and no two retained holdings claim the same limb over the same "
            "held object at the same position. Every pair that does is "
            "reported with its first shared position and is never resolved "
            "in favour of either holding."),
        "prerequisites": [
            "OWNER-4.2, and through it OWNER-4.1, as represented here: a "
            "declared chain per held object with a bound origin instrument and "
            "exactly-once coverage from origin to head",
            "independently selected exact OWNER record, collection, retained "
            "holdings, chains and instrument bytes, installed policy and "
            "finite checker limits"],
        "exclusions": [
            "legal title, liens, encumbrances or any law of property",
            "authority of an instrument's issuer or a holder's power to act",
            "consent, personhood, or that a HUMAN record names a natural person",
            "OWNER-4.4 admissibility at issue time",
            "OWNER-4.5 accountability floor",
            "OWNER-4.6 closure result: a chain is never reported closed here",
            "declared-shared limbs and OWNER statics asymmetry",
            "which holding of a fork is legitimate: no fork is resolved",
            "the holder's own ACTOR certificate and the held object's own certificate",
            "whole OWNER closure tier or object-profile conformance",
            "privacy, governance, security, spending or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class OwnerForksDescriptor:
    """Native public route metadata for one retained fork-detection proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, OwnerForksError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, OwnerForksError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_OWNER_FORKS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=OwnerForksError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def owner_forks_policy(*, trust_roots: list[str],
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
            raise OwnerForksError("selected OWNER fork objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > _MAX_LABEL):
        raise OwnerForksError("bounded OWNER subject required")
    for field in ("object_digest", "collection_digest", "inputs_digest",
                  "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, OwnerForksError)
    return selected


def owner_forks_request(*, subject_id: str, object_digest: str,
        collection_digest: str, inputs_digest: str, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise OwnerForksError("unsupported limit override")
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


def _holdings(rows: Any, scope: _Scope, limits: dict[str, int],
              budget: common_module.Budget) -> dict[str, dict[str, Any]]:
    if type(rows) is not list:
        raise Refuted("retained holdings require a list")
    if len(rows) > limits["max_holdings"]:
        raise Unavailable("retained holding bound exhausted")
    table: dict[str, dict[str, Any]] = {}
    for value in rows:
        budget.tick()
        row = _row(value, {"id", "object", "holder", "limbs", "first_position",
                           "last_position"}, "holding")
        hid = _label(row["id"], "holding identifier")
        if hid in table:
            raise Refuted("holding identifiers must be unique")
        obj = scope.held_object(row["object"])
        scope.holder(row["holder"])
        limbs = row["limbs"]
        if type(limbs) is not list or not limbs:
            raise Refuted("a holding enumerates a nonempty list of limbs")
        names = []
        for limb in limbs:
            budget.tick()
            entry = _row(limb, {"limb", "kind"}, "limb")
            names.append(_label(entry["limb"], "limb"))
            if type(entry["kind"]) is not str or entry["kind"] not in LIMB_KINDS:
                raise Refuted("limb kind must be a right, discharge-duty or answering-duty")
        if names != sorted(set(names)):
            raise Refuted("a holding's limbs must be sorted and unique")
        first = _position(row["first_position"], "holding first")
        last = _position(row["last_position"], "holding last")
        if last < first:
            raise Refuted("a holding's last position precedes its first")
        table[hid] = {"object": obj, "limbs": names, "first": first, "last": last}
    return table


def _chain_findings(chains: Any, holdings: dict[str, dict[str, Any]],
                    bound: set[str], scope: _Scope, limits: dict[str, int],
                    budget: common_module.Budget) -> tuple[list[str], set[str]]:
    if type(chains) is not list:
        raise Refuted("retained chains require a list")
    if len(chains) > limits["max_chains"]:
        raise Unavailable("retained chain bound exhausted")
    findings: list[str] = []
    chained: set[str] = set()
    placed: set[str] = set()
    for value in chains:
        budget.tick()
        chain = _row(value, {"object", "origin_position", "origin_instrument_digest",
                             "head_position", "holdings"}, "chain")
        obj = scope.held_object(chain["object"])
        if obj in chained:
            raise Refuted("each held object has at most one selected chain")
        chained.add(obj)
        origin = _position(chain["origin_position"], "chain origin")
        head = _position(chain["head_position"], "chain head")
        if head < origin:
            raise Refuted("a chain head precedes its origin")
        ids = chain["holdings"]
        if type(ids) is not list:
            raise Refuted("a chain lists its holdings")
        members = []
        for hid in ids:
            budget.tick()
            if type(hid) is not str or hid not in holdings:
                raise Refuted("a chain names an unretained holding")
            if hid in placed:
                raise Refuted("a holding belongs to at most one chain")
            placed.add(hid)
            if holdings[hid]["object"] != obj:
                raise Refuted("a chain names a holding over a different object")
            members.append((holdings[hid]["first"], holdings[hid]["last"], hid))
        if chain["origin_instrument_digest"] not in bound:
            findings.append(obj + ": chain origin instrument is not bound to retained "
                            "instrument bytes")
        cursor, covered = origin, None
        for first, last, hid in sorted(members):
            budget.tick()
            if first < origin:
                findings.append(obj + ": holding " + hid + " begins before the chain origin")
            if first > cursor:
                findings.append(obj + ": positions " + str(cursor) + " through "
                                + str(first - 1) + " are covered by no holding")
            if (covered is not None
                    and max(first, origin) <= min(covered, last, head)):
                findings.append(obj + ": position " + str(max(first, origin))
                                + " is covered by more than one holding")
            if last > head:
                findings.append(obj + ": holding " + hid + " extends past the chain head")
            covered = last if covered is None else max(covered, last)
            cursor = max(cursor, last + 1)
        if cursor <= head:
            findings.append(obj + ": positions " + str(cursor) + " through "
                            + str(head) + " are covered by no holding")
    return findings, chained


def _forks(holdings: dict[str, dict[str, Any]],
           budget: common_module.Budget) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[tuple[int, int, str]]] = {}
    for hid, row in holdings.items():
        for limb in row["limbs"]:
            budget.tick()
            groups.setdefault((row["object"], limb), []).append(
                (row["first"], row["last"], hid))
    found = []
    for (obj, limb), intervals in groups.items():
        active: list[tuple[int, int, str]] = []
        for first, last, hid in sorted(intervals):
            budget.tick(len(active) + 1)
            active = [item for item in active if item[1] >= first]
            for other in active:
                found.append(((obj, limb, tuple(sorted((other[2], hid)))), first))
            active.append((first, last, hid))
    return [{"holdings": list(pair), "object": obj, "limb": limb,
             "first_shared_position": position}
            for (obj, limb, pair), position in sorted(found)]


def _detect(inputs: Any, scope: _Scope, request: dict[str, Any],
            budget: common_module.Budget) -> MechanismDecision:
    limits = request["limits"]
    data = _row(inputs, {"instruments", "holdings", "chains"}, "fork inputs")
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
    holdings = _holdings(data["holdings"], scope, limits, budget)
    findings, chained = _chain_findings(data["chains"], holdings, bound, scope,
                                        limits, budget)
    forks = _forks(holdings, budget)
    if forks or findings:
        return MechanismDecision(MechanismOutcome.FAIL,
            "retained holdings fork or a selected chain is not a gapless bound chain; "
            "every fork is reported and none is resolved",
            {"forks": forks, "chain_findings": findings})
    unchained = sorted(scope.objects - chained)
    if unchained:
        return MechanismDecision(MechanismOutcome.UNKNOWN,
            "a held object has no selected chain, so its prerequisite chain is unestablished",
            {"unchained_objects": unchained})
    return MechanismDecision(MechanismOutcome.PASS,
        "no two retained holdings claim the same limb over the same object at the same "
        "position, over gapless chains from bound origins",
        {"forks": [], "chain_findings": [], "holdings": len(holdings),
         "chains": len(chained), "operations": budget.used})


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
            raise Refuted("unsupported selected OWNER fork scope")
        if value["inputs"] is None:
            raise Unavailable("retained holdings and chains absent")
        observed = "sha256:" + canonical_digest(value["inputs"])
        if observed != payload["inputs_digest"] or observed != request["inputs_digest"]:
            raise Refuted("retained fork inputs differ from the OWNER record or selection")
        return _detect(value["inputs"], _Scope(objects, subject, budget), request, budget)
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _OwnerForksMechanism:
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
                                     "bound OWNER fork proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained holdings bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise OwnerForksError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_OwnerForksMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "OWNER", "scope": SCOPE,
        "fork_freedom": ("PASS" if evaluation.outcome == MechanismOutcome.PASS
                         else "NOT_ESTABLISHED"),
        "admissibility_at_issue_time": "NOT_ESTABLISHED",
        "accountability_floor": "NOT_ESTABLISHED",
        "chain_closure_result": "NOT_ESTABLISHED",
        "legal_title": "NOT_ESTABLISHED",
        "liens": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED",
        "consent": "NOT_ESTABLISHED",
        "personhood": "NOT_ESTABLISHED",
        "whole_owner_closure_tier": "NOT_ESTABLISHED",
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
        raise OwnerForksError("certificate byte bound exhausted")
    return encoded


def build_owner_forks_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise OwnerForksError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise OwnerForksError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_owner_forks_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise OwnerForksError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise OwnerForksError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise OwnerForksError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise OwnerForksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, OwnerForksError):
            raise
        raise OwnerForksError("invalid retained OWNER fork certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "OwnerForksDescriptor",
           "OwnerForksError", "registration", "owner_forks_policy",
           "owner_forks_request", "build_owner_forks_certificate",
           "recheck_owner_forks_certificate"]
