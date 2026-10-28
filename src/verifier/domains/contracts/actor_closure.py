"""Versioned current ACTOR closure-result certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Positions, decision counts and operation counts
are dimensionless; byte ceilings count encoded bytes. This check reports a
retained decision inventory, its attributions and their independence together,
and treats a missing component as incomplete rather than passing.
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
COORDINATE = "ACTOR-4.6"
REQUEST_VERSION = "verifier-current-actor-closure-request-1"
POLICY_VERSION = "verifier-current-actor-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-actor-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-actor-closure-evidence-1"
MECHANISM_ID = "verifier.current-actor.closure-result.1"
SCOPE = "finite_retained_decision_inventory_attribution_independence"
OBLIGATION_ROW = (
    "The inventory, the attributions and their independence are reported "
    "together; a closure missing any of the three is incomplete rather than passing."
)
COMPONENTS = ("inventory", "attributions", "independence")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_POSITION = 2**53 - 1
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_decisions": 4096, "max_records": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class ActorClosureError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "ACTOR",
        "scope": SCOPE,
        "obligation_row": OBLIGATION_ROW,
        "proposition": (
            "The externally selected exact ACTOR namespace record occurs in the "
            "selected finite typed collection; each present retained closure component "
            "rehashes exactly to its external selection; the inventory, attribution and "
            "independence components are each evaluated and reported together; and the "
            "closure passes only when all three are present and pass: the inventory "
            "enumerates its decisions contiguously over its declared interval, one per "
            "stated position; every attribution names a typed ACTOR record and an "
            "inventoried decision, no decision is attributed twice, and every decision "
            "in the declared classes is attributed; and no attribution cites only "
            "records whose sole declared controller is the attributed actor. A closure "
            "missing any component is UNKNOWN rather than PASS, and any refuted "
            "component makes it FAIL."
        ),
        "prerequisites": [
            "independently selected exact ACTOR record, collection, retained inventory, "
            "attribution and independence components, installed policy and finite "
            "checker limits",
            "the ACTOR-4.1 to ACTOR-4.5 rows as declared prerequisites, checked here "
            "only as the finite component predicates stated above; those rows are not "
            "emitted",
        ],
        "exclusions": [
            "emission of ACTOR-4.1 through ACTOR-4.5 or of any other prerequisite row",
            "that the inventory is every decision the actor took, or that any decision happened",
            "that a cited record exists outside the retained independence component, "
            "or that its declared controllers are its real controllers",
            "personhood of any represented human",
            "authenticity of the retained records",
            "authority, legitimacy or legal effect of any decision or attribution",
            "consent of any party",
            "joint accountability declared through a collective",
            "whole ACTOR closure tier or object-profile conformance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ActorClosureDescriptor:
    """Native public route metadata for one retained closure proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != fields):
        raise ActorClosureError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ActorClosureError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_ACTOR_CLOSURE.md"):
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
        raise ActorClosureError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise ActorClosureError("policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise ActorClosureError("bounded sorted unique trust-root labels required")
    size = policy["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise ActorClosureError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def actor_closure_policy(*, trust_roots: list[str],
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
        raise ActorClosureError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "inventory_digest", "attributions_digest", "independence_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "ACTOR"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise ActorClosureError("selected closure objective differs")
    for field in ("object_digest", "collection_digest", "inventory_digest",
                  "attributions_digest", "independence_digest", "evidence_ref",
                  "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise ActorClosureError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def actor_closure_request(*, subject_id: str, object_digest: str, collection_digest: str,
                          inventory_digest: str, attributions_digest: str,
                          independence_digest: str, evidence_ref: str,
                          policy: dict[str, Any],
                          limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise ActorClosureError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "ACTOR", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "inventory_digest": inventory_digest, "attributions_digest": attributions_digest,
        "independence_digest": independence_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise Refuted("bounded " + label + " text required")
    return value


def _position(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_POSITION:
        raise Refuted(label + " must be a bounded nonnegative integer")
    return value


def _names(value: Any, label: str, *, nonempty: bool) -> list[str]:
    if type(value) is not list or (nonempty and not value):
        raise Refuted(label + " must be an array" + (" with members" if nonempty else ""))
    names = [_text(item, label) for item in value]
    if names != sorted(set(names)):
        raise Refuted(label + " must be sorted and unique")
    return names


def _typed(by_id: dict[str, NamespaceObject], ref: Any, label: str) -> str:
    # Kind comes from the typed namespace record, never from an identifier label.
    if type(ref) is not str or ref not in by_id or by_id[ref].kind.value != "ACTOR":
        raise Refuted(label + " does not resolve to a typed ACTOR record")
    return ref


# A malformed or refuted component fails that component alone; budget exhaustion
# (Unavailable) still leaves the whole closure UNKNOWN.
_COMPONENT_REFUTATIONS = (Refuted, ActorClosureError)


class _Component:
    """One closure component's status, reported beside the other two."""

    def __init__(self) -> None:
        self.status, self.reason = "PASS", "component holds"

    def mark(self, status: str, reason: str) -> None:
        if self.status == "FAIL" or (self.status == "UNKNOWN" and status != "FAIL"):
            return
        self.status, self.reason = status, reason

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "reason": self.reason}


def _parse_inventory(value: Any, limits: dict[str, int],
                     budget: common_module.Budget) -> tuple[list[int], list[str], list[dict[str, Any]]]:
    inventory = _record(value, {"interval", "decision_classes", "decisions"}, "inventory")
    interval = inventory["interval"]
    if type(interval) is not list or len(interval) != 2:
        raise Refuted("inventory interval must name a start and an end")
    start, end = _position(interval[0], "interval start"), _position(interval[1], "interval end")
    if start > end:
        raise Refuted("inventory interval must be ordered")
    classes = _names(inventory["decision_classes"], "declared decision class", nonempty=True)
    rows = inventory["decisions"]
    if type(rows) is not list:
        raise Refuted("inventoried decisions must be an array")
    if len(rows) > limits["max_decisions"]:
        raise Unavailable("selected decision bound exhausted")
    decisions, seen = [], set()
    for row in rows:
        budget.tick()
        decision = _record(row, {"decision_id", "position", "decision_class"}, "inventoried decision")
        identifier = _text(decision["decision_id"], "decision identifier")
        if identifier in seen:
            raise Refuted("inventoried decision identifiers must be unique")
        seen.add(identifier)
        decisions.append({
            "decision_id": identifier,
            "position": _position(decision["position"], "decision position"),
            "decision_class": _text(decision["decision_class"], "decision class"),
        })
    return [start, end], classes, decisions


def _parse_attributions(value: Any, limits: dict[str, int],
                        budget: common_module.Budget) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise Refuted("attributions must be an array")
    if len(value) > limits["max_decisions"]:
        raise Unavailable("selected decision bound exhausted")
    attributions = []
    for row in value:
        budget.tick()
        attribution = _record(row, {"decision_id", "actor", "evidence"}, "attribution")
        if type(attribution["actor"]) is not str:
            raise Refuted("attribution actor must be an identifier")
        attributions.append({
            "decision_id": _text(attribution["decision_id"], "decision identifier"),
            "actor": attribution["actor"],
            "evidence": _names(attribution["evidence"], "cited record", nonempty=False),
        })
    return attributions


def _closure(inputs: dict[str, Any], by_id: dict[str, NamespaceObject],
             request: dict[str, Any], budget: common_module.Budget) -> tuple[str, str, dict[str, Any]]:
    limits = request["limits"]
    present = {name: inputs.get(name) is not None for name in COMPONENTS}
    for name in COMPONENTS:
        if present[name] and "sha256:" + canonical_digest(inputs[name]) != request[name + "_digest"]:
            raise Refuted("retained " + name + " differs from external selection")
    status = {name: _Component() for name in COMPONENTS}
    for name in COMPONENTS:
        if not present[name]:
            status[name].status, status[name].reason = "ABSENT", name + " component absent"

    # ACTOR-4.1: enumerated, contiguous over the declared interval, one per stated position.
    parsed_inventory = None
    if present["inventory"]:
        try:
            interval, classes, decisions = _parse_inventory(inputs["inventory"], limits, budget)
            parsed_inventory = (classes, decisions)
            positions = [row["position"] for row in decisions]
            if positions != list(range(interval[0], interval[1] + 1)):
                status["inventory"].mark(
                    "FAIL", "inventoried decisions are not contiguous over the declared "
                    "interval at one stated position each")
        except _COMPONENT_REFUTATIONS as exc:
            status["inventory"].mark("FAIL", str(exc))

    # ACTOR-4.2 / 4.3 / 4.4: one typed actor each, none unattributed, none doubly attributed.
    parsed_attributions = None
    if present["attributions"]:
        try:
            parsed_attributions = _parse_attributions(inputs["attributions"], limits, budget)
            seen: set[str] = set()
            for row in parsed_attributions:
                budget.tick()
                _typed(by_id, row["actor"], "attributed actor")
                if row["decision_id"] in seen:
                    raise Refuted("a decision is attributed more than once")
                seen.add(row["decision_id"])
            if parsed_inventory is None:
                status["attributions"].mark(
                    "UNKNOWN", "attribution coverage needs a present, well-formed inventory")
            else:
                classes, decisions = parsed_inventory
                every = {row["decision_id"] for row in decisions}
                declared = {row["decision_id"] for row in decisions
                            if row["decision_class"] in classes}
                if seen - every:
                    raise Refuted("an attribution names a decision outside the inventory")
                if declared - seen:
                    raise Refuted("a decision in the declared classes is left unattributed")
        except _COMPONENT_REFUTATIONS as exc:
            status["attributions"].mark("FAIL", str(exc))

    # ACTOR-4.5: no attribution rests only on records the actor exclusively controls.
    if present["independence"]:
        try:
            independence = _record(inputs["independence"], {"records"}, "independence")
            rows = independence["records"]
            if type(rows) is not list:
                raise Refuted("independence records must be an array")
            if len(rows) > limits["max_records"]:
                raise Unavailable("selected record bound exhausted")
            controllers: dict[str, list[str]] = {}
            for row in rows:
                budget.tick()
                record = _record(row, {"record_id", "controllers"}, "independence record")
                identifier = _text(record["record_id"], "record identifier")
                if identifier in controllers:
                    raise Refuted("independence record identifiers must be unique")
                held = _names(record["controllers"], "record controller", nonempty=True)
                for controller in held:
                    _typed(by_id, controller, "record controller")
                controllers[identifier] = held
            if parsed_attributions is None:
                status["independence"].mark(
                    "UNKNOWN", "independence needs present, well-formed attributions")
            else:
                for row in parsed_attributions:
                    budget.tick(len(row["evidence"]) + 1)
                    cited = [controllers.get(name) for name in row["evidence"]]
                    if not cited or any(held is None for held in cited):
                        status["independence"].mark(
                            "UNKNOWN", "an attribution cites no retained independence record")
                        continue
                    own = [held == [row["actor"]] for held in cited]
                    if all(own):
                        raise Refuted("an attribution rests only on records its actor "
                                      "exclusively controls")
                    if any(own):
                        status["independence"].mark(
                            "UNKNOWN", "an attribution cites a record its actor exclusively "
                            "controls beside another record")
        except _COMPONENT_REFUTATIONS as exc:
            status["independence"].mark("FAIL", str(exc))

    report = {name: status[name].to_dict() for name in COMPONENTS}
    refuted = [name for name in COMPONENTS if report[name]["status"] == "FAIL"]
    if refuted:
        verdict = "FAIL"
        details = "; ".join("closure component refuted: " + name + ": " + report[name]["reason"]
                            for name in refuted)
    elif any(report[name]["status"] != "PASS" for name in COMPONENTS):
        verdict = "UNKNOWN"
        details = "closure incomplete: " + "; ".join(
            name + ": " + report[name]["reason"] for name in COMPONENTS
            if report[name]["status"] != "PASS")
    else:
        verdict, details = "PASS", "inventory, attributions and independence reported together and pass"
    observations = {
        "components": report,
        "decisions": len(parsed_inventory[1]) if parsed_inventory else None,
        "declared_class_decisions": (
            sum(1 for row in parsed_inventory[1] if row["decision_class"] in parsed_inventory[0])
            if parsed_inventory else None),
        "attributions": len(parsed_attributions) if parsed_attributions is not None else None,
    }
    return verdict, details, observations


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        raw = strict_json_loads(data.decode("utf-8"))
        if type(raw) is dict and set(raw) == {"schema_version", "objects"}:
            if raw["schema_version"] != EVIDENCE_VERSION or canonical_bytes(raw) != data:
                raise Refuted("retained evidence version or canonical bytes differ")
            raise Unavailable("retained closure components absent")
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
        if (len(matches) != 1 or matches[0].kind.value != "ACTOR"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained ACTOR subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        inputs = value["inputs"]
        if inputs is None:
            raise Unavailable("retained closure components absent")
        if (type(inputs) is not dict or any(type(key) is not str for key in inputs)
                or set(inputs) - set(COMPONENTS)):
            raise Refuted("closure inputs name only the inventory, attributions and independence")
        by_id = {obj.object_id: obj for obj in objects}
        verdict, details, observations = _closure(inputs, by_id, request, budget)
        return MechanismDecision(
            MechanismOutcome(verdict), details,
            {"closure": observations, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **{key: request[key] for key in (
            "semantic_version", "proposition_digest", "object_kind",
            "object_digest", "collection_digest", "inventory_digest",
            "attributions_digest", "independence_digest", "policy_digest",
        )},
        "limits_digest": "sha256:" + canonical_digest(request["limits"]),
    }


class _ActorClosureMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained closure evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ActorClosureError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_ActorClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    status = evaluation.outcome.value
    result = {
        "status": status, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ACTOR", "scope": SCOPE,
        "closure_result": "PASS" if status == "PASS" else "NOT_ESTABLISHED",
        "whole_actor_closure_tier": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "personhood": "NOT_ESTABLISHED",
        "real_world_completeness": "NOT_ESTABLISHED",
        "record_authenticity": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED",
        "consent": "NOT_ESTABLISHED",
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
        raise ActorClosureError("certificate byte bound exhausted")
    return encoded


def build_actor_closure_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                    *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise ActorClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ActorClosureError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_actor_closure_certificate(certificate_bytes: bytes, *,
                                      expected_request: dict[str, Any],
                                      policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ActorClosureError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise ActorClosureError("canonical certificate version differs")
        if value["request"] != selected:
            raise ActorClosureError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ActorClosureError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ActorClosureError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, ActorClosureError):
            raise
        raise ActorClosureError("invalid retained closure certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "OBLIGATION_ROW", "SCOPE", "COMPONENTS",
    "ActorClosureDescriptor", "ActorClosureError", "registration",
    "actor_closure_policy", "actor_closure_request", "build_actor_closure_certificate",
    "recheck_actor_closure_certificate",
]
