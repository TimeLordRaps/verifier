"""Current HARDWARE-4.1: retained inventory closure under independent records.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Scope members, entry identifiers, identity keys
and producer labels are exact bounded strings; counts and budgets are
dimensionless. Independence here means only that a retained producer label
differs from the inventory's author label. This check proves no physical
coverage, identity, isolation or producer independence.
"""
from __future__ import annotations

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
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "HARDWARE-4.1"
REQUEST_VERSION = "verifier-current-hardware-inventory-closure-request-1"
POLICY_VERSION = "verifier-current-hardware-inventory-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-hardware-inventory-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-hardware-inventory-closure-evidence-1"
MECHANISM_ID = "verifier.current-hardware.independent-inventory-closure.1"
SCOPE = "retained_independent_inventory_record_closure"
SUBJECT_SCOPE = "retained-hardware-records"
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_members": 4096, "max_entries": 4096, "max_evidence_records": 16384,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_SCOPE_FIELD = "independent_inventory_record_closure"
_EXCLUDED_FIELDS = (
    "complete_physical_coverage", "resource_isolation",
    "physical_identity_authenticity", "producer_independence_authenticity",
    "evidence_authenticity", "legacy_hardware_closure",
    "hardware_closure_tier_conformance", "object_profile_conformance",
    "privacy", "consent", "governance", "security",
)


class HardwareInventoryClosureError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "HARDWARE",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact HARDWARE namespace record occurs in "
            "the selected finite typed collection, its retained inventory "
            "rehashes, and the retained scope members equal the externally "
            "selected nonempty member list. No two inventory entries share an "
            "exact identity key; the entries' declared coverage lies within and "
            "covers every selected member; every retained evidence record "
            "states exactly its entry's identity key and coverage; and every "
            "entry has at least one retained evidence record whose producer "
            "label differs from the inventory's author label."
        ),
        "prerequisites": [
            "independently selected exact HARDWARE record, collection and "
            "scope member list, retained inventory and evidence-record bytes, "
            "installed policy and finite checker limits"
        ],
        "exclusions": [
            "complete physical coverage, including devices absent from the "
            "retained inventory or members the selected list omits",
            "resource isolation, exclusive occupancy or non-interference",
            "physical identity, identity-key normalisation or authenticity of "
            "any evidence record",
            "causal, organisational or statistical producer independence "
            "beyond distinct retained labels",
            "measured-boot attestation closure or hardware security module verification",
            "legacy domain-certificate HARDWARE-4.1 results",
            "whole closure tier or object-profile conformance",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class HardwareInventoryClosureDescriptor:
    """Native public route metadata for one retained closure proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, HardwareInventoryClosureError)


def _retained(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, Refuted)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, HardwareInventoryClosureError)


def _bounded_label(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def _label(value: Any, label: str) -> str:
    if not _bounded_label(value):
        raise Refuted(label + " must be a bounded nonempty string")
    return value


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_HARDWARE_INVENTORY_CLOSURE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=HardwareInventoryClosureError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def hardware_inventory_closure_policy(
        *, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "members_digest", "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "HARDWARE"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise HardwareInventoryClosureError("selected inventory closure objective differs")
    for field in ("object_digest", "collection_digest", "members_digest",
                  "evidence_ref", "policy_digest"):
        _digest(request[field])
    if not _bounded_label(request["subject_id"]):
        raise HardwareInventoryClosureError("bounded subject identifier required")
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, HardwareInventoryClosureError)
    return request


def hardware_inventory_closure_request(
        *, subject_id: str, object_digest: str, collection_digest: str,
        members_digest: str, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise HardwareInventoryClosureError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "HARDWARE", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "members_digest": members_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _members(value: Any, limits: dict[str, int], budget: common_module.Budget) -> set[str]:
    if type(value) is not list:
        raise Refuted("selected scope members require a list")
    if not value:
        raise Unavailable("an empty selected scope establishes no closure")
    if len(value) > limits["max_members"]:
        raise Unavailable("selected scope member bound exhausted")
    budget.tick(len(value))
    for member in value:
        _label(member, "scope member")
    if value != sorted(set(value)):
        raise Refuted("selected scope members must be sorted and unique")
    return set(value)


def _covers(value: Any, label: str) -> list[str]:
    if type(value) is not list or not value:
        raise Refuted(label + " coverage must be a nonempty list")
    for member in value:
        _label(member, label + " covered member")
    if value != sorted(set(value)):
        raise Refuted(label + " coverage must be sorted and unique")
    return value


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _retained(strict_json_loads(data.decode("utf-8")),
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
            selected = _retained(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "HARDWARE"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained hardware subject differs from external selection")
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
            raise Unavailable("retained scope members and inventory absent")
        inputs = _retained(value["inputs"], {"members", "inventory"}, "closure inputs")
        payload = _retained(matches[0].payload, {"scope", "inventory_digest"}, "hardware payload")
        if payload["scope"] != SUBJECT_SCOPE:
            raise Refuted("hardware record scope differs")
        if common_module.digest(inputs["members"]) != request["members_digest"]:
            raise Refuted("retained scope members differ from the external selection")
        if common_module.digest(inputs["inventory"]) != payload["inventory_digest"]:
            raise Refuted("retained inventory differs from the selected record")
        members = _members(inputs["members"], limits, budget)
        inventory = _retained(inputs["inventory"], {"author", "entries"}, "inventory")
        author = _label(inventory["author"], "inventory author")
        entries = inventory["entries"]
        if type(entries) is not list:
            raise Refuted("inventory entries require a list")
        if len(entries) > limits["max_entries"]:
            raise Unavailable("inventory entry bound exhausted")
        entry_ids: set[str] = set()
        identity_keys: set[str] = set()
        evidence_ids: set[str] = set()
        covered: set[str] = set()
        unsupported: list[str] = []
        records = 0
        for row in entries:
            budget.tick()
            entry = _retained(row, {"entry_id", "identity_key", "covers", "evidence"},
                              "inventory entry")
            entry_id = _label(entry["entry_id"], "entry identifier")
            if entry_id in entry_ids:
                raise Refuted("duplicate inventory entry identifier")
            entry_ids.add(entry_id)
            key = _label(entry["identity_key"], "identity key")
            if key in identity_keys:
                raise Refuted("two inventory entries alias one identity key")
            identity_keys.add(key)
            covers = _covers(entry["covers"], "entry")
            if not set(covers) <= members:
                raise Refuted("inventory entry covers a member outside the selected scope")
            covered.update(covers)
            evidence = entry["evidence"]
            if type(evidence) is not list:
                raise Refuted("entry evidence records require a list")
            records += len(evidence)
            if records > limits["max_evidence_records"]:
                raise Unavailable("evidence record bound exhausted")
            independent = False
            for item in evidence:
                budget.tick()
                cited = _retained(item, {"evidence_id", "producer", "identity_key", "covers"},
                                  "evidence record")
                evidence_id = _label(cited["evidence_id"], "evidence identifier")
                if evidence_id in evidence_ids:
                    raise Refuted("duplicate evidence record identifier")
                evidence_ids.add(evidence_id)
                producer = _label(cited["producer"], "evidence producer")
                if cited["identity_key"] != key or cited["covers"] != covers:
                    raise Refuted("evidence record contradicts its inventory entry")
                if producer != author:
                    independent = True
            if not independent:
                unsupported.append(entry_id)
        uncovered = sorted(members - covered)
        if uncovered:
            raise Refuted("selected scope member is uncovered: " + uncovered[0])
        # Every check above is a counterexample no added evidence record could repair.
        # A missing independent record could still be supplied, so it is UNKNOWN.
        if unsupported:
            raise Unavailable(
                "entry rests on the inventory alone without an independent record: "
                + unsupported[0])
        return MechanismDecision(
            MechanismOutcome.PASS,
            "nonaliasing covering inventory with an independent record per entry",
            {"members": len(members), "entries": len(entries),
             "evidence_records": records, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _HardwareInventoryClosureMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound inventory closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained hardware evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise HardwareInventoryClosureError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_HardwareInventoryClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "HARDWARE", "scope": SCOPE,
        _SCOPE_FIELD: ("PASS" if evaluation.outcome == MechanismOutcome.PASS
                       else "NOT_ESTABLISHED"),
        **{field: "NOT_ESTABLISHED" for field in _EXCLUDED_FIELDS},
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
        raise HardwareInventoryClosureError("certificate byte bound exhausted")
    return encoded


def build_hardware_inventory_closure_certificate(
        request: dict[str, Any], evidence_bytes: bytes | None,
        *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise HardwareInventoryClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise HardwareInventoryClosureError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_hardware_inventory_closure_certificate(
        certificate_bytes: bytes, *, expected_request: dict[str, Any],
        policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise HardwareInventoryClosureError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise HardwareInventoryClosureError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise HardwareInventoryClosureError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise HardwareInventoryClosureError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, HardwareInventoryClosureError):
            raise
        raise HardwareInventoryClosureError(
            "invalid retained HARDWARE inventory closure certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "SUBJECT_SCOPE", "HardwareInventoryClosureDescriptor",
    "HardwareInventoryClosureError", "registration",
    "hardware_inventory_closure_policy", "hardware_inventory_closure_request",
    "build_hardware_inventory_closure_certificate",
    "recheck_hardware_inventory_closure_certificate",
]
