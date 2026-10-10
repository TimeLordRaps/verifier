"""Current OWNER-3.1: declared hardware-ownership eligibility.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Simulation (SIM). This certificate transports the
existing accountability assessment over exactly selected namespace bytes and
the consumer's finite isolation binding. It establishes no legal title, human
authenticity, authority, physical host containment or whole statics tier.
Byte budgets measure encoded bytes; operation/item counts are dimensionless.
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
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.namespace import NamespaceObject, ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import accountability, retained_selection, sim_isolation


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "OWNER-3.1"
REQUEST_VERSION = "verifier-current-owner-eligibility-request-1"
POLICY_VERSION = "verifier-current-owner-eligibility-policy-1"
CERTIFICATE_VERSION = "verifier-current-owner-eligibility-certificate-1"
EVIDENCE_VERSION = "verifier-current-owner-eligibility-evidence-1"
MECHANISM_ID = "verifier.current-owner.declared-hardware-eligibility.1"
SCOPE = "declared_hardware_ownership_eligibility"
_CEILINGS = {"max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_nesting_depth": 48,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class OwnerEligibilityError(ValueError):
    """Malformed external selection or a certificate that does not replay."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "OWNER", "scope": SCOPE,
        "proposition": (
            "For the externally selected exact OWNER record and finite typed "
            "collection, freshly replay the declared hardware-ownership "
            "eligibility contract: a HUMAN may own declared physical or "
            "virtual HARDWARE; an AGENT may not own HARDWARE; a BOT may own "
            "only virtual HARDWARE inside its own freshly replayed finite "
            "isolated SIM, with exact SIM, evidence, object inventory and "
            "virtual resource identifier and kind bindings."),
        "prerequisites": [
            "exact independently selected OWNER record and complete typed collection",
            "for BOT virtual hardware, retained isolation evidence and the "
            "consumer's exact finite isolation binding"],
        "exclusions": [
            "legal title, acquisition permission, human authenticity or authority",
            "physical host containment, access control or actual enforcement",
            "ownership eligibility of non-HARDWARE objects (UNKNOWN)",
            "legacy OWNER-3.1 computational verdict independence",
            "whole OWNER statics tier, object profile, consent, governance or security"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class OwnerEligibilityDescriptor:
    """One current bounded statics proposition; no legacy semantic alias."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, OwnerEligibilityError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, OwnerEligibilityError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
        receipt_module, common_module, retained_selection, accountability, sim_isolation)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "SIM_ISOLATION.md",
                 "CURRENT_OWNER_HARDWARE_ELIGIBILITY.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=OwnerEligibilityError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def owner_eligibility_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _isolation_binding(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    selected = _record(value, {"sim_id", "evidence_digest", "max_operations", "max_items"},
                       "isolation binding")
    if (type(selected["sim_id"]) is not str or not selected["sim_id"].strip()
            or len(selected["sim_id"]) > 256):
        raise OwnerEligibilityError("bounded exact SIM identifier required")
    _digest(selected["evidence_digest"])
    for field, ceiling in (("max_operations", 10000000), ("max_items", 4096)):
        if type(selected[field]) is not int or not 1 <= selected[field] <= ceiling:
            raise OwnerEligibilityError("finite isolation checking limit differs")
    return selected


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest",
        "collection_digest", "isolation_binding", "evidence_ref", "policy_digest", "limits"},
        "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
        ("semantic_version", SEMANTIC_VERSION), ("coordinate", COORDINATE),
        ("proposition_digest", PROPOSITION_DIGEST), ("object_kind", "OWNER")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise OwnerEligibilityError("selected current OWNER statics proposition differs")
    if (type(selected["subject_id"]) is not str or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise OwnerEligibilityError("bounded exact OWNER identifier required")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["isolation_binding"] = _isolation_binding(selected["isolation_binding"])
    selected["limits"] = retained_selection.limits(selected["limits"], _CEILINGS,
                                                   OwnerEligibilityError)
    return selected


def owner_eligibility_request(*, subject_id: str, object_digest: str,
        collection_digest: str, evidence_ref: str, policy: dict[str, Any],
        isolation_binding: dict[str, Any] | None = None,
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise OwnerEligibilityError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "OWNER", "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "isolation_binding": isolation_binding,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _preflight(data: bytes, maximum_depth: int) -> None:
    """Bound decoder recursion and integers before allocating parsed values."""
    depth = digits = 0
    quoted = escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif 48 <= byte <= 57:
            digits += 1
            if digits > 1234:
                raise Unavailable("eligibility integer checking bound exhausted")
        elif byte == 34:
            digits = 0
            quoted = True
        elif byte in (91, 123):
            digits = 0
            depth += 1
            if depth > maximum_depth:
                raise Unavailable("eligibility nesting checking bound exhausted")
        elif byte in (93, 125):
            digits = 0
            depth -= 1
        else:
            digits = 0


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        _preflight(data, limits["max_nesting_depth"])
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "objects", "isolation_evidence"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("exact current eligibility evidence bytes differ")
        common_module.inspect_structure(value,
            common_module.Budget(limits["max_operations"], limits["max_items"]))
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires exact namespace records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            item = NamespaceObject.create(**_record(row,
                {"object_id", "kind", "payload", "operands"}, "namespace record"))
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        selected = [item for item in objects if item.object_id == request["subject_id"]]
        if (len(selected) != 1 or selected[0].kind is not ObjectKind.OWNER
                or selected[0].digest != request["object_digest"]):
            raise Refuted("OWNER record differs from external selection")
        composition = namespace_module.assess_composition(objects,
            expected_digest=request["collection_digest"], max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        result = accountability.assess_hardware_ownership(tuple(objects),
            owner_id=request["subject_id"], expected_digest=request["collection_digest"],
            isolation_evidence=value["isolation_evidence"],
            isolation_binding=request["isolation_binding"])
        return MechanismDecision(MechanismOutcome(result["status"]), result["reason"])
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _OwnerEligibilityMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound eligibility proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained eligibility bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise OwnerEligibilityError("request differs from independently selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_OwnerEligibilityMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "OWNER", "scope": SCOPE,
        "declared_hardware_ownership_eligibility":
            "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED",
        "legal_title": "NOT_ESTABLISHED", "human_authenticity": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "physical_host_containment": "NOT_ESTABLISHED",
        "actual_enforcement": "NOT_ESTABLISHED", "whole_owner_statics_tier": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise OwnerEligibilityError("certificate byte bound exhausted")
    return encoded


def build_owner_eligibility_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
        *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise OwnerEligibilityError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise OwnerEligibilityError("evidence differs from externally selected reference")
    return _build(selected, admitted, store)


def recheck_owner_eligibility_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise OwnerEligibilityError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest",
             "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION
                or canonical_bytes(value["request"]) != canonical_bytes(selected)):
            raise OwnerEligibilityError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise OwnerEligibilityError("retained evidence inventory differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise OwnerEligibilityError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, OwnerEligibilityError):
            raise
        raise OwnerEligibilityError("invalid retained eligibility certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "OwnerEligibilityDescriptor", "OwnerEligibilityError", "registration",
    "owner_eligibility_policy", "owner_eligibility_request", "build_owner_eligibility_certificate",
    "recheck_owner_eligibility_certificate"]
