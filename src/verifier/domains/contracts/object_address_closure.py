"""Current OBJECT-4.2: reachable operand-address closure of one selected root.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Record and reference counts and checking budgets
are dimensionless. PASS establishes no typed composition, receipt-to-subject
closure (reserved for OBJECT-4.1) or payload truth. The root may be a record
of any admitted kind, selected with its kind, as OBJECT-1.1 (object_facets.py)
admits any kind.
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
from verifier.core.namespace import NamespaceObject, ObjectKind, composition_digest
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "OBJECT-4.2"
REQUEST_VERSION = "verifier-current-object-address-closure-request-1"
POLICY_VERSION = "verifier-current-object-address-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-object-address-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-object-address-closure-evidence-1"
CLOSURE_SCHEMA = "verifier-object-address-closure-1"
MECHANISM_ID = "verifier.current-object.address-closure.1"
SCOPE = "selected_reachable_address_closure"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class ObjectAddressClosureError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "OBJECT", "scope": SCOPE,
        "proposition": (
            "In the selected finite collection of retained canonical namespace "
            "records, every operand reference reachable from the selected "
            "root record of the selected admitted kind names exactly one "
            "retained record, the reachable "
            "reference graph has no cycle, and the canonical manifest of the "
            "root identifier and every reached identifier with its record "
            "digest recomputes the selected closure commitment."),
        "prerequisites": [
            "externally selected root identifier, admitted kind and record "
            "digest, collection commitment and closure commitment; retained "
            "canonical namespace records; finite checker limits"],
        "exclusions": [
            "receipt-to-subject closure, which OBJECT-4.1 reserves",
            "typed composition or kind compatibility of reached records",
            "records outside the reachable closure",
            "payload meaning, truth or authorship",
            "whole OBJECT closure tier or object-profile conformance",
            "privacy, consent, governance, security or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ObjectAddressClosureDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, ObjectAddressClosureError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, ObjectAddressClosureError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               namespace_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_OBJECT_ADDRESS_CLOSURE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=ObjectAddressClosureError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def object_address_closure_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "closure_digest",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST)):
        if type(selected[field]) is not str or selected[field] != expected:
            raise ObjectAddressClosureError("selected OBJECT closure objective differs")
    if (type(selected["object_kind"]) is not str
            or selected["object_kind"] not in {kind.value for kind in ObjectKind}):
        raise ObjectAddressClosureError("selected root kind is not admitted")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise ObjectAddressClosureError("bounded root identifier required")
    for field in ("object_digest", "collection_digest", "closure_digest",
                  "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, ObjectAddressClosureError)
    return selected


def object_address_closure_request(*, subject_id: str, object_kind: str,
        object_digest: str, collection_digest: str, closure_digest: str,
        evidence_ref: str,
        policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ObjectAddressClosureError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": object_kind,
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "closure_digest": closure_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _targets(item: NamespaceObject) -> list[str]:
    return [target for _, group in item.operands for target in group]


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "objects"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained closure evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained records must be a list")
        by_id: dict[str, NamespaceObject] = {}
        for row in rows:
            budget.tick()
            try:
                fields = _record(row, {"object_id", "kind", "payload", "operands"},
                                 "namespace record")
                if type(fields["operands"]) is not dict:
                    raise ValueError("operand map required")
                item = NamespaceObject.create(fields["object_id"], fields["kind"],
                                              fields["payload"], fields["operands"])
                if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                    raise ValueError("record does not reconstruct exactly")
            except (ValueError, TypeError, RecursionError) as exc:
                raise Refuted("retained record is not an admitted namespace record") from exc
            if item.object_id in by_id:
                raise Refuted("retained record identifier occurs twice")
            by_id[item.object_id] = item
        budget.tick(len(by_id))
        if composition_digest(list(by_id.values())) != request["collection_digest"]:
            raise Refuted("retained collection commitment differs")
        root_id = request["subject_id"]
        root = by_id.get(root_id)
        # Identity first: the record digest commits to the kind, so a retained
        # record with the selected digest differs only in the selected kind.
        if root is None or root.digest != request["object_digest"]:
            raise Refuted("selected root identity differs")
        if root.kind.value != request["object_kind"]:
            raise Refuted("selected root kind differs")
        # Iterative depth-first walk: "active" marks the current path, so an
        # edge back to it is a cycle; "done" marks a fully checked subgraph.
        state = {root_id: "active"}
        stack = [(root_id, iter(_targets(root)))]
        edges = 0
        while stack:
            name, pending = stack[-1]
            target = next(pending, None)
            if target is None:
                state[name] = "done"
                stack.pop()
                continue
            budget.tick()
            edges += 1
            if target not in by_id:
                raise Refuted("dangling reference in the reachable closure")
            mark = state.get(target)
            if mark == "active":
                raise Refuted("reference cycle in the reachable closure")
            if mark is None:
                state[target] = "active"
                stack.append((target, iter(_targets(by_id[target]))))
        reached = sorted(state)
        budget.tick(len(reached))
        manifest = {"schema_version": CLOSURE_SCHEMA, "root_id": root_id,
            "addresses": [{"object_id": name, "record_digest": by_id[name].digest}
                          for name in reached]}
        if "sha256:" + canonical_digest(manifest) != request["closure_digest"]:
            raise Refuted("retained closure commitment differs")
        return MechanismDecision(MechanismOutcome.PASS,
            "every reachable reference resolves acyclically to the selected closure",
            {"reached_records": len(reached), "references": edges,
             "records": len(by_id), "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ObjectAddressClosureMechanism:
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
                                     "bound OBJECT closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected closure bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ObjectAddressClosureError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ObjectAddressClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": request["object_kind"], "scope": SCOPE,
        "reachable_address_closure": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "typed_composition": "NOT_ESTABLISHED",
        "receipt_to_subject_closure": "NOT_ESTABLISHED",
        "payload_truth": "NOT_ESTABLISHED",
        "whole_object_closure": "NOT_ESTABLISHED",
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
        raise ObjectAddressClosureError("certificate byte bound exhausted")
    return encoded


def build_object_address_closure_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ObjectAddressClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ObjectAddressClosureError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_object_address_closure_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ObjectAddressClosureError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise ObjectAddressClosureError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ObjectAddressClosureError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ObjectAddressClosureError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, ObjectAddressClosureError):
            raise
        raise ObjectAddressClosureError(
            "invalid retained OBJECT address closure certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "CLOSURE_SCHEMA", "PROPOSITION_DIGEST", "SCOPE",
           "ObjectAddressClosureDescriptor", "ObjectAddressClosureError",
           "registration", "object_address_closure_policy",
           "object_address_closure_request",
           "build_object_address_closure_certificate",
           "recheck_object_address_closure_certificate"]
