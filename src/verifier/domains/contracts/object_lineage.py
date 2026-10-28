"""Current OBJECT-2.1: declared linear version lineage with pinned operands.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Version numbers, counts and checking budgets are
dimensionless. PASS establishes a declared chain over retained records, not
actual revision history, authorship, time order or payload truth. The head and
every version may be records of any admitted kind, all of the one selected
kind, as OBJECT-1.1 (object_facets.py) admits any kind. The payload member
`lineage` is a convention this objective defines, not namespace text.
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
COORDINATE = "OBJECT-2.1"
REQUEST_VERSION = "verifier-current-object-lineage-request-1"
POLICY_VERSION = "verifier-current-object-lineage-policy-1"
CERTIFICATE_VERSION = "verifier-current-object-lineage-certificate-1"
EVIDENCE_VERSION = "verifier-current-object-lineage-evidence-1"
MECHANISM_ID = "verifier.current-object.version-lineage.1"
SCOPE = "selected_linear_version_lineage"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_LINEAGE_FIELDS = {"lineage_id", "version", "predecessor", "operand_digests"}
_MAX_VERSION = 2**53 - 1


class ObjectLineageError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "OBJECT", "scope": SCOPE,
        "proposition": (
            "In the selected finite collection the selected head record of "
            "the selected admitted kind declares the selected lineage "
            "identifier; following each declared predecessor record digest "
            "from the head reaches only retained records of that kind and "
            "lineage whose versions decrease by exactly "
            "one until version 1, which declares no predecessor; for every "
            "version the operand reference identifiers equal its pinned operand "
            "keys and each pinned operand is retained with exactly the pinned "
            "record digest; and no other retained record declares the selected "
            "lineage identifier."),
        "prerequisites": [
            "externally selected head identifier, admitted kind, record "
            "digest, collection commitment and lineage identifier; retained "
            "canonical namespace records; finite checker limits"],
        "exclusions": [
            "actual revision history, authorship, wall-clock or causal order",
            "typed composition of the selected collection",
            "payload meaning, truth or semantic compatibility between versions",
            "whole OBJECT dynamics tier or object-profile conformance",
            "privacy, consent, governance, security or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ObjectLineageDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, ObjectLineageError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, ObjectLineageError)


def _label(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               namespace_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_OBJECT_LINEAGE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=ObjectLineageError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def object_lineage_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "lineage_id", "evidence_ref",
        "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST)):
        if type(selected[field]) is not str or selected[field] != expected:
            raise ObjectLineageError("selected OBJECT lineage objective differs")
    if (type(selected["object_kind"]) is not str
            or selected["object_kind"] not in {kind.value for kind in ObjectKind}):
        raise ObjectLineageError("selected head kind is not admitted")
    if not _label(selected["subject_id"]):
        raise ObjectLineageError("bounded head identifier required")
    if not _label(selected["lineage_id"]):
        raise ObjectLineageError("bounded nonblank lineage identifier required")
    for field in ("object_digest", "collection_digest", "evidence_ref",
                  "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, ObjectLineageError)
    return selected


def object_lineage_request(*, subject_id: str, object_kind: str,
        object_digest: str, collection_digest: str, lineage_id: str,
        evidence_ref: str,
        policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ObjectLineageError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": object_kind,
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "lineage_id": lineage_id,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _declaration(item: NamespaceObject) -> dict[str, Any]:
    """Read the payload `lineage` member, this objective's convention, exactly."""
    payload = item.payload
    declared = payload.get("lineage")
    if (type(declared) is not dict or any(type(key) is not str for key in declared)
            or set(declared) != _LINEAGE_FIELDS):
        raise Refuted("lineage declaration fields differ")
    if not _label(declared["lineage_id"]):
        raise Refuted("lineage identifier must be bounded nonblank text")
    number = declared["version"]
    if type(number) is not int or not 1 <= number <= _MAX_VERSION:
        raise Refuted("lineage version must be a positive integer")
    if declared["predecessor"] is not None:
        retained_selection.commitment(declared["predecessor"], Refuted)
    pins = declared["operand_digests"]
    if type(pins) is not dict or len(pins) > 4096:
        raise Refuted("pinned operand map required")
    for name, pinned in pins.items():
        if not _label(name):
            raise Refuted("pinned operand identifier must be bounded text")
        retained_selection.commitment(pinned, Refuted)
    return declared


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "objects"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained lineage evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained records must be a list")
        by_id: dict[str, NamespaceObject] = {}
        by_digest: dict[str, NamespaceObject] = {}
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
            by_digest[item.digest] = item
        budget.tick(len(by_id))
        if composition_digest(list(by_id.values())) != request["collection_digest"]:
            raise Refuted("retained collection commitment differs")
        head = by_id.get(request["subject_id"])
        # Identity first: the record digest commits to the kind, so a retained
        # record with the selected digest differs only in the selected kind.
        if head is None or head.digest != request["object_digest"]:
            raise Refuted("selected head identity differs")
        if head.kind.value != request["object_kind"]:
            raise Refuted("selected head kind differs")
        declared = _declaration(head)
        if declared["lineage_id"] != request["lineage_id"]:
            raise Refuted("selected head lineage identifier differs")
        chain = [(head, declared)]
        while declared["version"] != 1:
            budget.tick()
            if declared["predecessor"] is None:
                raise Refuted("a later version declares no predecessor")
            previous = by_digest.get(declared["predecessor"])
            if previous is None:
                raise Refuted("declared predecessor is not retained")
            if previous.kind.value != request["object_kind"]:
                raise Refuted("lineage version kind differs from the selected kind")
            earlier = _declaration(previous)
            if earlier["lineage_id"] != declared["lineage_id"]:
                raise Refuted("lineage identifier changes along the chain")
            if earlier["version"] != declared["version"] - 1:
                raise Refuted("lineage versions are not consecutive")
            chain.append((previous, earlier))
            declared = earlier
        if declared["predecessor"] is not None:
            raise Refuted("first version has a predecessor")
        pinned = 0
        for member, declaration in chain:
            targets = {target for _, group in member.operands for target in group}
            budget.tick(len(targets) + 1)
            if targets != set(declaration["operand_digests"]):
                raise Refuted("operand pins differ from operands")
            for target in sorted(targets):
                retained = by_id.get(target)
                if retained is None:
                    raise Refuted("pinned operand is not retained")
                if retained.digest != declaration["operand_digests"][target]:
                    raise Refuted("pinned operand digest differs")
            pinned += len(targets)
        on_chain = {member.object_id for member, _ in chain}
        head_version = chain[0][1]["version"]
        outside = []
        for item in by_id.values():
            budget.tick()
            payload = item.payload
            claimed = payload.get("lineage")
            if (item.object_id not in on_chain and type(claimed) is dict
                    and claimed.get("lineage_id") == request["lineage_id"]):
                outside.append(_declaration(item)["version"])
        if any(number > head_version for number in outside):
            raise Refuted("selected head is not the latest retained version")
        if outside:
            raise Refuted("retained lineage version is outside the selected chain")
        return MechanismDecision(MechanismOutcome.PASS,
            "selected lineage is one consecutive pinned chain ending at the head",
            {"versions": len(chain), "pinned_operands": pinned,
             "records": len(by_id), "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ObjectLineageMechanism:
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
                                     "bound OBJECT lineage proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected lineage bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ObjectLineageError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ObjectLineageMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": request["object_kind"], "scope": SCOPE,
        "version_lineage_progression": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "typed_composition": "NOT_ESTABLISHED",
        "actual_revision_history": "NOT_ESTABLISHED",
        "payload_truth": "NOT_ESTABLISHED",
        "whole_object_dynamics": "NOT_ESTABLISHED",
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
        raise ObjectLineageError("certificate byte bound exhausted")
    return encoded


def build_object_lineage_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ObjectLineageError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ObjectLineageError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_object_lineage_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ObjectLineageError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise ObjectLineageError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ObjectLineageError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ObjectLineageError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, ObjectLineageError):
            raise
        raise ObjectLineageError("invalid retained OBJECT lineage certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SCOPE",
           "ObjectLineageDescriptor", "ObjectLineageError", "registration",
           "object_lineage_policy", "object_lineage_request",
           "build_object_lineage_certificate",
           "recheck_object_lineage_certificate"]
