"""Current RECEIPT-4.1: closed, acyclic declared receipt prerequisite cone.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Byte limits measure exact retained bytes. Counts
and operation budgets are dimensionless. Declared prerequisite identifiers are
mechanism-defined record content, not proven real dependency or causality.
"""
from __future__ import annotations

from collections import deque
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
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Budget, Refuted, Unavailable
from verifier.domains.contracts import receipt_statics, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "RECEIPT-4.1"
REQUEST_VERSION = "verifier-current-receipt-prerequisite-closure-request-1"
POLICY_VERSION = "verifier-current-receipt-prerequisite-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-receipt-prerequisite-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-receipt-prerequisite-closure-evidence-1"
MECHANISM_ID = "verifier.current-receipt.declared-prerequisite-cone.1"
SCOPE = "selected_declared_receipt_prerequisite_cone"
MAX_CHILDREN = 64
CHILD_FIELDS = frozenset({"subject_id", "request_digest", "policy_digest",
                          "certificate_digest"})
_CEILINGS = {"max_operations": 200000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024, "max_children": MAX_CHILDREN}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class ReceiptPrerequisiteClosureError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "RECEIPT", "scope": SCOPE,
        "proposition": (
            "Every externally selected exact RECEIPT-3.1 child request, policy and "
            "retained certificate replays PASS against the installed RECEIPT-3.1 "
            "mechanism; the selected root RECEIPT record is one of those children; "
            "every prerequisite identifier declared in a retained child record reached "
            "from the root names a selected child; every selected child is reached "
            "from the root through declared prerequisites; and the declared "
            "prerequisite relation over those children admits a Kahn topological "
            "order, so the retained cone is closed and acyclic."),
        "prerequisites": [
            "externally selected root RECEIPT record, one exact RECEIPT-3.1 request, "
            "policy and retained certificate per cone member, and finite checker limits"],
        "exclusions": [
            "real dependency, causality or derivation between receipts",
            "refutable transformation closure between member claims",
            "completeness of any proof bound",
            "claim truth or audit validation replay of any member (RECEIPT-2.1)",
            "bytes of source files, source artifacts or other external referents",
            "hash-chain continuity (RECEIPT-9.1) and issuer authenticity (RECEIPT-9.2)",
            "whole RECEIPT closure tier or object-profile conformance",
            "privacy, consent, governance, security, authority or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ReceiptPrerequisiteClosureDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, names: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, set(names), label,
                                     ReceiptPrerequisiteClosureError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module, namespace_module,
               common_module, retained_selection, receipt_statics)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_RECEIPT_STATICS.md",
                 "CURRENT_RECEIPT_PREREQUISITE_CLOSURE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())}
        | {"receipt_statics_mechanism": receipt_statics.mechanism_digest()})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=ReceiptPrerequisiteClosureError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def receipt_prerequisite_closure_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    """Format a policy; trust-root labels do not authenticate anyone."""
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _children(value: Any) -> list[dict[str, str]]:
    error = ReceiptPrerequisiteClosureError
    if type(value) is not list or not value or len(value) > MAX_CHILDREN:
        raise error("between one and 64 selected RECEIPT-3.1 children required")
    selected = []
    for item in value:
        row = _record(item, CHILD_FIELDS, "child selection")
        receipt_statics.subject_text(row["subject_id"], error)
        for name in ("request_digest", "policy_digest", "certificate_digest"):
            retained_selection.commitment(row[name], error)
        selected.append(row)
    subjects = [row["subject_id"] for row in selected]
    if subjects != sorted(set(subjects)):
        raise error("selected children must be sorted and unique by subject")
    return selected


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest",
        "children", "evidence_ref", "policy_digest", "limits"}, "request")
    for name, expected in (("schema_version", REQUEST_VERSION),
                           ("semantic_version", SEMANTIC_VERSION),
                           ("coordinate", COORDINATE),
                           ("proposition_digest", PROPOSITION_DIGEST),
                           ("object_kind", "RECEIPT")):
        if type(selected[name]) is not str or selected[name] != expected:
            raise ReceiptPrerequisiteClosureError(
                "selected RECEIPT closure objective differs")
    receipt_statics.subject_text(selected["subject_id"], ReceiptPrerequisiteClosureError)
    for name in ("object_digest", "evidence_ref", "policy_digest"):
        retained_selection.commitment(selected[name], ReceiptPrerequisiteClosureError)
    selected["children"] = _children(selected["children"])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, ReceiptPrerequisiteClosureError)
    return selected


def receipt_prerequisite_closure_request(*, subject_id: str, object_digest: str,
        children: list[dict[str, str]], evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    """Format intent; only external retention and selection make it authoritative."""
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ReceiptPrerequisiteClosureError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "RECEIPT",
        "subject_id": subject_id, "object_digest": object_digest,
        "children": children, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _child_record(certificate: bytes, child_request: dict[str, Any]) -> dict[str, Any]:
    """Read the retained namespace record of a child that already replayed PASS."""
    retained = strict_json_loads(certificate.decode("utf-8"))["evidence_payloads"]
    evidence = strict_json_loads(receipt_statics.decode_b64(
        retained[child_request["evidence_ref"]], "child retained evidence").decode("utf-8"))
    return evidence["receipt_object"]


def _replay_children(value: dict[str, Any], request: dict[str, Any],
                     budget: Budget) -> tuple[dict[str, list[str]], dict[str, str]]:
    selections = request["children"]
    retained = value["children"]
    if type(retained) is not list or len(retained) != len(selections):
        raise Refuted("retained children differ from the selected children")
    statuses, declared, digests = [], {}, {}
    for selection, item in zip(selections, retained):
        budget.tick()
        row = _record(item, {"child_request", "child_policy", "child_certificate"},
                      "retained child")
        child_request, child_policy = row["child_request"], row["child_policy"]
        if ("sha256:" + canonical_digest(child_request) != selection["request_digest"]
                or "sha256:" + canonical_digest(child_policy) != selection["policy_digest"]):
            raise Refuted("selected child request or policy differs")
        if (type(child_request) is not dict
                or child_request.get("subject_id") != selection["subject_id"]
                or child_request.get("semantic_version") != receipt_statics.SEMANTIC_VERSION
                or child_request.get("coordinate") != receipt_statics.COORDINATE
                or child_request.get("object_kind") != "RECEIPT"):
            raise Refuted("child is not the selected RECEIPT-3.1 subject")
        if (type(row["child_certificate"]) is not str or len(row["child_certificate"])
                > 4 * ((receipt_statics._MAX_CERTIFICATE_BYTES + 2) // 3)):
            raise Unavailable("child certificate bound exhausted")
        certificate = receipt_statics.decode_b64(row["child_certificate"], "child certificate")
        if "sha256:" + hashlib.sha256(certificate).hexdigest() != selection["certificate_digest"]:
            raise Refuted("selected child certificate differs")
        try:
            result = receipt_statics.recheck_receipt_statics_certificate(
                certificate, expected_request=child_request, policy=child_policy)
        except receipt_statics.ReceiptStaticsError as exc:
            raise Refuted("selected RECEIPT-3.1 child does not replay") from exc
        statuses.append(result["status"])
        if result["status"] == "PASS":
            record = _child_record(certificate, child_request)
            digest = NamespaceObject.create(record["object_id"], record["kind"],
                                            record["payload"], record["operands"]).digest
            if (record["object_id"] != selection["subject_id"]
                    or digest != child_request["object_digest"]):
                raise Refuted("retained child record differs from its selection")
            declared[selection["subject_id"]] = list(record["payload"]["prerequisites"])
            digests[selection["subject_id"]] = digest
    if any(status not in ("PASS", "UNKNOWN") for status in statuses):
        raise Refuted("a selected RECEIPT-3.1 child did not pass")
    if "UNKNOWN" in statuses:
        raise Unavailable("a selected RECEIPT-3.1 child remains UNKNOWN")
    return declared, digests


def _check_cone(declared: dict[str, list[str]], root: str, budget: Budget) -> int:
    """Closed reachability from the root, then Kahn acyclicity; returns edge count."""
    reached, pending = {root}, [root]
    while pending:
        node = pending.pop()
        for prerequisite in declared[node]:
            budget.tick()
            if prerequisite not in declared:
                raise Refuted("declared prerequisite " + prerequisite
                              + " is not a retained child")
            if prerequisite not in reached:
                reached.add(prerequisite)
                pending.append(prerequisite)
    if reached != set(declared):
        raise Refuted("a retained child lies outside the declared prerequisite cone")
    # Edge node -> prerequisite: a prerequisite must be ordered before its dependant.
    waiting = {node: len(declared[node]) for node in declared}
    dependants: dict[str, list[str]] = {node: [] for node in declared}
    for node, prerequisites in declared.items():
        for prerequisite in prerequisites:
            budget.tick()
            dependants[prerequisite].append(node)
    ready = deque(sorted(node for node, count in waiting.items() if count == 0))
    ordered = 0
    while ready:
        node = ready.popleft()
        ordered += 1
        for dependant in dependants[node]:
            budget.tick()
            waiting[dependant] -= 1
            if waiting[dependant] == 0:
                ready.append(dependant)
    if ordered != len(declared):
        raise Refuted("declared prerequisite cone has a cycle")
    return sum(len(prerequisites) for prerequisites in declared.values())


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        if len(data) > limits["max_evidence_bytes"]:
            raise Unavailable("retained evidence byte bound exhausted")
        if len(request["children"]) > limits["max_children"]:
            raise Unavailable("selected child count bound exhausted")
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "children"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained closure evidence differs")
        budget = Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        declared, digests = _replay_children(value, request, budget)
        if request["subject_id"] not in declared:
            raise Refuted("selected root RECEIPT is not among the selected children")
        if digests[request["subject_id"]] != request["object_digest"]:
            raise Refuted("selected root RECEIPT record differs from its child")
        edges = _check_cone(declared, request["subject_id"], budget)
        return MechanismDecision(MechanismOutcome.PASS,
            "declared prerequisite cone is closed over retained children and acyclic",
            {"members": len(declared), "declared_edges": edges,
             "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except RecursionError:
        return MechanismDecision(MechanismOutcome.UNKNOWN, "checker recursion ceiling exhausted")
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ReceiptPrerequisiteClosureMechanism:
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
                                     "bound RECEIPT closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected closure bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ReceiptPrerequisiteClosureError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ReceiptPrerequisiteClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "RECEIPT", "scope": SCOPE,
        "declared_prerequisite_cone_closure": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED"),
        "claim_truth": "NOT_ESTABLISHED",
        "actual_dependency": "NOT_ESTABLISHED",
        "transformation_closure": "NOT_ESTABLISHED",
        "proof_bound_completeness": "NOT_ESTABLISHED",
        "audit_validation_replay": "NOT_ESTABLISHED",
        "external_referent_bytes": "NOT_ESTABLISHED",
        "hash_chain_continuity": "NOT_ESTABLISHED",
        "issuer_authenticity": "NOT_ESTABLISHED",
        "whole_receipt_closure": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise ReceiptPrerequisiteClosureError("certificate byte bound exhausted")
    return encoded


def build_receipt_prerequisite_closure_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    """Replay selected children and the declared cone; retain exact evidence."""
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ReceiptPrerequisiteClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ReceiptPrerequisiteClosureError(
                "evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_receipt_prerequisite_closure_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Replay exact certificate bytes against independent request and policy."""
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ReceiptPrerequisiteClosureError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise ReceiptPrerequisiteClosureError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ReceiptPrerequisiteClosureError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ReceiptPrerequisiteClosureError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, ReceiptPrerequisiteClosureError):
            raise
        raise ReceiptPrerequisiteClosureError(
            "invalid retained RECEIPT closure certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "PROPOSITION_DIGEST", "MAX_CHILDREN", "ReceiptPrerequisiteClosureDescriptor",
           "ReceiptPrerequisiteClosureError", "registration",
           "receipt_prerequisite_closure_policy", "receipt_prerequisite_closure_request",
           "build_receipt_prerequisite_closure_certificate",
           "recheck_receipt_prerequisite_closure_certificate"]
