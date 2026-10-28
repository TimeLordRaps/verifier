"""Current HYPER-2.3: one UNKNOWN direct operand makes the composition UNKNOWN.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Byte limits are bytes; tiers, counts and
checking budgets are dimensionless. Each selected operand verdict comes from
replaying an exact retained child certificate through the registered public
route. No strength order, authority, privacy, consent or security conclusion.
"""
from __future__ import annotations

import base64
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
from verifier.core.namespace import (NamespaceObject, ObjectCoordinate,
    ObjectKind, assess_composition)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "HYPER-2.3"
REQUEST_VERSION = "verifier-current-hyper-unknown-absorption-request-1"
POLICY_VERSION = "verifier-current-hyper-unknown-absorption-policy-1"
CERTIFICATE_VERSION = "verifier-current-hyper-unknown-absorption-certificate-1"
EVIDENCE_VERSION = "verifier-current-hyper-unknown-absorption-evidence-1"
MECHANISM_ID = "verifier.current-hyper.unknown-absorption.1"
SCOPE = "selected_direct_operand_verdict_composition"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024, "max_objects": 256,
             "max_children": 64}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_SELECTION_FIELDS = frozenset({"target", "coordinate", "request_digest",
                               "policy_digest", "certificate_digest"})
_CHILD_FIELDS = frozenset({"target", "coordinate", "request", "policy", "certificate"})
_ROUTES_PATH = Path(__file__).with_name("current_object_routes.py")


class HyperUnknownAbsorptionError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "HYPER", "scope": SCOPE,
        "proposition": (
            "For one exact HYPER record in an exact retained typed collection, "
            "each selected child certificate is bound to one distinct direct "
            "operand record and replayed through the registered current-object "
            "route; a direct operand with no selected child, or whose child "
            "replays UNKNOWN or unavailable, is UNKNOWN, and one UNKNOWN direct "
            "operand makes the composed verdict UNKNOWN; otherwise any FAIL "
            "operand makes it FAIL and all PASS operands make it PASS."),
        "row": ("HYPER-2.3 UNKNOWN absorption: One UNKNOWN operand makes the "
                "composition UNKNOWN."),
        "prerequisites": [
            "exact HYPER record and complete retained typed collection",
            "at most one exact child request, policy and certificate per "
            "direct operand; finite checker limits"],
        "exclusions": [
            "a total order on operand strengths (HYPER-2.1) and strength "
            "non-increase (HYPER-2.2)",
            "recomposition, associativity and depth propagation (HYPER-2.4 "
            "to HYPER-2.6)",
            "transitive operand closure or saturation (HYPER-4.1)",
            "whole HYPER dynamics tier or object-profile conformance",
            "authority, privacy, consent, governance, security or payload truth"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class HyperUnknownAbsorptionDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, HyperUnknownAbsorptionError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, HyperUnknownAbsorptionError)


def dependency_paths() -> dict[str, Path]:
    """Installed files whose bytes this objective's decision depends on."""
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["current_object_routes.py"] = _ROUTES_PATH
    for name in ("NAMESPACE_OBJECTS.md", "DOMAIN_OBLIGATIONS.md",
                 "CURRENT_HYPER_UNKNOWN_ABSORPTION.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return paths


def mechanism_digest() -> str:
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(dependency_paths().items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=HyperUnknownAbsorptionError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def hyper_unknown_absorption_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def select_children(value: Any, *, max_children: int, by_tier: bool,
                    error_type: type[ValueError]) -> list[dict[str, Any]]:
    """Capture sorted unique child selections before any evidence is read.

    Without ``by_tier`` one selection per target is admitted; with it, one per
    target and meta-tier, sorted by target then tier.
    """
    if type(value) is not list or len(value) > max_children:
        raise error_type("bounded child selection list required")
    rows, keys = [], []
    for item in value:
        row = retained_selection.record(item, set(_SELECTION_FIELDS),
                                        "child selection", error_type)
        target, coordinate = row["target"], row["coordinate"]
        if type(target) is not str or not target.strip() or len(target) > 256:
            raise error_type("bounded child target required")
        if type(coordinate) is not str:
            raise error_type("child coordinate must be plain text")
        try:
            parsed = ObjectCoordinate.parse(coordinate)
        except ValueError as exc:
            raise error_type("child coordinate is not admitted") from exc
        if str(parsed) != coordinate:
            raise error_type("child coordinate is noncanonical")
        for field in ("request_digest", "policy_digest", "certificate_digest"):
            retained_selection.commitment(row[field], error_type)
        keys.append((target, int(parsed.tier)) if by_tier else (target, 0))
        rows.append(row)
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise error_type("child selections must be sorted and unique")
    return rows


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "child_selections",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "HYPER")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise HyperUnknownAbsorptionError("selected HYPER-2.3 objective differs")
    if (type(selected["subject_id"]) is not str or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise HyperUnknownAbsorptionError("bounded HYPER subject required")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, HyperUnknownAbsorptionError)
    selected["child_selections"] = select_children(
        selected["child_selections"], max_children=selected["limits"]["max_children"],
        by_tier=False, error_type=HyperUnknownAbsorptionError)
    return selected


def hyper_unknown_absorption_request(*, subject_id: str, object_digest: str,
        collection_digest: str, child_selections: list[dict[str, Any]],
        evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise HyperUnknownAbsorptionError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "HYPER",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "child_selections": child_selections, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_b64(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise Refuted(label + " must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted(label + " is noncanonical base64")
    return decoded


def _collection(rows: Any, request: dict[str, Any], limits: dict[str, int],
                budget: common_module.Budget) -> dict[str, NamespaceObject]:
    if type(rows) is not list:
        raise Refuted("retained collection requires object rows")
    if len(rows) > limits["max_objects"]:
        raise Unavailable("retained object count exhausted")
    objects = []
    for row in rows:
        budget.tick()
        item = _record(row, {"object_id", "kind", "payload", "operands"}, "object row")
        if type(item["operands"]) is not dict:
            raise Refuted("operand map required")
        record = NamespaceObject.create(item["object_id"], item["kind"],
                                        item["payload"], item["operands"])
        if record.to_dict() != row:
            raise Refuted("retained object row is noncanonical")
        objects.append(record)
    if [item.object_id for item in objects] != sorted(item.object_id for item in objects):
        raise Refuted("retained object rows are not in identifier order")
    assessed = assess_composition(objects, expected_digest=request["collection_digest"],
        max_objects=limits["max_objects"], max_operations=limits["max_operations"])
    if assessed.verdict.value == "UNKNOWN":
        raise Unavailable(assessed.reason)
    if assessed.verdict.value != "PASS":
        raise Refuted(assessed.reason)
    return {item.object_id: item for item in objects}


def bound_children(value: dict[str, Any], request: dict[str, Any],
                   budget: common_module.Budget, *, kind_must_match: bool
                   ) -> tuple[dict[str, NamespaceObject], NamespaceObject, list[dict[str, Any]]]:
    """Bind every selected child to one exact direct operand, then replay it.

    Every binding check finishes before the first replay. Returns the direct
    operand records, the HYPER root and one ``{target, coordinate, tier,
    status}`` row per selection in selection order. A route refusal is
    ``Refuted``; an unavailable route or a non-reproduced replay is ``UNKNOWN``.
    """
    limits = request["limits"]
    by_id = _collection(value["objects"], request, limits, budget)
    root = by_id.get(request["subject_id"])
    if root is None or root.kind is not ObjectKind.HYPER or root.digest != request["object_digest"]:
        raise Refuted("selected HYPER identifier, kind or digest differs")
    targets = sorted({target for _role, refs in root.operands for target in refs})
    if not targets or root.object_id in targets:
        raise Refuted("relational composition requires named nonempty foreign operands")
    operands = {target: by_id[target] for target in targets}
    selections, children = request["child_selections"], value["children"]
    if type(children) is not list or len(children) != len(selections):
        raise Refuted("retained children differ from the selected children")
    captured = []
    for selection, child in zip(selections, children):
        budget.tick()
        child = _record(child, set(_CHILD_FIELDS), "child")
        target = selection["target"]
        if child["target"] != target or child["coordinate"] != selection["coordinate"]:
            raise Refuted("retained child target or coordinate differs")
        if target not in operands:
            raise Refuted("selected child names a record that is not a direct operand")
        operand = operands[target]
        parsed = ObjectCoordinate.parse(selection["coordinate"])
        if kind_must_match and parsed.object_kind is not operand.kind:
            raise Refuted("selected child coordinate is on another kind's ladder")
        child_request, child_policy = child["request"], child["policy"]
        if ("sha256:" + canonical_digest(child_request) != selection["request_digest"]
                or "sha256:" + canonical_digest(child_policy) != selection["policy_digest"]):
            raise Refuted("selected child request or policy differs")
        certificate = _decode_b64(child["certificate"], "child certificate")
        if len(certificate) > _MAX_CERTIFICATE_BYTES:
            raise Unavailable("child certificate byte bound exhausted")
        if "sha256:" + hashlib.sha256(certificate).hexdigest() != selection["certificate_digest"]:
            raise Refuted("selected child certificate differs")
        if (type(child_request) is not dict or type(child_policy) is not dict
                or child_request.get("semantic_version") != SEMANTIC_VERSION
                or child_request.get("coordinate") != selection["coordinate"]
                or child_request.get("subject_id") != target
                or child_request.get("object_digest") != operand.digest):
            raise Refuted("selected child is not bound to the exact direct operand record")
        captured.append((selection, operand, child_request, child_policy,
                         certificate, int(parsed.tier)))
    from verifier.domains.contracts import current_object_routes as routes

    # The selector-migration route module raises this when a selected child checker cannot be reached. A route module
    # without it maps that case to a refusal, and an empty tuple in an except clause matches nothing.
    unavailable = getattr(routes, "CurrentObjectRouteUnavailable", ())
    rows = []
    for selection, operand, child_request, child_policy, certificate, tier in captured:
        budget.tick()
        try:
            report = routes.replay_current_object_certificate(
                certificate, semantic_version=SEMANTIC_VERSION,
                objective=selection["coordinate"], represented_kind=operand.kind.value,
                expected_request=child_request, policy=child_policy)
        except unavailable:
            status = "UNKNOWN"
        except routes.CurrentObjectRouteRefusal as exc:
            raise Refuted("selected child certificate does not replay") from exc
        else:
            status = (report["computational_status"]
                      if report["replay_status"] == "REPRODUCED" else "UNKNOWN")
        if status not in ("PASS", "FAIL", "UNKNOWN"):
            raise Refuted("selected child replay returned an unsupported verdict")
        rows.append({"target": selection["target"], "coordinate": selection["coordinate"],
                     "tier": tier, "status": status})
    return operands, root, rows


def read_evidence(data: bytes, request: dict[str, Any], version: str
                  ) -> tuple[dict[str, Any], common_module.Budget]:
    value = retained_selection.record(strict_json_loads(data.decode("utf-8")),
        {"schema_version", "objects", "children"}, "evidence", Refuted)
    if value["schema_version"] != version or canonical_bytes(value) != data:
        raise Refuted("retained composition evidence differs")
    limits = request["limits"]
    budget = common_module.Budget(limits["max_operations"], limits["max_items"])
    common_module.inspect_structure(value, budget)
    return value, budget


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    try:
        value, budget = read_evidence(data, request, EVIDENCE_VERSION)
        operands, _root, rows = bound_children(value, request, budget,
                                               kind_must_match=False)
        statuses = {target: "UNKNOWN" for target in operands}
        for row in rows:
            statuses[row["target"]] = row["status"]
        observations = {"operand_statuses": statuses, "operations": budget.used}
        if any(status == "UNKNOWN" for status in statuses.values()):
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                "one UNKNOWN direct operand makes the composition UNKNOWN", observations)
        if any(status == "FAIL" for status in statuses.values()):
            return MechanismDecision(MechanismOutcome.FAIL,
                "a direct operand FAILs and no direct operand is UNKNOWN", observations)
        return MechanismDecision(MechanismOutcome.PASS,
            "every direct operand replays PASS; nothing to absorb", observations)
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _Mechanism:
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
                                     "bound HYPER-2.3 proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected composition bundle required")
        return _evaluate(evidence[0], self.request)


_NOT_ESTABLISHED = ("hyper_dynamics_tier", "strength_total_order",
    "strength_non_increase", "recomposition", "associativity",
    "depth_propagation", "operand_saturation", "authority", "privacy",
    "consent", "governance", "security", "object_profile_conformance")


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise HyperUnknownAbsorptionError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_Mechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "HYPER", "scope": SCOPE,
        "operand_verdict_composition": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        **{field: "NOT_ESTABLISHED" for field in _NOT_ESTABLISHED},
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
        raise HyperUnknownAbsorptionError("certificate byte bound exhausted")
    return encoded


def build_hyper_unknown_absorption_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]):
            raise HyperUnknownAbsorptionError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise HyperUnknownAbsorptionError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_hyper_unknown_absorption_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise HyperUnknownAbsorptionError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise HyperUnknownAbsorptionError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise HyperUnknownAbsorptionError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise HyperUnknownAbsorptionError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, HyperUnknownAbsorptionError):
            raise
        raise HyperUnknownAbsorptionError(
            "invalid retained HYPER-2.3 certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST",
           "HyperUnknownAbsorptionDescriptor", "HyperUnknownAbsorptionError",
           "registration", "hyper_unknown_absorption_policy",
           "hyper_unknown_absorption_request",
           "build_hyper_unknown_absorption_certificate",
           "recheck_hyper_unknown_absorption_certificate"]
