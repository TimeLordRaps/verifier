"""Current VERIFIER-4.1: coverage closure over one declared finite claim class.

Verifier Standard (VSTD); directed acyclic graph (DAG); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Member, node and
boundary counts are dimensionless; evidence limits are bytes. The class is
enumerated from a retained DAG profile and policy; every member and every
declared counterexample boundary is replayed. Completeness beyond the
declared finite class remains NOT_ESTABLISHED.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
import threading
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
from verifier.domains.contracts import certificate_dag, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "VERIFIER-4.1"
REQUEST_VERSION = "verifier-current-verifier-coverage-closure-request-1"
POLICY_VERSION = "verifier-current-verifier-coverage-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-verifier-coverage-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-verifier-coverage-closure-evidence-1"
MECHANISM_ID = "verifier.current-verifier.declared-class-coverage-closure.1"
SCOPE = "selected_finite_claim_class_coverage_and_counterexample_boundaries"
EXCLUDED_FACETS = ("completeness_beyond_declared_class", "declared_class_authority",
    "class_wide_soundness", "checker_correctness", "whole_verifier_closure",
    "object_profile_conformance")
_SELF_OBJECTIVES = frozenset({"VERIFIER-3.1", "VERIFIER-4.1"})
_EXPECTED = ("FAIL", "UNKNOWN")
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024, "max_nodes": 512,
             "max_members": 512, "max_boundary_cases": 64}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_MAX_FILES = 1024
_ACTIVE = threading.local()


class VerifierCoverageClosureError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "VERIFIER", "scope": SCOPE,
        "proposition": (
            "The declared finite claim class equals the class enumerated from "
            "the retained independently selected DAG profiles; every member has "
            "a retained native decision that replays PASS with qualified PASS "
            "prerequisites; at least one declared counterexample-boundary case "
            "per class objective exists; and every boundary case replays to its "
            "declared FAIL or UNKNOWN through its registered route."),
        "prerequisites": [
            "exact VERIFIER record naming the class objectives; exact DAG bundle, "
            "policy and artifact file set; exact boundary requests, policies and "
            "certificates; finite checker limits; installed route dispatcher"],
        "exclusions": [
            "completeness beyond the declared finite class",
            "authority or adequacy of the declared class or its profiles",
            "class-wide soundness or correctness of any checker",
            "inputs, objects or claims outside the retained selection",
            "whole VERIFIER closure tier or object-profile conformance",
            "privacy, consent, governance, security, physical or safety conclusions"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class VerifierCoverageClosureDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, VerifierCoverageClosureError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, VerifierCoverageClosureError)


def _label(value: Any, label: str) -> str:
    if (type(value) is not str or not value.strip() or len(value) > 256
            or any(ord(c) < 32 for c in value)):
        raise VerifierCoverageClosureError("bounded " + label + " text required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               namespace_module, common_module, retained_selection, certificate_dag)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["current_object_routes.py"] = Path(__file__).parent / "current_object_routes.py"
    for name in ("NAMESPACE_OBJECTS.md", "CERTIFICATE_DAG.md",
                 "CURRENT_VERIFIER_COVERAGE_CLOSURE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=VerifierCoverageClosureError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def verifier_coverage_closure_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _not_self(objective: str) -> str:
    if objective in _SELF_OBJECTIVES:
        raise VerifierCoverageClosureError(
            "a VERIFIER-3.1 or VERIFIER-4.1 claim is not admissible in its own class")
    return objective


def _claim_class(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list or not 1 <= len(value) <= _CEILINGS["max_members"]:
        raise VerifierCoverageClosureError("one to five hundred twelve class members required")
    rows = []
    for item in value:
        row = _record(item, {"object_id", "claim_id", "semantic_version",
                             "objective", "proposition_digest"}, "class member")
        for field in ("object_id", "claim_id", "semantic_version"):
            _label(row[field], "class member " + field)
        _not_self(_label(row["objective"], "class member objective"))
        _digest(row["proposition_digest"])
        rows.append(row)
    keys = [(row["object_id"], row["claim_id"]) for row in rows]
    if keys != sorted(set(keys)):
        raise VerifierCoverageClosureError("sorted unique class members required")
    return rows


def _boundary_cases(value: Any, objectives: set[tuple[str, str]]) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > _CEILINGS["max_boundary_cases"]:
        raise VerifierCoverageClosureError("at most sixty-four boundary cases admitted")
    from verifier.domains.contracts.current_object_routes import (
        CurrentObjectRouteRefusal, select_current_object_route)
    rows = []
    for item in value:
        row = _record(item, {"case_id", "semantic_version", "objective",
                             "represented_kind", "request_digest", "policy_digest",
                             "certificate_digest", "expected"}, "boundary case")
        for field in ("case_id", "semantic_version", "represented_kind"):
            _label(row[field], "boundary " + field)
        _not_self(_label(row["objective"], "boundary objective"))
        if (row["semantic_version"], row["objective"]) not in objectives:
            raise VerifierCoverageClosureError("boundary case objective is outside the declared class")
        for field in ("request_digest", "policy_digest", "certificate_digest"):
            _digest(row[field])
        if type(row["expected"]) is not str or row["expected"] not in _EXPECTED:
            raise VerifierCoverageClosureError("boundary case must expect FAIL or UNKNOWN")
        try:
            select_current_object_route(semantic_version=row["semantic_version"],
                objective=row["objective"], represented_kind=row["represented_kind"])
        except CurrentObjectRouteRefusal as exc:
            raise VerifierCoverageClosureError("boundary route is not registered") from exc
        rows.append(row)
    identities = [row["case_id"] for row in rows]
    if identities != sorted(set(identities)):
        raise VerifierCoverageClosureError("sorted unique boundary case identifiers required")
    return rows


def _objectives(claim_class: list[dict[str, Any]]) -> list[list[str]]:
    return [list(pair) for pair in sorted({(row["semantic_version"], row["objective"])
                                           for row in claim_class})]


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "claim_class", "boundary_cases",
        "dag_bundle_digest", "dag_policy_digest", "artifact_files_digest",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "VERIFIER")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise VerifierCoverageClosureError("selected VERIFIER coverage objective differs")
    _label(selected["subject_id"], "VERIFIER subject")
    for field in ("object_digest", "collection_digest", "dag_bundle_digest",
                  "dag_policy_digest", "artifact_files_digest", "evidence_ref",
                  "policy_digest"):
        _digest(selected[field])
    selected["claim_class"] = _claim_class(selected["claim_class"])
    selected["boundary_cases"] = _boundary_cases(selected["boundary_cases"],
        {tuple(pair) for pair in _objectives(selected["claim_class"])})
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, VerifierCoverageClosureError)
    return selected


def verifier_coverage_closure_request(*, subject_id: str, object_digest: str,
        collection_digest: str, claim_class: list[dict[str, Any]],
        boundary_cases: list[dict[str, Any]], dag_bundle_digest: str,
        dag_policy_digest: str, artifact_files_digest: str, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise VerifierCoverageClosureError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "VERIFIER",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "claim_class": claim_class,
        "boundary_cases": boundary_cases, "dag_bundle_digest": dag_bundle_digest,
        "dag_policy_digest": dag_policy_digest,
        "artifact_files_digest": artifact_files_digest,
        "evidence_ref": evidence_ref,
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


def _raw(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _subject(record: Any, request: dict[str, Any]) -> None:
    if type(record) is not dict or set(record) != {"object_id", "kind", "payload", "operands"}:
        raise Refuted("retained VERIFIER record fields differ")
    item = NamespaceObject.create(record["object_id"], record["kind"],
                                  record["payload"], record["operands"])
    if item.to_dict() != record:
        raise Refuted("retained VERIFIER record is noncanonical")
    if (item.kind != ObjectKind.VERIFIER or item.object_id != request["subject_id"]
            or item.digest != request["object_digest"]
            or composition_digest([item]) != request["collection_digest"]):
        raise Refuted("retained VERIFIER record differs from the selected subject")
    if item.payload != {"checker_kind": "CURRENT_OBJECT_ROUTES",
                        "objectives": _objectives(request["claim_class"])}:
        raise Refuted("VERIFIER record does not name the declared class objectives")


def _dag_record(raw: bytes) -> dict[str, Any]:
    try:
        return certificate_dag._parse(raw)
    except certificate_dag._Exhausted as exc:
        raise Unavailable("retained DAG record bound exhausted") from exc


def _enumerate(bundle: dict[str, Any], dag_policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Read the claim class from the selected profiles; never from the request."""
    profiles = {_raw(canonical_bytes(profile)): profile for profile in bundle["profiles"]}
    approved = set(dag_policy["approved_profiles"])
    members = []
    for selected in dag_policy["required_objects"]:
        pin = selected["profile_digest"]
        if pin not in approved or pin not in profiles:
            raise Unavailable("CLASS_ENUMERATION_INCOMPLETE: profile for "
                              + str(selected["object_id"]) + " is not retained and approved")
        for claim in profiles[pin]["obligations"]:
            if claim["objective"] in _SELF_OBJECTIVES:
                raise Refuted("retained profile places a VERIFIER-3.1 or VERIFIER-4.1 claim in its own class")
            members.append({"object_id": selected["object_id"], "claim_id": claim["claim_id"],
                            "semantic_version": claim["semantic_version"],
                            "objective": claim["objective"],
                            "proposition_digest": claim["proposition_digest"]})
    return sorted(members, key=lambda row: (row["object_id"], row["claim_id"]))


def _boundary(case: dict[str, Any], entry: Any, routes: Any) -> str:
    if type(entry) is not dict or set(entry) != {"request", "policy", "certificate"}:
        raise Refuted("boundary evidence fields differ")
    certificate = _decode_b64(entry["certificate"], "boundary certificate")
    if ("sha256:" + canonical_digest(entry["request"]) != case["request_digest"]
            or "sha256:" + canonical_digest(entry["policy"]) != case["policy_digest"]
            or _raw(certificate) != case["certificate_digest"]):
        raise Refuted("selected boundary case bytes differ")
    # The selector-migration route module raises this when a selected child checker cannot be reached. A route module
    # without it maps that case to a refusal, and an empty tuple in an except clause matches nothing.
    unavailable = getattr(routes, "CurrentObjectRouteUnavailable", ())
    try:
        report = routes.replay_current_object_certificate(certificate,
            semantic_version=case["semantic_version"], objective=case["objective"],
            represented_kind=case["represented_kind"],
            expected_request=entry["request"], policy=entry["policy"])
    except unavailable:
        return "UNAVAILABLE"
    except routes.CurrentObjectRouteRefusal:
        return "REFUSED"
    if report["replay_status"] != "REPRODUCED":
        return "UNKNOWN"
    return report["computational_status"]


def _closure(request: dict[str, Any], value: dict[str, Any],
             budget: common_module.Budget) -> MechanismDecision:
    limits = request["limits"]
    bundle_bytes = _decode_b64(value["dag_bundle"], "DAG bundle")
    policy_bytes = _decode_b64(value["dag_policy"], "DAG policy")
    if (_raw(bundle_bytes) != request["dag_bundle_digest"]
            or _raw(policy_bytes) != request["dag_policy_digest"]):
        raise Refuted("selected DAG bundle or policy differs")
    carried = value["artifact_files"]
    if type(carried) is not dict or len(carried) > _MAX_FILES:
        raise Refuted("bounded artifact file map required")
    files = {path: _decode_b64(data, "artifact file") for path, data in sorted(carried.items())}
    if certificate_dag.artifact_files_digest(files) != request["artifact_files_digest"]:
        raise Refuted("selected artifact file set differs")
    bundle, dag_policy = _dag_record(bundle_bytes), _dag_record(policy_bytes)
    enumerated = _enumerate(bundle, dag_policy)
    if len(enumerated) > limits["max_members"] or len(request["claim_class"]) > limits["max_members"]:
        raise Unavailable("class member bound exhausted")
    if len(bundle["nodes"]) > limits["max_nodes"]:
        raise Unavailable("DAG node bound exhausted before native replay")
    if len(request["boundary_cases"]) > limits["max_boundary_cases"]:
        raise Unavailable("boundary case bound exhausted before native replay")
    budget.tick(len(enumerated) + len(bundle["nodes"]) + len(request["boundary_cases"]))
    failures, unknowns = [], []
    if enumerated != request["claim_class"]:
        failures.append("DECLARED_CLASS_DIFFERS_FROM_ENUMERATED_CLASS")
    assessment = certificate_dag.assess_certificate_dependencies(
        bundle_bytes, expected_policy_bytes=policy_bytes, artifact_files=files)
    if assessment["status"] == "FAIL":
        failures.append("DAG:" + ",".join(assessment["blockers"]))
    elif assessment["status"] != "PASS":
        unknowns.append("DAG:" + ",".join(assessment["blockers"]))
    claims = {(node["object_id"], node["claim_id"]): node["node_id"]
              for node in bundle["nodes"]}
    decided = {node["node_id"]: node for node in assessment["nodes"]}
    member_rows = []
    for member in enumerated:
        budget.tick()
        key = (member["object_id"], member["claim_id"])
        node = decided.get(claims.get(key))
        label = member["object_id"] + ":" + member["claim_id"]
        if node is None:
            unknowns.append("MEMBER_DECISION_MISSING:" + label)
            member_rows.append({"member": label, "node_id": claims.get(key),
                                "direct_status": None, "qualified_status": None,
                                "reason": None})
            continue
        member_rows.append({"member": label, "node_id": node["node_id"],
                            "direct_status": node["direct_status"],
                            "qualified_status": node["qualified_status"],
                            "reason": node["reason"]})
        if node["direct_status"] == "FAIL" or node["qualified_status"] == "FAIL":
            failures.append("MEMBER_FAILS:" + label)
        elif (node["direct_status"], node["qualified_status"], node["reason"]) != (
                "PASS", "PASS", "NATIVE_REPLAY"):
            unknowns.append("MEMBER_UNDECIDED:" + label)
    cases = request["boundary_cases"]
    covered = {(case["semantic_version"], case["objective"]) for case in cases}
    for semantic_version, objective in _objectives(request["claim_class"]):
        if (semantic_version, objective) not in covered:
            unknowns.append("COUNTEREXAMPLE_BOUNDARY_MISSING:" + objective)
    carried_cases = value["boundary_evidence"]
    if type(carried_cases) is not dict or set(carried_cases) - {case["case_id"] for case in cases}:
        raise Refuted("boundary evidence names an unselected case")
    from verifier.domains.contracts import current_object_routes as routes
    boundary_rows = []
    for case in cases:
        budget.tick()
        if case["case_id"] not in carried_cases:
            unknowns.append("BOUNDARY_EVIDENCE_MISSING:" + case["case_id"])
            boundary_rows.append({"case_id": case["case_id"], "expected": case["expected"],
                                  "observed": None})
            continue
        observed = _boundary(case, carried_cases[case["case_id"]], routes)
        boundary_rows.append({"case_id": case["case_id"], "expected": case["expected"],
                              "observed": observed})
        if observed == case["expected"]:
            continue
        if observed == "UNAVAILABLE" or (case["expected"] == "FAIL" and observed == "UNKNOWN"):
            unknowns.append("BOUNDARY_UNDECIDED:" + case["case_id"])
        else:
            failures.append("BOUNDARY_" + observed + ":" + case["case_id"])
    observations = {"members": len(enumerated), "boundary_cases": len(cases),
        "assessment_status": assessment["status"],
        "assessment_digest": assessment["assessment_digest"],
        "member_nodes": member_rows, "boundary": boundary_rows}
    if failures:
        return MechanismDecision(MechanismOutcome.FAIL,
            "declared class coverage refuted: " + ", ".join(failures), observations)
    if unknowns:
        return MechanismDecision(MechanismOutcome.UNKNOWN,
            "declared class coverage not established: " + ", ".join(unknowns), observations)
    return MechanismDecision(MechanismOutcome.PASS,
        "every enumerated member and declared counterexample boundary rechecks", observations)


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "verifier_object", "dag_bundle",
                         "dag_policy", "artifact_files", "boundary_evidence"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained coverage evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        _subject(value["verifier_object"], request)
        if getattr(_ACTIVE, "depth", 0):
            raise Unavailable("a nested VERIFIER-4.1 closure is not evaluated")
        _ACTIVE.depth = 1
        try:
            return _closure(request, value, budget)
        finally:
            _ACTIVE.depth = 0
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _VerifierCoverageClosureMechanism:
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
                                     "bound VERIFIER coverage proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected coverage evidence bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise VerifierCoverageClosureError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_VerifierCoverageClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "VERIFIER", "scope": SCOPE,
        "declared_class_coverage_closure": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        **{field: "NOT_ESTABLISHED" for field in EXCLUDED_FACETS},
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
        raise VerifierCoverageClosureError("certificate byte bound exhausted")
    return encoded


def build_verifier_coverage_closure_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise VerifierCoverageClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise VerifierCoverageClosureError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_verifier_coverage_closure_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise VerifierCoverageClosureError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise VerifierCoverageClosureError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise VerifierCoverageClosureError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise VerifierCoverageClosureError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, VerifierCoverageClosureError):
            raise
        raise VerifierCoverageClosureError(
            "invalid retained VERIFIER coverage certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SCOPE",
           "VerifierCoverageClosureDescriptor", "VerifierCoverageClosureError",
           "registration", "verifier_coverage_closure_policy",
           "verifier_coverage_closure_request",
           "build_verifier_coverage_closure_certificate",
           "recheck_verifier_coverage_closure_certificate"]
