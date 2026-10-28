"""Current VERIFIER-3.1: checker-observed constraints bound to one verifier run.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Event maxima count CPython trace events
(dimensionless); report maxima are bytes. The run is two in-process replays of
one separately selected registered child certificate. Caller declarations are
retained and counted but never admitted as observations. Execution-substrate
identity, physical resources and isolation remain NOT_ESTABLISHED.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys
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
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "VERIFIER-3.1"
REQUEST_VERSION = "verifier-current-verifier-run-constraints-request-1"
POLICY_VERSION = "verifier-current-verifier-run-constraints-policy-1"
CERTIFICATE_VERSION = "verifier-current-verifier-run-constraints-certificate-1"
EVIDENCE_VERSION = "verifier-current-verifier-run-constraints-evidence-1"
RUN_VERSION = "verifier-current-verifier-run-1"
MECHANISM_ID = "verifier.current-verifier.run-bound-constraint-observations.1"
SCOPE = "selected_run_bound_constraint_observations"
PRODUCER = "checker:" + MECHANISM_ID
OBSERVED_QUANTITIES = ("replay_report_bytes", "traced_python_events")
REPLAYS = 2
EXCLUDED_FACETS = ("execution_substrate_identity", "physical_resource_constraints",
    "isolation", "class_wide_soundness", "determinism_on_other_inputs",
    "cross_process_or_platform_determinism", "general_termination",
    "whole_verifier_statics", "object_profile_conformance")
_SELF_OBJECTIVES = frozenset({"VERIFIER-3.1", "VERIFIER-4.1"})
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024,
             "max_replay_events": 20_000_000}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_MAX_CONSTRAINTS = 32
_MAX_DECLARED = 64
_MAX_VALUE = 2**53 - 1
_ACTIVE = threading.local()


class VerifierRunConstraintsError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


class _TraceExhausted(BaseException):
    """Stops a traced replay once its selected event allowance is spent."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "VERIFIER", "scope": SCOPE,
        "proposition": (
            "Every declared constraint on the selected VERIFIER run is matched "
            "by an observation that this checker produced during that run, "
            "bound to the run digest, and within the declared maximum; the "
            "run is two traced in-process replays of one exact separately "
            "selected registered child certificate that reproduce identical "
            "canonical reports and a child PASS."),
        "prerequisites": [
            "exact VERIFIER record naming the child route; exact child request, "
            "policy and certificate; finite constraint maxima; finite checker "
            "limits; installed interpreter and route dispatcher"],
        "exclusions": [
            "execution-substrate identity, hardware, operating system or interpreter identity",
            "physical resource constraints such as memory, time, energy or device use",
            "process, sandbox, network or side-channel isolation",
            "caller-declared observations, determinism on other inputs or processes",
            "class-wide checker soundness, termination or whole VERIFIER statics",
            "object-profile conformance, privacy, consent, governance, security or authority"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class VerifierRunConstraintsDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, VerifierRunConstraintsError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, VerifierRunConstraintsError)


def _label(value: Any, label: str) -> str:
    if (type(value) is not str or not value.strip() or len(value) > 256
            or any(ord(c) < 32 for c in value)):
        raise VerifierRunConstraintsError("bounded " + label + " text required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               namespace_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["current_object_routes.py"] = Path(__file__).parent / "current_object_routes.py"
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_VERIFIER_RUN_CONSTRAINTS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=VerifierRunConstraintsError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def verifier_run_constraints_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _child_route(semantic_version: Any, objective: Any, kind: Any) -> None:
    for value, label in ((semantic_version, "child semantic version"),
                         (objective, "child objective"), (kind, "child kind")):
        _label(value, label)
    if objective in _SELF_OBJECTIVES:
        raise VerifierRunConstraintsError(
            "a VERIFIER-3.1 or VERIFIER-4.1 certificate is not an admissible child")
    from verifier.domains.contracts.current_object_routes import (
        CurrentObjectRouteRefusal, select_current_object_route)
    try:
        select_current_object_route(semantic_version=semantic_version,
                                    objective=objective, represented_kind=kind)
    except CurrentObjectRouteRefusal as exc:
        raise VerifierRunConstraintsError("child route is not registered") from exc


def _constraints(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list or not 1 <= len(value) <= _MAX_CONSTRAINTS:
        raise VerifierRunConstraintsError("one to thirty-two declared constraints required")
    rows = []
    for item in value:
        row = _record(item, {"constraint_id", "quantity", "maximum"}, "constraint")
        _label(row["constraint_id"], "constraint identifier")
        _label(row["quantity"], "constraint quantity")
        if type(row["maximum"]) is not int or not 0 <= row["maximum"] <= _MAX_VALUE:
            raise VerifierRunConstraintsError("finite nonnegative integer maximum required")
        rows.append(row)
    identities = [row["constraint_id"] for row in rows]
    if identities != sorted(set(identities)):
        raise VerifierRunConstraintsError("sorted unique constraint identifiers required")
    return rows


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "child_semantic_version",
        "child_objective", "child_represented_kind", "child_request_digest",
        "child_policy_digest", "child_certificate_digest", "declarant",
        "constraints", "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "VERIFIER")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise VerifierRunConstraintsError("selected VERIFIER run objective differs")
    _label(selected["subject_id"], "VERIFIER subject")
    _child_route(selected["child_semantic_version"], selected["child_objective"],
                 selected["child_represented_kind"])
    if _label(selected["declarant"], "declarant").startswith("checker:"):
        raise VerifierRunConstraintsError("a caller declarant cannot claim a checker producer")
    for field in ("object_digest", "collection_digest", "child_request_digest",
                  "child_policy_digest", "child_certificate_digest",
                  "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["constraints"] = _constraints(selected["constraints"])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, VerifierRunConstraintsError)
    return selected


def verifier_run_constraints_request(*, subject_id: str, object_digest: str,
        collection_digest: str, child_semantic_version: str, child_objective: str,
        child_represented_kind: str, child_request_digest: str,
        child_policy_digest: str, child_certificate_digest: str, declarant: str,
        constraints: list[dict[str, Any]], evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise VerifierRunConstraintsError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "VERIFIER",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "child_semantic_version": child_semantic_version,
        "child_objective": child_objective,
        "child_represented_kind": child_represented_kind,
        "child_request_digest": child_request_digest,
        "child_policy_digest": child_policy_digest,
        "child_certificate_digest": child_certificate_digest,
        "declarant": declarant, "constraints": constraints,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def run_digest(request: dict[str, Any]) -> str:
    """Name the run: mechanism, policy, subject, child selection and limits.

    Constraints, declarant and evidence are excluded so that a declaration can
    cite the run it describes without changing it.
    """
    selected = _request(request)
    return "sha256:" + canonical_digest({"schema_version": RUN_VERSION,
        "mechanism_id": MECHANISM_ID, "replays": REPLAYS,
        **{key: selected[key] for key in (
            "policy_digest", "subject_id", "object_digest", "collection_digest",
            "child_semantic_version", "child_objective", "child_represented_kind",
            "child_request_digest", "child_policy_digest",
            "child_certificate_digest", "limits")}})


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
    if item.payload != {"checker_kind": "CURRENT_OBJECT_ROUTE",
            "semantic_version": request["child_semantic_version"],
            "objective": request["child_objective"],
            "represented_kind": request["child_represented_kind"]}:
        raise Refuted("VERIFIER record does not name the observed checker route")


def _declared(value: Any, budget: common_module.Budget) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise Refuted("declared observations must be a list")
    if len(value) > _MAX_DECLARED:
        raise Unavailable("declared observation count exhausted")
    rows, seen = [], set()
    for item in value:
        budget.tick()
        if type(item) is not dict or set(item) != {
                "observation_id", "run_digest", "producer", "quantity", "value"}:
            raise Refuted("declared observation fields differ")
        for field in ("observation_id", "producer", "quantity"):
            if type(item[field]) is not str or not item[field].strip() or len(item[field]) > 256:
                raise Refuted("declared observation text is unbounded")
        if type(item["run_digest"]) is not str or not item["run_digest"].startswith("sha256:"):
            raise Refuted("declared observation run digest is malformed")
        if type(item["value"]) is not int or not 0 <= item["value"] <= _MAX_VALUE:
            raise Refuted("declared observation value is not a finite integer")
        if item["observation_id"] in seen:
            raise Refuted("declared observation identifiers repeat")
        seen.add(item["observation_id"])
        rows.append(item)
    return rows


def _canonical_copy(value: Any) -> Any:
    return strict_json_loads(canonical_bytes(value).decode("utf-8"))


def _traced_replay(routes: Any, certificate: bytes, request: dict[str, Any],
                   child_request: Any, child_policy: Any, allowance: int):
    """Replay the child once under a counting tracer; never trust its own report of cost."""
    expected_request, policy = _canonical_copy(child_request), _canonical_copy(child_policy)
    state = {"events": 0, "exhausted": False}

    def tracer(frame: Any, event: str, arg: Any) -> Any:
        state["events"] += 1
        if state["events"] > allowance:
            state["exhausted"] = True
            raise _TraceExhausted()
        return tracer

    # The selector-migration route module raises this when a selected child checker cannot be reached. A route module
    # without it maps that case to a refusal, and an empty tuple in an except clause matches nothing.
    unavailable = getattr(routes, "CurrentObjectRouteUnavailable", ())
    report, failure = None, None
    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        report = routes.replay_current_object_certificate(certificate,
            semantic_version=request["child_semantic_version"],
            objective=request["child_objective"],
            represented_kind=request["child_represented_kind"],
            expected_request=expected_request, policy=policy)
    except _TraceExhausted:
        pass
    except unavailable:
        failure = "UNAVAILABLE"
    except routes.CurrentObjectRouteRefusal:
        failure = "REFUSED"
    finally:
        intact = sys.gettrace() is tracer
        sys.settrace(previous)
    return report, failure, state["exhausted"], intact


def _observe(request: dict[str, Any], certificate: bytes, child_request: Any,
             child_policy: Any) -> MechanismDecision:
    limits = request["limits"]
    declared_events = [row["maximum"] for row in request["constraints"]
                       if row["quantity"] == "traced_python_events"]
    allowance = min(declared_events + [limits["max_replay_events"]])
    from verifier.domains.contracts import current_object_routes as routes
    reports = []
    for _ in range(REPLAYS):
        report, failure, exhausted, intact = _traced_replay(
            routes, certificate, request, child_request, child_policy, allowance)
        if exhausted:
            if declared_events and min(declared_events) <= limits["max_replay_events"]:
                raise Refuted("traced_python_events exceeded declared maximum "
                              + str(min(declared_events)))
            raise Unavailable("replay event ceiling exhausted before the declared maximum")
        if failure == "UNAVAILABLE":
            raise Unavailable("selected child checker is unavailable")
        if failure == "REFUSED":
            raise Refuted("selected child certificate is refused by its registered route")
        if not intact:
            raise Unavailable("run observation was displaced during replay")
        reports.append(canonical_bytes(report))
    if len(set(reports)) != 1:
        raise Refuted("two replays of the selected run produced different reports")
    report = strict_json_loads(reports[0].decode("utf-8"))
    if report["replay_status"] != "REPRODUCED" or report["computational_status"] == "UNKNOWN":
        raise Unavailable("selected child remains UNKNOWN")
    if report["computational_status"] != "PASS":
        raise Refuted("selected child did not pass")
    return MechanismDecision(MechanismOutcome.PASS, "run observed",
                             {"report_bytes": len(reports[0]),
                              "report_digest": "sha256:" + hashlib.sha256(reports[0]).hexdigest(),
                              "child_status": report["computational_status"]})


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "verifier_object", "child_request",
                         "child_policy", "child_certificate",
                         "declared_observations"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained run evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        _subject(value["verifier_object"], request)
        child_request, child_policy = value["child_request"], value["child_policy"]
        if ("sha256:" + canonical_digest(child_request) != request["child_request_digest"]
                or "sha256:" + canonical_digest(child_policy) != request["child_policy_digest"]):
            raise Refuted("selected child request or policy differs")
        certificate = _decode_b64(value["child_certificate"], "child certificate")
        if "sha256:" + hashlib.sha256(certificate).hexdigest() != request["child_certificate_digest"]:
            raise Refuted("selected child certificate differs")
        declared = _declared(value["declared_observations"], budget)
        if getattr(_ACTIVE, "depth", 0):
            raise Unavailable("a nested VERIFIER-3.1 run is not observed")
        _ACTIVE.depth = 1
        try:
            run = _observe(request, certificate, child_request, child_policy)
        finally:
            _ACTIVE.depth = 0
        run_id = run_digest(request)
        rows, violations, unobserved = [], [], []
        for constraint in request["constraints"]:
            budget.tick()
            quantity = constraint["quantity"]
            row = {**constraint, "run_digest": run_id}
            if quantity == "replay_report_bytes":
                observed = run.observations["report_bytes"]
                within = observed <= constraint["maximum"]
                row.update(producer=PRODUCER, observed_value=observed,
                           relation="WITHIN_MAXIMUM" if within else "EXCEEDS_MAXIMUM")
                if not within:
                    violations.append("replay_report_bytes:" + constraint["constraint_id"])
            elif quantity == "traced_python_events":
                row.update(producer=PRODUCER, observed_value=None, relation="WITHIN_MAXIMUM")
            else:
                reason = ("CALLER_DECLARATION_ONLY" if any(
                    item["quantity"] == quantity for item in declared)
                    else "NO_INDEPENDENT_OBSERVATION")
                row.update(producer=None, observed_value=None, relation=reason)
                unobserved.append(reason + ":" + constraint["constraint_id"])
            rows.append(row)
        observations = {"run_digest": run_id, "replays": REPLAYS,
            "child_report_digest": run.observations["report_digest"],
            "child_status": run.observations["child_status"],
            "constraints": rows,
            "caller_declared_observations": len(declared),
            "caller_declarations_admitted": 0}
        if violations:
            return MechanismDecision(MechanismOutcome.FAIL,
                "checker observation exceeds declared maximum: " + ", ".join(violations),
                observations)
        if unobserved:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                "constraint has no checker observation bound to the run: "
                + ", ".join(unobserved), observations)
        return MechanismDecision(MechanismOutcome.PASS,
            "every declared constraint is matched by a run-bound checker observation",
            observations)
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _VerifierRunConstraintsMechanism:
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
                                     "bound VERIFIER run proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected run evidence bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise VerifierRunConstraintsError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_VerifierRunConstraintsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "VERIFIER", "scope": SCOPE,
        "run_bound_constraint_observations": (
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
        raise VerifierRunConstraintsError("certificate byte bound exhausted")
    return encoded


def build_verifier_run_constraints_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise VerifierRunConstraintsError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise VerifierRunConstraintsError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_verifier_run_constraints_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise VerifierRunConstraintsError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise VerifierRunConstraintsError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise VerifierRunConstraintsError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise VerifierRunConstraintsError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, VerifierRunConstraintsError):
            raise
        raise VerifierRunConstraintsError(
            "invalid retained VERIFIER run certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "PRODUCER", "SCOPE",
           "VerifierRunConstraintsDescriptor", "VerifierRunConstraintsError",
           "registration", "run_digest", "verifier_run_constraints_policy",
           "verifier_run_constraints_request",
           "build_verifier_run_constraints_certificate",
           "recheck_verifier_run_constraints_certificate"]
