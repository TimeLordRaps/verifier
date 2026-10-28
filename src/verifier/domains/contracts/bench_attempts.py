"""Current BENCH-2.1: declared per-problem attempt bounds and best-of-N selection.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); benchmark specification graph (BENCH). Attempt
counts, bounds, scores, log positions and checker budgets are dimensionless;
evidence and certificate limits are bytes. A retained attempt is a recorded
answer, not proof that a candidate system produced it.
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
COORDINATE = "BENCH-2.1"
REQUEST_VERSION = "verifier-current-bench-attempts-request-1"
POLICY_VERSION = "verifier-current-bench-attempts-policy-1"
CERTIFICATE_VERSION = "verifier-current-bench-attempts-certificate-1"
EVIDENCE_VERSION = "verifier-current-bench-attempts-evidence-1"
MECHANISM_ID = "verifier.current-bench.retained-attempt-policy.1"
SCOPE = "finite_retained_declared_attempt_policy"
OBLIGATION_ROW = (
    "| BENCH-2.1 | Attempt policy | Repeated attempts and best-of-N selection "
    "are declared and bounded per problem. | none | none |")
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_MAX_SAFE_INTEGER = 2**53 - 1
# Each metric names its score and whether the best attempt maximises it.
_METRICS = {"exact-match": True, "absolute-error": False}
_SELECTION = "best-of-n"
_TIE_BREAK = "earliest-retained-attempt"


class BenchAttemptsError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "BENCH",
        "scope": SCOPE,
        "obligation_row": OBLIGATION_ROW,
        "proposition": (
            "The externally selected exact BENCH namespace record occurs in "
            "the selected finite typed collection and commits to a retained "
            "finite problem declaration giving each problem a positive "
            "maximum attempt count, and declares best-of-N selection under a "
            "named supported metric with earliest-retained-attempt tie "
            "breaking; over the retained attempts every attempt identifier "
            "is unique and names a declared problem, no problem has more "
            "attempts than its declared maximum, every problem with an "
            "attempt has exactly one selection and no selection names a "
            "problem without attempts, and each selection names the earliest "
            "retained attempt with the best recomputed score for its problem "
            "and records exactly that score."
        ),
        "prerequisites": [
            "independently selected exact BENCH record and full finite "
            "collection, retained problem declaration, attempts and "
            "selections, installed policy and finite checker limits"
        ],
        "exclusions": [
            "BENCH-2.2 attempt inventory completeness: attempts outside the "
            "retained list",
            "BENCH-2.3 sequential adaptivity, BENCH-2.4 contamination, "
            "BENCH-2.5 response curve and BENCH-2.6 measurement feedback",
            "candidate execution, answer authorship or reference correctness",
            "aggregate score, ranking, threshold or capability claims",
            "whole BENCH dynamics tier or object-profile conformance",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class BenchAttemptsDescriptor:
    """Native public route metadata for one declared attempt-policy proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, BenchAttemptsError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, BenchAttemptsError)


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "DOMAIN_OBLIGATIONS.md",
                 "CURRENT_BENCH_ATTEMPTS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=BenchAttemptsError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def bench_attempts_policy(*, trust_roots: list[str],
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
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "BENCH"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise BenchAttemptsError("selected bench attempt-policy objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise BenchAttemptsError("bounded subject identifier required")
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, BenchAttemptsError)
    return request


def bench_attempts_request(*, subject_id: str, object_digest: str,
                           collection_digest: str, evidence_ref: str,
                           policy: dict[str, Any],
                           limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise BenchAttemptsError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "BENCH", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _name(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise Refuted(label + " must be a bounded identifier")
    return value


def _sequence(value: Any, label: str, limits: dict[str, int]) -> list[Any]:
    if type(value) is not list:
        raise Refuted(label + " must be a sequence")
    if len(value) > limits["max_items"]:
        raise Unavailable(label + " bound exhausted")
    return value


def _problems(value: Any, limits: dict[str, int],
              budget: common_module.Budget) -> dict[str, dict[str, Any]]:
    rows = _sequence(value, "declared problems", limits)
    if not rows:
        raise Unavailable("nonempty problem declaration required")
    problems: dict[str, dict[str, Any]] = {}
    for row in rows:
        budget.tick()
        problem = _record(row, {"id", "reference", "max_attempts"}, "declared problem")
        identifier = _name(problem["id"], "problem identifier")
        if identifier in problems:
            raise Refuted("problem identifier repeats")
        bound = problem["max_attempts"]
        if type(bound) is not int or not 1 <= bound <= _MAX_SAFE_INTEGER:
            raise Refuted("declared attempt bound must be a positive safe integer")
        problems[identifier] = problem
    return problems


def _score(metric: str, answer: Any, reference: Any) -> int:
    if metric == "exact-match":
        return int(canonical_bytes(answer) == canonical_bytes(reference))
    for value in (answer, reference):
        if type(value) is not int or abs(value) > _MAX_SAFE_INTEGER:
            raise Unavailable("absolute-error is decided only over safe integers")
    return abs(answer - reference)


def _check(statement: dict[str, Any], inputs: dict[str, Any],
           limits: dict[str, int], budget: common_module.Budget) -> dict[str, int]:
    problems = _problems(inputs["problems"], limits, budget)
    attempts = _sequence(inputs["attempts"], "retained attempts", limits)
    counts = {identifier: 0 for identifier in problems}
    by_problem: dict[str, list[tuple[int, str, Any]]] = {name: [] for name in problems}
    seen: set[str] = set()
    for position, row in enumerate(attempts):
        budget.tick()
        attempt = _record(row, {"id", "problem", "answer"}, "retained attempt")
        identifier = _name(attempt["id"], "attempt identifier")
        if identifier in seen:
            raise Refuted("attempt identifier repeats")
        seen.add(identifier)
        problem = _name(attempt["problem"], "attempted problem")
        if problem not in problems:
            raise Refuted("attempt names an undeclared problem")
        counts[problem] += 1
        if counts[problem] > problems[problem]["max_attempts"]:
            raise Refuted("attempts exceed the problem's declared bound")
        by_problem[problem].append((position, identifier, attempt["answer"]))
    selections = _sequence(inputs["selections"], "retained selections", limits)
    chosen: dict[str, dict[str, Any]] = {}
    for row in selections:
        budget.tick()
        selection = _record(row, {"problem", "attempt", "score"}, "selection")
        problem = _name(selection["problem"], "selected problem")
        if problem not in problems:
            raise Refuted("selection names an undeclared problem")
        if problem in chosen:
            raise Refuted("problem has more than one selection")
        if not by_problem[problem]:
            raise Refuted("selection names a problem without attempts")
        _name(selection["attempt"], "selected attempt")
        if type(selection["score"]) is not int:
            raise Refuted("selected score must be an integer")
        chosen[problem] = selection
    for problem, rows in by_problem.items():
        budget.tick()
        if rows and problem not in chosen:
            raise Refuted("problem with attempts has no best-of-N selection")
    metric = statement["metric"]
    if (metric not in _METRICS or statement["selection"] != _SELECTION
            or statement["tie_break"] != _TIE_BREAK):
        raise Unavailable("declared selection rule or metric is not supported")
    maximise = _METRICS[metric]
    for problem, selection in chosen.items():
        reference = problems[problem]["reference"]
        best: tuple[int, str, int] | None = None
        for position, identifier, answer in by_problem[problem]:
            budget.tick()
            score = _score(metric, answer, reference)
            if (best is None or (score > best[2] if maximise else score < best[2])):
                best = (position, identifier, score)
        if best is None:
            raise Refuted("selection names a problem without attempts")
        if selection["attempt"] != best[1]:
            raise Refuted("selection is not the earliest best retained attempt")
        if selection["score"] != best[2]:
            raise Refuted("selected score differs from the recomputed score")
    if any(not rows for rows in by_problem.values()):
        raise Unavailable("declared problem has no retained attempt")
    return {"problems": len(problems), "attempts": len(attempts),
            "selections": len(chosen)}


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
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
            selected = _record(row, {"object_id", "kind", "payload", "operands"},
                               "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "BENCH"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained bench subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value),
                                     composition.reason)
        statement = _record(matches[0].payload, {
            "scope", "selection", "metric", "tie_break", "problems_digest"},
            "bench payload")
        if statement["scope"] != "retained-attempt-policy":
            raise Refuted("bench scope differs")
        for field in ("selection", "metric", "tie_break"):
            if type(statement[field]) is not str:
                raise Refuted("declared " + field + " must be a name")
        if value["inputs"] is None:
            raise Unavailable("retained problems, attempts and selections absent")
        inputs = _record(value["inputs"], {"problems", "attempts", "selections"},
                         "attempt inputs")
        if _hash(statement["problems_digest"]) != "sha256:" + canonical_digest(
                inputs["problems"]):
            raise Refuted("retained problem declaration commitment differs")
        counts = _check(statement, inputs, limits, budget)
        return MechanismDecision(
            MechanismOutcome.PASS, "declared attempt bounds and best-of-N selection reproduced",
            {**counts, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _BenchAttemptsMechanism:
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
                                     "bound bench attempt-policy proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained attempt evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise BenchAttemptsError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_BenchAttemptsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "BENCH", "scope": SCOPE,
        "declared_attempt_policy": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED"),
        "attempt_inventory_completeness": "NOT_ESTABLISHED",
        "sequential_adaptivity": "NOT_ESTABLISHED",
        "candidate_execution": "NOT_ESTABLISHED",
        "reference_validity": "NOT_ESTABLISHED",
        "contamination": "NOT_ESTABLISHED",
        "aggregate_score": "NOT_ESTABLISHED",
        "whole_bench_dynamics": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
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
        raise BenchAttemptsError("certificate byte bound exhausted")
    return encoded


def build_bench_attempts_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                     *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise BenchAttemptsError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise BenchAttemptsError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_bench_attempts_certificate(certificate_bytes: bytes, *,
                                       expected_request: dict[str, Any],
                                       policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise BenchAttemptsError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise BenchAttemptsError("canonical certificate version differs")
        if value["request"] != selected:
            raise BenchAttemptsError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise BenchAttemptsError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise BenchAttemptsError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, BenchAttemptsError):
            raise
        raise BenchAttemptsError("invalid retained bench attempt-policy certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "OBLIGATION_ROW",
    "BenchAttemptsDescriptor", "BenchAttemptsError", "registration",
    "bench_attempts_policy", "bench_attempts_request",
    "build_bench_attempts_certificate", "recheck_bench_attempts_certificate",
]
