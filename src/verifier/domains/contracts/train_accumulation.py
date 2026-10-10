"""Current TRAIN-3.2: a retained sequence reduced two ways, with a bounded effect.

Verifier Standard (VSTD); training run specification (TRAIN); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Institute of
Electrical and Electronics Engineers (IEEE) 754 binary64 floating point.
Values, results and bounds are dimensionless binary64 numbers. Counts and
checker budgets are dimensionless. The executing hardware is never observed.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
import math
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
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "TRAIN-3.2"
REQUEST_VERSION = "verifier-current-train-accumulation-request-1"
POLICY_VERSION = "verifier-current-train-accumulation-policy-1"
CERTIFICATE_VERSION = "verifier-current-train-accumulation-certificate-1"
EVIDENCE_VERSION = "verifier-current-train-accumulation-evidence-1"
MECHANISM_ID = "verifier.current-train.retained-two-order-reduction.1"
SCOPE = "retained_sequence_two_order_binary64_sum"
OPERATION = "binary64-sum-steps-1"
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_REDUCTION_FIELDS = {"operation", "values", "retained_order", "retained_result",
                     "alternative_order", "order_effect_bound"}


class TrainAccumulationError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "TRAIN", "scope": SCOPE,
        "proposition": (
            "The externally selected exact TRAIN record occurs once in the "
            "selected finite typed collection and commits to one retained "
            "reduction record. Reducing its retained finite binary64 sequence "
            "along its retained addition order, with binary64 "
            "round-to-nearest-even addition, reproduces its retained result "
            "exactly. Its retained alternative order is a different addition "
            "tree up to commutativity. The exact difference between the two "
            "reductions is at most its retained bound."),
        "prerequisites": [
            "independently selected exact TRAIN record, finite collection, "
            "retained reduction bytes, installed policy and finite checker "
            "limits; checking-host float addition passes the binary64 "
            "round-to-nearest-even self-check"],
        "exclusions": [
            "observation of the executing hardware's arithmetic (TRAIN-3.1)",
            "that the run executed the retained order: reproducing the retained "
            "result is consistent with that order, not proof of it",
            "the effect of orders other than the two retained, and of "
            "reductions the record does not retain",
            "fused multiply-add, extended or mixed precision, compensated, "
            "stochastic or non-default rounding",
            "loss, gradient, update or training correctness (TRAIN-2.x, TRAIN-3.3)",
            "whole TRAIN statics tier or object-profile conformance",
            "privacy, consent, governance and security admission"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class TrainAccumulationDescriptor:
    """Native public route metadata for one retained two-order reduction."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, TrainAccumulationError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, TrainAccumulationError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "DOMAIN_OBLIGATIONS.md",
                 "CURRENT_TRAIN_ACCUMULATION.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=TrainAccumulationError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def train_accumulation_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "TRAIN"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise TrainAccumulationError("selected accumulation objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise TrainAccumulationError("bounded subject identifier required")
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, TrainAccumulationError)
    return request


def train_accumulation_request(*, subject_id: str, object_digest: str,
        collection_digest: str, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise TrainAccumulationError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "TRAIN", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _host_adds_binary64() -> bool:
    """Self-check that this host's float addition is binary64 round-to-nearest-even."""
    one, half_ulp = 1.0, math.ldexp(1.0, -53)
    return (one + half_ulp == one
            and (one + 2 * half_ulp) + half_ulp == one + 4 * half_ulp
            and one + (half_ulp + math.ldexp(1.0, -64)) == one + 2 * half_ulp
            and math.copysign(1.0, -0.0 + -0.0) < 0
            and math.copysign(1.0, -1.0 + one) > 0
            and math.isinf(math.ldexp(1.0, 1023) + math.ldexp(1.0, 1023)))


def _number(text: Any, label: str) -> float:
    if type(text) is not str or len(text) > 32:
        raise Refuted(label + " must be canonical binary64 hexadecimal text")
    try:
        value = float.fromhex(text)
    except (ValueError, OverflowError) as exc:
        raise Refuted(label + " is not binary64 hexadecimal text") from exc
    if not math.isfinite(value) or value.hex() != text:
        raise Refuted(label + " must be finite canonical binary64 hexadecimal text")
    return value


def _steps(value: Any, count: int, label: str,
           budget: common_module.Budget) -> list[tuple[int, int]]:
    """One addition per value after the first; each operand is read once, earlier."""
    if type(value) is not list or len(value) != count - 1:
        raise Refuted(label + " requires one addition per value after the first")
    consumed: set[int] = set()
    steps = []
    for index, step in enumerate(value):
        budget.tick()
        if type(step) is not list or len(step) != 2:
            raise Refuted(label + " addition must name two operands")
        for operand in step:
            if type(operand) is not int or not 0 <= operand < count + index:
                raise Refuted(label + " reads an absent or later operand")
            if operand in consumed:
                raise Refuted(label + " consumes an operand twice")
            consumed.add(operand)
        steps.append((step[0], step[1]))
    return steps


def _reduce(values: list[float], steps: list[tuple[int, int]],
            budget: common_module.Budget) -> float:
    count, partial = len(values), []
    for left, right in steps:
        budget.tick()
        total = ((values[left] if left < count else partial[left - count])
                 + (values[right] if right < count else partial[right - count]))
        if not math.isfinite(total):
            raise Refuted("partial sum overflows binary64")
        partial.append(total)
    return partial[-1] if partial else values[0]


def _tree(steps: list[tuple[int, int]], count: int,
          budget: common_module.Budget) -> bytes:
    """Commit the addition tree up to commutativity, ignoring independent step order."""
    def leaf(operand: int) -> bytes:
        return hashlib.sha256(b"value:%d" % operand).digest()

    keys: list[bytes] = []
    for left, right in steps:
        budget.tick()
        pair = sorted(leaf(op) if op < count else keys[op - count] for op in (left, right))
        keys.append(hashlib.sha256(b"sum:" + pair[0] + pair[1]).digest())
    return keys[-1] if keys else leaf(0)


def _reduction(value: Any, budget: common_module.Budget, max_items: int) -> dict[str, Any]:
    record = _record(value, _REDUCTION_FIELDS, "retained reduction")
    if type(record["operation"]) is not str:
        raise Refuted("reduction operation must be named")
    if record["operation"] != OPERATION:
        raise Unavailable("reduction operation outside binary64 addition steps")
    if any(record[field] is None for field in ("values", "retained_order", "alternative_order")):
        raise Unavailable("retained sequence and both retained orders are required; "
                          "a declared result or bound alone is not observed")
    if not _host_adds_binary64():
        raise Unavailable("checking host float addition is not binary64 round-to-nearest-even")
    raw = record["values"]
    if type(raw) is not list or not raw:
        raise Refuted("retained sequence must be a nonempty list")
    if len(raw) > max_items:
        raise Unavailable("retained sequence item bound exhausted")
    values = []
    for text in raw:
        budget.tick()
        values.append(_number(text, "retained value"))
    retained_result = _number(record["retained_result"], "retained result")
    bound = _number(record["order_effect_bound"], "order effect bound")
    if math.copysign(1.0, bound) < 0:
        raise Refuted("order effect bound must be nonnegative")
    count = len(values)
    retained = _steps(record["retained_order"], count, "retained order", budget)
    alternative = _steps(record["alternative_order"], count, "alternative order", budget)
    first = _reduce(values, retained, budget)
    if first.hex() != retained_result.hex():
        raise Refuted("retained order does not reproduce the retained result")
    if _tree(retained, count, budget) == _tree(alternative, count, budget):
        raise Refuted("alternative order is the retained addition tree up to commutativity")
    second = _reduce(values, alternative, budget)
    effect = abs(Fraction(first) - Fraction(second))
    if effect > Fraction(bound):
        raise Refuted("order effect exceeds the retained bound")
    return {"values": count, "additions_per_order": count - 1,
            "results_differ": first.hex() != second.hex(),
            "order_effect": str(effect), "operations": budget.used}


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
            selected = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "TRAIN"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained TRAIN subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        payload = matches[0].payload
        if type(payload) is not dict:
            raise Refuted("TRAIN payload must be a record")
        if "reduction_digest" not in payload:
            raise Unavailable("selected TRAIN record commits to no retained reduction")
        commitment = _hash(payload["reduction_digest"])
        if value["inputs"] is None:
            raise Unavailable("retained reduction absent")
        retained = _record(value["inputs"], {"reduction"}, "accumulation inputs")
        if retained["reduction"] is None:
            raise Unavailable("retained reduction absent")
        if commitment != "sha256:" + canonical_digest(retained["reduction"]):
            raise Refuted("retained reduction commitment differs")
        measurements = _reduction(retained["reduction"], budget, limits["max_items"])
        return MechanismDecision(MechanismOutcome.PASS,
            "retained sequence reduced two ways; order effect within retained bound",
            measurements)
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, ZeroDivisionError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _TrainAccumulationMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound accumulation proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained accumulation evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise TrainAccumulationError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_TrainAccumulationMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "TRAIN", "scope": SCOPE,
        "accumulation_order_effect": ("PASS" if evaluation.outcome == MechanismOutcome.PASS
                                      else "NOT_ESTABLISHED"),
        "whole_train_statics": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "executing_hardware_arithmetic": "NOT_ESTABLISHED",
        "executed_order_identity": "NOT_ESTABLISHED",
        "unretained_orders_and_reductions": "NOT_ESTABLISHED",
        "fused_or_extended_precision_arithmetic": "NOT_ESTABLISHED",
        "training_correctness": "NOT_ESTABLISHED",
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
        raise TrainAccumulationError("certificate byte bound exhausted")
    return encoded


def build_train_accumulation_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                         *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise TrainAccumulationError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise TrainAccumulationError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_train_accumulation_certificate(certificate_bytes: bytes, *,
                                           expected_request: dict[str, Any],
                                           policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise TrainAccumulationError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise TrainAccumulationError("canonical certificate version differs")
        if value["request"] != selected:
            raise TrainAccumulationError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise TrainAccumulationError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise TrainAccumulationError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, TrainAccumulationError):
            raise
        raise TrainAccumulationError("invalid retained accumulation certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "OPERATION", "PROPOSITION_DIGEST", "TrainAccumulationDescriptor",
    "TrainAccumulationError", "registration", "train_accumulation_policy",
    "train_accumulation_request", "build_train_accumulation_certificate",
    "recheck_train_accumulation_certificate",
]
