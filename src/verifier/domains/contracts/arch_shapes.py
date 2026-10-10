"""Versioned computational model architecture (ARCH) tensor-graph certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Tensor dimensions, element counts and checker
limits are dimensionless. Shapes do not establish execution equivalence.
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
COORDINATE = "ARCH-3.1"
REQUEST_VERSION = "verifier-current-arch-shapes-request-1"
POLICY_VERSION = "verifier-current-arch-shapes-policy-1"
CERTIFICATE_VERSION = "verifier-current-arch-shapes-certificate-1"
EVIDENCE_VERSION = "verifier-current-arch-shapes-evidence-1"
MECHANISM_ID = "verifier.current-arch.retained-tensor-shapes.1"
SCOPE = "finite_retained_static_tensor_graph"
_MAX_SAFE_INTEGER = 2**53 - 1
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class ArchShapesError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "ARCH",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact ARCH record occurs once in the "
            "selected finite typed collection, and its retained nonempty "
            "static tensor graph rehashes, has unique ordered nodes and "
            "complete output ancestry, and satisfies exact shape equations "
            "for INPUT, rank-two MATMUL, shape-equal ADD and RELU."
        ),
        "prerequisites": [
            "independently selected exact ARCH record, finite collection, "
            "retained graph bytes, installed policy and finite checker limits"
        ],
        "exclusions": [
            "tensor values, numerical result or framework execution",
            "broadcasting, dynamic dimensions and operators outside the four named",
            "source authenticity, artifact completeness and backend portability",
            "whole ARCH statics tier or object-profile conformance",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ArchShapesDescriptor:
    """Native public route metadata for one retained tensor-graph proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, ArchShapesError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, ArchShapesError)


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_ARCH_SHAPES.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=ArchShapesError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def arch_shapes_policy(*, trust_roots: list[str],
                      max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    return retained_selection.limits(value, _CEILINGS, ArchShapesError)


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "ARCH"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise ArchShapesError("selected architecture objective differs")
    for field in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise ArchShapesError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def arch_shapes_request(*, subject_id: str, object_digest: str,
                       collection_digest: str, evidence_ref: str,
                       policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise ArchShapesError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "ARCH", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _shape(value: Any, budget: common_module.Budget) -> tuple[int, ...]:
    if type(value) is not list or not 1 <= len(value) <= 4:
        raise Refuted("tensor rank must be between one and four")
    extent = 1
    dims = []
    for dimension in value:
        budget.tick()
        if type(dimension) is not int or not 1 <= dimension <= 2**31 - 1:
            raise Refuted("tensor dimension must be a positive bounded integer")
        extent *= dimension
        if extent > _MAX_SAFE_INTEGER:
            raise Refuted("tensor element count exceeds exact integer bound")
        dims.append(dimension)
    return tuple(dims)


def _graph(value: Any, budget: common_module.Budget, max_items: int) -> dict[str, int]:
    selected = _record(value, {"nodes", "outputs"}, "tensor graph")
    rows, outputs = selected["nodes"], selected["outputs"]
    if type(rows) is not list or type(outputs) is not list:
        raise Refuted("tensor nodes and outputs must be lists")
    if len(rows) > max_items or len(outputs) > max_items:
        raise Unavailable("selected tensor graph item bound exhausted")
    if not rows:
        if outputs:
            raise Refuted("selected output has no retained tensor node")
        raise Unavailable("nonempty retained tensor graph required")
    known: dict[str, tuple[int, ...]] = {}
    dependencies: dict[str, tuple[str, ...]] = {}
    operators = {"INPUT": 0, "MATMUL": 2, "ADD": 2, "RELU": 1}
    for row in rows:
        budget.tick()
        node = _record(row, {"name", "op", "inputs", "shape"}, "tensor node")
        name, operator, inputs = node["name"], node["op"], node["inputs"]
        if type(name) is not str or not name.strip() or len(name) > 256 or name in known:
            raise Refuted("tensor node name is missing, duplicate or unbounded")
        if type(operator) is not str or operator not in operators:
            raise Refuted("tensor operator outside selected static basis")
        if type(inputs) is not list or len(inputs) != operators[operator]:
            raise Refuted("tensor operator arity differs")
        for source in inputs:
            budget.tick()
            if type(source) is not str or source not in known:
                raise Refuted("tensor input is absent or not earlier in graph")
        shape = _shape(node["shape"], budget)
        incoming = [known[source] for source in inputs]
        if operator == "MATMUL":
            if (len(incoming[0]) != 2 or len(incoming[1]) != 2
                    or incoming[0][1] != incoming[1][0]
                    or shape != (incoming[0][0], incoming[1][1])):
                raise Refuted("rank-two matrix multiplication shape differs")
        elif operator == "ADD":
            if shape != incoming[0] or shape != incoming[1]:
                raise Refuted("nonbroadcast addition shape differs")
        elif operator == "RELU":
            if shape != incoming[0]:
                raise Refuted("rectified output shape differs")
        known[name], dependencies[name] = shape, tuple(inputs)
    if not outputs:
        raise Unavailable("nonempty retained output selection required")
    reached: set[str] = set()
    pending: list[str] = []
    for output in outputs:
        budget.tick()
        if type(output) is not str or output not in known or output in pending:
            raise Refuted("output is absent or duplicate")
        pending.append(output)
    while pending:
        budget.tick()
        name = pending.pop()
        if name in reached:
            continue
        reached.add(name)
        pending.extend(dependencies[name])
    if reached != set(known):
        raise Refuted("retained graph includes nodes outside selected output ancestry")
    return {"nodes": len(rows), "outputs": len(outputs), "operations": budget.used}


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
        if len(matches) != 1 or matches[0].kind.value != "ARCH" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained architecture subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        payload = _record(matches[0].payload, {"scope", "graph_digest"}, "architecture payload")
        if payload["scope"] != "retained-static-tensor-graph":
            raise Refuted("architecture scope differs")
        commitment = _hash(payload["graph_digest"])
        if value["inputs"] is None:
            raise Unavailable("retained tensor graph absent")
        retained = _record(value["inputs"], {"graph"}, "architecture inputs")
        if retained["graph"] is None:
            raise Unavailable("retained tensor graph absent")
        if commitment != "sha256:" + canonical_digest(retained["graph"]):
            raise Refuted("retained tensor graph commitment differs")
        measurements = _graph(retained["graph"], budget, limits["max_items"])
        return MechanismDecision(
            MechanismOutcome.PASS, "selected retained tensor shapes reproduced",
            measurements,
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return retained_selection.parameters(request)


class _ArchShapesMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound architecture proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained architecture evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ArchShapesError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_ArchShapesMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "ARCH", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "execution_equivalence": "NOT_ESTABLISHED",
        "artifact_completeness": "NOT_ESTABLISHED",
        "backend_portability": "NOT_ESTABLISHED",
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
        raise ArchShapesError("certificate byte bound exhausted")
    return encoded


def build_arch_shapes_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                 *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise ArchShapesError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ArchShapesError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_arch_shapes_certificate(certificate_bytes: bytes, *,
                                   expected_request: dict[str, Any],
                                   policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ArchShapesError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise ArchShapesError("canonical certificate version differs")
        if value["request"] != selected:
            raise ArchShapesError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ArchShapesError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ArchShapesError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, ArchShapesError):
            raise
        raise ArchShapesError("invalid retained architecture certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "ArchShapesDescriptor",
    "ArchShapesError", "registration", "arch_shapes_policy",
    "arch_shapes_request", "build_arch_shapes_certificate",
    "recheck_arch_shapes_certificate",
]
