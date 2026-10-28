"""Current ARCH-2.1: retained execution order over a replayed ARCH-3.1 graph.

Verifier Standard (VSTD); computational model architecture (ARCH); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Schedule
positions, node and edge counts and checker budgets are dimensionless. A valid
order over a static graph establishes no fusion, routing or runtime behaviour.
"""
from __future__ import annotations

import base64
import binascii
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
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import arch_shapes, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "ARCH-2.1"
REQUEST_VERSION = "verifier-current-arch-schedule-request-1"
POLICY_VERSION = "verifier-current-arch-schedule-policy-1"
CERTIFICATE_VERSION = "verifier-current-arch-schedule-certificate-1"
EVIDENCE_VERSION = "verifier-current-arch-schedule-evidence-1"
MECHANISM_ID = "verifier.current-arch.retained-execution-schedule.1"
SCOPE = "selected_static_graph_execution_order"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class ArchScheduleError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "ARCH", "scope": SCOPE,
        "proposition": (
            "The independently selected exact ARCH-3.1 child replays PASS, "
            "and the retained execution schedule committed by the parent "
            "request names every node of the child's retained static tensor "
            "graph exactly once and places each node after every node it "
            "takes as input."),
        "prerequisites": [
            "exact separately selected ARCH-3.1 request, policy and retained "
            "certificate; child replay PASS; retained schedule bytes; finite "
            "checker limits"],
        "exclusions": [
            "forward graph compilation and layer fusion correctness",
            "dynamic routing, data-dependent control flow and conditional execution",
            "runtime execution, device or scheduler order, concurrency and timing",
            "tensor values and numerical equivalence of the scheduled computation",
            "whole ARCH dynamics tier or object-profile conformance",
            "privacy, consent, governance and security admission"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ArchScheduleDescriptor:
    """Native public route metadata for one retained execution-order proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, ArchScheduleError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, ArchScheduleError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection, arch_shapes)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_ARCH_SHAPES.md",
                 "CURRENT_ARCH_SCHEDULE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=ArchScheduleError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def arch_schedule_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "child_request_digest",
        "child_policy_digest", "child_certificate_digest", "schedule_digest",
        "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "ARCH")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise ArchScheduleError("selected architecture schedule objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise ArchScheduleError("bounded architecture subject required")
    for field in ("object_digest", "collection_digest", "child_request_digest",
                  "child_policy_digest", "child_certificate_digest",
                  "schedule_digest", "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, ArchScheduleError)
    return selected


def arch_schedule_request(*, subject_id: str, object_digest: str,
        collection_digest: str, child_request_digest: str,
        child_policy_digest: str, child_certificate_digest: str,
        schedule_digest: str, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ArchScheduleError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "ARCH",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "child_request_digest": child_request_digest,
        "child_policy_digest": child_policy_digest,
        "child_certificate_digest": child_certificate_digest,
        "schedule_digest": schedule_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_b64(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise Refuted(label + " must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted(label + " is noncanonical base64")
    return decoded


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _child_graph(value: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Replay the selected ARCH-3.1 child and return its retained graph."""
    child_request, child_policy = value["child_request"], value["child_policy"]
    if ("sha256:" + canonical_digest(child_request) != request["child_request_digest"]
            or "sha256:" + canonical_digest(child_policy)
            != request["child_policy_digest"]):
        raise Refuted("selected child request or policy differs")
    if (type(child_request) is not dict
            or child_request.get("subject_id") != request["subject_id"]
            or child_request.get("object_digest") != request["object_digest"]
            or child_request.get("collection_digest") != request["collection_digest"]
            or child_request.get("semantic_version") != arch_shapes.SEMANTIC_VERSION
            or child_request.get("coordinate") != arch_shapes.COORDINATE
            or child_request.get("object_kind") != "ARCH"):
        raise Refuted("child is not the selected ARCH-3.1 subject")
    certificate = _decode_b64(value["child_certificate"], "child certificate")
    if len(certificate) > arch_shapes._MAX_CERTIFICATE_BYTES:
        raise Unavailable("child certificate bound exhausted")
    if ("sha256:" + hashlib.sha256(certificate).hexdigest()
            != request["child_certificate_digest"]):
        raise Refuted("selected child certificate differs")
    try:
        result = arch_shapes.recheck_arch_shapes_certificate(
            certificate, expected_request=child_request, policy=child_policy)
    except arch_shapes.ArchShapesError as exc:
        raise Refuted("selected ARCH-3.1 child does not replay") from exc
    if result["status"] == "UNKNOWN":
        raise Unavailable("selected ARCH-3.1 child remains UNKNOWN")
    if result["status"] != "PASS":
        raise Refuted("selected ARCH-3.1 child did not pass")
    child = strict_json_loads(certificate.decode("utf-8"))
    retained = strict_json_loads(_decode_b64(
        child["evidence_payloads"][child_request["evidence_ref"]],
        "child retained evidence").decode("utf-8"))
    return retained["inputs"]["graph"]


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "child_request", "child_policy",
                         "child_certificate", "schedule"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained schedule evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        graph = _child_graph(value, request)
        schedule = value["schedule"]
        if schedule is None:
            raise Unavailable("retained execution schedule absent")
        if "sha256:" + canonical_digest(schedule) != request["schedule_digest"]:
            raise Refuted("retained execution schedule commitment differs")
        if type(schedule) is not list:
            raise Refuted("retained execution schedule must be a list")
        if len(schedule) > limits["max_items"]:
            raise Unavailable("selected schedule item bound exhausted")
        nodes = graph["nodes"]
        names = {row["name"] for row in nodes}
        position: dict[str, int] = {}
        for index, name in enumerate(schedule):
            budget.tick()
            if type(name) is not str or name not in names:
                raise Refuted("schedule entry is not a retained graph node")
            if name in position:
                raise Refuted("schedule runs a retained node twice")
            position[name] = index
        if len(position) != len(nodes):
            raise Refuted("schedule omits a retained graph node")
        edges = 0
        for row in nodes:
            for source in row["inputs"]:
                budget.tick()
                edges += 1
                if position[source] >= position[row["name"]]:
                    raise Refuted("schedule runs a consumer before its producer")
        return MechanismDecision(MechanismOutcome.PASS,
            "retained schedule is a dependency-respecting order of every node",
            {"nodes": len(nodes), "edges": edges, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ArchScheduleMechanism:
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
                                     "bound architecture schedule proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected schedule bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ArchScheduleError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_ArchScheduleMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "ARCH", "scope": SCOPE,
        "execution_order": ("PASS" if evaluation.outcome == MechanismOutcome.PASS
                            else "NOT_ESTABLISHED"),
        "whole_arch_dynamics": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "graph_compilation": "NOT_ESTABLISHED",
        "layer_fusion": "NOT_ESTABLISHED",
        "dynamic_routing": "NOT_ESTABLISHED",
        "runtime_execution": "NOT_ESTABLISHED",
        "numerical_equivalence": "NOT_ESTABLISHED",
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
        raise ArchScheduleError("certificate byte bound exhausted")
    return encoded


def build_arch_schedule_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ArchScheduleError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ArchScheduleError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_arch_schedule_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ArchScheduleError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise ArchScheduleError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ArchScheduleError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ArchScheduleError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, ArchScheduleError):
            raise
        raise ArchScheduleError("invalid retained architecture schedule certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "ArchScheduleDescriptor",
           "ArchScheduleError", "registration", "arch_schedule_policy",
           "arch_schedule_request", "build_arch_schedule_certificate",
           "recheck_arch_schedule_certificate"]
