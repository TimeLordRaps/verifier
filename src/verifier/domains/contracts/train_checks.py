"""Current training run specification (TRAIN) native check certificates.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless; byte limits count encoded
bytes. Numerical values use the selected contract units; arithmetic is ordered Python binary64.
Retained observations do not establish live execution or physical isolation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import struct
import sys
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession
from verifier.core.namespace import NamespaceObject
from verifier.domains import train as train_module
from verifier.domains import numerical as numerical_module
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-train-checks-request-1"
POLICY_VERSION = "verifier-current-train-checks-policy-1"
CERTIFICATE_VERSION = "verifier-current-train-checks-certificate-1"
EVIDENCE_VERSION = "verifier-current-train-checks-evidence-1"
MECHANISM_ID = "verifier.current-object.retained-train-checks.1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
             "max_items": 4096, "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024, "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
CHECKS = {"configuration": "TRAIN-1.2", "checkpoints": "TRAIN-1.3",
          "training": "TRAIN-2.1", "updates": "TRAIN-2.3", "lineage": "TRAIN-4.1"}
_CLAIMS = {
    "configuration": "The selected optimizer, constant schedule, accumulation and ordered Python binary64 numerical contract are admitted and bound to the exact retained training composition.",
    "checkpoints": "Every selected retained weight and optimizer-state record is rehashed against the exact checkpoint inventory and its dense network shape checked against the selected architecture.",
    "training": "Losses and analytic gradients are recomputed from the bound batches and dense network; each supported optimizer update reproduces the retained trajectory within the selected tolerance.",
    "updates": "Each selected optimizer update and moment transition is recomputed from the retained gradients and state within the selected tolerance, without claiming those gradients equal the loss derivative.",
    "lineage": "The finite retained trace has contiguous indices, exact checkpoint parents/results, configuration commitments and batch bindings in the selected event order.",
}
_LOSS_CONTRACT = {"loss": "mean-squared-error", "reduction": "mean-samples-and-outputs",
                  "arithmetic": "python-binary64", "relu_derivative_at_zero": 0}


def _check(value: Any) -> str:
    if type(value) is not str or value not in CHECKS:
        raise TrainChecksError("unsupported training check")
    return value


def scope(check: str) -> str:
    return "finite_retained_train_" + _check(check)


def registration(check: str) -> dict[str, Any]:
    check = _check(check)
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "subject_kind": "TRAIN", "scope": scope(check),
        "proposition": _CLAIMS[check],
        "prerequisites": ["independently selected exact TRAIN record, collection, evidence, native check, installed policy and finite limits"],
        "exclusions": ["actual training execution, physical event observation or discarded history",
                       "accelerator, mixed-precision or distributed arithmetic",
                       "empirical utility, generalization, independent observation or authority",
                       "unselected objectives, legacy prerequisites or whole tier conformance"]}


def proposition_digest(check: str) -> str:
    return "sha256:" + canonical_digest(registration(check))


@dataclass(frozen=True)
class TrainDescriptor:
    """One exact publicly selectable training proposition."""
    check: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return proposition_digest(self.check)


class TrainChecksError(ValueError):
    """Malformed external selection or substituted training certificate."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or any(type(key) is not str for key in value):
        raise TrainChecksError(label + " fields differ")
    if set(value) != fields:
        raise TrainChecksError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise TrainChecksError("canonical SHA-256 commitment required")
    return value


def _runtime_identity() -> dict[str, Any]:
    """Describe the exact local arithmetic runtime selected by this mechanism."""
    return {
        "implementation": sys.implementation.name,
        "version_info": list(sys.version_info),
        "version": sys.version,
        "platform": sys.platform,
        "pointer_bits": struct.calcsize("P") * 8,
        "byteorder": sys.byteorder,
        "float_info": {
            "radix": sys.float_info.radix,
            "mant_dig": sys.float_info.mant_dig,
            "max_exp": sys.float_info.max_exp,
            "min_exp": sys.float_info.min_exp,
            "rounds": sys.float_info.rounds,
        },
    }


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module, train_module, numerical_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_TRAIN_CHECKS.md", "DOMAIN_GROUNDING.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        "sources": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in sorted(paths.items())},
        "runtime": _runtime_identity(),
    })


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "policy")
    for field, expected in (("schema_version", POLICY_VERSION), ("mechanism_id", MECHANISM_ID)):
        if type(policy[field]) is not str or policy[field] != expected:
            raise TrainChecksError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise TrainChecksError("policy differs from installed mechanism")
    roots, size = policy["trust_roots"], policy["max_certificate_bytes"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise TrainChecksError("bounded sorted unique trust-root labels required")
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise TrainChecksError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def train_checks_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
        raise TrainChecksError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "check",
        "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    check = _check(request["check"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", CHECKS[check]), ("object_kind", "TRAIN")):
        if type(request[field]) is not str or request[field] != expected:
            raise TrainChecksError("selected training objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != proposition_digest(check):
        raise TrainChecksError("selected proposition differs")
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise TrainChecksError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def train_checks_request(*, check: str, subject_id: str, object_digest: str,
                        collection_digest: str, evidence_ref: str, policy: dict[str, Any],
                        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    check = _check(check)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise TrainChecksError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "proposition_digest": proposition_digest(check), "check": check,
        "object_kind": "TRAIN", "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted), "limits": {**_CEILINGS, **(limits or {})}})


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")), {"schema_version", "objects", "inputs"}, "evidence")
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
        if len(matches) != 1 or matches[0].kind.value != "TRAIN" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained subject differs from external selection")
        composition = namespace_module.assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        subject = matches[0]
        operands = dict(subject.operands)
        if any(len(operands[role]) != 1 for role in ("arch", "data", "bench")):
            raise Unavailable("one selected architecture, dataset and loss benchmark are required")
        records = {item.object_id: item for item in objects}
        architecture, dataset, benchmark = (records[operands[role][0]] for role in ("arch", "data", "bench"))
        common_module.same(architecture.payload, common_module.need(subject.payload, "architecture"),
                           "selected architecture differs from training artifact")
        common_module.obj(dataset.payload, {"batches"})
        common_module.obj(dataset.payload["batches"])
        common_module.same(benchmark.payload, _LOSS_CONTRACT, "selected loss benchmark differs")
        benchmark_operands = dict(benchmark.operands)
        if len(benchmark_operands["verifier"]) != 1 or len(benchmark_operands["data"]) != 1:
            raise Unavailable("one loss verifier and dataset are required")
        common_module.same(benchmark_operands["data"], operands["data"], "loss benchmark dataset differs")
        checker = records[benchmark_operands["verifier"][0]]
        common_module.same(checker.payload, {"mechanism_id": MECHANISM_ID,
            "mechanism_digest": mechanism_digest()}, "selected training verifier differs from installed mechanism")
        event_steps = []
        for event_id in operands["events"]:
            event = records[event_id]
            common_module.obj(event.payload, {"training_step"})
            step = common_module.obj(event.payload["training_step"])
            roles = dict(event.operands)
            if any(len(roles[role]) != 1 for role in ("time", "space", "meaning")):
                raise Unavailable("one time, space and meaning per retained event are required")
            common_module.same(records[roles["time"][0]].payload,
                {"index": common_module.need(step, "index")}, "retained event time differs")
            common_module.same(records[roles["space"][0]].payload,
                {"scope": "retained-training-trace"}, "retained event space differs")
            common_module.same(records[roles["meaning"][0]].payload,
                {"operation": "optimizer-update", "configuration_digest": common_module.digest(
                    common_module.need(subject.payload, "configuration"))}, "retained event meaning differs")
            event_steps.append(step)
        common_module.same(common_module.digest(event_steps), common_module.need(subject.payload, "steps_digest"),
                           "selected event order differs from training trace")
        if value["inputs"] is None:
            raise Unavailable("retained training inputs absent")
        retained = common_module.obj(value["inputs"])
        if any(type(key) is not str for key in retained) or set(retained) - {"checkpoints", "steps", "batches"}:
            raise Refuted("unsupported retained training input")
        if "batches" in retained:
            common_module.same(retained["batches"], dataset.payload["batches"], "selected training dataset differs")
        if "steps" in retained:
            common_module.same(retained["steps"], event_steps, "selected event trace differs")
        result = train_module.evaluate(request["check"], matches[0].payload, retained, budget)
        return MechanismDecision(MechanismOutcome.PASS, "selected retained training check reproduced",
                                 {"training": result, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "check", "collection_digest", "policy_digest")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _TrainChecksMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound training proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained training evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise TrainChecksError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_TrainChecksMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": request["coordinate"], "object_kind": request["object_kind"], "scope": scope(request["check"]),
        "object_profile_conformance": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request, "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"], "proposition_digest": request["proposition_digest"],
        "evidence_refs": [request["evidence_ref"]], "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise TrainChecksError("certificate byte bound exhausted")
    return encoded


def build_train_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise TrainChecksError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise TrainChecksError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_train_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise TrainChecksError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise TrainChecksError("canonical certificate version differs")
        if value["request"] != selected:
            raise TrainChecksError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise TrainChecksError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise TrainChecksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, TrainChecksError):
            raise
        raise TrainChecksError("invalid retained training certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "registration", "scope", "TrainDescriptor", "TrainChecksError", "train_checks_policy",
           "train_checks_request", "build_train_checks_certificate", "recheck_train_checks_certificate"]
