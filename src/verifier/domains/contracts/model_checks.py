"""Current model reproducibility specification (MODEL) native check certificates.

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
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession
from verifier.core.namespace import NamespaceObject
from verifier.domains import model as model_module
from verifier.domains import numerical as numerical_module
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable

SEMANTIC_VERSION = "verifier-current-object-obligations-1"
REQUEST_VERSION = "verifier-current-model-checks-request-1"
POLICY_VERSION = "verifier-current-model-checks-policy-1"
CERTIFICATE_VERSION = "verifier-current-model-checks-certificate-1"
EVIDENCE_VERSION = "verifier-current-model-checks-evidence-1"
MECHANISM_ID = "verifier.current-object.retained-model-checks.1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {"max_objects": 256, "max_operations": 100000, "max_composition_operations": 100000,
             "max_items": 4096, "max_evidence_bytes": 4 * 1024 * 1024,
             "max_reference_bytes": 4 * 1024 * 1024, "max_payload_bytes": 4 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
CHECKS = {"artifacts": "MODEL-1.5", "tensors": "MODEL-1.2",
          "inference": "MODEL-2.1", "evaluation": "MODEL-4.2", "challenges": "MODEL-4.4"}
_CLAIMS = {
    "artifacts": "The selected architecture, weights and dependency payloads rehash exactly; the weights equal the selected training record's final declared checkpoint weights.",
    "tensors": "Complete retained dense tensor shapes are compatible with the exact selected architecture and declared Python binary64 operations.",
    "inference": "The selected dense network executes on every retained sample and reproduces the recorded outputs within the independently selected tolerance.",
    "evaluation": "Regression or classification metrics are recomputed over the complete selected sample set, agree with the retained report, and satisfy the exact parsed metric thresholds.",
    "challenges": "Every selected finite counterexample probe executes against the bound dense model and satisfies its exact output condition.",
}


def _check(value: Any) -> str:
    if type(value) is not str or value not in CHECKS:
        raise ModelChecksError("unsupported model check")
    return value


def scope(check: str) -> str:
    return "finite_retained_model_" + _check(check)


def registration(check: str) -> dict[str, Any]:
    check = _check(check)
    return {"schema_version": "verifier-current-object-proposition-1", "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "subject_kind": "MODEL", "scope": scope(check),
        "proposition": _CLAIMS[check],
        "prerequisites": ["independently selected exact MODEL record, collection, evidence, native check, installed policy and finite limits"],
        "exclusions": ["actual training, deployment, event observation or hardware authenticity",
                       "training-gradient correctness, history completeness or empirical generalization",
                       "accelerator or distributed arithmetic and universal behavioral correctness",
                       "unselected objectives, legacy prerequisites, authority or whole tier conformance"]}


def proposition_digest(check: str) -> str:
    return "sha256:" + canonical_digest(registration(check))


@dataclass(frozen=True)
class ModelDescriptor:
    """One exact publicly selectable model proposition."""
    check: str

    @property
    def CERTIFICATE_VERSION(self) -> str:
        return CERTIFICATE_VERSION

    @property
    def PROPOSITION_DIGEST(self) -> str:
        return proposition_digest(self.check)


class ModelChecksError(ValueError):
    """Malformed external selection or substituted model certificate."""


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or any(type(key) is not str for key in value):
        raise ModelChecksError(label + " fields differ")
    if set(value) != fields:
        raise ModelChecksError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ModelChecksError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module, receipt_module, common_module, model_module, numerical_module)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_MODEL_CHECKS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {"schema_version", "mechanism_id", "mechanism_digest", "trust_roots", "max_certificate_bytes"}, "policy")
    for field, expected in (("schema_version", POLICY_VERSION), ("mechanism_id", MECHANISM_ID)):
        if type(policy[field]) is not str or policy[field] != expected:
            raise ModelChecksError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise ModelChecksError("policy differs from installed mechanism")
    roots, size = policy["trust_roots"], policy["max_certificate_bytes"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise ModelChecksError("bounded sorted unique trust-root labels required")
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise ModelChecksError("certificate byte bound is unsupported")
    policy["trust_roots"] = list(roots)
    return policy


def model_checks_policy(*, trust_roots: list[str], max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling for key, ceiling in _CEILINGS.items()):
        raise ModelChecksError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {"schema_version", "semantic_version", "coordinate", "proposition_digest", "check",
        "object_kind", "subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest", "limits"}, "request")
    check = _check(request["check"])
    for field, expected in (("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", CHECKS[check]), ("object_kind", "MODEL")):
        if type(request[field]) is not str or request[field] != expected:
            raise ModelChecksError("selected model objective differs")
    for field in ("proposition_digest", "object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if request["proposition_digest"] != proposition_digest(check):
        raise ModelChecksError("selected proposition differs")
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise ModelChecksError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def model_checks_request(*, check: str, subject_id: str, object_digest: str,
                        collection_digest: str, evidence_ref: str, policy: dict[str, Any],
                        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    check = _check(check)
    if limits is not None and (type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise ModelChecksError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": CHECKS[check], "proposition_digest": proposition_digest(check), "check": check,
        "object_kind": "MODEL", "subject_id": subject_id, "object_digest": object_digest,
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
        if len(matches) != 1 or matches[0].kind.value != "MODEL" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained subject differs from external selection")
        composition = namespace_module.assess_composition(objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"], max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"], max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        subject = matches[0]
        operands = dict(subject.operands)
        records = {item.object_id: item for item in objects}
        kinds = {"arch": "ARCH", "data": "DATA", "bench": "BENCH", "train": "TRAIN",
                 "env": "ENV", "hardware": "HARDWARE"}
        if any(len(operands[role]) != 1 or records[operands[role][0]].kind.value != kind
               for role, kind in kinds.items()):
            raise Unavailable("one direct native record per selected model role is required")
        selected = {role: records[operands[role][0]] for role in kinds}
        if value["inputs"] is None:
            raise Unavailable("retained native model inputs are absent")
        retained = common_module.obj(value["inputs"])
        if set(retained) - {"architecture", "weights", "dependencies", "samples", "metric_value"}:
            raise Refuted("unsupported retained model input")
        common_module.same(common_module.need(retained, "architecture"), selected["arch"].payload,
                           "selected architecture differs from model input")
        dependencies = common_module.obj(common_module.need(retained, "dependencies"))
        checkpoint = common_module.obj(common_module.need(dependencies, "checkpoint"), {"weights", "optimizer_state"})
        common_module.same(dependencies, {"training": selected["train"].payload, "checkpoint": checkpoint,
            "environment": selected["env"].payload, "hardware": selected["hardware"].payload},
            "selected model dependency payloads differ")
        training = selected["train"]
        common_module.same(dict(training.operands)["arch"], operands["arch"], "training architecture operand differs")
        common_module.same(common_module.need(training.payload, "architecture"), selected["arch"].payload,
                           "training architecture payload differs")
        commitments = common_module.seq(common_module.need(training.payload, "checkpoint_digests"), budget)
        common_module.same(common_module.digest(checkpoint), commitments[-1], "selected final training checkpoint differs")
        common_module.same(checkpoint["weights"], common_module.need(retained, "weights"),
                           "model weights differ from selected training checkpoint")
        benchmark = selected["bench"]
        benchmark_operands = dict(benchmark.operands)
        if len(benchmark_operands["verifier"]) != 1:
            raise Unavailable("one selected model verifier is required")
        checker = records[benchmark_operands["verifier"][0]]
        if checker.kind.value != "VERIFIER":
            raise Unavailable("a direct native model verifier is required")
        common_module.same(benchmark_operands["data"], operands["data"], "model benchmark dataset differs")
        common_module.same(checker.payload, {"mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest()},
                           "selected model verifier differs from installed mechanism")
        common_module.same(benchmark.payload, {key: common_module.need(subject.payload, key)
            for key in ("metric", "metric_bounds", "tolerance", "challenges")}, "selected model benchmark differs")
        dataset = common_module.obj(selected["data"].payload, {"samples"})
        samples = common_module.seq(dataset["samples"], budget)
        common_module.same(common_module.digest(samples), common_module.need(subject.payload, "samples_digest"),
                           "selected dataset differs from model sample commitment")
        if "samples" in retained:
            common_module.same(retained["samples"], samples, "selected model samples differ")
        event_samples = []
        for i, event_id in enumerate(operands["events"]):
            event = records[event_id]
            if event.kind.value != "EVENT":
                raise Unavailable("direct model event records are required")
            payload = common_module.obj(event.payload, {"index", "sample"})
            common_module.same(payload["index"], i, "model event index differs")
            roles = dict(event.operands)
            if any(len(roles[role]) != 1 or records[roles[role][0]].kind.value != kind
                   for role, kind in (("time", "TIME"), ("space", "SPACE"), ("meaning", "OBJECT"))):
                raise Unavailable("direct time, space and meaning records per model event are required")
            common_module.same(records[roles["time"][0]].payload, {"index": i}, "model event time differs")
            common_module.same(records[roles["space"][0]].payload, {"scope": "retained-model-evaluation"},
                               "model event space differs")
            common_module.same(records[roles["meaning"][0]].payload, {"operation": "model-inference",
                "weights_digest": common_module.need(subject.payload, "weights_digest"),
                "architecture_digest": common_module.need(subject.payload, "architecture_digest")},
                "model event meaning differs")
            event_samples.append(payload["sample"])
        common_module.same(event_samples, samples, "selected model event order differs from dataset")
        result = model_module.evaluate(request["check"], matches[0].payload, retained, budget)
        return MechanismDecision(MechanismOutcome.PASS, "selected retained model check reproduced",
                                 {"model": result, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {**{key: request[key] for key in ("semantic_version", "proposition_digest", "object_kind", "object_digest", "check", "collection_digest", "policy_digest")},
            "limits_digest": "sha256:" + canonical_digest(request["limits"])}


class _ModelChecksMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != self.request["coordinate"]
                or binding.expected is not True or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound model proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained model evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ModelChecksError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=request["coordinate"], expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"], evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]), bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]), parameters=_parameters(request))
    session = VerificationSession(store); session.register(_ModelChecksMechanism(request, policy))
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
        raise ModelChecksError("certificate byte bound exhausted")
    return encoded


def build_model_checks_certificate(request: dict[str, Any], evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise ModelChecksError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ModelChecksError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_model_checks_certificate(certificate_bytes: bytes, *, expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise ModelChecksError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {"schema_version", "request", "policy_digest", "mechanism_digest", "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise ModelChecksError("canonical certificate version differs")
        if value["request"] != selected:
            raise ModelChecksError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]} or any(type(data) is not str for data in payloads.values()):
            raise ModelChecksError("retained evidence differs")
        store = EvidenceStore(); store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ModelChecksError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, ModelChecksError):
            raise
        raise ModelChecksError("invalid retained model certificate") from exc


__all__ = ["SEMANTIC_VERSION", "CHECKS", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
           "registration", "scope", "ModelDescriptor", "ModelChecksError", "model_checks_policy",
           "model_checks_request", "build_model_checks_certificate", "recheck_model_checks_certificate"]
