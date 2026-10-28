"""Observed bounded MODEL execution on one installed Windows processor runtime.

Verifier Standard (VSTD); MODEL names the model reproducibility object;
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
central processing unit (CPU); graphics processing unit (GPU).
MiB means 1,048,576 bytes. Job memory limits count committed bytes, not
resident bytes. The observed bracket is not a universal hardware minimum.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import platform
import sys
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
from verifier.domains import numerical as numerical_module
from verifier.domains import verifier_execution as execution_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import model_artifact_bytes, retained_selection
from verifier.domains.verifier_execution import _run_windows


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "MODEL-3.2"
REQUEST_VERSION = "verifier-current-model-hardware-request-1"
POLICY_VERSION = "verifier-current-model-hardware-policy-1"
CERTIFICATE_VERSION = "verifier-current-model-hardware-certificate-1"
EVIDENCE_VERSION = "verifier-current-model-hardware-evidence-1"
MECHANISM_ID = "verifier.current-model.observed-hardware-bracket.1"
SCOPE = "finite_windows_cpu_model_memory_bracket"
BACKEND = execution_module.MECHANISM
_CEILINGS = {
    "max_objects": 256,
    "max_operations": 100000,
    "max_composition_operations": 100000,
    "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
_MAX_MEMORY_BYTES = 64 * 1024 * 1024
_MIN_MEMORY_BYTES = 8 * 1024 * 1024
_MAX_NATIVE_OPERATIONS = 1_000_000
_MAX_TRIALS = 3
_MAX_WALL_SECONDS = 5

# This is fixed installed source, never caller-supplied code. The selected
# payload is only bounded canonical JSON for the supported dense model.
_WORKER = """
import json
import sys
sys.path.insert(0, sys.argv[1])
from verifier.domains.numerical import network, forward
from verifier.domains.common import Budget
from verifier.core.receipt import strict_json_loads

try:
    packet = strict_json_loads(sys.stdin.buffer.read().decode("utf-8"))
    budget = Budget(int(sys.argv[2]), 4096)
    net = network(packet["architecture"], packet["weights"], budget)
    output, _ = forward(net, packet["input"], budget)
except MemoryError:
    sys.stdout.write('{"status":"RESOURCE_EXHAUSTED"}')
else:
    sys.stdout.write(json.dumps({
        "status": "PASS", "output": output, "operations": budget.used,
    }, sort_keys=True))
"""


class ModelHardwareError(ValueError):
    """Malformed selection, policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "MODEL",
        "scope": SCOPE,
        "proposition": (
            "For the externally selected exact MODEL, raw artifact bytes and "
            "typed HARDWARE operand, a fixed installed Windows CPU dense-model "
            "worker observes resource exhaustion under one selected enforced "
            "committed-memory cap and the selected output under a larger cap, "
            "with both Job Object limits verified before child resume."
        ),
        "prerequisites": [
            "independently selected MODEL and HARDWARE records, retained open "
            "architecture and weight bytes, finite selected input/output, "
            "Windows CPython Job Object enforcement and installed checker source"
        ],
        "exclusions": [
            "model-intrinsic minimum memory or every input/runtime",
            "resident memory, GPU, quantum or other accelerator requirements",
            "authenticated physical device identity or sensor calibration",
            "storage, network, power, thermal or whole-hardware profile",
            "training, quantization accuracy, provenance and disclosure authority",
            "whole MODEL statics tier or cross-runtime portability",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class ModelHardwareDescriptor:
    """Native route metadata for one local resource-bracket observation."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, numerical_module, execution_module,
        model_artifact_bytes, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in (
        "NAMESPACE_OBJECTS.md", "DOMAIN_OBLIGATIONS.md",
        "CURRENT_MODEL_ARTIFACT_BYTES.md", "CURRENT_MODEL_HARDWARE_OBSERVATION.md",
    ):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _supported_platform() -> bool:
    return os.name == "nt" and sys.implementation.name == "cpython"


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=ModelHardwareError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def model_hardware_policy(*, trust_roots: list[str],
                          max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                          ) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _request(value: Any) -> dict[str, Any]:
    request = retained_selection.record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "evidence_ref", "policy_digest", "limits", "lower_memory_bytes",
        "upper_memory_bytes", "wall_seconds", "trials", "max_native_operations",
    }, "request", ModelHardwareError)
    for key, expected in (
        ("schema_version", REQUEST_VERSION),
        ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE),
        ("proposition_digest", PROPOSITION_DIGEST),
        ("object_kind", "MODEL"),
    ):
        if type(request[key]) is not str or request[key] != expected:
            raise ModelHardwareError("selected model hardware objective differs")
    if (type(request["subject_id"]) is not str
            or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise ModelHardwareError("bounded subject identifier required")
    for key in ("object_digest", "collection_digest", "evidence_ref", "policy_digest"):
        retained_selection.commitment(request[key], ModelHardwareError)
    request["limits"] = retained_selection.limits(
        request["limits"], _CEILINGS, ModelHardwareError,
    )
    low, high = request["lower_memory_bytes"], request["upper_memory_bytes"]
    if (type(low) is not int or type(high) is not int
            or not _MIN_MEMORY_BYTES <= low < high <= _MAX_MEMORY_BYTES):
        raise ModelHardwareError("finite increasing job-memory bracket required")
    if (type(request["wall_seconds"]) is not int
            or not 1 <= request["wall_seconds"] <= _MAX_WALL_SECONDS):
        raise ModelHardwareError("bounded wall seconds required")
    if (type(request["trials"]) is not int
            or not 1 <= request["trials"] <= _MAX_TRIALS):
        raise ModelHardwareError("bounded trial count required")
    if (type(request["max_native_operations"]) is not int
            or not 1 <= request["max_native_operations"] <= _MAX_NATIVE_OPERATIONS):
        raise ModelHardwareError("bounded native operations required")
    return request


def model_hardware_request(*, subject_id: str, object_digest: str,
                           collection_digest: str, evidence_ref: str,
                           policy: dict[str, Any], lower_memory_bytes: int,
                           upper_memory_bytes: int, wall_seconds: int,
                           trials: int, max_native_operations: int,
                           limits: dict[str, int] | None = None
                           ) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise ModelHardwareError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "MODEL",
        "subject_id": subject_id,
        "object_digest": object_digest,
        "collection_digest": collection_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
        "lower_memory_bytes": lower_memory_bytes,
        "upper_memory_bytes": upper_memory_bytes,
        "wall_seconds": wall_seconds,
        "trials": trials,
        "max_native_operations": max_native_operations,
    })


def _native_observation(data: bytes, cap: int, request: dict[str, Any],
                        expected_output: list[float]) -> tuple[str, str]:
    source = str(Path(__file__).resolve().parents[3])
    argv = [
        sys.executable, "-I", "-S", "-B", "-u", "-c", _WORKER, source,
        str(request["max_native_operations"]),
    ]
    try:
        run = _run_windows(argv, data, cap, float(request["wall_seconds"]))
    except OSError as exc:
        raise Unavailable("native hardware enforcement unavailable: " + str(exc)) from exc
    if (run.get("timed_out") or run.get("output_exhausted")
            or run.get("owned_job_empty") is not True
            or run.get("limits_verified_before_resume") is not True
            or run.get("applied_limits") != {
                "job_committed_memory_bytes": cap, "job_limit_flags": 0x2200,
            }):
        raise Unavailable("verified native resource bounds or cleanup unavailable")
    if (run.get("exit_code") != 0 or run.get("stderr")
            or type(run.get("stdout")) is not bytes):
        raise Unavailable("native child result is ambiguous")
    try:
        observed = strict_json_loads(run["stdout"].decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise Unavailable("native child returned no bounded result") from exc
    if observed == {"status": "RESOURCE_EXHAUSTED"}:
        return "RESOURCE_EXHAUSTED", "selected job limit exhausted after worker admission"
    record = retained_selection.record(
        observed, {"status", "output", "operations"},
        "native model result", ModelHardwareError,
    )
    if record["status"] != "PASS":
        raise Unavailable("native child has unsupported status")
    count = record["operations"]
    if (type(count) is not int or not 1 <= count <= request["max_native_operations"]):
        raise Refuted("native work exceeds selected operation bound")
    if type(record["output"]) is not list or record["output"] != expected_output:
        raise Refuted("observed model output differs from selected output")
    return "PASS", "selected output observed under verified job cap"


def _evaluate(data: bytes, request: dict[str, Any],
              policy: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = retained_selection.record(
            strict_json_loads(data.decode("utf-8")),
            {"schema_version", "objects", "inputs"}, "evidence",
            ModelHardwareError,
        )
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
            selected = retained_selection.record(
                row, {"object_id", "kind", "payload", "operands"},
                "namespace record", ModelHardwareError,
            )
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if (len(matches) != 1 or matches[0].kind.value != "MODEL"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained model subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(
                MechanismOutcome(composition.verdict.value), composition.reason,
            )
        if value["inputs"] is None:
            raise Unavailable("retained model workload absent")
        inputs = retained_selection.record(
            value["inputs"], {
                "architecture_b64", "weights_b64", "input", "expected_output",
            }, "model workload", ModelHardwareError,
        )
        prereq_bytes = canonical_bytes({
            "schema_version": model_artifact_bytes.EVIDENCE_VERSION,
            "objects": rows,
            "inputs": {
                "architecture_b64": inputs["architecture_b64"],
                "weights_b64": inputs["weights_b64"],
            },
        })
        prereq_policy = model_artifact_bytes.model_artifact_bytes_policy(
            trust_roots=policy["trust_roots"],
        )
        prereq_request = model_artifact_bytes.model_artifact_bytes_request(
            subject_id=request["subject_id"],
            object_digest=request["object_digest"],
            collection_digest=request["collection_digest"],
            evidence_ref="sha256:" + hashlib.sha256(prereq_bytes).hexdigest(),
            policy=prereq_policy,
        )
        prereq = model_artifact_bytes.build_model_artifact_bytes_certificate(
            prereq_request, prereq_bytes, policy=prereq_policy,
        )
        prereq_result = model_artifact_bytes.recheck_model_artifact_bytes_certificate(
            prereq, expected_request=prereq_request, policy=prereq_policy,
        )
        if prereq_result["status"] != "PASS":
            return MechanismDecision(
                MechanismOutcome(prereq_result["status"]),
                "MODEL-3.1 raw-byte prerequisite did not reproduce",
            )
        hardware_refs = dict(matches[0].operands).get("hardware", ())
        if len(hardware_refs) != 1:
            raise Refuted("one selected HARDWARE operand required")
        hardware = next(
            (item for item in objects if item.object_id == hardware_refs[0]), None,
        )
        if hardware is None or hardware.kind.value != "HARDWARE":
            raise Refuted("selected HARDWARE operand differs")
        if not _supported_platform():
            raise Unavailable("Windows CPython Job Object observation unavailable")
        if (type(hardware.payload) is not dict
                or hardware.payload.get("process_backend") != BACKEND
                or hardware.payload.get("machine") != platform.machine()):
            raise Refuted("selected HARDWARE declaration differs from local runtime")
        try:
            architecture = strict_json_loads(base64.b64decode(
                inputs["architecture_b64"], validate=True,
            ).decode("utf-8"))
            weights = strict_json_loads(base64.b64decode(
                inputs["weights_b64"], validate=True,
            ).decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise Unavailable("retained raw artifacts are not supported JSON models") from exc
        if (canonical_bytes(architecture) != base64.b64decode(inputs["architecture_b64"])
                or canonical_bytes(weights) != base64.b64decode(inputs["weights_b64"])):
            raise Unavailable("retained raw artifacts are not canonical dense JSON")
        if type(inputs["input"]) is not list or type(inputs["expected_output"]) is not list:
            raise Refuted("finite input and expected output vectors required")
        if not 1 <= len(inputs["input"]) <= limits["max_items"]:
            raise Refuted("selected input vector length invalid")
        if not 1 <= len(inputs["expected_output"]) <= limits["max_items"]:
            raise Refuted("selected output vector length invalid")
        vector_budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        model_input = numerical_module.vector(inputs["input"], vector_budget)
        expected_output = numerical_module.vector(
            inputs["expected_output"], vector_budget,
        )
        packet = canonical_bytes({
            "architecture": architecture, "weights": weights, "input": model_input,
        })
        if len(packet) > limits["max_evidence_bytes"]:
            raise Unavailable("native model payload bound exhausted")
        observations = []
        for trial in range(request["trials"]):
            low, _ = _native_observation(
                packet, request["lower_memory_bytes"], request, expected_output,
            )
            if low != "RESOURCE_EXHAUSTED":
                raise Refuted("selected lower cap did not exhaust this workload")
            high, _ = _native_observation(
                packet, request["upper_memory_bytes"], request, expected_output,
            )
            if high != "PASS":
                raise Unavailable("selected upper cap did not complete this workload")
            observations.append({
                "trial": trial, "lower": low, "upper": high,
            })
        return MechanismDecision(
            MechanismOutcome.PASS,
            "selected workload resource bracket reproduced on local Windows CPU",
            {
                "lower_memory_bytes": request["lower_memory_bytes"],
                "upper_memory_bytes": request["upper_memory_bytes"],
                "trials": observations,
                "machine": platform.machine(),
                "python": list(sys.version_info[:3]),
                "backend": BACKEND,
                "model_3_1_prerequisite": "REPLAYED_LOCAL",
            },
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _ModelHardwareMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != retained_selection.parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound model hardware proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one retained model workload is required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise ModelHardwareError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=retained_selection.parameters(request),
    )
    session = VerificationSession(store)
    session.register(_ModelHardwareMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "object_kind": "MODEL",
        "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "statics_profile_conformance": "NOT_ESTABLISHED",
        "model_3_1_prerequisite": (
            "REPLAYED_LOCAL" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"
        ),
        "minimum_required_memory": "NOT_ESTABLISHED",
        "cross_runtime_hardware": "NOT_ESTABLISHED",
        "physical_device_authenticity": "NOT_ESTABLISHED",
        "storage_and_accelerators": "NOT_ESTABLISHED",
        "public_disclosure_authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION,
        "request": request,
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
        raise ModelHardwareError("certificate byte bound exhausted")
    return encoded


def build_model_hardware_certificate(request: dict[str, Any],
                                     evidence_bytes: bytes | None, *,
                                     policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise ModelHardwareError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise ModelHardwareError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_model_hardware_certificate(certificate_bytes: bytes, *,
                                        expected_request: dict[str, Any],
                                        policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise ModelHardwareError("bounded immutable certificate bytes required")
    try:
        value = retained_selection.record(
            strict_json_loads(certificate_bytes.decode("utf-8")), {
                "schema_version", "request", "policy_digest", "mechanism_digest",
                "proposition_digest", "evidence_refs", "evidence_payloads",
                "result", "digest",
            }, "certificate", ModelHardwareError,
        )
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION):
            raise ModelHardwareError("canonical certificate version differs")
        if value["request"] != selected:
            raise ModelHardwareError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise ModelHardwareError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise ModelHardwareError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError,
            RecursionError, OverflowError) as exc:
        if isinstance(exc, ModelHardwareError):
            raise
        raise ModelHardwareError("invalid retained model hardware certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "BACKEND",
    "ModelHardwareDescriptor", "ModelHardwareError", "registration",
    "model_hardware_policy", "model_hardware_request",
    "build_model_hardware_certificate", "recheck_model_hardware_certificate",
]
