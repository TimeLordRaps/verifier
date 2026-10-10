"""Current SIM-2.4: signed per-step local resource capture over an exact replay.

Simulation (SIM) is a generative simulation specification. Acronyms:
application programming interface (API); central processing unit (CPU);
graphics processing unit (GPU).
Measured units are thread CPU nanoseconds and traced Python allocation bytes.
This checker verifies a selected collector's statement, not its honesty or
physical device attribution; neither a limit nor Budget.used is a measurement.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.core.signature_keys import admit_ed25519_public_key
from verifier.domains import common as common_module, sim as native_sim
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, sim_dynamics


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-2.4"
REQUEST_VERSION = "verifier-current-sim-resource-request-1"
POLICY_VERSION = "verifier-current-sim-resource-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-resource-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-resource-evidence-1"
MECHANISM_ID = "verifier.current-sim.signed-step-resource-capture.1"
SCOPE = "signed_selected_local_transition_resource_capture"
METHOD = "cpython-thread-cpu-tracemalloc-1"
_CEILINGS = {"max_evidence_bytes": 8 * 1024 * 1024,
             "max_operations": 100000, "max_items": 4096}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class SimResourceError(ValueError):
    """Malformed external SIM resource selection or certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "For the exact selected passing SIM-2.1 trace, an externally admitted "
            "collector key signs one bounded local CPython thread-CPU-time and "
            "traced-Python-allocation record per transition, with each record "
            "bound to its selected input and output state."),
        "prerequisites": ["exact passing selected SIM-2.1 child certificate",
                          "externally admitted collector public key and signature",
                          "retained per-step capture with current installed meter source"],
        "exclusions": ["collector honesty, host attestation and historical execution",
                       "whole-device CPU, resident memory, GPU, energy or cloud billing",
                       "whole dynamics tier, privacy, consent, governance and publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimResourceDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimResourceError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, SimResourceError)


def _raw_hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, native_sim, retained_selection,
               sim_dynamics)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    paths["sim_resource_worker"] = Path(__file__).with_name("sim_resource_worker.py")
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_RESOURCE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    selected = retained_selection.policy(value, error_type=SimResourceError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)
    for key in selected["trust_roots"]:
        try:
            admit_ed25519_public_key(bytes.fromhex(key))
        except (TypeError, ValueError) as exc:
            raise SimResourceError("collector trust root must be an admitted Ed25519 key") from exc
    return selected


def sim_resource_policy(*, trust_roots: list[str],
                        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
                    "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
                    "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest",
        "collection_digest", "trajectory_request", "trajectory_policy",
        "trajectory_certificate_digest", "evidence_ref", "policy_digest", "limits"},
        "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE), ("object_kind", "SIM"),
                            ("proposition_digest", PROPOSITION_DIGEST)):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SimResourceError("selected SIM resource objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise SimResourceError("bounded SIM subject required")
    for field in ("object_digest", "collection_digest", "trajectory_certificate_digest",
                  "evidence_ref", "policy_digest"):
        _hash(selected[field])
    child_request = sim_dynamics._request(selected["trajectory_request"])
    child_policy = sim_dynamics._policy(selected["trajectory_policy"])
    if (child_request["subject_id"] != selected["subject_id"]
            or child_request["object_digest"] != selected["object_digest"]
            or child_request["collection_digest"] != selected["collection_digest"]
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise SimResourceError("selected SIM-2.1 prerequisite differs")
    selected["trajectory_request"] = child_request
    selected["trajectory_policy"] = child_policy
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SimResourceError)
    return selected


def sim_resource_request(*, subject_id: str, object_digest: str,
        collection_digest: str, trajectory_request: dict[str, Any],
        trajectory_policy: dict[str, Any], trajectory_certificate_digest: str,
        evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise SimResourceError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "SIM",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "trajectory_request": trajectory_request, "trajectory_policy": trajectory_policy,
        "trajectory_certificate_digest": trajectory_certificate_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_child(encoded: Any, selected_digest: str) -> bytes:
    if type(encoded) is not str or len(encoded) > 12 * 1024 * 1024:
        raise Refuted("bounded SIM-2.1 certificate encoding required")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise Refuted("retained SIM-2.1 encoding differs") from exc
    if _raw_hash(raw) != selected_digest:
        raise Refuted("retained SIM-2.1 certificate differs from selection")
    return raw


def _child_data(certificate: bytes, request: dict[str, Any]) -> tuple[dict, dict]:
    child = strict_json_loads(certificate.decode("utf-8"))
    encoded = child["evidence_payloads"][request["evidence_ref"]]
    data = strict_json_loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
    return data["artifact"], data["inputs"]


def _capture_shape(value: Any, request: dict[str, Any], child: bytes) -> dict:
    record = _intrinsic_capture(value)
    artifact, inputs = _child_data(child, request["trajectory_request"])
    states, entropy = inputs["states"], inputs["entropy"]
    rows = record["steps"]
    if (len(rows) != len(entropy)
            or len(rows) > request["limits"]["max_items"]):
        raise Refuted("per-step resource coverage differs")
    for index, row in enumerate(rows):
        if (row["step"] != index
                or row["input_state_digest"] != "sha256:" + canonical_digest(states[index])
                or row["output_state_digest"] != "sha256:" + canonical_digest(states[index + 1])):
            raise Refuted("resource step differs from selected trajectory")
    return record


def _intrinsic_capture(value: Any) -> dict:
    record = _record(value, {"method", "target", "worker_source_digest",
                             "run_id", "process_id", "steps"}, "capture")
    if record["method"] != METHOD or (type(record["target"]) is not str
            or not record["target"].startswith("CPython ")
            or len(record["target"]) > 64):
        raise Refuted("selected resource meter method or target differs")
    if record["worker_source_digest"] != _raw_hash(
            Path(__file__).with_name("sim_resource_worker.py").read_bytes()):
        raise Refuted("resource meter source differs from installed source")
    if (type(record["run_id"]) is not str
            or re.fullmatch(r"[0-9a-f]{32}", record["run_id"]) is None
            or type(record["process_id"]) is not int
            or not 1 <= record["process_id"] <= 2**31 - 1):
        raise Refuted("bounded new-run execution identity required")
    rows = record["steps"]
    if type(rows) is not list or len(rows) > _CEILINGS["max_items"]:
        raise Refuted("bounded per-step resource records required")
    for row in rows:
        row = _record(row, {"step", "input_state_digest", "output_state_digest",
                            "thread_cpu_ns", "traced_peak_bytes"}, "step")
        if type(row["step"]) is not int or not 0 <= row["step"] < _CEILINGS["max_items"]:
            raise Refuted("bounded resource step index required")
        for name in ("input_state_digest", "output_state_digest"):
            retained_selection.commitment(row[name], SimResourceError)
        for name in ("thread_cpu_ns", "traced_peak_bytes"):
            if type(row[name]) is not int or not 0 <= row[name] <= 2**63 - 1:
                raise Refuted("bounded measured unit required for every step")
    return record


def _verify_signature(value: dict, policy: dict) -> None:
    key = value["collector_key"]
    if type(key) is not str or key not in policy["trust_roots"]:
        raise Refuted("collector key is not externally admitted")
    try:
        public = admit_ed25519_public_key(bytes.fromhex(key))
        signature = base64.b64decode(value["signature"], validate=True)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        signed = {k: v for k, v in value.items() if k != "signature"}
        Ed25519PublicKey.from_public_bytes(public).verify(signature,
                                                          canonical_bytes(signed))
    except ImportError as exc:
        raise Unavailable("signature backend unavailable") from exc
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise Refuted("collector signature does not bind retained capture") from exc


def _evaluate(data: bytes, request: dict[str, Any], policy: dict[str, Any]) -> MechanismDecision:
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "trajectory_certificate", "capture",
             "collector_key", "signature"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained SIM resource evidence differs")
        child = None
        if value["trajectory_certificate"] is not None:
            child = _decode_child(value["trajectory_certificate"],
                                  request["trajectory_certificate_digest"])
        if value["capture"] is not None:
            _intrinsic_capture(value["capture"])
        _verify_signature(value, policy)
        if child is None:
            raise Unavailable("selected SIM-2.1 certificate absent")
        try:
            prerequisite = sim_dynamics.recheck_sim_dynamics_certificate(
                child, expected_request=request["trajectory_request"],
                policy=request["trajectory_policy"])
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise Refuted("selected SIM-2.1 certificate does not replay") from exc
        if prerequisite["status"] == "FAIL":
            raise Refuted("selected SIM-2.1 prerequisite failed")
        if prerequisite["status"] != "PASS":
            raise Unavailable("selected SIM-2.1 prerequisite not established")
        if value["capture"] is None:
            raise Unavailable("selected per-step capture absent")
        _capture_shape(value["capture"], request, child)
        return MechanismDecision(MechanismOutcome.PASS,
            "admitted collector signature binds selected per-step local measurements",
            {"measured_steps": len(value["capture"]["steps"])})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SimResourceMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict, policy: dict) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound SIM resource proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one SIM resource bundle required")
        return _evaluate(evidence[0], self.request, self.policy)


def _build(request: dict, policy: dict, store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SimResourceError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)})
    session = VerificationSession(store)
    session.register(_SimResourceMechanism(request, policy))
    evaluation = session.evaluate(binding)
    # Signature replay is only an auxiliary. An admitted signer can fabricate
    # numbers, so it cannot establish actual historical consumption.
    result = {"status": "FAIL" if evaluation.outcome == MechanismOutcome.FAIL else "UNKNOWN",
        "signed_record_status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "SIM", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "sim_tier_2_conformance": "NOT_ESTABLISHED",
        "historical_device_use": "NOT_ESTABLISHED",
        "collector_honesty": "NOT_ESTABLISHED",
        "actual_consumption_correspondence": "NOT_ESTABLISHED",
        "physical_resource_truth": "NOT_ESTABLISHED",
        "authority": "SELECTED_COLLECTOR_KEY_ONLY", "evaluation": evaluation.to_dict()}
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
        raise SimResourceError("SIM resource certificate byte bound exhausted")
    return encoded


def build_sim_resource_certificate(request: dict, evidence_bytes: bytes | None,
                                   *, policy: dict) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]:
            raise SimResourceError("immutable bounded SIM resource evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimResourceError("SIM resource evidence differs from selected reference")
    return _build(selected, admitted, store)


def recheck_sim_resource_certificate(certificate_bytes: bytes, *,
        expected_request: dict, policy: dict) -> dict:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise SimResourceError("bounded immutable SIM resource certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"},
            "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise SimResourceError("canonical SIM resource certificate version differs")
        if value["request"] != selected:
            raise SimResourceError("SIM resource certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimResourceError("retained SIM resource evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimResourceError("SIM resource certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, SimResourceError):
            raise
        raise SimResourceError("invalid retained SIM resource certificate") from exc


def assess_fresh_sim_resource(trajectory_certificate: bytes, *,
        child_request: dict, child_policy: dict,
        timeout_seconds: float = 15.0) -> dict[str, Any]:
    """Observe this new bounded local replay, never historical producer metrics.

    The fixed worker is invoked by this checker. Its source and the host are
    trusted local assumptions. A returned report is not third-party attestation.
    """
    if (type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 30):
        raise SimResourceError("finite meter timeout of at most 30 seconds required")
    if type(trajectory_certificate) is not bytes or len(trajectory_certificate) > 8 * 1024 * 1024:
        raise SimResourceError("bounded immutable SIM-2.1 child required")
    request, policy = sim_dynamics._request(child_request), sim_dynamics._policy(child_policy)
    try:
        result = sim_dynamics.recheck_sim_dynamics_certificate(
            trajectory_certificate, expected_request=request, policy=policy)
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise SimResourceError("selected SIM-2.1 child does not replay") from exc
    if result["status"] != "PASS":
        raise SimResourceError("SIM-2.1 child must pass before resource capture")
    artifact, inputs = _child_data(trajectory_certificate, request)
    work = canonical_bytes({"artifact": artifact, "inputs": inputs,
        "max_operations": request["limits"]["max_operations"],
        "max_items": request["limits"]["max_items"]})
    if len(work) > 4 * 1024 * 1024:
        raise SimResourceError("worker input bound exhausted")
    path = Path(__file__).with_name("sim_resource_worker.py")
    try:
        completed = subprocess.run([sys.executable, "-I", str(path)], input=work,
            capture_output=True, timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired as exc:
        raise SimResourceError("resource meter timed out") from exc
    except OSError as exc:
        raise SimResourceError("resource meter could not start") from exc
    if completed.returncode != 0 or len(completed.stdout) > 1024 * 1024:
        raise SimResourceError("resource meter failed or output bound exhausted")
    try:
        capture = strict_json_loads(completed.stdout.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise SimResourceError("resource meter returned invalid output") from exc
    if type(capture) is not dict:
        raise SimResourceError("resource meter returned invalid record")
    capture["worker_source_digest"] = _raw_hash(path.read_bytes())
    selected = {"trajectory_request": request, "limits": _CEILINGS}
    try:
        _capture_shape(capture, selected, trajectory_certificate)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise SimResourceError("resource meter output differs from selected trace") from exc
    return {"status": "PASS", "scope": "this_new_bounded_replay_only",
        "selected_child_digest": _raw_hash(trajectory_certificate),
        "historical_metric_correspondence": "NOT_ESTABLISHED",
        "collector_attestation": "NOT_ESTABLISHED",
        "physical_device_use": "NOT_ESTABLISHED",
        "capture": capture}


def capture_sim_resource_evidence(trajectory_certificate: bytes, *,
        child_request: dict, child_policy: dict, signing_key: Any,
        timeout_seconds: float = 15.0) -> bytes:
    """Sign one fresh observation as an auxiliary, not a SIM-2.4 closure.

    The signer must be controlled by an externally admitted collector. Invoking
    this API with an arbitrary key does not establish collector independence.
    """
    report = assess_fresh_sim_resource(trajectory_certificate,
        child_request=child_request, child_policy=child_policy,
        timeout_seconds=timeout_seconds)
    try:
        from cryptography.hazmat.primitives import serialization
        public = signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex()
        admit_ed25519_public_key(bytes.fromhex(public))
        body = {"schema_version": EVIDENCE_VERSION,
            "trajectory_certificate": base64.b64encode(trajectory_certificate).decode("ascii"),
            "capture": report["capture"], "collector_key": public}
        signature = signing_key.sign(canonical_bytes(body))
    except (ImportError, TypeError, ValueError, AttributeError) as exc:
        raise SimResourceError("admitted collector signing key required") from exc
    body["signature"] = base64.b64encode(signature).decode("ascii")
    return canonical_bytes(body)


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SimResourceDescriptor",
    "SimResourceError", "registration", "sim_resource_policy",
    "sim_resource_request", "assess_fresh_sim_resource",
    "capture_sim_resource_evidence",
    "build_sim_resource_certificate", "recheck_sim_resource_certificate"]
