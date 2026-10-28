"""Current SIM-2.5: selected finite macro projection over an exact child trace.

Simulation (SIM) is a generative simulation specification. Verifier Standard
(VSTD) binds canonical JavaScript Object Notation (JSON) with Secure Hash
Algorithm 256-bit (SHA-256). Model values and tolerance use the externally
declared common macro unit; operation/item counts are dimensionless and
transport bounds count bytes. Numeric agreement is not physical truth.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module, sim as native_sim
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, sim_dynamics, sim_internal_state


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-2.5"
REQUEST_VERSION = "verifier-current-sim-perspective-request-1"
POLICY_VERSION = "verifier-current-sim-perspective-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-perspective-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-perspective-evidence-1"
MECHANISM_ID = "verifier.current-sim.selected-perspective-shift.1"
SCOPE = "finite_selected_macro_projection_alignment"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class SimPerspectiveError(ValueError):
    """Malformed external selection or substituted SIM perspective certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "For the exact selected passing SIM-2.3 child and its embedded SIM-2.1 "
            "trajectory, execute the child-bound finite projection on every retained "
            "micro state and compare each aligned retained macro state within the "
            "externally selected absolute tolerance and declared common macro unit."),
        "prerequisites": [
            "exact externally selected and replayed SIM-2.3 PASS certificate",
            "same embedded SIM-2.1 artifact and inputs with projection and macro states",
            "externally selected projection, macro-state, tolerance and unit contract",
            "bounded installed native finite refinement interpreter"],
        "exclusions": [
            "independent macro-state producer or unit-declaration authority",
            "physical correspondence, historical execution and unselected states",
            "whole SIM dynamics tier or object profile",
            "privacy, consent, governance, security and publication authority"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimPerspectiveDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimPerspectiveError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, SimPerspectiveError)


def _raw_hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, native_sim, retained_selection,
               sim_dynamics, sim_internal_state)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_PERSPECTIVE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=SimPerspectiveError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def sim_perspective_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
                    "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
                    "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest",
        "collection_digest", "internal_state_request", "internal_state_policy",
        "internal_state_certificate_digest", "projection_digest", "macro_states_digest",
        "tolerance", "macro_unit", "evidence_ref", "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE), ("object_kind", "SIM"),
                            ("proposition_digest", PROPOSITION_DIGEST)):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SimPerspectiveError("selected SIM perspective objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise SimPerspectiveError("bounded SIM subject required")
    for field in ("object_digest", "collection_digest", "internal_state_certificate_digest",
                  "projection_digest", "macro_states_digest", "evidence_ref", "policy_digest"):
        _hash(selected[field])
    child_request = sim_internal_state._request(selected["internal_state_request"])
    child_policy = sim_internal_state._policy(selected["internal_state_policy"])
    if (child_request["subject_id"] != selected["subject_id"]
            or child_request["object_digest"] != selected["object_digest"]
            or child_request["collection_digest"] != selected["collection_digest"]
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise SimPerspectiveError("selected SIM-2.3 prerequisite differs")
    selected["internal_state_request"] = child_request
    selected["internal_state_policy"] = child_policy
    try:
        tolerance = common_module.number(selected["tolerance"])
    except (ValueError, TypeError) as exc:
        raise SimPerspectiveError("bounded finite absolute tolerance required") from exc
    if tolerance < 0:
        raise SimPerspectiveError("nonnegative absolute tolerance required")
    if (type(selected["macro_unit"]) is not str
            or not selected["macro_unit"].strip()
            or len(selected["macro_unit"]) > 80):
        raise SimPerspectiveError("declared common macro unit required")
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SimPerspectiveError)
    return selected


def sim_perspective_request(*, subject_id: str, object_digest: str,
        collection_digest: str, internal_state_request: dict[str, Any],
        internal_state_policy: dict[str, Any], internal_state_certificate_digest: str,
        projection_digest: str, macro_states_digest: str, tolerance: float,
        macro_unit: str, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise SimPerspectiveError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "SIM",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "internal_state_request": internal_state_request,
        "internal_state_policy": internal_state_policy,
        "internal_state_certificate_digest": internal_state_certificate_digest,
        "projection_digest": projection_digest,
        "macro_states_digest": macro_states_digest, "tolerance": tolerance,
        "macro_unit": macro_unit, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_child(encoded: Any, selected_digest: str) -> bytes:
    if type(encoded) is not str or len(encoded) > 11 * 1024 * 1024:
        raise Refuted("bounded SIM-2.3 certificate encoding required")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise Refuted("retained SIM-2.3 encoding differs") from exc
    if len(raw) > 8 * 1024 * 1024 or _raw_hash(raw) != selected_digest:
        raise Refuted("retained SIM-2.3 certificate differs from selection")
    return raw


def _child_artifact_inputs(certificate: bytes, child_request: dict[str, Any]) -> tuple[dict, dict]:
    child = strict_json_loads(certificate.decode("utf-8"))
    encoded = child["evidence_payloads"][child_request["evidence_ref"]]
    internal_evidence = strict_json_loads(base64.b64decode(
        encoded, validate=True).decode("utf-8"))
    trajectory_raw = base64.b64decode(
        internal_evidence["trajectory_certificate"], validate=True)
    if _raw_hash(trajectory_raw) != child_request["trajectory_certificate_digest"]:
        raise Refuted("SIM-2.3 retained trajectory differs")
    trajectory = strict_json_loads(trajectory_raw.decode("utf-8"))
    encoded = trajectory["evidence_payloads"][child_request["trajectory_request"]["evidence_ref"]]
    retained = strict_json_loads(base64.b64decode(
        encoded, validate=True).decode("utf-8"))
    return retained["artifact"], retained["inputs"]


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "internal_state_certificate"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained SIM perspective evidence differs")
        if value["internal_state_certificate"] is None:
            raise Unavailable("selected SIM-2.3 prerequisite absent")
        child_raw = _decode_child(value["internal_state_certificate"],
                                  request["internal_state_certificate_digest"])
        try:
            child = sim_internal_state.recheck_sim_internal_state_certificate(
                child_raw, expected_request=request["internal_state_request"],
                policy=request["internal_state_policy"])
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise Refuted("selected SIM-2.3 certificate does not replay") from exc
        if child["status"] == "FAIL":
            raise Refuted("selected SIM-2.3 prerequisite failed")
        if child["status"] != "PASS":
            raise Unavailable("selected SIM-2.3 prerequisite not established")
        artifact, inputs = _child_artifact_inputs(
            child_raw, request["internal_state_request"])
        for name, selected_digest in (("projection", request["projection_digest"]),
                ("macro_states", request["macro_states_digest"])):
            source = artifact if name == "projection" else inputs
            if name not in source or source[name] is None:
                raise Unavailable("selected " + name + " evidence absent")
            retained = source[name]
            if type(retained) is not (dict if name == "projection" else list):
                raise Refuted("selected " + name + " shape differs")
            if "sha256:" + canonical_digest(retained) != selected_digest:
                raise Refuted("selected " + name + " differs from external selection")
        if not artifact["projection"]:
            raise Unavailable("empty selected macro projection")
        for name in ("macro_digest", "tolerance", "macro_unit"):
            if name not in artifact or artifact[name] is None:
                raise Unavailable("selected " + name + " declaration absent")
        if artifact["macro_digest"] != request["macro_states_digest"]:
            raise Refuted("selected macro commitment differs")
        if (type(artifact["tolerance"]) not in (int, float)
                or canonical_bytes(artifact["tolerance"]) != canonical_bytes(request["tolerance"])
                or type(artifact["macro_unit"]) is not str
                or artifact["macro_unit"] != request["macro_unit"]):
            raise Refuted("selected macro tolerance or unit differs")
        budget = common_module.Budget(request["limits"]["max_operations"],
                                      request["limits"]["max_items"])
        common_module.inspect_structure({"projection": artifact["projection"],
            "macro_states": inputs["macro_states"]}, budget)
        observed = native_sim.evaluate("refinement", artifact, inputs, budget,
                                       witness_keys={})
        expected = request["internal_state_request"]["trajectory_request"]["expected_counts"]
        if observed != expected:
            raise Refuted("selected macro trajectory counts differ")
        return MechanismDecision(MechanismOutcome.PASS,
            "every selected aligned macro state matches the executed finite projection",
            {"states": observed["states"], "transitions": observed["transitions"],
             "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            ArithmeticError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SimPerspectiveMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict, policy: dict) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound SIM perspective proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected SIM perspective bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict, policy: dict, store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SimPerspectiveError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)})
    session = VerificationSession(store)
    session.register(_SimPerspectiveMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "SIM", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "sim_tier_2_conformance": "NOT_ESTABLISHED",
        "historical_execution": "NOT_ESTABLISHED",
        "physical_macro_truth": "NOT_ESTABLISHED",
        "macro_source_authority": "NOT_ESTABLISHED",
        "macro_unit_authority": "NOT_ESTABLISHED",
        "tolerance_authority": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict()}
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
        raise SimPerspectiveError("SIM perspective certificate byte bound exhausted")
    return encoded


def build_sim_perspective_certificate(request: dict, evidence_bytes: bytes | None,
                                      *, policy: dict) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]):
            raise SimPerspectiveError("immutable bounded SIM perspective evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimPerspectiveError("SIM perspective evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_sim_perspective_certificate(certificate_bytes: bytes, *,
        expected_request: dict, policy: dict) -> dict:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise SimPerspectiveError("bounded immutable SIM perspective certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"},
            "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise SimPerspectiveError("canonical SIM perspective certificate version differs")
        if value["request"] != selected:
            raise SimPerspectiveError("SIM perspective certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimPerspectiveError("retained SIM perspective evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimPerspectiveError("SIM perspective certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, SimPerspectiveError):
            raise
        raise SimPerspectiveError("invalid retained SIM perspective certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SimPerspectiveDescriptor",
    "SimPerspectiveError", "registration", "sim_perspective_policy",
    "sim_perspective_request", "build_sim_perspective_certificate",
    "recheck_sim_perspective_certificate"]
