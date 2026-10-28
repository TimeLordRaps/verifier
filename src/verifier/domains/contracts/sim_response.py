"""Current simulation (SIM) action response in a selected finite model.

Verifier Standard (VSTD) claims model-relative action effects, not historical
or physical causality. JavaScript Object Notation (JSON) and Secure Hash
Algorithm 256-bit (SHA-256) bind retained bytes. Times and delay use the
selected model's time unit; counts are dimensionless and limits count bytes.
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
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module, sim as native_sim
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, sim_dynamics


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-2.2"
REQUEST_VERSION = "verifier-current-sim-response-request-1"
POLICY_VERSION = "verifier-current-sim-response-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-response-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-response-evidence-1"
MECHANISM_ID = "verifier.current-sim.selected-action-response.1"
SCOPE = "finite_model_relative_action_response"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class SimResponseError(ValueError):
    """Malformed external selection or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "For an externally selected exact SIM-2.1 PASS certificate and the same "
            "retained trajectory, each selected in-bounds action produces its exact "
            "next state under an action-aware transition expression, differs from "
            "the declared baseline action's next state, and responds within the "
            "selected simulated-time limit."
        ),
        "prerequisites": [
            "independently selected and replayed SIM-2.1 PASS certificate",
            "exact action program, actions, baseline, bounds, time unit and delay limit",
            "retained next states, entropy and increasing model times",
        ],
        "exclusions": [
            "historical or physical causality, intervention outside the selected model",
            "unselected actions, hidden states, complete SIM dynamics tier or object profile",
            "privacy, consent, governance, security and publication authority",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimResponseDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimResponseError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, SimResponseError)


def _raw_hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, native_sim, retained_selection,
               sim_dynamics)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_RESPONSE.md",
                 "CURRENT_SIM_DYNAMICS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=SimResponseError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def sim_response_policy(*, trust_roots: list[str],
                        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
                    "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
                    "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "trajectory_request", "trajectory_policy", "trajectory_certificate_digest",
        "action_artifact_digest", "action_inputs_digest", "max_response_delay",
        "time_unit", "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "SIM"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SimResponseError("selected action-response objective differs")
    if type(selected["subject_id"]) is not str or not selected["subject_id"].strip():
        raise SimResponseError("selected SIM subject required")
    for field in ("object_digest", "collection_digest", "trajectory_certificate_digest",
                  "action_artifact_digest", "action_inputs_digest", "evidence_ref",
                  "policy_digest"):
        _hash(selected[field])
    child_request = sim_dynamics._request(selected["trajectory_request"])
    child_policy = sim_dynamics._policy(selected["trajectory_policy"])
    if (child_request["subject_id"] != selected["subject_id"]
            or child_request["object_digest"] != selected["object_digest"]
            or child_request["collection_digest"] != selected["collection_digest"]
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise SimResponseError("selected SIM-2.1 dependency differs")
    selected["trajectory_request"] = child_request
    selected["trajectory_policy"] = child_policy
    delay = selected["max_response_delay"]
    if type(delay) not in (int, float) or not 0 < delay <= 1e100:
        raise SimResponseError("positive finite simulated-time response limit required")
    unit = selected["time_unit"]
    if type(unit) is not str or not unit.strip() or len(unit) > 64:
        raise SimResponseError("bounded model time unit required")
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SimResponseError)
    return selected


def sim_response_request(*, subject_id: str, object_digest: str,
                         collection_digest: str, trajectory_request: dict[str, Any],
                         trajectory_policy: dict[str, Any],
                         trajectory_certificate_digest: str,
                         action_artifact_digest: str, action_inputs_digest: str,
                         max_response_delay: float, time_unit: str,
                         evidence_ref: str, policy: dict[str, Any],
                         limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise SimResponseError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "SIM", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "trajectory_request": trajectory_request, "trajectory_policy": trajectory_policy,
        "trajectory_certificate_digest": trajectory_certificate_digest,
        "action_artifact_digest": action_artifact_digest,
        "action_inputs_digest": action_inputs_digest,
        "max_response_delay": max_response_delay, "time_unit": time_unit,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _decode_child(encoded: str, selected_digest: str) -> bytes:
    if type(encoded) is not str or len(encoded) > 8 * 1024 * 1024:
        raise Refuted("bounded SIM-2.1 certificate encoding required")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise Refuted("retained SIM-2.1 certificate encoding differs") from exc
    if _raw_hash(raw) != selected_digest:
        raise Refuted("retained SIM-2.1 certificate differs from selection")
    return raw


def _trajectory_inputs(certificate: bytes, child_request: dict[str, Any]) -> dict[str, Any]:
    child = strict_json_loads(certificate.decode("utf-8"))
    encoded = child["evidence_payloads"][child_request["evidence_ref"]]
    evidence = strict_json_loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
    return evidence["inputs"]


def _action_transition(program: dict[str, Any], state: dict[str, Any],
                       entropy: Any, action: dict[str, Any],
                       budget: common_module.Budget) -> dict[str, float]:
    common_module.same(sorted(program), sorted(state), "action-response state inventory differs")
    if "entropy" in state or any(key.startswith("action.") for key in state):
        raise Refuted("state shadows reserved action-response variable")
    variables = {**state, "entropy": common_module.number(entropy)}
    for key, value in action.items():
        variables["action." + key] = common_module.number(value)
    try:
        return {key: common_module.number(common_module.expression(tree, variables, budget))
                for key, tree in program.items()}
    except Unavailable as exc:
        if str(exc).startswith("required evidence absent:"):
            raise Refuted("action-response expression exceeds complete selected inputs") from exc
        raise


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "trajectory_certificate",
                         "action_artifact", "action_inputs"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained SIM action-response evidence differs")
        child_raw = None
        if value["trajectory_certificate"] is not None:
            child_raw = _decode_child(value["trajectory_certificate"],
                                      request["trajectory_certificate_digest"])
        for field, selected_digest in (("action_artifact", request["action_artifact_digest"]),
                                       ("action_inputs", request["action_inputs_digest"])):
            retained = value[field]
            if retained is not None and (type(retained) is not dict
                                        or "sha256:" + canonical_digest(retained) != selected_digest):
                raise Refuted("retained " + field + " differs from external selection")
        if child_raw is None:
            raise Unavailable("selected SIM-2.1 trajectory certificate absent")
        try:
            child = sim_dynamics.recheck_sim_dynamics_certificate(
                child_raw, expected_request=request["trajectory_request"],
                policy=request["trajectory_policy"])
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise Refuted("selected SIM-2.1 certificate does not replay") from exc
        if child["status"] == "FAIL":
            raise Refuted("selected SIM-2.1 prerequisite failed")
        if child["status"] != "PASS":
            raise Unavailable("selected SIM-2.1 prerequisite not established")
        if value["action_artifact"] is None or value["action_inputs"] is None:
            raise Unavailable("selected action evidence absent")
        trajectory = _trajectory_inputs(child_raw, request["trajectory_request"])
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        action_artifact = _record(value["action_artifact"],
            {"program", "baseline_action", "action_bounds", "time_unit"}, "action artifact")
        action_inputs = _record(value["action_inputs"], {"actions"}, "action inputs")
        if action_artifact["time_unit"] != request["time_unit"]:
            raise Refuted("selected model time unit differs")
        program = common_module.obj(action_artifact["program"])
        bounds = common_module.obj(action_artifact["action_bounds"])
        baseline = common_module.obj(action_artifact["baseline_action"])
        actions = common_module.seq(action_inputs["actions"], budget, nonempty=False)
        states = common_module.seq(trajectory["states"], budget)
        entropy = common_module.seq(trajectory["entropy"], budget)
        times = common_module.seq(trajectory["times"], budget)
        if (not program or not bounds or set(baseline) != set(bounds)
                or len(actions) != len(entropy) or len(states) != len(actions) + 1
                or len(times) != len(states)):
            raise Refuted("action-response inventory or coverage differs")
        admitted_bounds = {}
        for key, interval in bounds.items():
            if type(key) is not str or not key.strip() or "." in key:
                raise Refuted("bounded action name required")
            row = common_module.obj(interval, {"minimum", "maximum"})
            lo, hi = common_module.number(row["minimum"]), common_module.number(row["maximum"])
            if lo > hi or not lo <= common_module.number(baseline[key]) <= hi:
                raise Refuted("baseline action outside selected bounds")
            admitted_bounds[key] = (lo, hi)
        for i, action_value in enumerate(actions):
            action = common_module.obj(action_value, set(bounds))
            for key, (lo, hi) in admitted_bounds.items():
                if not lo <= common_module.number(action[key]) <= hi:
                    raise Refuted("retained action outside selected bounds")
            if action == baseline:
                raise Refuted("selected action equals baseline action")
            actual = _action_transition(program, states[i], entropy[i], action, budget)
            common_module.same(actual, states[i + 1], "action-aware next state differs")
            counterfactual = _action_transition(program, states[i], entropy[i], baseline, budget)
            if actual == counterfactual:
                raise Refuted("selected action has no next-state effect in the model")
            start, end = common_module.number(times[i]), common_module.number(times[i + 1])
            if not 0 < end - start <= request["max_response_delay"]:
                raise Refuted("selected simulated-time response bound exceeded")
        return MechanismDecision(MechanismOutcome.PASS,
            "every selected action changes and reproduces its bounded next model state",
            {"responsive_steps": len(actions), "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SimResponseMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound SIM response proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one selected SIM response bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SimResponseError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)},
    )
    session = VerificationSession(store)
    session.register(_SimResponseMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "SIM", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "sim_tier_2_conformance": "NOT_ESTABLISHED",
        "historical_execution": "NOT_ESTABLISHED",
        "physical_time_truth": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise SimResponseError("SIM response certificate byte bound exhausted")
    return encoded


def build_sim_response_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                   *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise SimResponseError("immutable bounded SIM response evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimResponseError("SIM response evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_sim_response_certificate(certificate_bytes: bytes, *,
                                     expected_request: dict[str, Any],
                                     policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise SimResponseError("bounded immutable SIM response certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise SimResponseError("canonical SIM response certificate version differs")
        if value["request"] != selected:
            raise SimResponseError("SIM response certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimResponseError("retained SIM response evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimResponseError("SIM response certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, SimResponseError):
            raise
        raise SimResponseError("invalid retained SIM response certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "SimResponseDescriptor", "SimResponseError", "registration",
    "sim_response_policy", "sim_response_request", "build_sim_response_certificate",
    "recheck_sim_response_certificate",
]
