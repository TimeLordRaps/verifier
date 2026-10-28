"""Current simulation (SIM) selected internal-state enumeration.

Verifier Standard (VSTD) binds retained bytes with canonical JavaScript Object
Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256). State values use
the selected model's units; counts are dimensionless and limits count bytes.
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
from verifier.domains.contracts import sim_internal_core
from verifier.domains.contracts.sim_internal_core import enumerate_hidden_changes


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-2.3"
REQUEST_VERSION = "verifier-current-sim-internal-state-request-1"
POLICY_VERSION = "verifier-current-sim-internal-state-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-internal-state-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-internal-state-evidence-1"
MECHANISM_ID = "verifier.current-sim.selected-internal-state.1"
SCOPE = "finite_model_relative_internal_state"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class SimInternalStateError(ValueError):
    """Malformed external selection or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "For an externally selected exact SIM-2.1 PASS trajectory and a "
            "externally selected declaration of a complete finite observation-channel inventory, "
            "enumerate every changed state key invisible under every endpoint "
            "hybrid of the other changed keys in each retained transition."
        ),
        "prerequisites": [
            "independently selected and replayed SIM-2.1 PASS certificate",
            "externally selected exact channel program and expected hidden-change list",
            "finite retained states and bounded installed expression interpreter",
        ],
        "exclusions": [
            "physical observation, undeclared channels and unselected trajectories",
            "complete SIM dynamics tier or object profile",
            "privacy, consent, governance, security and publication authority",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimInternalStateDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimInternalStateError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, SimInternalStateError)


def _raw_hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, native_sim, retained_selection,
               sim_dynamics, sim_internal_core)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_INTERNAL_STATE.md",
                 "CURRENT_SIM_DYNAMICS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=SimInternalStateError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def sim_internal_state_policy(*, trust_roots: list[str],
                        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
                    "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
                    "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "trajectory_request", "trajectory_policy", "trajectory_certificate_digest",
        "observation_artifact_digest", "hidden_changes_digest",
        "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "SIM"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SimInternalStateError("selected internal-state objective differs")
    if type(selected["subject_id"]) is not str or not selected["subject_id"].strip():
        raise SimInternalStateError("selected SIM subject required")
    for field in ("object_digest", "collection_digest", "trajectory_certificate_digest",
                  "observation_artifact_digest", "hidden_changes_digest", "evidence_ref",
                  "policy_digest"):
        _hash(selected[field])
    child_request = sim_dynamics._request(selected["trajectory_request"])
    child_policy = sim_dynamics._policy(selected["trajectory_policy"])
    if (child_request["subject_id"] != selected["subject_id"]
            or child_request["object_digest"] != selected["object_digest"]
            or child_request["collection_digest"] != selected["collection_digest"]
            or child_request["policy_digest"] != "sha256:" + canonical_digest(child_policy)):
        raise SimInternalStateError("selected SIM-2.1 dependency differs")
    selected["trajectory_request"] = child_request
    selected["trajectory_policy"] = child_policy
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SimInternalStateError)
    return selected


def sim_internal_state_request(*, subject_id: str, object_digest: str,
                         collection_digest: str, trajectory_request: dict[str, Any],
                         trajectory_policy: dict[str, Any],
                         trajectory_certificate_digest: str,
                         observation_artifact_digest: str,
                         hidden_changes_digest: str,
                         evidence_ref: str, policy: dict[str, Any],
                         limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise SimInternalStateError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "SIM", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "trajectory_request": trajectory_request, "trajectory_policy": trajectory_policy,
        "trajectory_certificate_digest": trajectory_certificate_digest,
        "observation_artifact_digest": observation_artifact_digest,
        "hidden_changes_digest": hidden_changes_digest,
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


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")), {
            "schema_version", "trajectory_certificate", "observation_artifact",
            "declared_hidden_changes",
        }, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained SIM internal-state evidence differs")
        child_raw = None
        if value["trajectory_certificate"] is not None:
            child_raw = _decode_child(value["trajectory_certificate"],
                                      request["trajectory_certificate_digest"])
        for field, selected_digest in (
            ("observation_artifact", request["observation_artifact_digest"]),
            ("declared_hidden_changes", request["hidden_changes_digest"]),
        ):
            retained = value[field]
            if retained is not None and (
                type(retained) is not (dict if field == "observation_artifact" else list)
                or "sha256:" + canonical_digest(retained) != selected_digest
            ):
                raise Refuted("retained " + field + " differs from external selection")
        artifact = None
        if value["observation_artifact"] is not None:
            artifact = _record(value["observation_artifact"],
                               {"declared_complete", "channels"}, "observation artifact")
            if type(artifact["declared_complete"]) is not bool:
                raise Refuted("declared channel-inventory completeness must be Boolean")
            if type(artifact["channels"]) is not dict:
                raise Refuted("selected observation channels must be an object")
            if any(type(name) is not str or not name.strip()
                   for name in artifact["channels"]):
                raise Refuted("bounded observation-channel identifier required")
        if value["declared_hidden_changes"] is not None:
            for row in value["declared_hidden_changes"]:
                change = _record(row, {"step", "state_key", "before", "after"},
                                 "declared hidden change")
                if type(change["step"]) is not int or change["step"] < 0:
                    raise Refuted("nonnegative hidden-change step required")
                if type(change["state_key"]) is not str or not change["state_key"].strip():
                    raise Refuted("bounded hidden-change state key required")
                before = common_module.number(change["before"])
                after = common_module.number(change["after"])
                if before == after:
                    raise Refuted("declared hidden change has no numeric delta")
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
        if artifact is None or value["declared_hidden_changes"] is None:
            raise Unavailable("selected observation or enumeration evidence absent")
        if not artifact["declared_complete"]:
            raise Unavailable("complete selected channel inventory not declared")
        trajectory = _trajectory_inputs(child_raw, request["trajectory_request"])
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        states = common_module.seq(trajectory["states"], budget)
        channels = common_module.obj(artifact["channels"])
        actual = enumerate_hidden_changes(states, channels, budget)
        common_module.same(actual, value["declared_hidden_changes"],
                           "selected hidden-state enumeration differs")
        return MechanismDecision(
            MechanismOutcome.PASS,
            "all selected finite internal state changes are enumerated relative to declared channels",
            {"hidden_changes": len(actual), "steps": len(states) - 1,
             "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            ArithmeticError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))

class _SimInternalStateMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound SIM internal-state proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one selected SIM internal-state bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SimInternalStateError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)},
    )
    session = VerificationSession(store)
    session.register(_SimInternalStateMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "SIM", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "sim_tier_2_conformance": "NOT_ESTABLISHED",
        "historical_execution": "NOT_ESTABLISHED",
        "physical_observation_truth": "NOT_ESTABLISHED",
        "channel_inventory_authority": "NOT_ESTABLISHED",
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
        raise SimInternalStateError("SIM internal-state certificate byte bound exhausted")
    return encoded


def build_sim_internal_state_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                   *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise SimInternalStateError("immutable bounded SIM internal-state evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimInternalStateError("SIM internal-state evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_sim_internal_state_certificate(certificate_bytes: bytes, *,
                                     expected_request: dict[str, Any],
                                     policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise SimInternalStateError("bounded immutable SIM internal-state certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise SimInternalStateError("canonical SIM internal-state certificate version differs")
        if value["request"] != selected:
            raise SimInternalStateError("SIM internal-state certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimInternalStateError("retained SIM internal-state evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimInternalStateError("SIM internal-state certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, SimInternalStateError):
            raise
        raise SimInternalStateError("invalid retained SIM internal-state certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "SimInternalStateDescriptor", "SimInternalStateError", "registration",
    "sim_internal_state_policy", "sim_internal_state_request", "build_sim_internal_state_certificate",
    "recheck_sim_internal_state_certificate", "enumerate_hidden_changes",
]
