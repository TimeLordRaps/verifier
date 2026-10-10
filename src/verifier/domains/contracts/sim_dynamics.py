"""Current SIM dynamics: replay one exact selected finite transition trajectory.

Verifier Standard (VSTD); generative simulation specification (SIM);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
States and times use the model's declared units. Counts are dimensionless;
transport limits count bytes. Retained replay is not historical execution.
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
from verifier.domains import common as common_module, sim as native_sim
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-2.1"
REQUEST_VERSION = "verifier-current-sim-dynamics-request-1"
POLICY_VERSION = "verifier-current-sim-dynamics-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-dynamics-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-dynamics-evidence-1"
MECHANISM_ID = "verifier.current-sim.selected-transition-replay.1"
SCOPE = "finite_selected_native_transition_replay"
PAYLOAD_SCOPE = "selected-retained-trajectory-replay"
# Admitted members of a composable retained SIM payload scope, in ascending
# code-point order. Current SIM-3.4 (sim_external_law) keeps this identical
# tuple so one exact SIM record can be selected by both routes separately;
# neither route's pass establishes the other.
SCOPE_MEMBERS = ("selected-external-law-statement", PAYLOAD_SCOPE)
_CEILINGS = {
    "max_objects": 256, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 4096,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class SimDynamicsError(ValueError):
    """Malformed external selection or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "For the externally selected exact SIM object, finite typed collection, "
            "transition program and retained state, entropy and causal-time sequence, "
            "the installed native interpreter replays every selected transition "
            "and returns the selected state and transition counts."
        ),
        "prerequisites": [
            "externally selected SIM, collection, exact program and trace commitments",
            "retained canonical program and trace bytes, admitted installed interpreter and finite limits",
        ],
        "exclusions": [
            "historical or physical execution, actual causal-time truth and collector authenticity",
            "action responsiveness, observation projection, hidden state or resource consumption",
            "perspective agreement, complete dynamics tier or object profile",
            "privacy, consent, governance, security and publication authority",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimDynamicsDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimDynamicsError)


def _hash(value: Any) -> str:
    return retained_selection.commitment(value, SimDynamicsError)


def _declares_scope(value: Any) -> bool:
    """Whether the retained payload ``scope`` declares this route's member.

    A string is the legacy scalar form and declares exactly one member. A
    list is the composable form: nonempty, string members only, every member
    admitted, no repeated member, ascending code-point order. A malformed
    list is refuted as a present contradiction; it is never reordered,
    deduplicated or otherwise canonicalized by the checker.
    """
    if type(value) is str:
        return value == PAYLOAD_SCOPE
    if type(value) is not list:
        return False
    if not value or any(type(member) is not str for member in value):
        raise Refuted("composable SIM scope requires nonempty string members")
    if any(member not in SCOPE_MEMBERS for member in value):
        raise Refuted("composable SIM scope names an unknown member")
    if len(set(value)) != len(value):
        raise Refuted("composable SIM scope repeats a member")
    if value != sorted(value):
        raise Refuted("composable SIM scope is not in ascending code-point order")
    return PAYLOAD_SCOPE in value


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module, native_sim, retained_selection,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_DYNAMICS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(
        value, error_type=SimDynamicsError, version=POLICY_VERSION,
        mechanism_id=MECHANISM_ID, current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES,
    )


def sim_dynamics_policy(*, trust_roots: list[str],
                        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "artifact_digest", "inputs_digest", "expected_counts", "evidence_ref",
        "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "SIM"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise SimDynamicsError("selected simulation dynamics objective differs")
    if (type(request["subject_id"]) is not str or not request["subject_id"].strip()
            or len(request["subject_id"]) > 256):
        raise SimDynamicsError("bounded SIM subject identifier required")
    for field in ("object_digest", "collection_digest", "artifact_digest",
                  "inputs_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    counts = _record(request["expected_counts"], {"states", "transitions"}, "expected counts")
    if (any(type(counts[key]) is not int or not 1 <= counts[key] <= _CEILINGS["max_items"]
            for key in counts) or counts["states"] != counts["transitions"] + 1):
        raise SimDynamicsError("selected positive finite trajectory counts required")
    request["expected_counts"] = counts
    request["limits"] = retained_selection.limits(request["limits"], _CEILINGS, SimDynamicsError)
    return request


def sim_dynamics_request(*, subject_id: str, object_digest: str,
                         collection_digest: str, artifact_digest: str,
                         inputs_digest: str, expected_counts: dict[str, int],
                         evidence_ref: str, policy: dict[str, Any],
                         limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise SimDynamicsError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "SIM", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "artifact_digest": artifact_digest, "inputs_digest": inputs_digest,
        "expected_counts": expected_counts, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "objects", "artifact", "inputs"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained SIM dynamics evidence differs")
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
        if (len(matches) != 1 or matches[0].kind.value != "SIM"
                or matches[0].digest != request["object_digest"]):
            raise Refuted("retained SIM subject differs from external selection")
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
        if (not _declares_scope(payload.get("scope"))
                or payload.get("artifact_digest") != request["artifact_digest"]
                or payload.get("inputs_digest") != request["inputs_digest"]):
            raise Refuted("SIM replay declarations differ from external selection")
        for field, selected_digest in (
            ("artifact", request["artifact_digest"]),
            ("inputs", request["inputs_digest"]),
        ):
            retained = value[field]
            if retained is not None:
                if type(retained) is not dict or "sha256:" + canonical_digest(retained) != selected_digest:
                    raise Refuted("retained SIM " + field + " differs from selection")
        if value["artifact"] is None or value["inputs"] is None:
            raise Unavailable("selected transition program or trace is absent")
        try:
            native = native_sim.evaluate("replay", value["artifact"], value["inputs"],
                                         budget, witness_keys={})
        except Refuted:
            raise
        except (ArithmeticError, ValueError, KeyError, TypeError, RecursionError) as exc:
            raise Unavailable("native transition semantics unavailable: " + str(exc)) from exc
        if (type(native) is not dict or set(native) != {"states", "transitions"}
                or any(type(v) is not int or v < 1 for v in native.values())):
            raise Unavailable("native interpreter returned unsupported counts")
        if native != request["expected_counts"]:
            raise Refuted("native trajectory counts differ from external selection")
        return MechanismDecision(MechanismOutcome.PASS,
                                 "selected native transition trajectory reproduced",
                                 {**native, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SimDynamicsMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound SIM proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one selected SIM evidence bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SimDynamicsError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)},
    )
    session = VerificationSession(store)
    session.register(_SimDynamicsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "SIM", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "sim_tier_2_conformance": "NOT_ESTABLISHED",
        "historical_execution": "NOT_ESTABLISHED",
        "physical_time_truth": "NOT_ESTABLISHED",
        "action_observation_response": "NOT_ESTABLISHED",
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
        raise SimDynamicsError("SIM dynamics certificate byte bound exhausted")
    return encoded


def build_sim_dynamics_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                   *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise SimDynamicsError("immutable bounded SIM evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimDynamicsError("SIM evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_sim_dynamics_certificate(certificate_bytes: bytes, *,
                                     expected_request: dict[str, Any],
                                     policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise SimDynamicsError("bounded immutable SIM certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise SimDynamicsError("canonical SIM certificate version differs")
        if value["request"] != selected:
            raise SimDynamicsError("SIM certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimDynamicsError("retained SIM evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimDynamicsError("SIM certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, SimDynamicsError):
            raise
        raise SimDynamicsError("invalid retained SIM certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "SimDynamicsDescriptor", "SimDynamicsError", "registration",
    "sim_dynamics_policy", "sim_dynamics_request", "build_sim_dynamics_certificate",
    "recheck_sim_dynamics_certificate",
]
