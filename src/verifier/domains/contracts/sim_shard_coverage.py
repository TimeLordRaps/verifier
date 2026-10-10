"""Current simulation (SIM) closure: selected finite shard-time coverage.

Verifier Standard (VSTD) binds canonical JavaScript Object Notation (JSON)
with Secure Hash Algorithm 256-bit (SHA-256). Time values share the selected
model's unit; byte limits use bytes and item/operation counts are dimensionless.
This check does not establish physical execution or whole-simulation closure.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module, sim as native_sim
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import retained_selection, sim_dynamics


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-4.1"
REQUEST_VERSION = "verifier-current-sim-shard-coverage-request-1"
POLICY_VERSION = "verifier-current-sim-shard-coverage-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-shard-coverage-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-shard-coverage-evidence-1"
MECHANISM_ID = "verifier.current-sim.selected-shard-time-coverage.1"
SCOPE = "finite_selected_retained_shard_time_coverage"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class SimShardCoverageError(ValueError):
    """Malformed selection or substituted shard-coverage certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "For the exact externally selected passing SIM-2.1 finite trajectory, "
            "the selected declared shard identifiers equal the retained shard "
            "inventory, and every selected shard has exactly one retained finite "
            "state row at every selected trajectory time in the same order."),
        "prerequisites": [
            "exact separately selected SIM-2.1 request, policy and retained certificate",
            "child replay PASS and its retained finite state and time arrays",
            "exact selected shard identifiers and complete retained per-shard rows",
            "bounded installed native checker and externally selected trust roots"],
        "exclusions": [
            "undeclared shards, unretained states, physical or historical execution",
            "cross-shard relations, signatures or independent shard producer authority",
            "no unattributed transition or whole simulated-surface coverage",
            "whole SIM closure tier or object-profile conformance",
            "privacy, consent, governance, security and publication authority"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimShardCoverageDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimShardCoverageError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, SimShardCoverageError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               common_module, native_sim, retained_selection, sim_dynamics)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_DYNAMICS.md",
                 "CURRENT_SIM_SHARD_COVERAGE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=SimShardCoverageError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def sim_shard_coverage_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "dynamics_request_digest",
        "dynamics_policy_digest", "dynamics_certificate_digest",
        "shard_ids_digest", "shard_rows_digest", "evidence_ref",
        "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "SIM")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SimShardCoverageError("selected SIM shard objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise SimShardCoverageError("bounded SIM subject required")
    for field in ("object_digest", "collection_digest", "dynamics_request_digest",
                  "dynamics_policy_digest", "dynamics_certificate_digest",
                  "shard_ids_digest", "shard_rows_digest", "evidence_ref",
                  "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SimShardCoverageError)
    return selected


def sim_shard_coverage_request(*, subject_id: str, object_digest: str,
        collection_digest: str, dynamics_request_digest: str,
        dynamics_policy_digest: str, dynamics_certificate_digest: str,
        shard_ids_digest: str, shard_rows_digest: str, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise SimShardCoverageError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "SIM",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "dynamics_request_digest": dynamics_request_digest,
        "dynamics_policy_digest": dynamics_policy_digest,
        "dynamics_certificate_digest": dynamics_certificate_digest,
        "shard_ids_digest": shard_ids_digest,
        "shard_rows_digest": shard_rows_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_b64(value: Any, label: str, *, maximum: int) -> bytes:
    if type(value) is not str or len(value) > (4 * maximum // 3 + 4):
        raise Refuted(label + " must be bounded canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if (len(decoded) > maximum
            or base64.b64encode(decoded).decode("ascii") != value):
        raise Refuted(label + " is noncanonical or exceeds bounds")
    return decoded


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    try:
        retained = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "dynamics_request", "dynamics_policy",
             "dynamics_certificate", "shard_ids", "shard_rows"}, "evidence")
        if retained["schema_version"] != EVIDENCE_VERSION or canonical_bytes(retained) != data:
            raise Refuted("retained SIM shard evidence differs")
        budget = common_module.Budget(request["limits"]["max_operations"],
                                      request["limits"]["max_items"])
        common_module.inspect_structure(retained, budget)
        child_request = retained["dynamics_request"]
        child_policy = retained["dynamics_policy"]
        ids = retained["shard_ids"]
        rows = retained["shard_rows"]
        for field, value in (("dynamics_request_digest", child_request),
                             ("dynamics_policy_digest", child_policy),
                             ("shard_ids_digest", ids),
                             ("shard_rows_digest", rows)):
            if "sha256:" + canonical_digest(value) != request[field]:
                raise Refuted("selected " + field + " differs")
        if (type(child_request) is not dict
                or child_request.get("semantic_version") != sim_dynamics.SEMANTIC_VERSION
                or child_request.get("coordinate") != sim_dynamics.COORDINATE
                or child_request.get("object_kind") != "SIM"
                or child_request.get("subject_id") != request["subject_id"]
                or child_request.get("object_digest") != request["object_digest"]
                or child_request.get("collection_digest") != request["collection_digest"]):
            raise Refuted("selected SIM-2.1 child subject differs")
        if retained["dynamics_certificate"] is None:
            raise Unavailable("selected SIM-2.1 certificate absent")
        child_raw = _decode_b64(retained["dynamics_certificate"],
            "SIM-2.1 certificate", maximum=sim_dynamics._MAX_CERTIFICATE_BYTES)
        if "sha256:" + hashlib.sha256(child_raw).hexdigest() != request["dynamics_certificate_digest"]:
            raise Refuted("selected SIM-2.1 certificate bytes differ")
        try:
            child_result = sim_dynamics.recheck_sim_dynamics_certificate(
                child_raw, expected_request=child_request, policy=child_policy)
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise Refuted("selected SIM-2.1 certificate does not replay") from exc
        if child_result["status"] == "UNKNOWN":
            raise Unavailable("selected SIM-2.1 trajectory remains UNKNOWN")
        if child_result["status"] != "PASS":
            raise Refuted("selected SIM-2.1 trajectory did not pass")
        child = strict_json_loads(child_raw.decode("utf-8"))
        encoded = child["evidence_payloads"][child_request["evidence_ref"]]
        child_data = _decode_b64(encoded, "SIM-2.1 retained evidence",
                                 maximum=sim_dynamics._CEILINGS["max_evidence_bytes"])
        child_retained = strict_json_loads(child_data.decode("utf-8"))
        states = child_retained["inputs"]["states"]
        times = child_retained["inputs"]["times"]
        if (type(states) is not list or type(times) is not list
                or len(states) != len(times)):
            raise Refuted("selected SIM-2.1 trajectory coverage differs")
        if type(ids) is not list or not 2 <= len(ids) <= request["limits"]["max_items"]:
            raise Refuted("at least two bounded declared shards required")
        if (any(type(key) is not str or not key.strip() or len(key) > 128
                or key == "root" or "." in key for key in ids)
                or len(set(ids)) != len(ids)):
            raise Refuted("declared shard identifiers are invalid or duplicated")
        if (type(rows) is not dict or any(type(key) is not str for key in rows)
                or set(rows) != set(ids)):
            raise Refuted("retained shard inventory differs from declaration")
        for key in ids:
            shard = rows[key]
            if type(shard) is not list or len(shard) != len(states):
                raise Refuted("shard trajectory coverage differs")
            for index, row in enumerate(shard):
                budget.tick()
                if type(row) is not dict or set(row) != {"time", "state"}:
                    raise Refuted("retained shard row shape differs")
                common_module.number(row["time"])
                if canonical_bytes(row["time"]) != canonical_bytes(times[index]):
                    raise Refuted("shard time differs from selected trajectory")
                state = row["state"]
                if type(state) is not dict or not state:
                    raise Refuted("nonempty finite shard state required")
                for variable, value in state.items():
                    if type(variable) is not str or not variable.strip():
                        raise Refuted("named shard state variable required")
                    common_module.number(value)
        return MechanismDecision(MechanismOutcome.PASS,
            "every declared shard has one finite row at each selected trajectory time",
            {"shards": len(ids), "states": len(states),
             "transitions": len(states) - 1, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SimShardCoverageMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound SIM shard proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected shard bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SimShardCoverageError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)})
    session = VerificationSession(store)
    session.register(_SimShardCoverageMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "SIM", "scope": SCOPE,
        "retained_shard_time_coverage": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "cross_shard_relations": "NOT_ESTABLISHED",
        "shard_signatures": "NOT_ESTABLISHED",
        "whole_surface_coverage": "NOT_ESTABLISHED",
        "sim_tier_4_conformance": "NOT_ESTABLISHED",
        "historical_execution": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
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
        raise SimShardCoverageError("SIM shard certificate byte bound exhausted")
    return encoded


def build_sim_shard_coverage_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]):
            raise SimShardCoverageError("immutable bounded SIM shard evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimShardCoverageError("SIM shard evidence differs from byte selection")
    return _build(selected, admitted, store)


def recheck_sim_shard_coverage_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise SimShardCoverageError("bounded immutable SIM shard certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise SimShardCoverageError("selected canonical SIM shard certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimShardCoverageError("retained SIM shard evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimShardCoverageError("SIM shard certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, SimShardCoverageError):
            raise
        raise SimShardCoverageError("invalid retained SIM shard certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SimShardCoverageDescriptor",
    "SimShardCoverageError", "registration", "sim_shard_coverage_policy",
    "sim_shard_coverage_request", "build_sim_shard_coverage_certificate",
    "recheck_sim_shard_coverage_certificate"]
