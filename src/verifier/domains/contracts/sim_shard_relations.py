"""Current simulation (SIM) closure: selected finite cross-shard relations.

Verifier Standard (VSTD) binds canonical JavaScript Object Notation (JSON)
with Secure Hash Algorithm 256-bit (SHA-256). Time values share the selected
model's units; byte limits use bytes and item/operation counts are dimensionless.
This check does not establish dimensional validity or physical truth.
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
from verifier.domains.contracts import retained_selection, sim_shard_coverage


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-4.2"
REQUEST_VERSION = "verifier-current-sim-shard-relations-request-1"
POLICY_VERSION = "verifier-current-sim-shard-relations-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-shard-relations-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-shard-relations-evidence-1"
MECHANISM_ID = "verifier.current-sim.selected-cross-shard-relations.1"
SCOPE = "finite_selected_retained_cross_shard_relations"
_CEILINGS = {"max_operations": 100000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class SimShardRelationsError(ValueError):
    """Malformed selection or substituted cross-shard certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "For an exact externally selected passing SIM-4.1 shard-time "
            "certificate, every nonempty selected finite relation that references "
            "at least two distinct declared shards evaluates true at every "
            "retained aligned shard time."),
        "prerequisites": [
            "exact separately selected SIM-4.1 request, policy and retained certificate",
            "child replay PASS and its retained aligned shard rows",
            "nonempty externally selected finite cross-shard expression list",
            "bounded installed native checker and externally selected trust roots"],
        "exclusions": [
            "unselected relations, dimensional validity, physical or historical execution",
            "undeclared shards, signatures or independent shard producer authority",
            "no unattributed transition or whole simulated-surface coverage",
            "whole SIM closure tier or object-profile conformance",
            "privacy, consent, governance, security and publication authority"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimShardRelationsDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimShardRelationsError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, SimShardRelationsError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               common_module, native_sim, retained_selection, sim_shard_coverage)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_SHARD_COVERAGE.md",
                 "CURRENT_SIM_SHARD_RELATIONS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=SimShardRelationsError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def sim_shard_relations_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest", "shard_request_digest",
        "shard_policy_digest", "shard_certificate_digest",
        "relations_digest", "evidence_ref",
        "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "SIM")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SimShardRelationsError("selected SIM cross-shard objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise SimShardRelationsError("bounded SIM subject required")
    for field in ("object_digest", "collection_digest", "shard_request_digest",
                  "shard_policy_digest", "shard_certificate_digest",
                  "relations_digest", "evidence_ref",
                  "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SimShardRelationsError)
    return selected


def sim_shard_relations_request(*, subject_id: str, object_digest: str,
        collection_digest: str, shard_request_digest: str,
        shard_policy_digest: str, shard_certificate_digest: str,
        relations_digest: str, evidence_ref: str,
        policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise SimShardRelationsError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "SIM",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "shard_request_digest": shard_request_digest,
        "shard_policy_digest": shard_policy_digest,
        "shard_certificate_digest": shard_certificate_digest,
        "relations_digest": relations_digest,
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
            {"schema_version", "shard_request", "shard_policy",
             "shard_certificate", "relations"}, "evidence")
        if retained["schema_version"] != EVIDENCE_VERSION or canonical_bytes(retained) != data:
            raise Refuted("retained SIM cross-shard evidence differs")
        budget = common_module.Budget(request["limits"]["max_operations"],
                                      request["limits"]["max_items"])
        common_module.inspect_structure(retained, budget)
        child_request = retained["shard_request"]
        child_policy = retained["shard_policy"]
        relations = retained["relations"]
        for field, value in (("shard_request_digest", child_request),
                             ("shard_policy_digest", child_policy),
                             ("relations_digest", relations)):
            if "sha256:" + canonical_digest(value) != request[field]:
                raise Refuted("selected " + field + " differs")
        if (type(child_request) is not dict
                or child_request.get("semantic_version") != sim_shard_coverage.SEMANTIC_VERSION
                or child_request.get("coordinate") != sim_shard_coverage.COORDINATE
                or child_request.get("object_kind") != "SIM"
                or child_request.get("subject_id") != request["subject_id"]
                or child_request.get("object_digest") != request["object_digest"]
                or child_request.get("collection_digest") != request["collection_digest"]):
            raise Refuted("selected SIM-4.1 child subject differs")
        if retained["shard_certificate"] is None:
            raise Unavailable("selected SIM-4.1 certificate absent")
        child_raw = _decode_b64(retained["shard_certificate"],
            "SIM-4.1 certificate", maximum=sim_shard_coverage._MAX_CERTIFICATE_BYTES)
        budget.tick(len(child_raw))
        if "sha256:" + hashlib.sha256(child_raw).hexdigest() != request["shard_certificate_digest"]:
            raise Refuted("selected SIM-4.1 certificate bytes differ")
        try:
            child_result = sim_shard_coverage.recheck_sim_shard_coverage_certificate(
                child_raw, expected_request=child_request, policy=child_policy)
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise Refuted("selected SIM-4.1 certificate does not replay") from exc
        if child_result["status"] == "UNKNOWN":
            raise Unavailable("selected SIM-4.1 coverage remains UNKNOWN")
        if child_result["status"] != "PASS":
            raise Refuted("selected SIM-4.1 coverage did not pass")
        child = strict_json_loads(child_raw.decode("utf-8"))
        encoded = child["evidence_payloads"][child_request["evidence_ref"]]
        child_data = _decode_b64(encoded, "SIM-4.1 retained evidence",
                                 maximum=sim_shard_coverage._CEILINGS["max_evidence_bytes"])
        child_retained = strict_json_loads(child_data.decode("utf-8"))
        ids = child_retained["shard_ids"]
        rows = child_retained["shard_rows"]
        if type(relations) is not list or not 1 <= len(relations) <= budget.max_items:
            raise Refuted("nonempty bounded relation list required")
        referenced_names: set[str] = set()
        for relation in relations:
            referenced: set[str] = set()
            pending = [relation]
            while pending:
                node = pending.pop()
                budget.tick()
                if type(node) in (int, float):
                    common_module.number(node)
                elif type(node) is dict and set(node) == {"var"}:
                    name = node["var"]
                    if type(name) is not str or "." not in name:
                        raise Refuted("qualified shard variable required")
                    shard, field = name.split(".", 1)
                    if shard not in ids or not field:
                        raise Refuted("relation variable is outside selected shards")
                    referenced.add(shard)
                    referenced_names.add(name)
                elif type(node) is dict and set(node) == {"op", "args"}:
                    if type(node["args"]) is not list:
                        raise Refuted("relation arguments must be finite array")
                    pending.extend(node["args"])
                else:
                    raise Refuted("unsupported relation expression shape")
            if len(referenced) < 2:
                raise Refuted("relation must reference two distinct shards")
        for index in range(len(rows[ids[0]])):
            variables = {f"{shard}.{name}": value
                         for shard in ids for name, value in rows[shard][index]["state"].items()}
            if not referenced_names <= variables.keys():
                raise Refuted("selected relation variable absent from retained shard row")
            for relation in relations:
                if common_module.expression(relation, variables, budget) is not True:
                    raise Refuted("selected cross-shard relation refuted")
        return MechanismDecision(MechanismOutcome.PASS,
            "all selected cross-shard relations hold at every retained shard time",
            {"shards": len(ids), "states": len(rows[ids[0]]),
             "relations": len(relations),
             "evaluations": len(rows[ids[0]]) * len(relations),
             "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            ArithmeticError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SimShardRelationsMechanism:
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
        raise SimShardRelationsError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)})
    session = VerificationSession(store)
    session.register(_SimShardRelationsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "SIM", "scope": SCOPE,
        "selected_cross_shard_relations": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "all_cross_shard_relations": "NOT_ESTABLISHED",
        "selected_retained_shard_time_coverage": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
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
        raise SimShardRelationsError("SIM shard certificate byte bound exhausted")
    return encoded


def build_sim_shard_relations_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]):
            raise SimShardRelationsError("immutable bounded SIM shard evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimShardRelationsError("SIM shard evidence differs from byte selection")
    return _build(selected, admitted, store)


def recheck_sim_shard_relations_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise SimShardRelationsError("bounded immutable SIM shard certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise SimShardRelationsError("selected canonical SIM shard certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimShardRelationsError("retained SIM shard evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimShardRelationsError("SIM shard certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, SimShardRelationsError):
            raise
        raise SimShardRelationsError("invalid retained SIM shard certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "SimShardRelationsDescriptor",
    "SimShardRelationsError", "registration", "sim_shard_relations_policy",
    "sim_shard_relations_request", "build_sim_shard_relations_certificate",
    "recheck_sim_shard_relations_certificate"]
