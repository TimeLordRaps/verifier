"""Current simulation (SIM): exact finite declared state-partition accounting.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256). Time and state retain the model's units. Limits count bytes
or dimensionless items/operations. Hidden runtime or physical state is excluded.
"""
from __future__ import annotations

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
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import (retained_selection, sim_dynamics,
    sim_shard_coverage, sim_shard_relations, sim_shard_signatures)


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "SIM-4.4"
REQUEST_VERSION = "verifier-current-sim-surface-partition-request-1"
POLICY_VERSION = "verifier-current-sim-surface-partition-policy-1"
CERTIFICATE_VERSION = "verifier-current-sim-surface-partition-certificate-1"
EVIDENCE_VERSION = "verifier-current-sim-surface-partition-evidence-1"
SURFACE_VERSION = "verifier-current-sim-surface-map-1"
MECHANISM_ID = "verifier.current-sim.finite-surface-partition.1"
SCOPE = "finite_declared_state_partition_accounting"
_CEILINGS = {"max_operations": 1000000, "max_items": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class SimSurfacePartitionError(ValueError):
    """Malformed selection or substituted finite surface-accounting certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "SIM", "scope": SCOPE,
        "proposition": (
            "For an exact externally selected passing SIM-4.3 child on the same "
            "subject and collection, the externally selected finite map bijects "
            "every root state variable with every retained shard field, preserves "
            "canonical values at every aligned retained time, and attributes each "
            "mapped transition to its exact replayed root transition expression."),
        "prerequisites": [
            "exact separately selected SIM-4.3 request, policy and retained certificate",
            "passing child replay including aligned shard rows and root trajectory",
            "external complete finite state-partition map and expression commitments",
            "bounded canonical identity and inventory replay"],
        "exclusions": [
            "hidden process memory, physical reality and unretained states",
            "nonlinear projections and entropy, action or observation channel completeness",
            "signatures beyond the child's selected required-shard policy",
            "independent origin, historical execution or cryptographic backend correctness",
            "whole runtime surface, whole SIM closure tier or object-profile conformance",
            "privacy, consent, governance, security and publication authority"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class SimSurfacePartitionDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, SimSurfacePartitionError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, receipt_module,
               common_module, retained_selection)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_SIM_SURFACE_PARTITION.md",
                 "CURRENT_SIM_DYNAMICS.md", "CURRENT_SIM_SHARD_COVERAGE.md",
                 "CURRENT_SIM_SHARD_RELATIONS.md", "CURRENT_SIM_SHARD_SIGNATURES.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        "sources": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in sorted(paths.items())},
        "selected_child_mechanisms": {
            module.COORDINATE: module.mechanism_digest() for module in
            (sim_dynamics, sim_shard_coverage, sim_shard_relations, sim_shard_signatures)}})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=SimSurfacePartitionError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def sim_surface_partition_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID, "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots, "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version", "coordinate",
        "proposition_digest", "object_kind", "subject_id", "object_digest",
        "collection_digest", "signatures_request_digest", "signatures_policy_digest",
        "signatures_certificate_digest", "surface_digest", "evidence_ref",
        "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
            ("semantic_version", SEMANTIC_VERSION), ("coordinate", COORDINATE),
            ("proposition_digest", PROPOSITION_DIGEST), ("object_kind", "SIM")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise SimSurfacePartitionError("selected surface-accounting objective differs")
    if (type(selected["subject_id"]) is not str or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise SimSurfacePartitionError("bounded SIM subject required")
    for field in ("object_digest", "collection_digest", "signatures_request_digest",
                  "signatures_policy_digest", "signatures_certificate_digest",
                  "surface_digest", "evidence_ref", "policy_digest"):
        retained_selection.commitment(selected[field], SimSurfacePartitionError)
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, SimSurfacePartitionError)
    return selected


def sim_surface_partition_request(*, subject_id: str, object_digest: str,
        collection_digest: str, signatures_request_digest: str,
        signatures_policy_digest: str, signatures_certificate_digest: str,
        surface_digest: str, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS))):
        raise SimSurfacePartitionError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "SIM",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "signatures_request_digest": signatures_request_digest,
        "signatures_policy_digest": signatures_policy_digest,
        "signatures_certificate_digest": signatures_certificate_digest,
        "surface_digest": surface_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _retained(raw: bytes, request: dict[str, Any], module: Any,
              budget: common_module.Budget) -> dict[str, Any]:
    """Unpack a fixed-depth already-replayed child; charge bytes before parsing."""
    child = strict_json_loads(raw.decode("utf-8"))
    common_module.inspect_structure(child, budget)
    data = sim_shard_signatures._decode_b64(
        child["evidence_payloads"][request["evidence_ref"]],
        "replayed child evidence", maximum=module._CEILINGS["max_evidence_bytes"])
    budget.tick(len(data))
    retained = strict_json_loads(data.decode("utf-8"))
    common_module.inspect_structure(retained, budget)
    return retained


def _next(retained: dict[str, Any], prefix: str, module: Any,
          budget: common_module.Budget) -> dict[str, Any]:
    raw = sim_shard_signatures._decode_b64(retained[prefix + "_certificate"],
        "replayed child certificate", maximum=module._MAX_CERTIFICATE_BYTES)
    budget.tick(len(raw))
    return _retained(raw, retained[prefix + "_request"], module, budget)


def _unavailable_signature_child(raw: bytes, request: dict[str, Any],
        policy: dict[str, Any], budget: common_module.Budget) -> None:
    """Separate unavailable child semantics from detectable envelope forgery.

    This never accepts a carried child verdict. A reconstructed UNKNOWN can
    supply only UNKNOWN to the parent, after checking known envelope bindings,
    static result fields and independently countable positive observations.
    """
    carried = _record(strict_json_loads(raw.decode("utf-8")),
        {"schema_version", "request", "policy_digest", "mechanism_digest",
         "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"},
        "selected child certificate")
    if (canonical_bytes(carried) != raw
            or carried["digest"] != "sha256:" + canonical_digest(
                {key: value for key, value in carried.items() if key != "digest"})):
        raise Refuted("selected child canonical bytes or digest differs")
    data = _retained(raw, request, sim_shard_signatures, budget)
    rebuilt = strict_json_loads(sim_shard_signatures.build_sim_shard_signatures_certificate(
        request, canonical_bytes(data), policy=policy).decode("utf-8"))
    if rebuilt["result"]["status"] != "UNKNOWN":
        raise Refuted("selected SIM-4.3 certificate does not replay")
    static = set(carried) - {"result", "digest"}
    if canonical_bytes({key: carried[key] for key in static}) != canonical_bytes(
            {key: rebuilt[key] for key in static}):
        raise Refuted("selected child envelope binding differs")
    result = _record(carried["result"], set(rebuilt["result"]), "selected child result")
    status = result["status"]
    if type(status) is not str or status not in {"PASS", "FAIL", "UNKNOWN"}:
        raise Refuted("selected child verdict is invalid")
    for key in set(result) - {"status", "selected_shard_signatures", "evaluation"}:
        if canonical_bytes(result[key]) != canonical_bytes(rebuilt["result"][key]):
            raise Refuted("selected child static result or authority differs")
    if result["selected_shard_signatures"] != ("PASS" if status == "PASS" else "NOT_ESTABLISHED"):
        raise Refuted("selected child signature claim contradicts its verdict")
    expected_evaluation = rebuilt["result"]["evaluation"]
    evaluation = _record(result["evaluation"], set(expected_evaluation), "selected child evaluation")
    for key in set(evaluation) - {"outcome", "details", "observations"}:
        if canonical_bytes(evaluation[key]) != canonical_bytes(expected_evaluation[key]):
            raise Refuted("selected child evaluation binding differs")
    if evaluation["outcome"] != status or type(evaluation["details"]) is not str:
        raise Refuted("selected child evaluation contradicts its verdict")
    if status == "PASS":
        relation_data = _next(data, "relations", sim_shard_relations, budget)
        shard_data = _next(relation_data, "shard", sim_shard_coverage, budget)
        required = policy["required_shards"]
        if any(policy["public_keys"][name] is None
               or any(signature is None for signature in data["signatures"][name])
               for name in required):
            raise Refuted("carried child PASS has absent required key or signature")
        count = sum(len(shard_data["shard_rows"][name]) for name in required)
        counts = {"required_shards": len(required), "retained_shards": len(shard_data["shard_ids"]),
                  "verified_signatures": count, "retained_rows": count}
        observations = _record(evaluation["observations"], set(counts) | {"operations"},
                               "selected child positive observations")
        if any(type(observations[key]) is not int or observations[key] != value
               for key, value in counts.items()):
            raise Refuted("carried child positive counts differ from retained rows")
        operations = observations["operations"]
        if (type(operations) is not int or not 1 <= operations <= request["limits"]["max_operations"]
                or count > request["limits"]["max_signatures"]):
            raise Refuted("carried child positive observations exceed selected bounds")
    elif evaluation["observations"] != {}:
        raise Refuted("carried nonpassing child has positive observations")
    raise Unavailable("selected SIM-4.3 child mechanism remains unavailable; no carried verdict accepted")


def _partition_rows(surface: Any, budget: common_module.Budget) -> list[dict[str, Any]]:
    """Refute an intrinsic map contradiction before unavailable child evidence."""
    selected = _record(surface, {"schema_version", "partitions"}, "surface map")
    if selected["schema_version"] != SURFACE_VERSION:
        raise Refuted("finite surface map version differs")
    rows = selected["partitions"]
    if type(rows) is not list or not rows:
        raise Refuted("nonempty declared finite partition required")
    roots, pairs = set(), set()
    for value in rows:
        budget.tick()
        row = _record(value, {"root_variable", "shard_id", "shard_variable",
                             "transition_digest"}, "partition row")
        for field in ("root_variable", "shard_id", "shard_variable"):
            if type(row[field]) is not str or not row[field].strip() or len(row[field]) > 128:
                raise Refuted("bounded partition field name required")
        retained_selection.commitment(row["transition_digest"], SimSurfacePartitionError)
        name, pair = row["root_variable"], (row["shard_id"], row["shard_variable"])
        if name in roots or pair in pairs:
            raise Refuted("multiply attributed root or shard field")
        roots.add(name)
        pairs.add(pair)
    return rows


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    try:
        retained = _record(strict_json_loads(data.decode("utf-8")),
            {"schema_version", "signatures_request", "signatures_policy",
             "signatures_certificate", "surface"}, "evidence")
        if retained["schema_version"] != EVIDENCE_VERSION or canonical_bytes(retained) != data:
            raise Refuted("retained surface-accounting evidence differs")
        budget = common_module.Budget(request["limits"]["max_operations"],
                                      request["limits"]["max_items"])
        common_module.inspect_structure(retained, budget)
        child_request, child_policy = retained["signatures_request"], retained["signatures_policy"]
        for field, value in (("signatures_request_digest", child_request),
                             ("signatures_policy_digest", child_policy)):
            if "sha256:" + canonical_digest(value) != request[field]:
                raise Refuted("selected " + field + " differs")
        if (type(child_request) is not dict
                or child_request.get("semantic_version") != sim_shard_signatures.SEMANTIC_VERSION
                or child_request.get("coordinate") != sim_shard_signatures.COORDINATE
                or child_request.get("object_kind") != "SIM"
                or any(child_request.get(field) != request[field]
                       for field in ("subject_id", "object_digest", "collection_digest"))):
            raise Refuted("selected SIM-4.3 child subject differs")
        surface = retained["surface"]
        if surface is not None and "sha256:" + canonical_digest(surface) != request["surface_digest"]:
            raise Refuted("selected finite surface map differs")
        partitions = _partition_rows(surface, budget) if surface is not None else None
        if retained["signatures_certificate"] is None or surface is None:
            raise Unavailable("selected SIM-4.3 certificate or finite surface map absent")
        child_raw = sim_shard_signatures._decode_b64(retained["signatures_certificate"],
            "SIM-4.3 certificate", maximum=sim_shard_signatures._MAX_CERTIFICATE_BYTES)
        # Charge admission before invoking the separately bounded child replay.
        budget.tick(len(child_raw))
        if "sha256:" + hashlib.sha256(child_raw).hexdigest() != request["signatures_certificate_digest"]:
            raise Refuted("selected SIM-4.3 certificate bytes differ")
        try:
            child_result = sim_shard_signatures.recheck_sim_shard_signatures_certificate(
                child_raw, expected_request=child_request, policy=child_policy)
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            _unavailable_signature_child(child_raw, child_request, child_policy, budget)
            raise Refuted("selected SIM-4.3 certificate does not replay") from exc
        if child_result["status"] == "UNKNOWN":
            raise Unavailable("selected SIM-4.3 signatures remain UNKNOWN")
        if child_result["status"] != "PASS":
            raise Refuted("selected SIM-4.3 signatures did not pass")
        signature_data = _retained(child_raw, child_request, sim_shard_signatures, budget)
        relation_data = _next(signature_data, "relations", sim_shard_relations, budget)
        shard_data = _next(relation_data, "shard", sim_shard_coverage, budget)
        dynamics_data = _next(shard_data, "dynamics", sim_dynamics, budget)
        states = dynamics_data["inputs"]["states"]
        program = dynamics_data["artifact"]["transition"]
        rows = shard_data["shard_rows"]
        root_fields = set(program)
        shard_fields = {(shard, name) for shard in shard_data["shard_ids"]
                        for name in rows[shard][0]["state"]}
        roots, pairs = set(), set()
        for row in partitions:
            budget.tick()
            name, pair = row["root_variable"], (row["shard_id"], row["shard_variable"])
            if name not in root_fields or pair not in shard_fields:
                raise Refuted("partition names an undeclared root or shard field")
            if row["transition_digest"] != "sha256:" + canonical_digest(program[name]):
                raise Refuted("partition transition expression differs from replayed root")
            roots.add(name)
            pairs.add(pair)
        if roots != root_fields or pairs != shard_fields:
            raise Refuted("partition does not exactly cover declared root and shard fields")
        mapped_values = changes = 0
        for index, state in enumerate(states):
            budget.tick()
            if set(state) != root_fields:
                raise Refuted("retained root field inventory differs")
            current_fields = {(shard, name) for shard in shard_data["shard_ids"]
                              for name in rows[shard][index]["state"]}
            if current_fields != pairs:
                raise Refuted("retained shard field inventory differs at an aligned time")
            for row in partitions:
                budget.tick()
                name = row["root_variable"]
                value = rows[row["shard_id"]][index]["state"][row["shard_variable"]]
                if canonical_bytes(state[name]) != canonical_bytes(value):
                    raise Refuted("mapped retained value differs from exact root state")
                mapped_values += 1
                if index and canonical_bytes(states[index - 1][name]) != canonical_bytes(state[name]):
                    changes += 1
        return MechanismDecision(MechanismOutcome.PASS,
            "declared finite state partition and transition attribution reproduce exactly",
            {"root_variables": len(roots), "shard_fields": len(pairs),
             "states": len(states), "mapped_values": mapped_values,
             "attributed_transitions": (len(states) - 1) * len(roots),
             "observed_changes": changes, "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError, ArithmeticError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _SimSurfacePartitionMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"] or binding.predicate != COORDINATE
                or binding.expected is not True
                or dict(binding.parameters) != {"request_digest": "sha256:" + canonical_digest(self.request)}
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound surface proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one selected surface bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise SimSurfacePartitionError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters={"request_digest": "sha256:" + canonical_digest(request)})
    session = VerificationSession(store)
    session.register(_SimSurfacePartitionMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "SIM", "scope": SCOPE,
        "declared_surface_accounting": "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED",
        "declared_transition_attribution": "PASS" if evaluation.outcome == MechanismOutcome.PASS else "NOT_ESTABLISHED",
        "whole_runtime_surface": "NOT_ESTABLISHED", "whole_surface_coverage": "NOT_ESTABLISHED",
        "sim_tier_4_conformance": "NOT_ESTABLISHED", "historical_execution": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED", "authority": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise SimSurfacePartitionError("surface certificate byte bound exhausted")
    return encoded


def build_sim_surface_partition_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
        *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > selected["limits"]["max_evidence_bytes"]:
            raise SimSurfacePartitionError("immutable bounded surface evidence required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise SimSurfacePartitionError("surface evidence differs from byte selection")
    return _build(selected, admitted, store)


def recheck_sim_surface_partition_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise SimSurfacePartitionError("bounded immutable surface certificate required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise SimSurfacePartitionError("selected canonical surface certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1 or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise SimSurfacePartitionError("retained surface evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise SimSurfacePartitionError("surface certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, SimSurfacePartitionError):
            raise
        raise SimSurfacePartitionError("invalid retained surface certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "SURFACE_VERSION", "PROPOSITION_DIGEST", "SimSurfacePartitionDescriptor", "SimSurfacePartitionError",
    "registration", "sim_surface_partition_policy", "sim_surface_partition_request",
    "build_sim_surface_partition_certificate", "recheck_sim_surface_partition_certificate"]
