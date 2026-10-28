"""Verifier Standard (VSTD) bounded polished-artifact admission assessment.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
This experimental gate replays available objectives and exposes missing closure.
It does not yet issue a polished artifact. Counts are dimensionless; limits on
encoded inputs and cumulative certificate replay are measured in bytes.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import MetaTier, NamespaceObject, ObjectCoordinate, assess_composition
from verifier.core.receipt import strict_json_loads
from verifier.domains import certification as domain_certification
from verifier.domains.contracts import object_governance, subject_security
from verifier.domains.contracts.current_object_routes import (
    CurrentObjectRouteRefusal, CurrentObjectRouteUnavailable, current_object_route_catalog,
    replay_current_object_certificate, select_current_object_route,
)

MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_OBJECTS = 64
MAX_OBJECTIVES = 64
BOUNDARY = ("Selected finite object wiring and registered objective replay only. "
            "Complete applicable objective inventories, authenticated inapplicability, "
            "private-witness public proofs and polished-artifact issuance are not established. "
            "Freeze, seal, thaw and publication are separate operations.")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism_digest() -> str:
    """Bind installed assessment code, executed helpers and its specification."""
    root = Path(__file__).parents[1]
    paths = ("runtime/polish.py", "runtime/polish_capacity.py", "core/namespace.py", "core/certificate.py",
             "core/receipt.py", "domains/contracts/current_object_routes.py",
             "runtime/__init__.py", "runtime/permission_slot.py",
             "standard/CURRENT_PERMISSION_SLOT.md",
             "domains/contracts/verifier_composed_security.py",
             "standard/CURRENT_VERIFIER_COMPOSED_SECURITY.md",
             "domains/contracts/verifier_replacement.py",
             "standard/CURRENT_VERIFIER_REPLACEMENT.md",
             "domains/inventory.py",
             "domains/contracts/object_facets.py", "domains/contracts/object_grounding.py",
             "domains/contracts/hyper_closure.py", "domains/common.py",
             "standard/CURRENT_OBJECT_FACETS.md", "standard/CURRENT_OBJECT_GROUNDING.md",
             "standard/CURRENT_HYPER_CLOSURE.md",
             "domains/contracts/__init__.py", "consent/__init__.py", "privacy/__init__.py",
             "core/checker.py", "core/provenance.py", "domains/statics.py",
             "domains/contracts/certificate_dag.py", "standard/CERTIFICATE_DAG.md",
             "domains/contracts/sim_isolation.py", "standard/SIM_ISOLATION.md",
             "domains/contracts/token_checks.py", "standard/CURRENT_TOKEN_CHECKS.md",
             "domains/contracts/independence_checks.py", "standard/CURRENT_INDEPENDENCE_CHECKS.md",
             "domains/contracts/sim_checker.py", "domains/sim.py", "core/evidence.py",
             "standard/CURRENT_SIM_CHECKER.md",
             "domains/contracts/sim_dynamics.py", "standard/CURRENT_SIM_DYNAMICS.md",
             "domains/contracts/sim_resource.py", "standard/CURRENT_SIM_RESOURCE.md",
             "domains/contracts/sim_response.py", "standard/CURRENT_SIM_RESPONSE.md",
             "domains/contracts/sim_internal_state.py", "domains/contracts/sim_internal_core.py",
             "standard/CURRENT_SIM_INTERNAL_STATE.md",
             "domains/contracts/sim_perspective.py", "standard/CURRENT_SIM_PERSPECTIVE.md",
             "domains/contracts/sim_external_law.py", "standard/CURRENT_SIM_EXTERNAL_LAW.md",
             "domains/contracts/sim_shard_coverage.py",
             "standard/CURRENT_SIM_SHARD_COVERAGE.md",
             "domains/contracts/sim_shard_relations.py",
             "standard/CURRENT_SIM_SHARD_RELATIONS.md",
             "domains/contracts/sim_shard_signatures.py",
             "standard/CURRENT_SIM_SHARD_SIGNATURES.md",
             "domains/contracts/sim_surface_partition.py",
             "standard/CURRENT_SIM_SURFACE_PARTITION.md",
             "domains/contracts/receipt_chain.py",
             "domains/contracts/subject_security.py", "standard/CURRENT_SUBJECT_SECURITY.md", "standard/CURRENT_RECEIPT_CHAIN.md",
             "domains/contracts/receipt_authenticity.py", "standard/CURRENT_RECEIPT_AUTHENTICITY.md",
             "domains/contracts/typed_facets.py", "standard/CURRENT_TYPED_FACETS.md",
             "domains/contracts/hardware_inventory.py", "domains/hardware.py",
             "standard/CURRENT_HARDWARE_INVENTORY.md",
             "domains/contracts/hardware_topology.py", "standard/CURRENT_HARDWARE_TOPOLOGY.md",
             "domains/contracts/graph_statics.py", "standard/CURRENT_GRAPH_STATICS.md",
             "domains/contracts/graph_closure.py", "standard/CURRENT_GRAPH_CLOSURE.md",
             "domains/contracts/graph_order.py", "standard/CURRENT_GRAPH_ORDER.md",
             "domains/contracts/graph_lineage.py", "standard/CURRENT_GRAPH_LINEAGE.md",
             "domains/contracts/identity_scope.py", "domains/contracts/identity_occupancy.py",
             "standard/CURRENT_IDENTITY_SCOPE.md", "standard/IDENTITY_OCCUPANCY.md",
             "domains/contracts/data_checks.py", "domains/data.py", "standard/CURRENT_DATA_CHECKS.md",
             "domains/contracts/env_checks.py", "domains/env.py", "standard/CURRENT_ENV_CHECKS.md",
             "domains/contracts/env_executable.py", "standard/CURRENT_ENV_EXECUTABLE.md",
             "domains/contracts/env_configuration_surface.py", "standard/CURRENT_ENV_CONFIGURATION_SURFACE.md",
             "domains/contracts/env_pin_closure.py", "standard/CURRENT_ENV_PIN_CLOSURE.md",
             "domains/contracts/bench_checks.py", "domains/bench.py", "standard/CURRENT_BENCH_CHECKS.md",
             "domains/contracts/train_checks.py", "domains/train.py", "domains/numerical.py", "standard/CURRENT_TRAIN_CHECKS.md",
             "domains/contracts/train_data_bridge.py", "standard/CURRENT_TRAIN_DATA_BRIDGE.md",
             "domains/contracts/model_checks.py", "domains/model.py", "standard/CURRENT_MODEL_CHECKS.md",
             "domains/contracts/model_artifact_bytes.py", "standard/CURRENT_MODEL_ARTIFACT_BYTES.md",
             "domains/contracts/model_quantization.py", "standard/CURRENT_MODEL_QUANTIZATION.md",
             "domains/contracts/model_hardware_observation.py", "standard/CURRENT_MODEL_HARDWARE_OBSERVATION.md",
             "domains/contracts/model_data_citation.py", "standard/CURRENT_MODEL_DATA_CITATION.md",
             "domains/contracts/model_train_citation.py", "standard/CURRENT_MODEL_TRAIN_CITATION.md",
             "domains/contracts/model_data_lineage.py", "standard/CURRENT_MODEL_DATA_LINEAGE.md",
             "domains/verifier_execution.py", "domains/numerical.py",
             "domains/contracts/harness_checks.py", "domains/harness.py", "standard/CURRENT_HARNESS_CHECKS.md",
             "domains/contracts/agent_checks.py", "domains/agent.py", "standard/CURRENT_AGENT_CHECKS.md",
             "domains/contracts/bot_checks.py", "domains/bot.py", "standard/CURRENT_BOT_CHECKS.md",
             "domains/contracts/privacy_checks.py", "standard/CURRENT_PRIVACY_CHECKS.md",
             "domains/contracts/consent_checks.py", "standard/CURRENT_CONSENT_CHECKS.md",
             "consent/stages.py", "consent/public.py", "consent/engine.py", "core/signature_keys.py",
             "standard/CONSENT_STAGES.md", "standard/CONSENT_PUBLIC_ADMISSION.md",
             "domains/contracts/time_order.py", "standard/CURRENT_TIME_ORDER.md",
             "domains/contracts/time_strict.py", "standard/CURRENT_TIME_STRICT.md",
             "domains/contracts/time_closure.py", "standard/CURRENT_TIME_CLOSURE.md",
             "domains/contracts/role_closure.py", "standard/CURRENT_ROLE_DECISION_CLOSURE.md",
             "schemas/role_closure_evidence.json",
             "domains/contracts/collective_closure.py", "standard/CURRENT_COLLECTIVE_DECISION_CLOSURE.md",
             "schemas/collective_closure_evidence.json",
             "domains/contracts/identity_lifecycle.py", "domains/contracts/identity_lifecycle_replay.py",
             "standard/CURRENT_IDENTITY_LIFECYCLE.md", "schemas/identity_lifecycle_evidence.json",
             "domains/contracts/identity_presentation.py", "standard/CURRENT_IDENTITY_PRESENTATION.md",
             "schemas/identity_presentation_evidence.json",
             "domains/contracts/arch_shapes.py", "standard/CURRENT_ARCH_SHAPES.md",
             "domains/contracts/data_distribution.py",
             "standard/CURRENT_DATA_DISTRIBUTION.md",
             "domains/contracts/space_layout.py", "standard/CURRENT_SPACE_LAYOUT.md",
             "domains/contracts/space_closure.py", "standard/CURRENT_SPACE_CLOSURE.md",
             "domains/contracts/event_prerequisites.py", "standard/CURRENT_EVENT_PREREQUISITES.md",
             "domains/contracts/event_closure.py", "standard/CURRENT_EVENT_CLOSURE.md",
             "domains/contracts/object_governance.py", "standard/CURRENT_OBJECT_GOVERNANCE.md",
             "domains/contracts/hardware_capacity.py", "standard/CURRENT_HARDWARE_CAPACITY.md",
             "domains/contracts/hardware_measurements.py",
             "standard/CURRENT_HARDWARE_MEASUREMENTS.md",
             "domains/contracts/retained_selection.py",
             "domains/contracts/receipt_statics.py", "standard/CURRENT_RECEIPT_STATICS.md",
             "domains/contracts/receipt_validation_replay.py",
             "standard/CURRENT_RECEIPT_VALIDATION_REPLAY.md",
             "domains/contracts/receipt_prerequisite_closure.py",
             "standard/CURRENT_RECEIPT_PREREQUISITE_CLOSURE.md",
             "domains/contracts/object_statics.py", "standard/CURRENT_OBJECT_STATICS.md",
             "domains/contracts/object_address_closure.py", "standard/CURRENT_OBJECT_ADDRESS_CLOSURE.md",
             "domains/contracts/object_lineage.py", "standard/CURRENT_OBJECT_LINEAGE.md",
             "domains/contracts/arch_schedule.py", "standard/CURRENT_ARCH_SCHEDULE.md",
             "domains/contracts/train_accumulation.py", "standard/CURRENT_TRAIN_ACCUMULATION.md",
             "domains/contracts/hyper_unknown_absorption.py", "standard/CURRENT_HYPER_UNKNOWN_ABSORPTION.md",
             "domains/contracts/hyper_composed_ceiling.py", "standard/CURRENT_HYPER_COMPOSED_CEILING.md",
             "domains/contracts/hardware_substrate_observations.py",
             "standard/CURRENT_HARDWARE_SUBSTRATE_OBSERVATIONS.md",
             "domains/contracts/hardware_inventory_closure.py",
             "standard/CURRENT_HARDWARE_INVENTORY_CLOSURE.md",
             "domains/contracts/agent_ceiling_fixity.py", "standard/CURRENT_AGENT_CEILING_FIXITY.md",
             "domains/contracts/bot_inherited_ceiling.py", "standard/CURRENT_BOT_INHERITED_CEILING.md",
             "domains/contracts/harness_gap_boundary.py", "standard/CURRENT_HARNESS_GAP_BOUNDARY.md",
             "domains/contracts/event_dispatch.py", "standard/CURRENT_EVENT_DISPATCH.md",
             "domains/contracts/space_migration.py", "standard/CURRENT_SPACE_MIGRATION.md",
             "domains/contracts/bench_attempts.py", "standard/CURRENT_BENCH_ATTEMPTS.md",
             "domains/contracts/actor_replay.py", "standard/CURRENT_ACTOR_REPLAY.md",
             "domains/contracts/actor_decision_record.py",
             "standard/CURRENT_ACTOR_DECISION_RECORD.md",
             "domains/contracts/actor_closure.py", "standard/CURRENT_ACTOR_CLOSURE.md",
             "domains/contracts/human_template_irreversibility.py",
             "standard/CURRENT_HUMAN_TEMPLATE_IRREVERSIBILITY.md",
             "domains/contracts/human_no_composition.py",
             "standard/CURRENT_HUMAN_NO_COMPOSITION.md",
             "domains/contracts/human_population_declaration.py",
             "standard/CURRENT_HUMAN_POPULATION_DECLARATION.md",
             "domains/contracts/owner_replay.py", "standard/CURRENT_OWNER_REPLAY.md",
             "domains/contracts/owner_forks.py", "standard/CURRENT_OWNER_FORKS.md",
             "domains/contracts/owner_eligibility.py", "domains/contracts/accountability.py",
             "standard/CURRENT_OWNER_HARDWARE_ELIGIBILITY.md",
             "domains/contracts/verifier_run_constraints.py", "standard/CURRENT_VERIFIER_RUN_CONSTRAINTS.md", "domains/contracts/verifier_coverage_closure.py", "standard/CURRENT_VERIFIER_COVERAGE_CLOSURE.md",
             "domains/contracts/role_constraints.py", "standard/CURRENT_ROLE_CONSTRAINTS.md",
             "domains/contracts/collective_constraints.py", "standard/CURRENT_COLLECTIVE_CONSTRAINTS.md",
             "domains/contracts/role_lifecycle.py", "standard/CURRENT_ROLE_LIFECYCLE.md",
             "domains/contracts/collective_lifecycle.py", "standard/CURRENT_COLLECTIVE_LIFECYCLE.md",
             "domains/contracts/arch_resolution.py", "standard/CURRENT_ARCH_RESOLUTION.md",
             "privacy/engine.py", "privacy/models.py", "privacy/composition.py",
             "privacy/independence.py", "privacy/adapters.py",
             "standard/NAMESPACE_OBJECTS.md",
             "standard/POLISHED_ARTIFACTS.md")
    return _digest(canonical_bytes({
        "direct_sources": {name: _digest((root / name).read_bytes()) for name in paths},
        "native_domain_implementation": domain_certification.implementation_digest()}))


def _keys(value: Any, fields: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(fields.split()):
        raise ValueError("unexpected record fields")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ValueError("bounded nonempty text required")
    return value


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError("canonical digest required")
    return value


def _load(raw: bytes, bound: int) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > bound:
        raise ValueError("immutable input byte bound exceeded")
    value = strict_json_loads(raw.decode("utf-8"))
    if type(value) is not dict:
        raise ValueError("input must be a JSON object")
    return value


def polish_catalog(include_inventory: bool = False) -> dict[str, Any]:
    """Expose implemented replay routes and the unimplemented closure admission."""
    data: dict[str, Any] = {
        "schema_version": "verifier-polish-catalog-1",
        "polished": False,
        "objective_inventory_closure": "NOT_ESTABLISHED",
        "tiers": [{"tier": t.value, "name": t.name} for t in MetaTier],
        "routes": current_object_route_catalog(),
        "claim_boundary": BOUNDARY,
    }
    if include_inventory:
        from verifier.domains.inventory import slot_inventory
        inv = slot_inventory()
        data["inventory"] = inv
        data["slot_count"] = len(inv)
    return data


def _objective(selection: dict[str, Any], item: NamespaceObject,
               certificates: dict[str, bytes], collection_digest: str) -> dict[str, Any]:
    coordinate = selection["coordinate"]
    report = {"object_id": item.object_id, "coordinate": coordinate,
              "semantic_version": selection["semantic_version"],
              "certificate_digest": selection["certificate_digest"],
              "status": "UNKNOWN", "reason": "UNREGISTERED_OBJECTIVE"}
    try:
        route = select_current_object_route(semantic_version=selection["semantic_version"],
            objective=coordinate, represented_kind=item.kind.value)
    except CurrentObjectRouteRefusal:
        return report
    request = selection["request"]
    if coordinate == "OBJECT-1.1" or isinstance(route.module, object_governance.GovernanceDescriptor):
        bound = (request.get("object_id") == item.object_id and
                 request.get("record_digest") == item.digest)
    elif isinstance(route.module, subject_security.SubjectSecurityDescriptor):
        bound = (request.get("subject_id") == item.object_id and
                 request.get("object_kind") == item.kind.value and
                 request.get("object_digest") == item.digest)
    elif coordinate == "VERIFIER-2.1":
        bound = (request.get("object_id") == item.object_id and
                 request.get("object_digest") == item.digest)
    elif coordinate in ("RECEIPT-9.1", "RECEIPT-9.2"):
        bound = (request.get("receipt_object_id") == item.object_id and
                 request.get("receipt_object_digest") == item.digest)
    else:
        bound = (request.get("subject_id") == item.object_id and
                 request.get("object_digest") == item.digest and
                 request.get("collection_digest") == collection_digest)
    if not bound:
        return {**report, "status": "FAIL", "reason": "SUBJECT_BINDING_DIFFERS"}
    certificate = certificates.get(selection["certificate_digest"])
    if certificate is None:
        return {**report, "reason": "PUBLIC_REPLAY_EVIDENCE_MISSING"}
    try:
        replay = replay_current_object_certificate(certificate,
            semantic_version=selection["semantic_version"], objective=coordinate,
            represented_kind=item.kind.value, expected_request=request,
            policy=selection["policy"])
    except CurrentObjectRouteUnavailable:
        return {**report, "status": "UNKNOWN", "reason": "CHECKER_UNAVAILABLE"}
    except CurrentObjectRouteRefusal:
        return {**report, "status": "FAIL", "reason": "NATIVE_REPLAY_REJECTED"}
    if replay["replay_status"] == "UNAVAILABLE":
        return {**report, "status": "UNKNOWN", "reason": "NATIVE_REPLAY_UNAVAILABLE",
                "request_digest": replay["request_sha256"], "policy_digest": replay["policy_sha256"],
                "replay_observation": "RETAINED_CERTIFICATE_REPLAY_UNAVAILABLE",
                "public_checkability": "NOT_ESTABLISHED"}
    return {**report, "status": replay["computational_status"], "reason": "NATIVE_REPLAY",
            "request_digest": replay["request_sha256"],
            "policy_digest": replay["policy_sha256"],
            "replay_observation": "RETAINED_CERTIFICATE_REPLAYED_LOCALLY",
            "public_checkability": "NOT_ESTABLISHED"}


def _assess(bundle: dict[str, Any], request: dict[str, Any], raw: bytes) -> dict[str, Any]:
    _keys(bundle, "schema_version objects certificates")
    _keys(request, "schema_version root_id collection_digest bundle_digest requirements")
    if (bundle["schema_version"] != "verifier-polish-bundle-1" or
            request["schema_version"] != "verifier-polish-request-1"):
        raise ValueError("unsupported contract version")
    if _hash(request["bundle_digest"]) != _digest(raw):
        raise ValueError("bundle differs from externally selected commitment")
    collection_digest = _hash(request["collection_digest"])
    records = bundle["objects"]
    if type(records) is not list or not 1 <= len(records) <= MAX_OBJECTS:
        raise ValueError("object inventory exceeds bounds or is empty")
    objects = {}
    for record in records:
        _keys(record, "object_id kind payload operands")
        if type(record["operands"]) is not dict:
            raise ValueError("operand map required")
        item = NamespaceObject.create(record["object_id"], record["kind"],
                                      record["payload"], record["operands"])
        if item.object_id in objects:
            raise ValueError("duplicate object identity")
        objects[item.object_id] = item
    if _text(request["root_id"]) not in objects:
        raise ValueError("selected root is absent")
    composition = assess_composition(tuple(objects.values()), expected_digest=collection_digest,
                                     max_objects=MAX_OBJECTS)
    certificates = bundle["certificates"]
    if type(certificates) is not dict or len(certificates) > MAX_OBJECTIVES:
        raise ValueError("certificate inventory exceeds bounds")
    captured = {}
    for digest, encoded in certificates.items():
        _hash(digest)
        if type(encoded) is not str:
            raise ValueError("retained certificate requires exact text bytes")
        payload = encoded.encode("utf-8")
        if _digest(payload) != digest:
            raise ValueError("certificate inventory commitment differs")
        captured[digest] = payload
    requirements = request["requirements"]
    if type(requirements) is not list or len(requirements) > MAX_OBJECTS * 9:
        raise ValueError("applicability inventory exceeds bounds")
    seen = set()
    selections = []
    applicability = []
    replay_bytes = 0
    for row in requirements:
        _keys(row, "object_id tier applicability rationale objectives")
        object_id = _text(row["object_id"])
        tier = row["tier"]
        if (object_id not in objects or type(tier) is not int or not 1 <= tier <= 9 or
                (object_id, tier) in seen):
            raise ValueError("unknown or duplicate applicability coordinate")
        seen.add((object_id, tier))
        if row["applicability"] not in ("REQUIRED", "NOT_APPLICABLE", "UNKNOWN"):
            raise ValueError("unknown applicability declaration")
        _text(row["rationale"])
        objectives = row["objectives"]
        if type(objectives) is not list or len(objectives) + len(selections) > MAX_OBJECTIVES:
            raise ValueError("objective inventory exceeds bounds")
        if row["applicability"] != "REQUIRED" and objectives:
            raise ValueError("non-required row cannot carry admitted objectives")
        applicability.append(row["applicability"])
        unique = set()
        for selected in objectives:
            _keys(selected, "semantic_version coordinate request policy certificate_digest")
            semantic = _text(selected["semantic_version"])
            if semantic == "verifier-current-ten-tier-object-obligations-1":
                raise ValueError("historical nine-tier polish semantic version differs")
            address = ObjectCoordinate.parse(_text(selected["coordinate"]))
            if (address.tier.value != tier or address.object_kind.value not in
                    ("OBJECT", objects[object_id].kind.value) or (semantic, str(address)) in unique):
                raise ValueError("objective differs from declared object-tier coordinate")
            unique.add((semantic, str(address)))
            _hash(selected["certificate_digest"])
            if type(selected["request"]) is not dict or type(selected["policy"]) is not dict:
                raise ValueError("independent native request and policy required")
            replay_bytes += len(captured.get(selected["certificate_digest"], b""))
            if replay_bytes > MAX_BUNDLE_BYTES:
                raise ValueError("cumulative replay byte bound exceeded")
            selections.append((selected, objects[object_id]))
    missing = [{"object_id": object_id, "tier": tier} for object_id in sorted(objects)
               for tier in range(1, 10) if (object_id, tier) not in seen]
    # All shape, cardinality and workload checks precede any native replay.
    results = [_objective(selected, item, captured, collection_digest)
               for selected, item in selections]
    status = "FAIL" if composition.verdict.value == "FAIL" or any(
        result["status"] == "FAIL" for result in results) else "UNKNOWN"
    return {"status": status, "composition_status": composition.verdict.value,
            "root_id": request["root_id"], "collection_digest": collection_digest,
            "tier_inventory_status": "UNKNOWN" if missing else "PASS",
            "applicability_status": "PASS" if not missing and all(
                value == "REQUIRED" for value in applicability) else "UNKNOWN",
            "missing_tiers": missing, "objectives": results,
            "remaining_gates": ["APPLICABLE_OBJECTIVE_INVENTORY_CLOSURE",
                                "PUBLIC_CHECKABILITY_FOR_EVERY_REQUIRED_OBJECTIVE",
                                "AUTHENTICATED_AUTHORITY_AND_INAPPLICABILITY"]}


def assess_polish(bundle_bytes: bytes, *, request_bytes: bytes,
                  contract_version: str = "1") -> dict[str, Any]:
    """Replay a bounded inventory without promoting partial results to polished."""
    if type(contract_version) is not str or contract_version not in ("1", "2"):
        raise ValueError("explicit supported polish contract required")
    if contract_version == "2":
        from verifier.runtime.polish_capacity import assess
        return assess(bundle_bytes, request_bytes)
    report = {"schema_version": "verifier-polish-assessment-1", "polished": False,
              "objective_inventory_closure": "NOT_ESTABLISHED", "claim_boundary": BOUNDARY,
              "mechanism_digest": mechanism_digest()}
    try:
        bundle = _load(bundle_bytes, MAX_BUNDLE_BYTES)
        request = _load(request_bytes, MAX_REQUEST_BYTES)
        report.update(_assess(bundle, request, bundle_bytes))
        report.update(bundle_digest=_digest(bundle_bytes), request_digest=_digest(request_bytes))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        # Never echo caller-controlled witnesses, paths or exception text.
        report.update(status="FAIL", reason="INVALID_OR_SUBSTITUTED_INPUT")
    report["assessment_digest"] = _digest(canonical_bytes(report))
    return report


def recheck_polish(assessment_bytes: bytes, *, bundle_bytes: bytes,
                   request_bytes: bytes, contract_version: str = "1") -> dict[str, Any]:
    """Recompute the entire assessment against externally selected retained inputs."""
    if type(contract_version) is not str or contract_version not in ("1", "2"):
        raise ValueError("explicit supported polish contract required")
    limit = MAX_REQUEST_BYTES
    if contract_version == "2":
        from verifier.runtime.polish_capacity import CEILINGS
        limit = CEILINGS["output_bytes"]
    result = {"schema_version": "verifier-polish-replay-" + contract_version, "polished": False,
              "status": "FAIL", "replay_status": "REJECTED", "claim_boundary": BOUNDARY}
    try:
        stored = _load(assessment_bytes, limit)
        expected = assess_polish(bundle_bytes, request_bytes=request_bytes, contract_version=contract_version)
        if canonical_bytes(stored) != canonical_bytes(expected):
            return result
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return result
    return {**result, "status": expected["status"], "replay_status": "REPRODUCED",
            "assessment_digest": expected["assessment_digest"],
            "mechanism_digest": expected["mechanism_digest"]}


def add_polish_parsers(subparsers: Any) -> None:
    """Lazily register the polish command-line interface."""
    from verifier.runtime.polish_cli import add_polish_parsers as add_parsers

    add_parsers(subparsers)


def handle_polish_command(args: Any) -> int:
    """Lazily route a parsed polish command through its interface module."""
    from verifier.runtime.polish_cli import handle_polish_command as handle_command

    return handle_command(args)
