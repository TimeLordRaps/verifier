"""Verifier Standard (VSTD) bounded polished-artifact admission assessment.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
This experimental gate replays available objectives and exposes missing closure.
It does not yet issue a polished artifact. Counts are dimensionless; limits on
encoded inputs and cumulative certificate replay are measured in bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
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
    parser = subparsers.add_parser(
        "polish", help="Assess declared object wiring and polishing gaps."
    )
    commands = parser.add_subparsers(dest="polish_command", required=True)
    # The public entry point dispatches these two numeric commands before
    # argparse because their evidence surfaces are intentionally isolated from
    # the historical artifact-polish parser.  Register help-only entries here
    # as well so the parent command truthfully advertises the gate sequence.
    commands.add_parser(
        "1",
        help=(
            "Attempt complete Tier 1 mechanics across the repository/package "
            "estate."
        ),
    )
    commands.add_parser(
        "2",
        help="Run Tier 2 dynamics after a mechanically replayed Tier 1 PASS.",
    )
    from verifier.runtime.polish_findings import add_report_parser
    add_report_parser(commands)
    from verifier.runtime.application_release import add_application_parser
    add_application_parser(commands)
    from verifier.runtime.core_application_release import (
        add_application_parser as add_core_application_parser,
    )
    add_core_application_parser(commands)
    catalog = commands.add_parser(
        "catalog", help="Show installed routes and outstanding closure gates."
    )
    catalog.add_argument("--json", action="store_true")
    catalog.add_argument(
        "--inventory",
        action="store_true",
        help="Include the complete 234-slot applicability and objective inventory.",
    )
    assess = commands.add_parser(
        "assess", help="Replay a retained bundle against an external request."
    )
    assess.add_argument("bundle")
    assess.add_argument("--request", required=True)
    assess.add_argument("--json", action="store_true")
    assess.add_argument(
        "--contract-version",
        choices=("1", "2"),
        default="1",
        help=(
            "Select the exact bundle/request contract; version 2 has "
            "explicit resource limits."
        ),
    )
    coverage = commands.add_parser(
        "coverage",
        help="Replay obligations against a separately pinned requirements inventory.",
    )
    coverage.add_argument("bundle")
    coverage.add_argument("--request", required=True)
    coverage.add_argument("--requirements", required=True)
    coverage.add_argument(
        "--requirements-digest",
        required=True,
        help="Independently selected exact inventory byte digest (sha256:...).",
    )
    coverage.add_argument("--json", action="store_true")
    coverage.add_argument("--contract-version", choices=("1", "2"), default="1")
    check = commands.add_parser(
        "check", help="Recompute a stored assessment against exact inputs."
    )
    check.add_argument("assessment")
    check.add_argument("--bundle", required=True)
    check.add_argument("--request", required=True)
    check.add_argument("--json", action="store_true")
    check.add_argument(
        "--contract-version",
        choices=("1", "2"),
        default="1",
        help="Select the exact assessment and retained input contract.",
    )
    from verifier.runtime.polish_workflow import STAGES

    preparation = commands.add_parser(
        "prepare",
        help="Prepare selected source, explanations and optional quality checks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Run admitted preparation stages without publication or "
            "polished status. Default check-only stages projected "
            "bytes outside the source. Explicit --apply uses a "
            "retained recovery plan.\n\nStages:\n"
        )
        + "\n".join("  " + row["id"] + ": " + row["description"] for row in STAGES),
    )
    preparation.add_argument(
        "artifact",
        help="Ordinary artifact; the workflow format selects files in a directory.",
    )
    preparation.add_argument(
        "--report-format",
        choices=("verifier-polish-workflow-report-1", "verifier-polish-preparation-1"),
        default="verifier-polish-workflow-report-1",
        help="Select the workflow report or the existing gates preparation contract.",
    )
    preparation.add_argument(
        "--normalize-text",
        action="store_true",
        help=(
            "With verifier-polish-preparation-1, select the existing "
            "source/prose text fix."
        ),
    )
    preparation.add_argument(
        "--dry-run",
        action="store_true",
        help="With verifier-polish-preparation-1, inspect without applying changes.",
    )
    preparation.add_argument(
        "--policy", help="Separately selected closed workflow policy."
    )
    preparation.add_argument(
        "--policy-digest", help="Exact selected policy byte digest (sha256:...)."
    )
    preparation.add_argument(
        "--definition", help="Canonical versioned authored explanation definitions."
    )
    preparation.add_argument(
        "--quality-profile", help="Opt-in independently selected quality profile."
    )
    preparation.add_argument(
        "--quality-profile-digest", help="Exact selected quality profile byte digest."
    )
    preparation.add_argument(
        "--requirements", help="Independent requirements for committed explanations."
    )
    preparation.add_argument(
        "--requirements-digest",
        help="Exact independently selected requirement byte digest.",
    )
    preparation.add_argument(
        "--git-root", help="Repository containing exact committed explanation source."
    )
    preparation.add_argument("--base", help="Exact committed explanation base.")
    preparation.add_argument(
        "--commit", help="Exact committed explanation head or later association commit."
    )
    preparation.add_argument(
        "--output",
        help="External directory for immutable bundles, attempts and apply plans.",
    )
    preparation.add_argument(
        "--resume",
        help="Prior retained attempt or bundle; rechecks all selected stages.",
    )
    preparation.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Explicitly apply successful staged comment bytes using "
            "a retained recovery plan."
        ),
    )
    actions = preparation.add_mutually_exclusive_group()
    actions.add_argument(
        "--recover",
        help="Recover a retained local apply plan after comparing current bytes.",
    )
    actions.add_argument(
        "--associate",
        help="Compare a retained bundle manifest with the exact later whole Git tree.",
    )
    preparation.add_argument(
        "--rollback",
        action="store_true",
        help=(
            "With --recover, restore retained prior bytes unless a "
            "later edit intervened."
        ),
    )
    preparation.add_argument("--json", action="store_true")


def _handle_preparation(args: argparse.Namespace) -> dict[str, Any]:
    from verifier.runtime.gate import _prdel_file
    from verifier.runtime.polish_workflow import (
        REPORT_SCHEMA,
        associate_commit,
        prepare_workflow,
        recover_apply,
    )

    try:
        if args.normalize_text or args.dry_run:
            raise ValueError(
                "text normalization and dry-run select verifier-polish-preparation-1"
            )
        if args.recover or args.associate:
            if any(
                (
                    args.policy,
                    args.policy_digest,
                    args.definition,
                    args.quality_profile,
                    args.quality_profile_digest,
                    args.requirements,
                    args.requirements_digest,
                    args.base,
                    args.resume,
                    args.apply,
                )
            ):
                raise ValueError(
                    "recovery and association cannot select preparation inputs"
                )
            if args.recover:
                if args.commit or args.git_root or args.output:
                    raise ValueError(
                        "recovery uses only the retained plan and selected artifact"
                    )
                return recover_apply(
                    args.artifact, args.recover, rollback=args.rollback
                )
            if not args.commit or args.rollback or args.output:
                raise ValueError(
                    (
                        "association requires one exact commit and "
                        "does not rewrite a bundle"
                    )
                )
            value = strict_json_loads(_prdel_file(args.associate).decode("utf-8"))
            if type(value) is not dict:
                raise ValueError("manifest must be an object")
            if "bundle" in value:
                value = value["bundle"]["manifest"]
            return associate_commit(args.git_root or args.artifact, value, args.commit)
        if args.rollback or not args.policy or not args.policy_digest:
            raise ValueError("preparation requires a separately pinned workflow policy")
        definition_path = None
        if args.definition and args.git_root:
            try:
                definition_path = (
                    Path(args.definition)
                    .absolute()
                    .relative_to(Path(args.git_root).absolute())
                    .as_posix()
                )
            except ValueError:
                pass
        return prepare_workflow(
            args.artifact,
            policy_bytes=_prdel_file(args.policy),
            expected_policy_digest=args.policy_digest,
            definition_bytes=_prdel_file(args.definition) if args.definition else None,
            quality_profile_bytes=(
                _prdel_file(args.quality_profile) if args.quality_profile else None
            ),
            expected_quality_profile_digest=args.quality_profile_digest,
            requirements_bytes=(
                _prdel_file(args.requirements) if args.requirements else None
            ),
            expected_requirements_digest=args.requirements_digest,
            definition_path=definition_path,
            git_root=args.git_root,
            base=args.base,
            head=args.commit,
            output=args.output,
            resume=args.resume,
            apply=args.apply,
        )
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        status = (
            "UNKNOWN"
            if isinstance(error, OSError) and not isinstance(error, FileNotFoundError)
            else "FAIL"
        )
        return {
            "schema_version": REPORT_SCHEMA,
            "status": status,
            "polished": False,
            "promotable": False,
            "reason": "INVALID_OR_UNAVAILABLE_SELECTED_PREPARATION_INPUT",
        }


def handle_polish_command(args: argparse.Namespace) -> int:
    if args.polish_command == "application":
        from verifier.runtime.application_release import handle_application_command
        return handle_application_command(args)
    if args.polish_command == "core-application":
        from verifier.runtime.core_application_release import handle_application_command
        return handle_application_command(args)
    if args.polish_command == "report":
        from verifier.runtime.polish_findings import handle_report_command
        return handle_report_command(args)
    if args.polish_command == "prepare":
        if args.report_format == "verifier-polish-preparation-1":
            incompatible = any(
                getattr(args, name)
                for name in (
                    "policy",
                    "policy_digest",
                    "definition",
                    "quality_profile",
                    "quality_profile_digest",
                    "requirements",
                    "requirements_digest",
                    "git_root",
                    "base",
                    "commit",
                    "resume",
                    "recover",
                    "associate",
                    "rollback",
                )
            ) or (args.dry_run and args.apply)
            if incompatible:
                result = {
                    "schema_version": args.report_format,
                    "status": "FAIL",
                    "polished": False,
                    "reason": "INCOMPATIBLE_PREPARATION_OPTIONS",
                }
                print(
                    json.dumps(result, sort_keys=True)
                    if args.json
                    else "[FAIL] Incompatible preparation report options."
                )
                return 1
            from verifier.runtime.polish_prepare import handle_prepare_command

            return handle_prepare_command(args)
        result = _handle_preparation(args)
        code = {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}.get(result["status"], 2)
    elif args.polish_command == "catalog":
        result = polish_catalog(include_inventory=getattr(args, "inventory", False))
        code = 0
    else:
        version = getattr(args, "contract_version", "1")
        bundle_limit, request_limit, output_limit = (
            MAX_BUNDLE_BYTES,
            MAX_REQUEST_BYTES,
            MAX_REQUEST_BYTES,
        )
        if version == "2":
            from verifier.runtime.polish_capacity import CEILINGS

            bundle_limit, request_limit, output_limit = (
                CEILINGS["bundle_bytes"],
                CEILINGS["request_bytes"],
                CEILINGS["output_bytes"],
            )
        try:
            with Path(args.bundle).open("rb") as handle:
                bundle = handle.read(bundle_limit + 1)
            with Path(args.request).open("rb") as handle:
                request = handle.read(request_limit + 1)
            if args.polish_command == "check":
                with Path(args.assessment).open("rb") as handle:
                    assessment = handle.read(output_limit + 1)
                result = recheck_polish(
                    assessment,
                    bundle_bytes=bundle,
                    request_bytes=request,
                    contract_version=version,
                )
            elif args.polish_command == "coverage":
                from verifier.runtime.polish_requirements import (
                    MAX_INVENTORY_BYTES,
                    assess_polish_inventory,
                )

                with Path(args.requirements).open("rb") as handle:
                    inventory = handle.read(MAX_INVENTORY_BYTES + 1)
                result = assess_polish_inventory(
                    bundle,
                    request_bytes=request,
                    inventory_bytes=inventory,
                    expected_inventory_digest=args.requirements_digest,
                    contract_version=version,
                )
            else:
                result = assess_polish(
                    bundle, request_bytes=request, contract_version=version
                )
        except OSError:
            result = {
                "schema_version": "verifier-polish-assessment-" + version,
                "status": "UNKNOWN",
                "polished": False,
                "reason": "INPUT_UNAVAILABLE",
                "claim_boundary": BOUNDARY,
            }
            if args.polish_command == "coverage":
                result.update(
                    schema_version="verifier-polish-requirements-assessment-1",
                    declared_coverage="UNKNOWN",
                    inventory_authentication="NOT_ESTABLISHED",
                    objective_inventory_closure="NOT_ESTABLISHED",
                )
        code = {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    else:
        print(f"[{result.get('status', 'CATALOG')}] polished=false")
        if "inventory" in result:
            print(
                (
                    f"234-slot applicability and objective "
                    f"inventory ("
                    f"{result['slot_count']}"
                    f" slots)"
                )
            )
        print(result.get("claim_boundary", BOUNDARY))
        if args.polish_command != "catalog":
            from verifier.runtime.polish_findings import project_reports, render_findings
            print(render_findings(project_reports(canonical_bytes(result))))
    return code
