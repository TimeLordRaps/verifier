# Terminology: application programming interface (API); central processing unit (CPU); identifier (ID).
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

from verifier.runtime.package_semantic_ownership import (
    CLAIM_BOUNDARY,
    SEMANTIC_OWNERSHIP_SPECS,
    SemanticOwnershipSpec,
    catalog_document,
    validate_catalog,
)
from verifier.runtime.package_semantic_ownership_model import (
    RootRoleDecision,
    root_role_decision,
)
from verifier.runtime.package_semantic_ownership_normative_assets import (
    AGENCY_CROSSWALK_ROOT_APPLIES,
)
from verifier.runtime.package_semantic_review_partitions import (
    PARTITION_OBJECT_IDS,
    PENDING_REFUTATION_AUDIT_OBJECT_IDS,
    REFUTED_KINDS_BY_OBJECT,
    unresolved_inventory,
)
from verifier.runtime import namespace_manifest
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for


ROOT = Path(__file__).parents[1]


EXPECTED_ORIGINAL_OBJECTS = {
    "vstd-added-kind-behavioral-verifier",
    "vstd-amd-live-sensor",
    "vstd-anchor-history-ledger",
    "vstd-artifact-control-lifecycle",
    "vstd-artifact-network-history",
    "vstd-asset-tier0-execution-verifier",
    "vstd-assurance-event-ledger",
    "vstd-challenge-record-ledger",
    "vstd-claim-garden-lifecycle",
    "vstd-component-package-storage",
    "vstd-consent-policy",
    "vstd-core-mechanism-executor",
    "vstd-core-pure-verifier",
    "vstd-core-provenance-sensor",
    "vstd-core-receipt-transaction",
    "vstd-core-self-polish-assessor",
    "vstd-controlled-emission-controller",
    "vstd-dataset-provenance-policy",
    "vstd-deriver-process-exchange",
    "vstd-digest-validation-policy",
    "vstd-firmware-emulator-accounting",
    "vstd-finite-record-issuance",
    "vstd-gate-pipeline-controller",
    "vstd-gated-publication",
    "vstd-governance-policy",
    "vstd-hardware-receipt-publication",
    "vstd-hardware-resource-accounting",
    "vstd-hardware-cli-protocol",
    "vstd-accelerator-profile-reader",
    "vstd-accelerator-discovery-command",
    "vstd-virtual-firmware-probe-harness",
    "vstd-hardware-receipt-assessor",
    "vstd-javascript-parser-protocol",
    "vstd-invocation-ledger",
    "vstd-logit-constraint-controller",
    "vstd-native-gate-suite",
    "vstd-network-fixture-corpus",
    "vstd-nvidia-live-sensor",
    "vstd-openshell-environment",
    "vstd-package-worker-exchange",
    "vstd-permission-slot-controller",
    "vstd-policy-enforcement-engine",
    "vstd-polish-workflow-transaction",
    "vstd-precommitment-ledger",
    "vstd-privacy-emission-policy",
    "vstd-repository-admission-reconciler",
    "vstd-retention-policy",
    "vstd-scitt-evidence-protocol",
    "vstd-selected-source-admission",
    "vstd-self-polish-case-materializer",
    "vstd-self-polish-full-candidate-capture",
    "vstd-self-polish-native-case-corpus",
    "vstd-sim-artifact-publication",
    "vstd-sim-resource-measurement",
    "vstd-software-diode-effect",
    "vstd-source-provenance-observer",
    "vstd-systems-parser-protocol",
    "vstd-train-control-session",
    "vstd-transaction-execution-coordinator",
    "vstd-tier1-evidence-ledger",
    "vstd-verifier-native-execution-controller",
    "vstd-verifier-run-constraint-controller",
    "vstd-workflow-parser-protocol",
    "vstd-runtime-package-marker",
    "vstd-namespace-rule-engine",
    "vstd-namespace-source-census",
    "vstd-manifest-admission",
    "vstd-package-semantic-review-policy",
    "vstd-package-semantic-ownership-policy",
    "vstd-package-graph-contract",
    "vstd-package-worker-dependency-relation",
    "vstd-package-instance-evidence",
    "vstd-package-kind-requirements",
    "vstd-package-obligation-candidate",
    "vstd-package-owner-decision",
    "vstd-native-operation-metadata",
    "vstd-object-context-closure",
    "vstd-artifact-snapshot-transaction",
    "vstd-accessibility-artifact-reader",
    "vstd-graph-topology-reader",
    "vstd-current-object-reader",
    "vstd-experimental-workflow-reader",
    "vstd-security-artifact-reader",
    "vstd-certification-command",
    "vstd-clearance-publication-preparation",
    "vstd-demo-specimen-materializer",
    "vstd-core-obligation-union-policy",
    "vstd-security9-accounting-policy",
    "vstd-application-authority-protocol",
    "vstd-release-source-binding",
    "vstd-tier-progression-controller",
    "vstd-application-release-controller",
    "vstd-package-polish-controller",
    "vstd-package-self-polish-controller",
    "vstd-package-self-polish-rechecker",
    "vstd-polish-assessment-engine",
    "vstd-polish-command-controller",
    "vstd-polish-capacity-policy",
    "vstd-polish-findings-projection",
    "vstd-polish-inventory-policy",
    "vstd-polish-inventory-authority",
    "vstd-polish-public-authority",
    "vstd-prdel-coverage-policy",
    "vstd-prdel-impact-graph",
    "vstd-prdel-source-compiler",
    "vstd-prdel-shard-protocol",
    "vstd-prdel-v2-shard-protocol",
    "vstd-public-checkability-protocol",
    "vstd-self-polish-dynamics-controller",
    "vstd-self-polish-estate-authority",
    "vstd-self-polish-estate-evidence",
    "vstd-self-polish-estate-native-sensor",
    "vstd-self-polish-facet-reason-ledger",
    "vstd-self-polish-native-adapters",
    "vstd-self-polish-native-case-registry",
    "vstd-self-polish-native-extension-registry",
    "vstd-self-polish-native-replay-controller",
    "vstd-self-polish-statics-controller",
    "vstd-self-polish-tier-controller",
    "vstd-tier-zero-orchestrator",
    "vstd-tier-zero-profile-policy",
    "vstd-tier-zero-reason-ledger",
}
EXPECTED_OBJECTS = EXPECTED_ORIGINAL_OBJECTS | set(PARTITION_OBJECT_IDS)
# Observed exact denominators for the current central catalog.  The path count
# moves only when an owned source path is added, removed, or reassigned.
EXPECTED_OBJECT_COUNT = 441
EXPECTED_PATH_COUNT = 1845
AGENCY_OBJECT_ID = "vstd-agency-surface-crosswalk-assets"
AGENCY_PATH = "src/verifier/standard/AGENCY_SURFACE.md"


def _aggregate_failures(specs: Iterable[SemanticOwnershipSpec]) -> list[str]:
    """Return every aggregate-contract violation, naming exact IDs and paths.

    The check is deliberately exhaustive rather than first-failure: a mutated
    catalog must report all omissions, duplicates, shared paths and role drift
    in one run so the reviewer sees the exact denominator defect.
    """
    selected = tuple(specs)
    failures: list[str] = []
    if len(selected) != EXPECTED_OBJECT_COUNT:
        failures.append(
            f"object count {len(selected)} differs from {EXPECTED_OBJECT_COUNT}"
        )
    id_counts = Counter(item.object_id for item in selected)
    missing = sorted(EXPECTED_OBJECTS - set(id_counts))
    unexpected = sorted(set(id_counts) - EXPECTED_OBJECTS)
    duplicated = sorted(object_id for object_id, count in id_counts.items() if count > 1)
    if missing:
        failures.append("missing object IDs: " + ", ".join(missing))
    if unexpected:
        failures.append("unexpected object IDs: " + ", ".join(unexpected))
    if duplicated:
        failures.append("duplicated object IDs: " + ", ".join(duplicated))
    path_counts = Counter(path for item in selected for path in item.owned_paths)
    shared = sorted(path for path, count in path_counts.items() if count > 1)
    if shared:
        failures.append("shared owned paths: " + ", ".join(shared))
    for item in selected:
        if item.object_id != AGENCY_OBJECT_ID:
            continue
        if "OBJECT" in (item.primary_kind, *item.specializations):
            failures.append("agency OBJECT bypass")
        if any(decision.status == "DOES_NOT_APPLY" for decision in item.root_role_decisions):
            failures.append("agency applicability exempted by DOES_NOT_APPLY")
        if (
            item.primary_kind,
            item.specializations,
            item.owned_paths,
        ) != ("POLICY", ("PROTOCOL",), (AGENCY_PATH,)):
            failures.append("agency roles or path differ from POLICY+PROTOCOL")
        if tuple(decision.kind for decision in item.root_role_decisions) != (
            AGENCY_CROSSWALK_ROOT_APPLIES
        ) or any(decision.status != "APPLIES" for decision in item.root_role_decisions):
            failures.append("agency conservative applicability decisions differ")
    return failures


def _without(object_id: str) -> tuple[SemanticOwnershipSpec, ...]:
    return tuple(item for item in SEMANTIC_OWNERSHIP_SPECS if item.object_id != object_id)


def _mutated(object_id: str, **changes: object) -> tuple[SemanticOwnershipSpec, ...]:
    return tuple(
        replace(item, **changes) if item.object_id == object_id else item
        for item in SEMANTIC_OWNERSHIP_SPECS
    )


def _one(path: str = "owned.py", *, kind: str = "POLICY") -> SemanticOwnershipSpec:
    return SemanticOwnershipSpec(
        object_id="audit-owned-object",
        primary_kind=kind,
        specializations=(),
        owned_paths=(path,),
        representation_role="Exact audited subject mechanism.",
        necessity_reason="Generic ownership would hide its consequential contract.",
        consequence_boundary="No claim beyond the selected source path.",
    )


def test_runtime_fallback_is_exactly_the_audited_verifier_core_surface() -> None:
    """Only paths explicitly admitted by the core review may use its fallback owner.

    A new runtime source with no semantic owner must not silently join
    ``verifier-core-self``.  The retained core audit is the independent exact
    denominator for the few runtime files intentionally assigned there.
    """
    from verifier.runtime import package_manifest_migration as migration
    from verifier.runtime import package_semantic_review_core as core_review

    fallback = "FALLBACK"
    by_kind = {"HARNESS": "HARNESS", "VERIFIER": fallback, "OBJECT": "OBJECT"}
    owners = migration._semantic_owner_index(SEMANTIC_OWNERSHIP_SPECS)
    runtime = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "src" / "verifier" / "runtime").glob("*.py")
    )
    assert runtime
    fell_through = [
        path
        for path in runtime
        if migration._owner_for_path(path, by_kind, owners) == fallback
    ]
    expected_fallback = sorted(set(runtime) & set(core_review.CORE_PATHS))
    assert expected_fallback == [
        "src/verifier/runtime/package_review_stage_gaps.py",
        "src/verifier/runtime/package_verifier_graph.py",
    ]
    assert fell_through == expected_fallback


def test_new_runtime_mechanisms_have_exact_source_owners() -> None:
    owners = {
        path: spec.object_id for spec in SEMANTIC_OWNERSHIP_SPECS for path in spec.owned_paths
    }
    expected = {
        "src/verifier/runtime/namespace_refutation.py": "vstd-namespace-rule-engine",
        "src/verifier/runtime/source_declaration_inputs.py": "vstd-namespace-source-census",
        "src/verifier/runtime/package_checker_worker.py": "vstd-package-worker-exchange",
        "src/verifier/runtime/package_api_surface_admission.py": "vstd-package-semantic-review-policy",
        "src/verifier/runtime/policy_enforcement_execution.py": "vstd-policy-enforcement-engine",
        "src/verifier/runtime/policy_enforcement_routes.py": "vstd-policy-enforcement-engine",
        "src/verifier/runtime/policy_enforcement_worker.py": "vstd-policy-enforcement-engine",
        "src/verifier/runtime/transaction_execution.py": "vstd-transaction-execution-coordinator",
    }
    for module in (
        "package_semantic_ownership_current_untracked",
        "package_semantic_ownership_domains_agency_collective",
        "package_semantic_ownership_domains_context",
        "package_semantic_ownership_domains_sim_model",
        "package_semantic_ownership_domains_systems",
    ):
        expected["src/verifier/runtime/" + module + ".py"] = "vstd-package-semantic-ownership-policy"
    assert {path: owners.get(path) for path in expected} == expected
    by_id = {spec.object_id: spec for spec in SEMANTIC_OWNERSHIP_SPECS}
    assert by_id["vstd-policy-enforcement-engine"].primary_kind == "POLICY"
    assert by_id["vstd-policy-enforcement-engine"].specializations == ("PROTOCOL",)
    assert by_id["vstd-transaction-execution-coordinator"].primary_kind == "TRANSACTION"
    assert by_id["vstd-transaction-execution-coordinator"].specializations == ("POLICY", "PROTOCOL")


def test_current_catalog_is_exact_path_disjoint_and_deterministic() -> None:
    validated = validate_catalog(ROOT)
    assert _aggregate_failures(validated) == []
    assert len(validated) == EXPECTED_OBJECT_COUNT
    assert {item.object_id for item in validated} == EXPECTED_OBJECTS
    assert sum(len(item.owned_paths) for item in validated) == EXPECTED_PATH_COUNT
    paths = [path for item in validated for path in item.owned_paths]
    assert len(paths) == len(set(paths))
    assert all(item.necessity_reason.strip() for item in validated)
    assert all(item.consequence_boundary.strip() for item in validated)
    assert "not a complete package partition" in CLAIM_BOUNDARY

    first = catalog_document(ROOT)
    second = catalog_document(ROOT, reversed(SEMANTIC_OWNERSHIP_SPECS))
    assert first == second
    assert first["digest"].startswith("sha256:")
    assert [row["object_id"] for row in first["objects"]] == sorted(EXPECTED_OBJECTS)


def test_current_catalog_composes_with_the_complete_retained_package_graph() -> None:
    from verifier.runtime.package_manifest_migration import expand_compact_document

    stored = json.loads((ROOT / "objects.vstd").read_text(encoding="utf-8"))
    document = expand_compact_document(stored)
    rows = deepcopy(document["namespace"]["objects"])
    identifiers = {row["object_id"] for row in rows}
    by_id = {row["object_id"]: row for row in rows}
    registry = namespace_registry()
    # Collect every drift before failing so a stale root manifest reports its
    # exact missing IDs together with every per-object disagreement.  The root
    # manifest is migrated only by a later reviewed change; it is never accepted
    # or regenerated here, so any entry below keeps this gate RED.
    failures: list[str] = []
    missing_rows = sorted(EXPECTED_OBJECTS - identifiers)
    if missing_rows:
        failures.append("objects.vstd lacks ownership objects: " + ", ".join(missing_rows))
    if len(identifiers) != len(rows):
        failures.append("objects.vstd repeats an object identifier")
    for spec in SEMANTIC_OWNERSHIP_SPECS:
        installed = by_id.get(spec.object_id)
        if installed is None:
            continue
        if installed["kind"] != spec.primary_kind:
            failures.append(f"{spec.object_id}: primary kind differs")
        # The ownership catalog is the minimum source-role denominator.  A
        # source-specific semantic review may add consequential roles later in
        # migration, but every such addition must remain an evidenced APPLIES
        # decision with its complete obligation denominator; it cannot be an
        # unexplained label that the composition test silently tolerates.
        installed_roles = set(installed["specializations"])
        absent_roles = sorted(set(spec.specializations) - installed_roles)
        if absent_roles:
            failures.append(f"{spec.object_id}: specializations absent {absent_roles}")
        for kind in sorted(installed_roles - set(spec.specializations)):
            decision = installed["classification"].get(kind, {})
            if (
                decision.get("status") != "APPLIES"
                or not str(decision.get("reason", "")).strip()
                or not decision.get("evidence")
            ):
                failures.append(f"{spec.object_id}: accumulated {kind} lacks APPLIES evidence")
            obligations = {
                obligation["id"] for obligation in requirements_for(registry, (kind,))
            }
            absent_obligations = sorted(obligations - set(installed["obligations"]))
            if absent_obligations:
                failures.append(
                    f"{spec.object_id}: {kind} obligations absent {absent_obligations}"
                )
        surfaces = {
            surface.removeprefix("file:")
            for surface in installed["surfaces"]
            if surface.startswith("file:")
        }
        if surfaces != set(spec.owned_paths):
            failures.append(f"{spec.object_id}: file surfaces differ from owned paths")
        # Admission keeps both halves of the source-specific rationale.  The
        # necessity explains why the object must exist; the boundary prevents
        # that reason from silently widening into a behavioral or authority
        # claim when the catalog is materialized into objects.vstd.
        expected_reason = spec.necessity_reason + " Boundary: " + spec.consequence_boundary
        if installed["reason"] != expected_reason:
            failures.append(f"{spec.object_id}: reason differs from necessity and boundary")

    graph = next(row for row in rows if row["kind"] == "GRAPH")
    graph_missing = sorted(EXPECTED_OBJECTS - set(graph["operands"]["members"]))
    if graph_missing:
        failures.append("GRAPH members lack ownership objects: " + ", ".join(graph_missing))
    assert not failures, "objects.vstd disagrees with central ownership catalog:\n" + "\n".join(
        failures
    )

    namespace_manifest.validate_manifest(
        {
            "schema_version": namespace_manifest.SCHEMA,
            "registry_digest": document["namespace"]["registry_digest"],
            "extensions": [],
            "objects": rows,
        }
    )
    composition = namespace_manifest.check_composition(rows, registry)
    assert composition["status"] == "PASS"


def test_agency_surface_is_exactly_once_with_its_normative_roles() -> None:
    matches = [item for item in SEMANTIC_OWNERSHIP_SPECS if item.object_id == AGENCY_OBJECT_ID]
    assert len(matches) == 1
    item = matches[0]
    assert item.primary_kind == "POLICY"
    assert item.specializations == ("PROTOCOL",)
    assert item.owned_paths == (AGENCY_PATH,)
    assert tuple(decision.kind for decision in item.root_role_decisions) == (
        AGENCY_CROSSWALK_ROOT_APPLIES
    )
    assert all(decision.status == "APPLIES" for decision in item.root_role_decisions)
    assert "ROBOT" in item.representation_role
    assert "FINBOT" in item.representation_role
    assert (
        "an OBJECT label or unknown applicability cannot exempt a conditional route"
        in item.necessity_reason
    )
    assert "supplies no new evidence source" in item.consequence_boundary
    assert "real-money effect" in item.consequence_boundary


def test_agency_conservative_applicability_remains_non_exempt() -> None:
    item = next(row for row in SEMANTIC_OWNERSHIP_SPECS if row.object_id == AGENCY_OBJECT_ID)
    assert AGENCY_OBJECT_ID in PENDING_REFUTATION_AUDIT_OBJECT_IDS
    assert AGENCY_OBJECT_ID not in {object_id for object_id, _ in REFUTED_KINDS_BY_OBJECT}
    assert all(decision.status != "DOES_NOT_APPLY" for decision in item.root_role_decisions)
    assert unresolved_inventory()[AGENCY_OBJECT_ID] == ()


def test_agency_has_no_object_bypass() -> None:
    item = next(row for row in SEMANTIC_OWNERSHIP_SPECS if row.object_id == AGENCY_OBJECT_ID)
    assert "OBJECT" not in (item.primary_kind, *item.specializations)
    assert "OBJECT" not in {decision.kind for decision in item.root_role_decisions}


def _agency_spec() -> SemanticOwnershipSpec:
    return next(item for item in SEMANTIC_OWNERSHIP_SPECS if item.object_id == AGENCY_OBJECT_ID)


def _non_agency_spec() -> SemanticOwnershipSpec:
    return next(item for item in SEMANTIC_OWNERSHIP_SPECS if item.object_id != AGENCY_OBJECT_ID)


@pytest.mark.parametrize(
    "specs,expected",
    (
        (_without(AGENCY_OBJECT_ID), "missing object IDs: " + AGENCY_OBJECT_ID),
        (
            (*SEMANTIC_OWNERSHIP_SPECS, _agency_spec()),
            "duplicated object IDs: " + AGENCY_OBJECT_ID,
        ),
        (
            _mutated(AGENCY_OBJECT_ID, specializations=("PROTOCOL", "SENSOR")),
            "agency roles or path differ",
        ),
        (
            _mutated(AGENCY_OBJECT_ID, primary_kind="PROTOCOL", specializations=()),
            "agency roles or path differ",
        ),
        (
            _mutated(
                AGENCY_OBJECT_ID,
                root_role_decisions=(
                    root_role_decision(
                        "ROBOT",
                        "DOES_NOT_APPLY",
                        "Unknown applicability exempted by omission.",
                    ),
                ),
            ),
            "agency applicability exempted by DOES_NOT_APPLY",
        ),
        (
            _mutated(AGENCY_OBJECT_ID, specializations=("OBJECT", "PROTOCOL")),
            "agency OBJECT bypass",
        ),
        (
            _mutated(
                _non_agency_spec().object_id,
                owned_paths=tuple(sorted((*_non_agency_spec().owned_paths, AGENCY_PATH))),
            ),
            "shared owned paths: " + AGENCY_PATH,
        ),
    ),
    ids=(
        "omission",
        "duplication",
        "wrong-specializations",
        "wrong-primary",
        "does-not-apply-exemption",
        "object-bypass",
        "shared-path",
    ),
)
def test_aggregate_contract_refuses_adversarial_mutations(
    specs: tuple[SemanticOwnershipSpec, ...],
    expected: str,
) -> None:
    failures = _aggregate_failures(specs)
    assert failures
    assert any(expected in failure for failure in failures), failures


def test_catalog_preserves_simulated_physical_and_financial_boundaries() -> None:
    specs = {item.object_id: item for item in SEMANTIC_OWNERSHIP_SPECS}
    emulator = specs["vstd-firmware-emulator-accounting"]
    assert emulator.primary_kind == "LEDGER"
    assert emulator.specializations == (
        "ACTUATOR",
        "CONTROLLER",
        "PROTOCOL",
        "TRANSACTION",
    )
    assert (
        "Caller, emulator, anchor provider, and verifier participate in an ordered "
        "boot/challenge/attestation/execution/accounting state machine."
        in emulator.necessity_reason
    )
    assert (
        "Its commands mutate multi-part in-memory state and sometimes an anchor "
        "provider, requiring explicit precondition, commit, partial-failure, retry, "
        "and replay boundaries."
        in emulator.necessity_reason
    )
    assert "Software simulation only" in emulator.consequence_boundary
    for sensor_id in ("vstd-amd-live-sensor", "vstd-nvidia-live-sensor"):
        assert specs[sensor_id].primary_kind == "SENSOR"
        assert specs[sensor_id].specializations == ("MEASUREMENT",)
        assert "commands no device" in specs[sensor_id].consequence_boundary
    delegated = {
        "vstd-accelerator-discovery-command",
        "vstd-accelerator-profile-reader",
        "vstd-accelerator-profile-registry",
        "vstd-accessibility-artifact-reader",
        "vstd-added-kind-behavioral-verifier",
        "vstd-hardware-cli-protocol",
    }
    for object_id, item in specs.items():
        roles = (item.primary_kind, *item.specializations)
        if object_id in delegated:
            assert "ROBOT" in roles
            assert "FINBOT" in roles
            assert "physical" in item.consequence_boundary
            assert "financial" in item.consequence_boundary
            assert (
                "establishes neither" in item.consequence_boundary
                or "establishes no" in item.consequence_boundary
                or "not artifact validity" in item.consequence_boundary
                or "remain unestablished" in item.consequence_boundary
            )
        else:
            assert "ROBOT" not in roles
            assert "FINBOT" not in roles


def test_submission_controls_do_not_claim_actuator_without_owned_effect_endpoint() -> None:
    specs = {item.object_id: item for item in SEMANTIC_OWNERSHIP_SPECS}
    effect_controls = {
        "vstd-gate-pipeline-controller": "Process-command submission",
        "vstd-permission-slot-controller": "Callback admission and submission",
        "vstd-controlled-emission-controller": "Callback submission",
        "vstd-train-control-session": "Action or callback submission",
    }
    for object_id, boundary in effect_controls.items():
        item = specs[object_id]
        assert "ACTUATOR" not in item.specializations
        assert boundary in item.consequence_boundary
        assert "not proof of downstream effect" in item.consequence_boundary
        assert "ROBOT or FINBOT" in item.consequence_boundary
        assert "ROBOT" not in (item.primary_kind, *item.specializations)
        assert "FINBOT" not in (item.primary_kind, *item.specializations)
    assert "ACTUATOR" in specs["vstd-firmware-emulator-accounting"].specializations


def test_command_only_operations_drop_actuator_but_emulator_worker_keeps_it() -> None:
    specs = {item.object_id: item for item in SEMANTIC_OWNERSHIP_SPECS}
    unsupported = {
        "vstd-controlled-emission-controller",
        "vstd-core-mechanism-executor",
        "vstd-core-provenance-sensor",
        "vstd-gate-pipeline-controller",
        "vstd-javascript-parser-protocol",
        "vstd-permission-slot-controller",
        "vstd-systems-parser-protocol",
        "vstd-train-control-session",
        "vstd-workflow-parser-protocol",
        "vstd-verifier-run-constraint-controller",
        "vstd-native-gate-suite",
        "vstd-repository-admission-reconciler",
        "vstd-source-provenance-observer",
    }

    assert all("ACTUATOR" not in specs[name].specializations for name in unsupported)
    worker = specs["vstd-package-worker-exchange"]
    assert "ACTUATOR" in worker.specializations
    assert {
        "src/verifier/runtime/emulator_control_execution.py",
        "src/verifier/runtime/emulator_control_worker.py",
    } <= set(worker.owned_paths)


def test_gate_pipeline_owns_all_five_process_running_gate_sources() -> None:
    item = next(
        row
        for row in SEMANTIC_OWNERSHIP_SPECS
        if row.object_id == "vstd-gate-pipeline-controller"
    )
    assert item.owned_paths == (
        "src/verifier/runtime/gate_pipeline.py",
        "src/verifier/runtime/prdel_evidence.py",
        "src/verifier/runtime/quality_checks.py",
        "src/verifier/runtime/secret_gate.py",
        "src/verifier/runtime/self_polish_evidence.py",
    )
    assert item.specializations == (
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    )


def test_openshell_is_an_optional_environment_with_accumulated_roles() -> None:
    item = next(
        row
        for row in SEMANTIC_OWNERSHIP_SPECS
        if row.object_id == "vstd-openshell-environment"
    )
    assert item.primary_kind == "ENV"
    assert item.specializations == (
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
    )
    assert item.owned_paths == (
        "extensions/openshell/pyproject.toml",
        "extensions/openshell/src/vstd_openshell/__init__.py",
        "extensions/openshell/src/vstd_openshell/environment.py",
        "extensions/openshell/src/vstd_openshell/live.py",
    )
    assert "Optional path only" in item.consequence_boundary
    assert "basic runner does not require OpenShell" in item.consequence_boundary
    assert "whole-object conformance" in item.consequence_boundary
    assert "ROBOT" not in (item.primary_kind, *item.specializations)
    assert "FINBOT" not in (item.primary_kind, *item.specializations)


def test_invocation_ledger_semantic_owner_accumulates_exact_local_roles() -> None:
    item = next(
        row
        for row in SEMANTIC_OWNERSHIP_SPECS
        if row.object_id == "vstd-invocation-ledger"
    )
    assert item.primary_kind == "LEDGER"
    assert item.specializations == ("POLICY", "PROTOCOL", "TRANSACTION")
    assert item.owned_paths == (
        "src/verifier/runtime/local_ledger_control_checks.py",
        "src/verifier/runtime/local_ledger_controls.py",
        "src/verifier/runtime/local_ledger_execution.py",
        "src/verifier/runtime/local_ledger_worker.py",
        "src/verifier/runtime/polish_invocation_ledger.py",
    )
    assert "roles must accumulate" in item.necessity_reason
    assert "nonmonetary local SQLite ledger" in item.consequence_boundary
    for excluded in (
        "no actor authentication",
        "automatic retry",
        "liveness guarantee",
        "financial accounting",
        "global finality",
    ):
        assert excluded in item.consequence_boundary


def test_worker_parent_interface_observation_is_sensor_measurement_not_confinement() -> (
    None
):
    item = next(
        row
        for row in SEMANTIC_OWNERSHIP_SPECS
        if row.object_id == "vstd-package-worker-exchange"
    )
    assert item.primary_kind == "PROTOCOL"
    assert item.specializations == (
        "ACTUATOR",
        "MEASUREMENT",
        "SENSOR",
        "TRANSACTION",
    )
    assert "return code" in item.consequence_boundary
    assert "stream bytes, counts, digests and completeness" in item.consequence_boundary
    assert "does not observe child internals" in item.consequence_boundary
    assert "external effects" in item.consequence_boundary


def test_fresh_sim_resource_meter_is_software_measurement_not_physical_control() -> (
    None
):
    item = next(
        row
        for row in SEMANTIC_OWNERSHIP_SPECS
        if row.object_id == "vstd-sim-resource-measurement"
    )
    assert item.primary_kind == "MEASUREMENT"
    assert item.specializations == ("SENSOR",)
    assert item.owned_paths == (
        "src/verifier/runtime/resource_measurement_execution.py",
        "src/verifier/runtime/resource_measurement_worker.py",
    )
    assert "CPython thread CPU nanoseconds" in item.consequence_boundary
    assert "tracemalloc peak bytes" in item.consequence_boundary
    assert "no physical calibration" in item.consequence_boundary
    assert "ROBOT" not in (item.primary_kind, *item.specializations)
    assert "FINBOT" not in (item.primary_kind, *item.specializations)


def test_core_semantic_splits_preserve_effect_and_observation_boundaries() -> None:
    from verifier.runtime import package_semantic_review_operations as semantic_review

    specs = {item.object_id: item for item in SEMANTIC_OWNERSHIP_SPECS}
    executor = specs["vstd-core-mechanism-executor"]
    assert executor.primary_kind == "VERIFIER"
    assert executor.specializations == ("POLICY", "TRANSACTION")
    assert len(executor.owned_paths) == 7
    assert "not a sandbox" in executor.consequence_boundary
    assert "ROBOT or FINBOT" in executor.consequence_boundary

    pure = specs["vstd-core-pure-verifier"]
    assert pure.primary_kind == "VERIFIER"
    assert pure.specializations == ()
    assert len(pure.owned_paths) == 12
    assert "invoke no caller mechanism" in pure.consequence_boundary

    provenance = specs["vstd-core-provenance-sensor"]
    assert provenance.primary_kind == "SENSOR"
    assert provenance.specializations == (
        "MEASUREMENT",
        "PROTOCOL",
    )
    assert provenance.owned_paths == ("src/verifier/core/provenance.py",)
    assert "no coordinated durable effect or replay unit" in provenance.consequence_boundary
    transaction = semantic_review.review_document()[
        "vstd-core-provenance-sensor"
    ]["classification"]["TRANSACTION"]
    assert transaction == {
        "status": "DOES_NOT_APPLY",
        "reason": (
            "core provenance acquisition does not apply as TRANSACTION. Its current "
            "role has no separately owned coordinated effect/commit unit; process setup "
            "or response production is infrastructure for the named role. Reviewed "
            "boundary: This is host-visible software acquisition, not hostile-host "
            "attestation, physical calibration, confinement or proof that a represented "
            "command ran."
        ),
        "evidence_paths": ["src/verifier/core/provenance.py"],
    }
    assert "not hostile-host attestation" in provenance.consequence_boundary

    receipt = specs["vstd-core-receipt-transaction"]
    assert receipt.primary_kind == "TRANSACTION"
    assert receipt.specializations == ()
    assert receipt.owned_paths == ("src/verifier/core/receipt.py",)
    assert "not atomic across files" in receipt.consequence_boundary


def test_local_lifecycle_journals_retain_ledger_without_financial_overclaim() -> None:
    specs = {item.object_id: item for item in SEMANTIC_OWNERSHIP_SPECS}
    slot = specs["vstd-permission-slot-controller"]
    assert "LEDGER" in slot.specializations
    assert "append-only event trace" in slot.representation_role
    assert (
        "not effect replay, durable global history or financial accounting"
        in slot.consequence_boundary
    )

    workflow = specs["vstd-polish-workflow-transaction"]
    assert "LEDGER" in workflow.specializations
    assert "hash-chained append-only local journal" in workflow.representation_role
    assert "unwitnessed local journal" in workflow.consequence_boundary
    assert (
        "not external authoritative execution or financial accounting"
        in workflow.consequence_boundary
    )
    assert workflow.owned_paths == (
        "src/verifier/runtime/polish_prepare.py",
        "src/verifier/runtime/polish_workflow.py",
        "src/verifier/runtime/polish_workflow_cli.py",
        "src/verifier/runtime/polish_workflow_replay.py",
    )


def test_polish_split_has_exact_engine_and_command_owners() -> None:
    specs = {item.object_id: item for item in SEMANTIC_OWNERSHIP_SPECS}
    package = specs["vstd-package-polish-controller"]
    assert package.owned_paths == (
        "src/verifier/runtime/package_polish.py",
        "src/verifier/runtime/package_polish_schema_validation.py",
        "src/verifier/runtime/package_source_contracts.py",
    )
    engine = specs["vstd-polish-assessment-engine"]
    assert engine.primary_kind == "VERIFIER"
    assert engine.specializations == (
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
    )
    assert engine.owned_paths == ("src/verifier/runtime/polish.py",)
    assert "polished remains false" in engine.consequence_boundary

    command = specs["vstd-polish-command-controller"]
    assert command.primary_kind == "CONTROLLER"
    assert command.specializations == (
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    )
    assert command.owned_paths == ("src/verifier/runtime/polish_cli.py",)
    assert "atomic preparation" in command.consequence_boundary


def test_claim_garden_phases_are_one_disclosed_path_owned_instance() -> None:
    item = next(
        row
        for row in SEMANTIC_OWNERSHIP_SPECS
        if row.object_id == "vstd-claim-garden-lifecycle"
    )
    assert item.owned_paths == ("src/verifier/interoperability/claim_garden.py",)
    for phase in ("registration", "upload", "finalization", "publication"):
        assert phase in item.representation_role.lower()
    assert "Path-level ownership cannot split" in item.consequence_boundary


def test_network_cli_stays_with_its_authoritative_artifact_history() -> None:
    item = next(
        row
        for row in SEMANTIC_OWNERSHIP_SPECS
        if row.object_id == "vstd-artifact-network-history"
    )
    assert item.owned_paths == (
        "examples/artifact-network/build_specimen.py",
        "src/verifier/interoperability/network.py",
        "src/verifier/runtime/network_cli.py",
    )
    assert item.primary_kind == "LEDGER"
    assert item.specializations == ("POLICY", "PROTOCOL", "TRANSACTION")
    assert (
        "The source implements explicit authority-model and silo-composition "
        "admission rules over allowable actions, local additions, and closure evidence."
        in item.necessity_reason
    )


def test_finite_record_issuance_never_promotes_full_application_polish() -> None:
    item = next(
        row
        for row in SEMANTIC_OWNERSHIP_SPECS
        if row.object_id == "vstd-finite-record-issuance"
    )
    assert item.primary_kind == "TRANSACTION"
    assert item.specializations == ("LEDGER", "POLICY", "PROTOCOL")
    assert item.owned_paths == ("src/verifier/runtime/finite_record_issuance.py",)
    assert "full-application polish UNKNOWN" in item.consequence_boundary
    assert "no transport" in item.consequence_boundary


def test_new_audited_children_preserve_exact_accumulated_roles() -> None:
    specs = {item.object_id: item for item in SEMANTIC_OWNERSHIP_SPECS}
    expected = {
        "vstd-artifact-control-lifecycle": ("TRANSACTION", ("PROTOCOL",), 3),
        "vstd-component-package-storage": ("DATA", ("TRANSACTION",), 3),
        "vstd-core-self-polish-assessor": (
            "VERIFIER",
            ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR", "TRANSACTION"),
            1,
        ),
        "vstd-deriver-process-exchange": (
            "PROTOCOL",
            ("ACTUATOR", "CONTROLLER", "MEASUREMENT", "SENSOR", "TRANSACTION"),
            1,
        ),
        "vstd-hardware-receipt-publication": ("RECEIPT", ("TRANSACTION",), 1),
        "vstd-hardware-resource-accounting": ("MEASUREMENT", ("ASSET", "POLICY"), 1),
        "vstd-logit-constraint-controller": (
            "CONTROLLER",
            ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR", "TRANSACTION"),
            5,
        ),
        "vstd-native-gate-suite": (
            "VERIFIER",
            ("MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR", "TRANSACTION"),
            3,
        ),
        "vstd-network-fixture-corpus": (
            "LEDGER",
            ("PROTOCOL", "TRANSACTION"),
            6,
        ),
        "vstd-privacy-emission-policy": ("POLICY", ("LEDGER", "TRANSACTION"), 8),
        "vstd-repository-admission-reconciler": (
            "VERIFIER",
            ("MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR", "TRANSACTION"),
            4,
        ),
        "vstd-scitt-evidence-protocol": ("PROTOCOL", ("POLICY",), 4),
        "vstd-selected-source-admission": (
            "POLICY",
            ("CONTROLLER", "MEASUREMENT", "PROTOCOL", "SENSOR", "TRANSACTION"),
            4,
        ),
        "vstd-self-polish-case-materializer": (
            "TRANSACTION",
            ("ACTUATOR", "POLICY"),
                3,
        ),
        "vstd-self-polish-full-candidate-capture": (
            "CONTROLLER",
            ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR", "TRANSACTION"),
            1,
        ),
        "vstd-self-polish-native-case-corpus": (
            "POLICY",
            ("MEASUREMENT", "SENSOR"),
            8,
        ),
        "vstd-software-diode-effect": (
            "ACTUATOR",
            ("MEASUREMENT", "PROTOCOL", "SENSOR", "TRANSACTION"),
            1,
        ),
        "vstd-source-provenance-observer": (
            "SENSOR",
            ("MEASUREMENT", "PROTOCOL", "TRANSACTION"),
            3,
        ),
        "vstd-verifier-native-execution-controller": (
            "VERIFIER",
            (
                "ACTUATOR",
                "CONTROLLER",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            1,
        ),
        "vstd-verifier-run-constraint-controller": (
            "VERIFIER",
            (
                "CONTROLLER",
                "MEASUREMENT",
                "POLICY",
                "SENSOR",
                "TRANSACTION",
            ),
            1,
        ),
        "vstd-tier1-evidence-ledger": (
            "LEDGER",
            (
                "ACTUATOR",
                "CONTROLLER",
                "MEASUREMENT",
                "POLICY",
                "PROTOCOL",
                "SENSOR",
                "TRANSACTION",
            ),
            1,
        ),
    }
    for object_id, (primary, specializations, path_count) in expected.items():
        item = specs[object_id]
        assert item.primary_kind == primary
        assert item.specializations == specializations
        assert len(item.owned_paths) == path_count
        assert item.necessity_reason.strip()
        assert item.consequence_boundary.strip()
        assert "ROBOT" not in (item.primary_kind, *item.specializations)
        assert "FINBOT" not in (item.primary_kind, *item.specializations)

    assert (
        "PROTOCOL"
        not in specs["vstd-verifier-run-constraint-controller"].specializations
    )
    assert "SENSOR" not in specs["vstd-hardware-resource-accounting"].specializations
    assert specs["vstd-hardware-receipt-publication"].operands == (
        ("hardware", ("vstd-hardware",)),
        ("subject", ("vstd-hardware",)),
    )


def test_duplicate_object_id_is_refused(tmp_path: Path) -> None:
    (tmp_path / "one.py").write_text("pass\n", encoding="utf-8")
    first = _one("one.py")
    second = replace(first, owned_paths=("two.py",))
    with pytest.raises(ValueError, match="ID_DUPLICATED"):
        validate_catalog(tmp_path, (first, second))


def test_duplicate_path_ownership_is_refused(tmp_path: Path) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    first = _one()
    second = replace(first, object_id="another-owned-object")
    with pytest.raises(ValueError, match="PATH_DUPLICATED"):
        validate_catalog(tmp_path, (first, second))


def test_missing_current_path_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="PATH_MISSING"):
        validate_catalog(tmp_path, (_one(),))


def test_unregistered_kind_is_refused_before_path_use(tmp_path: Path) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="KIND_UNREGISTERED"):
        validate_catalog(tmp_path, (_one(kind="NOTAKIND"),))


def test_retained_root_kind_cannot_masquerade_as_a_specialization(
    tmp_path: Path,
) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SPECIALIZATION_NOT_REFINEMENT"):
        validate_catalog(
            tmp_path,
            (replace(_one(), specializations=("VERIFIER",)),),
        )


def test_narrow_local_specialization_must_match_the_primary_base(
    tmp_path: Path,
) -> None:
    from verifier.runtime.namespace_contracts import namespace_registry

    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    registry = namespace_registry(
        [
            {
                "kind": "SPECIALSIM",
                "extends": "SIM",
                "version": "1",
                "reason": "A simulation-only local refinement.",
                "obligations": [
                    {
                        "id": "SPECIALSIM-0.1-boundary",
                        "name": "Boundary",
                        "reason": "The local refinement needs a boundary.",
                        "evidence_requirement": "Bind the selected simulation boundary.",
                    }
                ],
            }
        ]
    )
    with pytest.raises(ValueError, match="SPECIALIZATION_BASE_DIFFERS"):
        validate_catalog(
            tmp_path,
            (replace(_one(), specializations=("SPECIALSIM",)),),
            registry=registry,
        )


def test_evidence_backed_retained_root_role_is_distinct_from_structure(
    tmp_path: Path,
) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    selected = replace(
        _one(),
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "This policy also computes one bounded repository decision.",
            ),
        ),
    )
    assert validate_catalog(tmp_path, (selected,)) == (selected,)
    assert selected.specializations == ()


@pytest.mark.parametrize(
    "decisions",
    (
        [root_role_decision("VERIFIER", "APPLIES", "List is not immutable.")],
        (
            root_role_decision("VERIFIER", "APPLIES", "First duplicate."),
            root_role_decision("VERIFIER", "DOES_NOT_APPLY", "Second duplicate."),
        ),
        (
            root_role_decision("VERIFIER", "APPLIES", "Sorts after HARNESS."),
            root_role_decision("HARNESS", "APPLIES", "Out of order."),
        ),
    ),
    ids=("not-tuple", "duplicate", "unsorted"),
)
def test_root_role_collection_shape_is_refused(
    tmp_path: Path,
    decisions: object,
) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="ROOT_ROLES_INVALID"):
        validate_catalog(
            tmp_path,
            (replace(_one(), root_role_decisions=decisions),),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "decision",
    (
        root_role_decision("POLICY", "APPLIES", "Cannot repeat the primary."),
        root_role_decision("NOTAKIND", "APPLIES", "Not registered."),
        RootRoleDecision("VERIFIER", "MAYBE", "Unsupported status."),  # type: ignore[arg-type]
        root_role_decision("VERIFIER", "APPLIES", " "),
    ),
    ids=("primary", "unregistered", "status", "blank-reason"),
)
def test_invalid_root_role_decision_is_refused(
    tmp_path: Path,
    decision: RootRoleDecision,
) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="ROOT_ROLE_INVALID"):
        validate_catalog(
            tmp_path,
            (replace(_one(), root_role_decisions=(decision,)),),
        )


@pytest.mark.parametrize(
    "path",
    ("../escape.py", "C" + ":/escape.py", "/escape.py", "a\\b.py"),
    ids=("parent-traversal", "drive-qualified", "absolute", "backslash"),
)
def test_nonportable_path_is_refused(tmp_path: Path, path: str) -> None:
    with pytest.raises(ValueError, match="PATH_NOT_PORTABLE"):
        validate_catalog(tmp_path, (_one(path),))


def test_blank_reason_or_boundary_is_refused(tmp_path: Path) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="REASON_REQUIRED"):
        validate_catalog(tmp_path, (replace(_one(), necessity_reason=""),))
    with pytest.raises(ValueError, match="REASON_REQUIRED"):
        validate_catalog(tmp_path, (replace(_one(), consequence_boundary=" "),))


@pytest.mark.parametrize(
    "operands",
    (
        (("subject", ()),),
        (("Bad Role", ("vstd-hardware",)),),
        (("subject", ("BAD",)),),
        (("subject", ("vstd-hardware",)), ("subject", ("vstd-package-object",))),
    ),
)
def test_invalid_semantic_operands_are_refused(
    tmp_path: Path,
    operands: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="OPERANDS_INVALID"):
        validate_catalog(tmp_path, (replace(_one(), operands=operands),))


@pytest.mark.parametrize("kind", ("RECEIPT", "GRAPH", "HYPER"))
def test_typed_primary_cannot_omit_its_composition_layout(
    tmp_path: Path,
    kind: str,
) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="TYPED_LAYOUT_INVALID"):
        validate_catalog(tmp_path, (_one(kind=kind),))


@pytest.mark.parametrize(
    "kind,operands",
    (
        (
            "RECEIPT",
            (
                ("hardware", ("vstd-hardware",)),
                ("subject", ("vstd-subject",)),
            ),
        ),
        ("HYPER", (("members", ("vstd-subject",)),)),
    ),
    ids=("receipt", "hyper"),
)
def test_typed_primary_accepts_its_complete_local_layout(
    tmp_path: Path,
    kind: str,
    operands: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    (tmp_path / "owned.py").write_text("pass\n", encoding="utf-8")
    selected = replace(_one(kind=kind), operands=operands)
    assert validate_catalog(tmp_path, (selected,)) == (selected,)


# Pure completeness of a supplied candidate census against semantic specs.
# The API is referenced through a module alias so these gates fail on their own
# absent behavior rather than hiding the existing aggregate assertions above.
from verifier.runtime import package_semantic_ownership as ownership  # noqa: E402

MANIFEST = "objects.vstd"


def _owned(object_id: str, *paths: str, kind: str = "POLICY") -> SemanticOwnershipSpec:
    return SemanticOwnershipSpec(
        object_id=object_id,
        primary_kind=kind,
        specializations=(),
        owned_paths=tuple(sorted(paths)),
        representation_role="Exact audited subject mechanism.",
        necessity_reason="Generic ownership would hide its consequential contract.",
        consequence_boundary="No claim beyond the selected source path.",
    )


def _kinds(failures: Iterable[object]) -> list[tuple[str, str]]:
    return [(item.kind, item.path) for item in failures]


def test_unowned_census_paths_are_each_reported_with_exact_diagnostics() -> None:
    failures = ownership.completeness_failures(
        ["a.py", "b.py", "c.py"], (_owned("owner-a", "a.py"),)
    )
    assert _kinds(failures) == [
        (ownership.FAILURE_UNOWNED, "b.py"),
        (ownership.FAILURE_UNOWNED, "c.py"),
    ]
    first = failures[0]
    assert isinstance(first, ownership.CompletenessFailure)
    assert first.owners == () and first.fallback_owners == ()
    assert first.reason.strip() and first.next_action.strip()
    rendered = first.render()
    assert "b.py" in rendered and first.reason in rendered and first.next_action in rendered


def test_complete_census_yields_no_failures_and_is_order_independent() -> None:
    specs = (_owned("owner-a", "a.py"), _owned("owner-b", "b.py"))
    assert ownership.completeness_failures(["a.py", "b.py"], specs) == ()
    forward = ownership.completeness_failures(["b.py", "c.py", "a.py"], specs[:1])
    backward = ownership.completeness_failures(["a.py", "c.py", "b.py"], reversed(specs[:1]))
    assert forward == backward
    assert _kinds(forward) == [(ownership.FAILURE_UNOWNED, "b.py"), (ownership.FAILURE_UNOWNED, "c.py")]


def test_generic_object_fallback_never_counts_as_ownership() -> None:
    failures = ownership.completeness_failures(
        ["a.py"], (_owned("generic-fallback", "a.py", kind="OBJECT"),)
    )
    assert _kinds(failures) == [(ownership.FAILURE_GENERIC_FALLBACK_ONLY, "a.py")]
    assert failures[0].fallback_owners == ("generic-fallback",)
    assert failures[0].owners == ()
    assert "generic-fallback" in failures[0].render()


def test_fallback_overlapping_a_specific_owner_is_a_duplicate_owner() -> None:
    failures = ownership.completeness_failures(
        ["a.py"],
        (_owned("generic-fallback", "a.py", kind="OBJECT"), _owned("owner-a", "a.py")),
    )
    assert _kinds(failures) == [(ownership.FAILURE_DUPLICATE_OWNER, "a.py")]
    assert failures[0].owners == ("owner-a",)
    assert failures[0].fallback_owners == ("generic-fallback",)


def test_duplicate_specific_owners_are_each_named() -> None:
    failures = ownership.completeness_failures(
        ["a.py"], (_owned("owner-z", "a.py"), _owned("owner-b", "a.py"))
    )
    assert _kinds(failures) == [(ownership.FAILURE_DUPLICATE_OWNER, "a.py")]
    assert failures[0].owners == ("owner-b", "owner-z")


def test_owned_path_absent_from_census_is_a_missing_owned_path() -> None:
    failures = ownership.completeness_failures(
        ["a.py"], (_owned("owner-a", "a.py"), _owned("owner-gone", "gone.py"))
    )
    assert _kinds(failures) == [(ownership.FAILURE_MISSING_OWNED_PATH, "gone.py")]
    assert failures[0].owners == ("owner-gone",)


def test_manifest_is_excluded_only_when_it_is_explicitly_the_manifest_path() -> None:
    specs = (_owned("owner-a", "a.py"),)
    assert _kinds(ownership.completeness_failures(["a.py", MANIFEST], specs)) == [
        (ownership.FAILURE_UNOWNED, MANIFEST)
    ]
    assert ownership.completeness_failures(["a.py", MANIFEST], specs, manifest_path=MANIFEST) == ()


def test_manifest_path_claimed_by_a_spec_is_refused_as_self_ownership() -> None:
    failures = ownership.completeness_failures(
        ["a.py", MANIFEST],
        (_owned("owner-a", "a.py"), _owned("manifest-owner", MANIFEST)),
        manifest_path=MANIFEST,
    )
    assert _kinds(failures) == [(ownership.FAILURE_MANIFEST_SELF_OWNED, MANIFEST)]
    assert failures[0].owners == ("manifest-owner",)


@pytest.mark.parametrize(
    "name",
    [".pytest-tmp-run.log", "build/.pytest-tmp-run.log", "objects.vstd.bak", "src/objects.vstd"],
)
def test_no_pattern_or_lookalike_is_excluded_from_the_census(name: str) -> None:
    assert _kinds(ownership.completeness_failures([name], (), manifest_path=MANIFEST)) == [
        (ownership.FAILURE_UNOWNED, name)
    ]


@pytest.mark.parametrize(
    "census",
    [
        ["", "a.py"],
        [" a.py"],
        ["a.py "],
        ["/abs/a.py"],
        ["C:" "/x.py"],
        ["..\\x.py"],
        ["../x.py"],
        ["a/../b.py"],
        ["./a.py"],
        ["a//b.py"],
        ["src/*.py"],
        ["src/**"],
        ["src/?.py"],
        ["src/[ab].py"],
        ["src/{a,b}.py"],
        ["a\nb.py"],
        ["a\x00b.py"],
        [42],
        [None],
        [b"a.py"],
    ],
)
def test_malformed_or_broad_census_entries_are_refused(census: list[object]) -> None:
    with pytest.raises(ValueError):
        ownership.completeness_failures(census, ())  # type: ignore[arg-type]


def test_census_supplied_as_a_bare_string_is_refused() -> None:
    with pytest.raises(ValueError):
        ownership.completeness_failures("a.py", ())  # type: ignore[arg-type]


def test_duplicate_census_entries_are_refused() -> None:
    with pytest.raises(ValueError):
        ownership.completeness_failures(["a.py", "b.py", "a.py"], (_owned("owner-a", "a.py"),))


@pytest.mark.parametrize("manifest", ["../objects.vstd", "*.vstd", "/objects.vstd", "", "a\\b"])
def test_malformed_manifest_path_is_refused(manifest: str) -> None:
    with pytest.raises(ValueError):
        ownership.completeness_failures(["a.py"], (), manifest_path=manifest)


@pytest.mark.parametrize(
    "owned",
    [("../a.py",), ("src/*.py",), ("/a.py",), ("a.py", "a.py"), ("a.py", "./b.py")],
)
def test_malformed_or_broad_owned_paths_are_refused(owned: tuple[str, ...]) -> None:
    spec = replace(_owned("owner-a", "a.py"), owned_paths=owned)
    with pytest.raises(ValueError):
        ownership.completeness_failures(["a.py"], (spec,))


def test_duplicate_spec_object_ids_and_foreign_objects_are_refused() -> None:
    with pytest.raises(ValueError):
        ownership.completeness_failures(
            ["a.py"], (_owned("owner-a", "a.py"), _owned("owner-a", "b.py"))
        )
    with pytest.raises(ValueError):
        ownership.completeness_failures(["a.py"], ({"object_id": "owner-a"},))  # type: ignore[arg-type]


def test_failures_are_frozen_typed_and_sorted_by_path_then_kind() -> None:
    failures = ownership.completeness_failures(
        ["z.py", "m.py"],
        (_owned("generic-fallback", "m.py", kind="OBJECT"),),
    )
    assert [(item.path, item.kind) for item in failures] == [
        ("m.py", ownership.FAILURE_GENERIC_FALLBACK_ONLY),
        ("z.py", ownership.FAILURE_UNOWNED),
    ]
    with pytest.raises(Exception):
        failures[0].path = "other.py"  # type: ignore[misc]


def test_completeness_is_pure_and_touches_no_filesystem_or_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("pure completeness must not touch the filesystem or processes")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    failures = ownership.completeness_failures(["a.py", "b.py"], (_owned("owner-a", "a.py"),))
    assert _kinds(failures) == [(ownership.FAILURE_UNOWNED, "b.py")]


def test_live_census_source_matches_polish_zero_discovery() -> None:
    from verifier.runtime import self_polish_estate

    census = self_polish_estate.capture_candidate_source_census(ROOT)
    paths = [entry["path"] for entry in census["files"]]
    assert len(paths) == len(set(paths))
    assert {entry["provenance"] for entry in census["files"]} <= {
        "GIT_TRACKED",
        "WORKTREE_UNTRACKED_NONIGNORED",
    }
    assert MANIFEST in paths


def test_live_census_is_fully_semantically_owned_with_only_the_manifest_excluded() -> None:
    from verifier.runtime import self_polish_estate

    census = self_polish_estate.capture_candidate_source_census(ROOT)
    paths = [entry["path"] for entry in census["files"]]
    failures = ownership.completeness_failures(
        paths, SEMANTIC_OWNERSHIP_SPECS, manifest_path=MANIFEST
    )
    assert not failures, (
        f"{len(failures)} census paths lack a specific semantic owner:\n"
        + "\n".join(item.render() for item in failures)
    )


# The observer's fsmonitor claim is source-bound: only the mutable worktree-state
# capture (self_polish_estate.py's Git helper) disables repository-configured
# fsmonitor.  The read-only object-database helpers assert neither index refresh
# nor fsmonitor behavior, so they must not be described as disabling it.
OBSERVER_ID = "vstd-source-provenance-observer"
OBSERVER_MODULES = ("explanation_projection.py", "prdel.py", "self_polish_estate.py")
CAPTURE_PHRASE = "mutable worktree-state capture"
HELPER_DISCLAIMER = "assert neither index refresh nor fsmonitor behavior"


def _observer_spec():
    return next(item for item in SEMANTIC_OWNERSHIP_SPECS if item.object_id == OBSERVER_ID)


def _clauses(text: str) -> list[str]:
    return text.replace(". ", "; ").split("; ")


def _unscoped_fsmonitor_clauses(text: str) -> list[str]:
    """Clauses claiming fsmonitor behavior without naming the mutable capture."""
    return [
        clause
        for clause in _clauses(text)
        if "fsmonitor" in clause
        and CAPTURE_PHRASE not in clause
        and HELPER_DISCLAIMER not in clause
    ]


def _capture_sites_named(text: str) -> set[str]:
    return {
        name
        for clause in _clauses(text)
        if CAPTURE_PHRASE in clause
        for name in OBSERVER_MODULES
        if name in clause
    }


def _disabling_sites() -> set[str]:
    source_dir = ROOT / "src" / "verifier" / "runtime"
    return {
        name
        for name in OBSERVER_MODULES
        if "core.fsmonitor=false" in (source_dir / name).read_text(encoding="utf-8")
    }


def test_observer_declaration_scopes_fsmonitor_disabling_to_the_mutable_capture() -> None:
    boundary = _observer_spec().consequence_boundary
    assert _unscoped_fsmonitor_clauses(boundary) == []


def test_declared_capture_site_is_the_only_source_site_that_disables_fsmonitor() -> None:
    assert _disabling_sites() == {"self_polish_estate.py"}
    assert _capture_sites_named(_observer_spec().consequence_boundary) == _disabling_sites()


def test_substituting_the_capture_site_with_a_helper_is_refuted() -> None:
    substituted = _observer_spec().consequence_boundary.replace(
        "self_polish_estate.py", "prdel.py"
    )
    assert _capture_sites_named(substituted) != _disabling_sites()


@pytest.mark.parametrize(
    "rebroadened_claim",
    [
        "All observer Git queries run with repository-configured fsmonitor disabled.",
        "The observer disables repository-configured fsmonitor execution.",
        "Read-only object-database helpers run with repository-configured fsmonitor disabled.",
        "Fixed Git observation runs with repository-configured fsmonitor disabled.",
    ],
)
def test_rebroadened_fsmonitor_claims_are_rejected(rebroadened_claim: str) -> None:
    rebroadened = _observer_spec().consequence_boundary + " " + rebroadened_claim
    assert _unscoped_fsmonitor_clauses(rebroadened) != []


def test_actuator_stays_retired_from_the_observer_declaration() -> None:
    assert _observer_spec().specializations == ("MEASUREMENT", "PROTOCOL", "TRANSACTION")
    assert "ACTUATOR" not in _observer_spec().specializations
