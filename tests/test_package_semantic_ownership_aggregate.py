"""Fail-closed aggregation contracts for standalone semantic ownership audits."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from verifier.runtime import package_api_surface_admission as api_admission
from verifier.runtime import package_semantic_ownership as central
from verifier.runtime import package_semantic_ownership_current_untracked as current
from verifier.runtime import package_semantic_ownership_domains_agency_collective as agency
from verifier.runtime import package_semantic_ownership_domains_context as context
from verifier.runtime import package_semantic_ownership_domains_sim_model as sim_model
from verifier.runtime import package_semantic_ownership_domains_systems as systems
from verifier.runtime import self_polish_estate
from verifier.runtime.package_semantic_ownership_model import ownership_spec


ROOT = Path(__file__).resolve().parents[1]

RUNTIME_SELF_HOSTING = {
    "src/verifier/runtime/package_semantic_ownership_current_untracked.py",
    "src/verifier/runtime/package_semantic_ownership_domains_agency_collective.py",
    "src/verifier/runtime/package_semantic_ownership_domains_context.py",
    "src/verifier/runtime/package_semantic_ownership_domains_sim_model.py",
    "src/verifier/runtime/package_semantic_ownership_domains_systems.py",
}
API_SELF_HOSTING = {"src/verifier/runtime/package_api_surface_admission.py"}
TEST_SELF_HOSTING = {
    "tests/test_package_api_surface_admission.py",
    "tests/test_package_semantic_ownership_aggregate.py",
    "tests/test_package_semantic_ownership_current_untracked.py",
    "tests/test_package_semantic_ownership_domains_agency_collective.py",
    "tests/test_package_semantic_ownership_domains_context.py",
    "tests/test_package_semantic_ownership_domains_sim_model.py",
    "tests/test_package_semantic_ownership_domains_systems.py",
}
DOCS_WITH_UNKNOWN_PRIMARY = {
    "docs/assets/vstd-overview.png",
    "docs/guides.html",
    "docs/index.html",
    "docs/reference.html",
}


def _by_id():
    return {spec.object_id: spec for spec in central.SEMANTIC_OWNERSHIP_SPECS}


def _aggregate_by_id():
    return {
        spec.object_id: spec
        for spec in central.AGGREGATED_SEMANTIC_OWNERSHIP_SPECS
    }


def _finding_codes(findings):
    return {finding.code for finding in findings}


def test_self_hosting_paths_use_the_three_existing_exact_owners() -> None:
    by_id = _aggregate_by_id()
    assert RUNTIME_SELF_HOSTING <= set(
        by_id["vstd-package-semantic-ownership-policy"].owned_paths
    )
    assert API_SELF_HOSTING <= set(
        by_id["vstd-package-semantic-review-policy"].owned_paths
    )
    assert TEST_SELF_HOSTING <= set(
        by_id["vstd-test-namespace-admission-regressions"].owned_paths
    )


def test_batch_statuses_accept_ready_system_and_agency_rows() -> None:
    statuses = {item.name: item for item in central.AGGREGATE_BATCH_STATUSES}
    assert set(statuses) == {
        "context",
        "agency_collective",
        "sim_model",
        "systems",
        "current_untracked",
    }
    assert statuses["context"].counts == (10, 0, 10)
    assert statuses["agency_collective"].counts == (7, 7, 0)
    assert statuses["sim_model"].counts == (26, 0, 26)
    assert statuses["systems"].counts == (47, 43, 4)
    assert statuses["current_untracked"].counts == (10, 0, 10)
    assert statuses["systems"].state == "PARTIAL"
    assert statuses["agency_collective"].state == "ACCEPTED"
    assert all(statuses[name].state == "BLOCKED" for name in (
        "context", "sim_model", "current_untracked",
    ))

    normative_ids = set(_by_id())
    aggregate_ids = set(_aggregate_by_id())
    accepted_system_ids = set(statuses["systems"].accepted_object_ids)
    accepted_agency_ids = set(statuses["agency_collective"].accepted_object_ids)
    assert accepted_system_ids <= aggregate_ids
    assert accepted_agency_ids <= aggregate_ids
    assert normative_ids.isdisjoint(accepted_system_ids)
    for name in ("context", "sim_model", "current_untracked"):
        assert aggregate_ids.isdisjoint(statuses[name].candidate_object_ids)
    assert aggregate_ids.isdisjoint(statuses["systems"].blocked_object_ids)


def test_all_unresolved_and_blocker_sidecars_remain_typed_and_visible() -> None:
    unresolved = dict(central.AGGREGATE_UNRESOLVED_SIDECARS)
    blockers = dict(central.AGGREGATE_BLOCKER_SIDECARS)

    assert unresolved["context"] == context.unknown_decisions()
    assert unresolved["agency_collective"] == agency.unresolved_records()
    assert unresolved["systems"] == systems.UNRESOLVED_RECORDS
    current_unknown = tuple(
        record
        for spec in current.CURRENT_UNTRACKED_OWNERSHIP_SPECS
        for record in current.applicability_records(spec)
        if record.status == "UNKNOWN"
    )
    assert unresolved["current_untracked"] == current_unknown
    assert {name: len(rows) for name, rows in unresolved.items()} == {
        "context": 2,
        "agency_collective": 0,
        "systems": 22,
        "current_untracked": 338,
    }
    assert all(
        getattr(record, "status", "UNKNOWN") == "UNKNOWN"
        and type(record).__name__ in {
            "SourceRoleDecision",
            "SourceRoleUnresolved",
            "UnresolvedRecord",
            "ApplicabilityRecord",
        }
        for rows in unresolved.values()
        for record in rows
    )

    assert blockers["context"] == context.aggregation_blockers()
    assert blockers["agency_collective"] == agency.integration_blockers()
    assert blockers["sim_model"] == sim_model.INTEGRATION_BLOCKERS
    assert blockers["systems"] == systems.INTEGRATION_BLOCKERS
    assert blockers["current_untracked"] == current.INTEGRATION_BLOCKERS
    assert {name: len(rows) for name, rows in blockers.items()} == {
        "context": 4,
        "agency_collective": 0,
        "sim_model": 128,
        "systems": 16,
        "current_untracked": 3,
    }


def test_live_census_is_reduced_only_by_explicitly_accepted_rows() -> None:
    census = self_polish_estate.capture_candidate_source_census(ROOT)
    paths = tuple(
        row["path"] if isinstance(row, dict) else row.path for row in census["files"]
    )
    failures = central.completeness_failures(
        paths,
        central.AGGREGATED_SEMANTIC_OWNERSHIP_SPECS,
        manifest_path="objects.vstd",
    )
    assert {failure.kind for failure in failures} == {central.FAILURE_UNOWNED}

    statuses = {item.name: item for item in central.AGGREGATE_BATCH_STATUSES}
    blocked_ids = {
        object_id
        for item in statuses.values()
        for object_id in item.blocked_object_ids
    }
    blocked_specs = tuple(
        spec
        for batch in (
            context.DOMAIN_CONTEXT_OWNERSHIP_SPECS,
            agency.SEMANTIC_OWNERSHIP_SPECS,
            sim_model.SIM_MODEL_OWNERSHIP_SPECS,
            systems.DOMAIN_SYSTEMS_OWNERSHIP_SPECS,
            current.CURRENT_UNTRACKED_OWNERSHIP_SPECS,
        )
        for spec in batch
        if spec.object_id in blocked_ids
    )
    expected = DOCS_WITH_UNKNOWN_PRIMARY | {
        path for spec in blocked_specs for path in spec.owned_paths
    }
    assert {failure.path for failure in failures} == expected
    assert len(expected) == 110


def _row(object_id: str, kind: str, *, operands=()):
    return ownership_spec(
        object_id,
        kind,
        (f"tmp/{object_id}.py",),
        "Synthetic aggregate validation row.",
        "The focused test needs one explicit owner.",
        "No production claim.",
        operands=operands,
    )


def test_aggregate_operand_validation_accepts_exact_targets() -> None:
    data = _row("test-data", "DATA")
    hardware = _row("test-hardware", "HARDWARE")
    receipt = _row(
        "test-receipt",
        "RECEIPT",
        operands=(("hardware", (hardware.object_id,)), ("subject", (data.object_id,))),
    )
    assert central.aggregate_operand_findings((data, hardware, receipt)) == ()


def test_current_aggregate_exposes_exact_unresolved_operand_targets() -> None:
    findings = central.aggregate_operand_findings()
    assert {
        (finding.code, finding.object_id, finding.operand_role, finding.target_id)
        for finding in findings
    } == {
        (
            "OPERAND_TARGET_MISSING",
            "vstd-package-worker-dependency-relation",
            "dependents",
            "vstd-manifest-write",
        ),
    }


def test_aggregate_operand_validation_refuses_missing_wrong_and_invented_targets() -> None:
    data = _row("test-data", "DATA")
    missing = _row(
        "test-missing-receipt",
        "RECEIPT",
        operands=(("hardware", ("test-absent",)), ("subject", (data.object_id,))),
    )
    wrong = _row(
        "test-wrong-receipt",
        "RECEIPT",
        operands=(("hardware", (data.object_id,)), ("subject", (data.object_id,))),
    )
    invented_target = _row("test-invented-hardware", "HARDWARE")
    invented = _row(
        "test-invented-receipt",
        "RECEIPT",
        operands=(("hardware", (invented_target.object_id,)), ("subject", (data.object_id,))),
    )
    assert "OPERAND_TARGET_MISSING" in _finding_codes(
        central.aggregate_operand_findings((data, missing))
    )
    assert "OPERAND_TARGET_KIND_DIFFERS" in _finding_codes(
        central.aggregate_operand_findings((data, wrong))
    )
    assert "OPERAND_TARGET_INVENTED" in _finding_codes(
        central.aggregate_operand_findings((data, invented_target, invented))
    )


def test_aggregate_operand_validation_refuses_duplicate_targets_and_target_owners() -> None:
    data = _row("test-data", "DATA")
    hardware = _row("test-hardware", "HARDWARE")
    duplicate_target = _row(
        "test-duplicate-receipt",
        "RECEIPT",
        operands=(
            ("hardware", (hardware.object_id, hardware.object_id)),
            ("subject", (data.object_id,)),
        ),
    )
    assert "OPERAND_TARGET_DUPLICATED" in _finding_codes(
        central.aggregate_operand_findings((data, hardware, duplicate_target))
    )
    assert "OPERAND_TARGET_OWNER_DUPLICATED" in _finding_codes(
        central.aggregate_operand_findings((data, hardware, replace(hardware)))
    )


def test_aggregate_operand_validation_refuses_cycles() -> None:
    left = _row(
        "test-left",
        "HYPER",
        operands=(("relation", ("test-right",)),),
    )
    right = _row(
        "test-right",
        "HYPER",
        operands=(("relation", ("test-left",)),),
    )
    findings = central.aggregate_operand_findings((left, right))
    assert {finding.object_id for finding in findings if finding.code == "OPERAND_CYCLE"} == {
        "test-left",
        "test-right",
    }


def test_omitted_required_operands_are_unknown_blockers_not_non_applicability() -> None:
    bench = _row("test-bench", "BENCH")
    findings = central.aggregate_operand_findings((bench,))
    unbound = [finding for finding in findings if finding.code == "OPERAND_UNBOUND"]
    assert {(finding.operand_role, finding.required_kinds) for finding in unbound} == {
        ("data", ("DATA",)),
        ("verifier", ("VERIFIER",)),
    }
    assert all("UNKNOWN" in finding.reason for finding in unbound)
    assert all(finding.code != "DOES_NOT_APPLY" for finding in findings)


def test_api_rows_are_cross_checked_as_an_overlay_not_concatenated() -> None:
    assert central.api_surface_overlay_findings() == ()
    api_ids = {owner.owner_id for owner in api_admission.ADMITTED}
    assert len(api_ids & set(_by_id())) == len(api_ids)
    assert sum(spec.object_id in api_ids for spec in central.SEMANTIC_OWNERSHIP_SPECS) == len(api_ids)

    forged = tuple(
        replace(owner, primary_kind="DATA")
        if owner.owner_id == "vstd-consent-package-api"
        else owner
        for owner in api_admission.ADMITTED
    )
    assert "API_OWNER_KIND_DIFFERS" in _finding_codes(
        central.api_surface_overlay_findings(admitted=forged)
    )
