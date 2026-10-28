"""Verifier Standard (VSTD) root-command package selection regressions.

Terminology: identifier (ID).
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from verifier.runtime import core_obligation_union as binding
from verifier.runtime import manifest_gate
from verifier.runtime import namespace_contracts
from verifier.runtime import package_manifest_refresh
from verifier.runtime import package_polish as package
from verifier.runtime import package_polish_schema_validation
from verifier.runtime.public_cli import main


def test_next_target_selects_exact_lowest_tier_example() -> None:
    findings = [
        {
            "status": "UNKNOWN",
            "code": "NAMESPACE_CLASSIFICATION_UNRESOLVED",
            "gate_id": "namespace-admission",
            "reason": "A grouped namespace decision remains unresolved.",
            "explanation": (
                "ACTOR: Provide a repository-specific reason and current "
                "source evidence."
            ),
            "next_action": "Review the exact object's ACTOR classification.",
            "rerun_argv": ["vstd", "polish3", "--manifest", "objects.vstd"],
            "object_id": None,
            "obligation_id": None,
            "examples": [
                {
                    "object_id": "verifier-core-self",
                    "obligation_id": "VSTD-T0.2-namespace-admission",
                    "rerun_argv": [
                        "vstd", "gate", "--object", "verifier-core-self",
                        "--obligation", "VSTD-T0.2-namespace-admission",
                    ],
                }
            ],
        },
        {
            "status": "FAIL",
            "code": "TIER_TWO_FAILURE",
            "gate_id": "tier-two",
            "reason": "A later tier is refuted.",
            "explanation": "A later tier is refuted.",
            "next_action": "Repair the later tier.",
            "object_id": "later-object",
            "obligation_id": "later-tier-2",
            "rerun_argv": [
                "vstd", "gate", "--object", "later-object",
                "--obligation", "later-tier-2",
            ],
        },
    ]

    target = package._package_next_target(findings, 3)

    assert target is not None
    assert target["source_path"] == "objects.vstd"
    assert target["requested_tier"] == 3
    assert target["obligation_tier"] == 0
    assert target["status"] == "UNKNOWN"
    assert target["object_id"] == "verifier-core-self"
    assert target["obligation_id"] == "VSTD-T0.2-namespace-admission"
    assert target["focus"] == "ACTOR"
    assert target["finding_index"] == 0
    assert target["example_index"] == 0
    assert target["rerun_argv"] == [
        "vstd", "gate", "--object", "verifier-core-self",
        "--obligation", "VSTD-T0.2-namespace-admission",
    ]


def test_next_target_requires_an_exact_gate_coordinate() -> None:
    assert package._package_next_target(
        [
            {
                "status": "UNKNOWN",
                "code": "GROUPED_ONLY",
                "gate_id": "group",
                "reason": "No exact object is retained.",
                "explanation": "No exact object is retained.",
                "next_action": "Retain an exact example.",
                "object_id": None,
                "obligation_id": None,
                "rerun_argv": ["vstd", "polish3"],
            }
        ],
        3,
    ) is None

ROOT = Path(__file__).resolve().parents[1]
PIN = "sha256:" + "a" * 64


def test_v5_graph_report_references_the_exact_declaration_denominator() -> None:
    rows = [{"object_id": "one"}, {"object_id": "two"}]
    manifest = {"objects": [{"object_id": "retained"}]}
    ordinary = {
        "schema_version": package.package_manifest.SCHEMA,
        "namespace": {"objects": rows},
    }
    v5 = {
        "schema_version": package.package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
        "namespace": {"objects": rows},
    }

    assert package._graph_declaration_profile(ordinary, manifest) == {
        "declarations": rows
    }
    assert package._graph_declaration_profile(v5, manifest) == {
        "declaration_count": 2,
        "declaration_digest": binding.value_digest(rows),
        "object_payloads_transport": "MANIFEST_DIGEST_BOUND_REFERENCES",
        "object_payloads_claim": (
            "Every object ID, kind and operand edge remains inline. Each repeated "
            "payload is replaced only in this report by its exact byte digest and "
            "length; the selected root objects.vstd at manifest_digest is the "
            "authoritative payload transport."
        ),
    }


def test_v5_graph_report_retains_topology_and_binds_repeated_payloads() -> None:
    item = package.namespace.NamespaceObject.create(
        "subject", "OBJECT", {"large": "evidence" * 1024},
        operands={"depends_on": ["root"]},
    )
    document = {
        "schema_version": package.package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
    }

    [profile] = package._graph_object_profile((item,), document)

    assert profile["object_id"] == "subject"
    assert profile["kind"] == "OBJECT"
    assert profile["object_digest"] == item.digest
    assert profile["operands"] == {"depends_on": ["root"]}
    assert profile["payload"] == {
        "schema_version": "verifier-namespace-payload-reference-1",
        "payload_digest": binding.bytes_digest(item.payload_bytes),
        "payload_bytes": len(item.payload_bytes),
        "transport": "SELECTED_ROOT_OBJECTS_VSTD",
    }
    assert "large" not in json.dumps(profile)


def test_native_diagnostic_reference_binds_full_reports_without_repeating_ledgers() -> None:
    zero_obligations = [
        {
            "coordinate": f"VSTD-T0.{index}",
            "status": "PASS",
            "assessment_reason": "source-bound diagnostic detail " * 128,
        }
        for index in range(1, 10)
    ]
    zero_body = {
        "status": "PASS", "manifest_digest": PIN,
        "obligation_count": 9,
        "obligation_status_counts": {"PASS": 9, "FAIL": 0, "UNKNOWN": 0},
        "obligations": zero_obligations,
    }
    zero = {**zero_body, "report_digest": binding.value_digest(zero_body)}
    one_body = {
        "status": "PASS", "source_coordinate_digest": PIN,
        "post_replay_full_source_recapture": "PASS",
        "obligations": [{"coordinate": "OBJECT-1.1", "status": "PASS"}],
    }
    one = {**one_body, "report_digest": binding.value_digest(one_body)}
    two_body = {
        "status": "PASS", "source_coordinate_digest": PIN,
        "obligation_count": 4560,
        "obligation_status_counts": {"PASS": 4560},
        "post_replay_full_source_recapture": "PASS",
    }
    two = {**two_body, "report_digest": binding.value_digest(two_body)}
    execution = {
        str(tier): {
            "tier": tier,
            "tier_name": name,
            "execution_status": "EXECUTED",
            "status": "PASS",
            "evidence_digest": digest,
        }
        for tier, name, digest in (
            (0, "ADMISSION", zero["report_digest"]),
            (1, "FACETS", one["report_digest"]),
            (2, "DYNAMICS", two["report_digest"]),
            (3, "STATICS", PIN),
        )
    }
    body = {
        "status": "PASS", "claim_scope": "SOURCE_NATIVE_DIAGNOSTICS_NOT_PACKAGE_INSTANCES",
        "prerequisites": {"0": zero, "1": one, "2": two},
        "tier_execution": execution,
    }
    full = {**body, "report_digest": binding.value_digest(body)}

    reference = package._native_diagnostic_reference(full)

    assert reference["status"] == "PASS"
    assert reference["report_digest"] == full["report_digest"]
    assert reference["report_bytes"] == len(binding.canonical_bytes(full))
    assert reference["prerequisites"]["0"] == {
        "status": "PASS", "report_digest": zero["report_digest"],
        "manifest_digest": PIN, "obligation_count": 9,
        "obligation_status_counts": {"PASS": 9, "FAIL": 0, "UNKNOWN": 0},
        "obligations": zero_obligations,
    }
    assert reference["prerequisites"]["1"] == {
        "status": "PASS", "report_digest": one["report_digest"],
        "source_coordinate_digest": PIN,
        "post_replay_full_source_recapture": "PASS",
    }
    assert reference["prerequisites"]["2"] == {
        "status": "PASS", "report_digest": two["report_digest"],
        "source_coordinate_digest": PIN, "obligation_count": 4560,
        "obligation_status_counts": {"PASS": 4560},
        "post_replay_full_source_recapture": "PASS",
    }
    assert len(reference["prerequisites"]["0"]["obligations"]) == 9
    assert reference["prerequisites"]["0"]["obligations"][0]["coordinate"] == "VSTD-T0.1"
    assert set(reference["tier_execution"]) == {"0", "1", "2", "3"}
    assert reference["tier_execution"] == execution
    assert "obligations" not in reference["prerequisites"]["1"]
    assert reference["report_bytes"] == len(binding.canonical_bytes(full))


def test_native_diagnostic_reference_keeps_nonpass_lower_tier_detail() -> None:
    zero_body = {
        "status": "UNKNOWN", "manifest_digest": PIN,
        "blockers": ["TIER_ZERO_SOURCE_COVERAGE_NOT_ESTABLISHED"],
        "obligations": [{
            "coordinate": "VSTD-T0.1", "status": "UNKNOWN",
            "blockers": ["SOURCE_ROUTE_UNCOVERED"],
            "assessment_reason": "One exposed route is absent from objects.vstd.",
            "rerun_argv": [
                "vstd", "gate", "--object", "repository",
                "--obligation", "fixture-exposed-surface-route",
            ],
        }],
    }
    zero = {**zero_body, "report_digest": binding.value_digest(zero_body)}
    body = {
        "status": "UNKNOWN",
        "claim_scope": "SOURCE_NATIVE_DIAGNOSTICS_NOT_PACKAGE_INSTANCES",
        "blockers": ["TIER0_FRESH_PASS_REQUIRED"],
        "prerequisites": {"0": zero},
    }
    full = {**body, "report_digest": binding.value_digest(body)}

    reference = package._native_diagnostic_reference(full)

    assert reference["status"] == "UNKNOWN"
    zero_reference = reference["prerequisites"]["0"]
    assert zero_reference["status"] == "UNKNOWN"
    assert zero_reference["report_digest"] == zero["report_digest"]
    assert zero_reference["blockers"] == zero["blockers"]
    assert any(
        row.get("coordinate") == "VSTD-T0.1"
        and row["blockers"] == ["SOURCE_ROUTE_UNCOVERED"]
        and row["rerun_argv"] == [
            "vstd", "gate", "--object", "repository", "--obligation",
            "fixture-exposed-surface-route",
        ]
        for row in zero_reference["nonpass_records"]
    )
    assert reference["nonpass_detail"]["status"] == "UNKNOWN"
    assert reference["nonpass_detail"]["blockers"] == ["TIER0_FRESH_PASS_REQUIRED"]


def test_native_nonpass_records_ignore_expected_nested_control_outcomes() -> None:
    cases = [
        {
            "case_kind": case_kind,
            "expected_native_status": native_status,
            "native_status": native_status,
            "status": "PASS",
            "native_result": {
                "status": native_status,
                "reason": "The native checker produced the expected control outcome.",
            },
        }
        for case_kind, native_status in (
            ("POSITIVE", "PASS"),
            ("NEGATIVE", "FAIL"),
            ("UNKNOWN", "UNKNOWN"),
        )
    ]

    assert package._native_nonpass_records(
        {"status": "PASS", "cases": cases}, tier=3,
    ) == []


def test_native_nonpass_records_retain_actual_case_context_once() -> None:
    value = {
        "status": "FAIL",
        "cases": [{
            "case_kind": "POSITIVE",
            "expected_native_status": "PASS",
            "native_status": "FAIL",
            "status": "FAIL",
            "native_result": {
                "status": "FAIL",
                "reason": "The selected certificate violates the bound.",
                "details": {"constraint": "finite-bound", "observed": 2},
            },
        }],
    }

    records = package._native_nonpass_records(value, tier=3)
    case_records = [row for row in records if row.get("case_kind") == "POSITIVE"]

    assert len(case_records) == 1
    assert case_records[0]["expected_native_status"] == "PASS"
    assert case_records[0]["native_status"] == "FAIL"
    assert case_records[0]["reason"] == (
        "The selected certificate violates the bound."
    )
    assert case_records[0]["details"] == {
        "constraint": "finite-bound", "observed": 2,
    }
    assert not any(
        row["path"].endswith(".native_result") for row in records
    )


def test_native_nonpass_records_are_projected_to_exact_top_level_findings() -> None:
    nested = {
        "status": "FAIL",
        "object_id": "sim-production",
        "object_kind": "SIM",
        "obligation_id": "SIM-3.1-state-invariants",
        "coordinate": "SIM-3.1",
        "gate_id": "statics-invariant",
        "reason": "The state invariant was refuted.",
        "blockers": ["SIM_STATE_INVARIANT_REFUTED"],
        "cases": [{
            "case_kind": "POSITIVE",
            "expected_native_status": "PASS",
            "native_status": "FAIL",
            "status": "FAIL",
            "native_result": {
                "status": "FAIL",
                "reason": "Observed state violates the declared invariant.",
                "details": {"step": 7},
            },
        }],
    }
    native_body = {
        "schema_version": "verifier-self-polish-statics-report-1",
        "tier": 3,
        "requested_tier": 3,
        "status": "FAIL",
        "selected_tier_status": "FAIL",
        "selected_depth": 2,
        "blockers": ["SIM_STATE_INVARIANT_REFUTED"],
        "source_coordinate_digest": PIN,
        "post_replay_full_source_recapture": "PASS",
        "prerequisites": {},
        "tier_execution": {},
        "complete_tier_evidence_replay": nested,
        "claim_scope": "SOURCE_BOUND_TIER3_NATIVE_STATICS",
    }
    native = {
        **native_body, "report_digest": binding.value_digest(native_body),
    }
    reference = package._native_diagnostic_reference(native)
    reference["prerequisites"]["1"] = {
        "status": "FAIL",
        "report_digest": PIN,
        "nonpass_records": [{
            "path": "$.prerequisites.1.obligations[4]",
            "status": "FAIL",
            "object_id": "policy-runtime",
            "object_kind": "POLICY",
            "obligation_id": "POLICY-1.2-rule-precedence",
            "coordinate": "POLICY-1.2",
            "gate_id": "facets-precedence",
            "reason": "Declared policy precedence was contradicted.",
            "blockers": ["POLICY_PRECEDENCE_REFUTED"],
            "rerun_argv": [
                "vstd", "gate", "--object", "policy-runtime",
                "--obligation", "POLICY-1.2-rule-precedence",
            ],
        }],
    }
    # Repeated transport rows must not duplicate the exact same locus.
    reference["nonpass_detail"]["nonpass_records"].append(
        deepcopy(reference["nonpass_detail"]["nonpass_records"][0])
    )
    findings = manifest_gate.package_findings({
        "status": "FAIL",
        "obligation_instances": [],
        "kind_requirements": {},
        "blockers": ["PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS"],
        "native_diagnostics": reference,
    })

    located = [
        finding for finding in findings
        if finding.get("object_id") == "sim-production"
        and finding.get("obligation_id") == "SIM-3.1-state-invariants"
    ]
    assert {finding["diagnostic_path"] for finding in located} == {
        "$.complete_tier_evidence_replay",
        "$.complete_tier_evidence_replay.cases[0]",
    }
    assert all(
        finding["object_kind"] == "SIM"
        and finding["coordinate"] == "SIM-3.1"
        and finding["gate_id"] == "statics-invariant"
        and finding["reason"].strip()
        and finding["rerun_argv"] == [
            "vstd", "gate", "--object", "sim-production",
            "--obligation", "SIM-3.1-state-invariants",
        ]
        for finding in located
    )
    assert sum(
        finding["diagnostic_path"]
        == "$.complete_tier_evidence_replay"
        for finding in located
    ) == 1
    assert any(
        finding["code"] == "PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS"
        and finding["object_id"] is None
        for finding in findings
    )
    [prerequisite_finding] = [
        finding for finding in findings
        if finding.get("object_id") == "policy-runtime"
    ]
    assert prerequisite_finding["diagnostic_path"] == (
        "$.prerequisites.1.obligations[4]"
    )
    assert prerequisite_finding["rerun_argv"] == [
        "vstd", "gate", "--object", "policy-runtime",
        "--obligation", "POLICY-1.2-rule-precedence",
    ]


def test_native_diagnostic_reference_keeps_exception_closed_tier_denominator() -> None:
    blocking = {
        "tier": 0,
        "tier_name": "ADMISSION",
        "required_status": "PASS",
        "observed_status": "UNKNOWN",
        "report_digest": None,
        "blockers": ["STATICS_ASSESSMENT_UNEXPECTED_EXCEPTION"],
        "failure_stage": "TIER0_ADMISSION_ASSESSMENT",
        "exception_type": "SyntheticUnexpected",
    }
    execution = {
        str(tier): {
            "tier": tier,
            "tier_name": name,
            "execution_status": "NOT_RUN",
            "status": "UNKNOWN",
            "reason": "No admissible prerequisite receipt was produced.",
            "evidence_digest": None,
            "blocking_prerequisite": blocking,
        }
        for tier, name in (
            (0, "ADMISSION"),
            (1, "FACETS"),
            (2, "DYNAMICS"),
            (3, "STATICS"),
        )
    }
    body = {
        "status": "FAIL",
        "claim_scope": "SOURCE_BOUND_TIER3_NATIVE_STATICS",
        "blockers": ["STATICS_ASSESSMENT_UNEXPECTED_EXCEPTION"],
        "prerequisites": {},
        "tier_execution": execution,
    }
    full = {**body, "report_digest": binding.value_digest(body)}

    reference = package._native_diagnostic_reference(full)

    assert reference["status"] == "FAIL"
    assert reference["prerequisites"] == {}
    assert reference["tier_execution"] == execution
    assert set(reference["tier_execution"]) == {"0", "1", "2", "3"}
    assert all(
        row["execution_status"] == "NOT_RUN"
        and row["status"] == "UNKNOWN"
        and row["blocking_prerequisite"] == blocking
        for row in reference["tier_execution"].values()
    )


@pytest.mark.parametrize("requested_tier", [1, 2])
def test_lower_native_diagnostics_emit_exact_sealed_execution_prefix(
    monkeypatch: pytest.MonkeyPatch,
    requested_tier: int,
) -> None:
    def sealed(body: dict) -> dict:
        return {**body, "report_digest": binding.value_digest(body)}

    zero = sealed({"status": "PASS", "blockers": []})
    monkeypatch.setattr(package.tier_zero, "assess_tier_zero", lambda _root: zero)

    def assess(depth: int, **_kwargs: object) -> dict:
        return sealed({"status": "PASS", "tier": depth, "blockers": []})

    monkeypatch.setattr(
        package.self_polish_tiers, "assess_self_polish_tier", assess,
    )

    report = package._run_native_diagnostics(requested_tier, ROOT)

    assert set(report["prerequisites"]) == {
        str(depth) for depth in range(requested_tier + 1)
    }
    assert set(report["tier_execution"]) == {
        str(depth) for depth in range(requested_tier + 1)
    }
    for depth in range(requested_tier + 1):
        record = report["tier_execution"][str(depth)]
        assert record["execution_status"] == "EXECUTED"
        assert record["status"] == "PASS"
        assert record["evidence_digest"] == report["prerequisites"][str(depth)][
            "report_digest"
        ]
        assert record["execution_record_digest"] == binding.value_digest({
            key: value for key, value in record.items()
            if key != "execution_record_digest"
        })


def test_lower_native_diagnostics_stop_after_first_nonpass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def sealed(body: dict) -> dict:
        return {**body, "report_digest": binding.value_digest(body)}

    zero = sealed({"status": "PASS", "blockers": []})
    one = sealed({"status": "FAIL", "blockers": ["SYNTHETIC_FACETS_FAILURE"]})
    calls: list[int] = []
    monkeypatch.setattr(package.tier_zero, "assess_tier_zero", lambda _root: zero)

    def assess(depth: int, **_kwargs: object) -> dict:
        calls.append(depth)
        assert depth == 1
        return one

    monkeypatch.setattr(
        package.self_polish_tiers, "assess_self_polish_tier", assess,
    )

    report = package._run_native_diagnostics(2, ROOT)

    assert calls == [1]
    assert report["status"] == "FAIL"
    assert set(report["prerequisites"]) == {"0", "1"}
    assert report["tier_execution"]["1"]["execution_status"] == "EXECUTED"
    skipped = report["tier_execution"]["2"]
    assert skipped["execution_status"] == "NOT_RUN"
    assert skipped["status"] == "UNKNOWN"
    assert skipped["evidence_digest"] is None
    assert skipped["blocking_prerequisite"] == {
        "tier": 1,
        "tier_name": "FACETS",
        "required_status": "PASS",
        "observed_status": "FAIL",
        "report_digest": one["report_digest"],
        "blockers": ["SYNTHETIC_FACETS_FAILURE"],
    }


def test_large_successful_check_reference_preserves_conditional_semantics() -> None:
    check = {
        "status": "PASS",
        "applicability_established": True,
        "fulfillment_required": False,
        "condition_status": "NOT_TRIGGERED",
        "reason": "The runtime-only variant is not selected by this source object.",
        "evidence": ["current-source-binding"] * 256,
    }

    reference = package._selected_check_reference(check)

    assert reference["status"] == "PASS"
    assert reference["fulfillment_required"] is False
    assert reference["condition_status"] == "NOT_TRIGGERED"
    assert reference["reason"] == check["reason"]
    assert reference["full_check_digest"] == binding.value_digest(check)
    assert len(binding.canonical_bytes(reference)) < len(binding.canonical_bytes(check))


def test_early_check_reference_retains_exact_conditional_route_binding() -> None:
    route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "OBJECT-1.2"
    )
    check_body = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
        "object_id": "source-object",
        "object_digest": PIN,
        "collection_digest": "sha256:" + "b" * 64,
        "applicability_established": True,
        "applicability_classification": "CONDITION_NOT_MET",
        "fulfillment_required": False,
        "native_coordinate": route["coordinate"],
        "conditional_coordinate": route["coordinate"],
        "adaptation_obligation_id": (
            "OBJECT-1.90-source-representation-facets"
        ),
        "adaptation_result_digest": "sha256:" + "c" * 64,
        "condition": route["applicability"]["condition"],
        "applicability_digest": route["applicability_digest"],
        "condition_status": "NOT_TRIGGERED",
        "reason": "The exact source representation does not select this variant.",
        "large_observation": "current-source" * 512,
    }
    check = {
        **check_body,
        "result_digest": binding.value_digest(check_body),
    }
    # Early transport compaction now leaves conditional rows complete (see
    # test_conditional_refutation_ledger_survives_early_check_compaction), so
    # the reference semantics are exercised through the builder directly.
    reference = package._selected_check_reference(check)
    assert reference["full_check_digest"] == binding.value_digest(check)
    assert reference["result_digest"] == binding.value_digest({
        key: value for key, value in reference.items()
        if key != "result_digest"
    })
    assert package._conditional_refutation_matches_route(route, reference)


def test_repository_realization_reference_keeps_reason_and_semantic_binding() -> None:
    realization = {
        "class": "DIRECT",
        "explanation": "The installed source implements the exact bounded route.",
        "adaptation_necessity": None,
        "obligation_semantic_digest": PIN,
        "mechanism_bindings": [{"source": "bound.py"}] * 128,
        "falsifiers": ["Any selected source change refutes this binding."] * 128,
    }

    reference = package._repository_realization_reference(realization)

    assert reference["class"] == "DIRECT"
    assert reference["explanation"] == realization["explanation"]
    assert reference["obligation_semantic_digest"] == PIN
    assert reference["full_realization_digest"] == binding.value_digest(realization)
    assert len(binding.canonical_bytes(reference)) < len(binding.canonical_bytes(realization))


def test_forced_row_projection_does_not_rebind_compacted_conditional_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
        "applicability_established": True,
        "applicability_classification": "CONDITION_NOT_MET",
        "fulfillment_required": False,
        "native_coordinate": "OBJECT-1.1",
        "conditional_coordinate": "OBJECT-1.1",
        "adaptation_obligation_id": "object-conditional-variant",
        "adaptation_result_digest": PIN,
        "condition": "The source selects the conditional variant.",
        "condition_status": "NOT_TRIGGERED",
        "reason": "The source does not select this variant.",
        "repeated_evidence": "current-source-evidence" * 256,
    }
    executed_check_digest = binding.value_digest(check)
    row = {
        "object_id": "subject",
        "object_digest": PIN,
        "coordinate": "OBJECT-1.1",
        "tier": 1,
        "proposition_digest": PIN,
        "instance_digest": PIN,
        "object_kind": "OBJECT",
        "verifier_id": "verifier",
        "checking_mechanism": "tests.synthetic",
        "scope": "finite_subject",
        "reason": "The exact repository subject needs a bounded check.",
        "repository_realization": {
            "explanation": "Replay the exact selected source."
        },
        "applicability": {
            "status": "PASS",
            "classification": "CONDITION_NOT_MET",
            "assessment_required": True,
            "reason": "The condition was evaluated against current source.",
        },
        "selected_package_check": check,
        "checker_status": "NOT_REQUIRED",
        "status": "PASS",
        "blockers": [],
        "native_specimen_is_instance_evidence": False,
        "package_graph_replay_is_instance_evidence": False,
        "declared_kind": "OBJECT",
        "specializations": [],
        "kind_requirement": {"kind": "OBJECT", "declared": True},
    }
    monkeypatch.setattr(package, "MAX_INLINE_INSTANCE_PAYLOAD_BYTES", 1)
    monkeypatch.setattr(package, "MAX_INLINE_SELECTED_CHECK_BYTES", 1)
    package._compact_successful_instance_checks([row])
    first_reference = deepcopy(row["selected_package_check"])
    # A conditional row stays complete through early compaction, so the
    # committed digest is the digest of the executed check itself.
    assert first_reference == check
    assert binding.value_digest(first_reference) == executed_check_digest

    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": namespace_contracts.kind_denominators(),
        "obligation_instances": [row],
    }
    assert package._attach_successful_instance_projection(report, force=True)

    retained = report["obligation_instances"][0]["selected_package_check"]
    assert retained == first_reference
    assert binding.value_digest(retained) == executed_check_digest


def test_large_obligation_ledger_projects_only_pass_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    common = {
        "object_id": "subject", "object_digest": PIN,
        "coordinate": "OBJECT-1.1", "tier": 1,
        "proposition_digest": PIN, "instance_digest": PIN,
        "object_kind": "OBJECT", "verifier_id": "verifier",
        "checking_mechanism": "tests.synthetic", "scope": "finite_subject",
        "reason": "The exact repository subject needs a bounded check.",
        "repository_realization": {"explanation": "Replay the exact selected source."},
        "applicability": {"status": "PASS", "classification": "NECESSARY",
                          "assessment_required": True, "reason": "Always necessary."},
        "selected_package_check": {"status": "PASS", "reason": "Fresh replay passed."},
        "checker_status": "PASS", "status": "PASS", "blockers": [],
        "native_specimen_is_instance_evidence": False,
        "package_graph_replay_is_instance_evidence": True,
        "declared_kind": "OBJECT", "specializations": [],
        "kind_requirement": {"kind": "OBJECT", "declared": True},
    }
    passed = deepcopy(common)
    failed = deepcopy(common)
    failed.update(object_id="failed", status="FAIL", checker_status="FAIL",
                  blockers=["PACKAGE_INSTANCE_CHECK_REFUTED"])
    before_failed = deepcopy(failed)
    committed_pass = deepcopy(passed)
    committed_pass["selected_package_check"] = \
        package._selected_check_reference(
            committed_pass["selected_package_check"]
        )
    complete_pass_digest = binding.value_digest(committed_pass)
    monkeypatch.setattr(package, "MAX_INLINE_OBLIGATION_ROWS_BYTES", 1)

    projection = package._compact_successful_instance_rows([passed, failed])

    assert projection is not None
    definitions, profile = projection
    assert profile["source_instance_count"] == 2
    assert profile["pass_reference_count"] == 1
    assert profile["expanded_nonpass_count"] == 1
    assert profile["schema_version"] == "verifier-pass-instance-projection-2"
    assert profile["transport"] == "DIGEST_BOUND_PASS_FACTORED_REFERENCES"
    assert len(definitions) == 2
    semantic_definition = next(
        definition
        for definition in definitions
        if definition["definition_kind"] == "SEMANTIC"
    )
    kind_definition = next(
        definition
        for definition in definitions
        if definition["definition_kind"] == "KIND_REQUIREMENT"
    )
    assert semantic_definition["reason"] == common["reason"]
    assert kind_definition["kind_requirement"] == common["kind_requirement"]
    assert passed["status"] == "PASS" and passed["blockers"] == []
    assert passed["repository_realization"]["complete_instance_digest"] == complete_pass_digest
    assert passed["repository_realization"][
        "semantic_definition_digest"
    ] == semantic_definition["definition_digest"]
    assert passed["repository_realization"][
        "kind_requirement_definition_digest"
    ] == kind_definition["definition_digest"]
    assert passed["selected_package_check"]["full_check_digest"] == binding.value_digest(
        common["selected_package_check"]
    )
    assert "kind_requirement" not in passed
    assert failed == before_failed
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": namespace_contracts.kind_denominators(),
        "obligation_instances": [passed, failed],
        "pass_instance_definitions": definitions,
        "obligation_instance_projection": profile,
    }

    assert package._upgrade_successful_instance_projection_v3(report)
    table_profile = report["obligation_instance_projection"]
    assert report["obligation_instances"] == [before_failed]
    assert table_profile["expanded_nonpass_source_indexes"] == [1]
    assert table_profile["pass_entries"][0][0] == 0


def test_forced_v2_projection_upgrades_pass_rows_to_v3_tables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    common = {
        "object_digest": PIN,
        "coordinate": "OBJECT-1.1",
        "tier": 1,
        "proposition_digest": PIN,
        "object_kind": "OBJECT",
        "verifier_id": "verifier",
        "checking_mechanism": "tests.synthetic",
        "scope": "finite_subject",
        "reason": "The exact repository subject needs a bounded check.",
        "repository_realization": {
            "explanation": "Replay the exact selected source."
        },
        "applicability": {
            "status": "PASS",
            "classification": "NECESSARY",
            "assessment_required": True,
            "reason": "Always necessary.",
        },
        "selected_package_check": {
            "status": "PASS", "reason": "Fresh replay passed.",
        },
        "checker_status": "PASS",
        "status": "PASS",
        "blockers": [],
        "native_specimen_is_instance_evidence": False,
        "package_graph_replay_is_instance_evidence": True,
        "declared_kind": "OBJECT",
        "specializations": [],
        "kind_requirement": {"kind": "OBJECT", "declared": True},
    }
    rows = []
    for index in range(64):
        object_id = f"subject-{index}"
        rows.append({
            **deepcopy(common),
            "object_id": object_id,
            "instance_digest": binding.value_digest({
                "object_id": object_id, "index": index,
            }),
        })
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": namespace_contracts.kind_denominators(),
        "obligation_instances": rows,
        "verifier_execution": {
            "obligation_denominator_commitment": {
                "schema_version": (
                    "verifier-package-obligation-denominator-commitment-1"
                ),
                "status": "COMMITTED",
                "selected_instance_count": 64,
                "selected_instance_index_digest": PIN,
                "conditional_refutation_count": 0,
                "conditional_refutations": [],
                "conditional_refutations_digest": binding.value_digest([]),
                "claim_boundary": "Synthetic committed denominator.",
                "commitment_digest": PIN,
            },
        },
    }
    # This unit isolates row transport; denominator compaction is covered by
    # the cumulative report tests with a semantically complete commitment.
    monkeypatch.setattr(
        package, "_compact_projected_denominator_commitment", lambda _report: True,
    )
    monkeypatch.setattr(package, "MAX_INLINE_OBLIGATION_ROWS_BYTES", 1)

    assert package._attach_successful_instance_projection(report)
    v2_rows_digest = report["obligation_instance_projection"][
        "source_instances_digest"
    ]
    # A report that is already below the hard 32 MiB envelope can still miss
    # the ordinary 24 MiB target.  Sealing must promote its existing v2 rows to
    # the denser v3 tables without waiting for capacity exhaustion.
    from verifier.runtime import manifest_gate
    report.update(status="PASS", blockers=[])
    monkeypatch.setattr(manifest_gate, "package_findings", lambda _report: [])
    monkeypatch.setattr(
        package,
        "TARGET_REPORT_BYTES",
        len(binding.canonical_bytes(report)) - 1,
    )
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", 10**9)

    report = package._seal(report)

    profile = report["obligation_instance_projection"]
    assert profile["schema_version"] == "verifier-pass-instance-projection-3"
    assert profile["transport"] == "DIGEST_BOUND_PASS_TABLE_REFERENCES"
    assert profile["source_instance_count"] == 64
    assert profile["pass_reference_count"] == 64
    assert profile["expanded_nonpass_count"] == 0
    assert profile["source_instances_digest"] == v2_rows_digest
    assert report["obligation_instances"] == []
    assert len(profile["pass_entries"]) == 64
    assert profile["expanded_nonpass_source_indexes"] == []
    assert profile["pass_entries_digest"] == binding.value_digest(
        profile["pass_entries"]
    )
    assert profile["object_table_digest"] == binding.value_digest(
        profile["object_table"]
    )
    assert profile["route_table_digest"] == binding.value_digest(
        profile["route_table"]
    )
    assert profile["check_definitions_digest"] == binding.value_digest(
        profile["check_definitions"]
    )


def test_v3_projection_bounds_current_tier3_denominator_shape() -> None:
    """20,675 PASS rows retain the current Tier-3 denominator under 24 MiB."""

    necessary_semantic = {
        "definition_kind": "SEMANTIC",
        "reason": "The exact repository subject needs a bounded check.",
        "repository_realization": {
            "explanation": "Replay the exact selected source."
        },
        "applicability": {
            "status": "PASS",
            "classification": "NECESSARY",
            "assessment_required": True,
            "reason": "Always necessary.",
        },
    }
    conditional_reason = "The exact installed condition is not triggered."
    conditional_semantic = {
        **necessary_semantic,
        "applicability": {
            "status": "PASS",
            "classification": "CONDITION_NOT_MET",
            "assessment_required": True,
            "reason": conditional_reason,
        },
    }
    semantic_bodies = (necessary_semantic, conditional_semantic)
    semantic_digests = [binding.value_digest(body) for body in semantic_bodies]
    definitions = sorted(
        ({"definition_digest": digest, **body}
         for digest, body in zip(semantic_digests, semantic_bodies)),
        key=lambda row: row["definition_digest"],
    )
    reference_reasons = [
        "See pass_instance_definitions semantic definition " + digest + "."
        for digest in semantic_digests
    ]
    conditional_route = next(
        route for route in manifest_gate.obligation_catalog()
        if route["coordinate"] == "OBJECT-1.2"
    )
    necessary_route = next(
        route for route in manifest_gate.obligation_catalog()
        if route["coordinate"] == "OBJECT-1.1"
    )

    def digest(index: int, domain: int) -> str:
        return "sha256:" + f"{domain:02x}{index:062x}"

    rows = []
    committed_rows = []
    conditional_count = 11_078
    source_count = 20_675
    for index in range(source_count):
        if index < conditional_count:
            route = conditional_route
            semantic_body = conditional_semantic
            semantic_digest = semantic_digests[1]
            reference_reason = reference_reasons[1]
            check_body = {
                "object_id": f"subject-{index}",
                "object_digest": digest(index, 3),
                "collection_digest": PIN,
                "adaptation_obligation_id": (
                    "OBJECT-1.90-source-representation-facets"
                ),
                "adaptation_result_digest": digest(index, 1),
                "applicability_classification": "CONDITION_NOT_MET",
                "applicability_established": True,
                "condition": route["applicability"]["condition"],
                "applicability_digest": route["applicability_digest"],
                "condition_status": "NOT_TRIGGERED",
                "conditional_coordinate": route["coordinate"],
                "evidence_origin": (
                    "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW"
                ),
                "fulfillment_required": False,
                "native_coordinate": route["coordinate"],
                "reason": conditional_reason,
                "status": "PASS",
            }
            selected_check = {
                **check_body,
                "result_digest": binding.value_digest(check_body),
            }
            checker_status = "NOT_REQUIRED"
        else:
            route = necessary_route
            semantic_body = necessary_semantic
            semantic_digest = semantic_digests[0]
            reference_reason = reference_reasons[0]
            selected_check = {
                "claim_boundary": "The full current check was consumed.",
                "full_check_bytes": 897,
                "full_check_digest": digest(index, 2),
                "schema_version": "verifier-package-check-reference-1",
                "status": "PASS",
                "transport": "DIGEST_BOUND_REFERENCE",
            }
            checker_status = "PASS"
        row = {
            "object_id": f"subject-{index}",
            "object_digest": digest(index, 3),
            "coordinate": route["coordinate"],
            "tier": route["tier"],
            "proposition_digest": route["proposition_digest"],
            "instance_digest": digest(index, 5),
            "object_kind": "OBJECT",
            "verifier_id": "vstd-package-verifier",
            "checking_mechanism": route["checking_mechanism"],
            "scope": route["scope"],
            "reason": reference_reason,
            "repository_realization": {
                "schema_version": (
                    "verifier-pass-instance-definition-reference-2"
                ),
                "semantic_definition_digest": semantic_digest,
                "complete_instance_digest": digest(index, 6),
                "transport": "REPORT_PASS_INSTANCE_FACTORED_DEFINITIONS",
            },
            "applicability": {
                "status": "PASS",
                "classification": semantic_body["applicability"][
                    "classification"
                ],
                "assessment_required": True,
                "reason": reference_reason,
            },
            "selected_package_check": selected_check,
            "checker_status": checker_status,
            "status": "PASS",
            "blockers": [],
            "native_specimen_is_instance_evidence": False,
            "package_graph_replay_is_instance_evidence": (
                checker_status == "PASS"
            ),
            "declared_kind": "OBJECT",
            "specializations": [],
        }
        committed = deepcopy(row)
        committed["reason"] = semantic_body["reason"]
        committed["repository_realization"] = semantic_body[
            "repository_realization"
        ]
        committed["applicability"] = semantic_body["applicability"]
        row["repository_realization"]["complete_instance_digest"] = (
            binding.value_digest(committed)
        )
        rows.append(row)
        committed_rows.append(committed)
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": namespace_contracts.kind_denominators(),
        "obligation_instances": rows,
        "pass_instance_definitions": definitions,
        "obligation_instance_projection": {
            "schema_version": "verifier-pass-instance-projection-2",
            "transport": "DIGEST_BOUND_PASS_FACTORED_REFERENCES",
            "source_instance_count": source_count,
            "pass_reference_count": source_count,
            "expanded_nonpass_count": 0,
            "source_instances_digest": binding.value_digest(committed_rows),
            "definition_count": len(definitions),
            "definitions_digest": binding.value_digest(definitions),
            "claim_boundary": "Synthetic complete Version-2 projection.",
        },
        # The same-coordinate Tier-2 report showed about 7.1 MiB outside its
        # obligation rows. Eight MiB is therefore a conservative Tier-3
        # non-row allowance for this transport regression.
        "synthetic_nonrow_evidence": "x" * (8 * 1024 * 1024),
    }

    assert package._upgrade_successful_instance_projection_v3(report)
    profile = report["obligation_instance_projection"]
    result_digest_index = profile["pass_entry_field_order"].index(
        "result_digest"
    )

    assert profile["source_instance_count"] == 20_675
    assert len(profile["pass_entries"]) == 20_675
    assert sum(
        entry[result_digest_index] is not None
        for entry in profile["pass_entries"]
    ) == 11_078
    assert report["obligation_instances"] == []
    assert len(binding.canonical_bytes(report)) <= 24 * 1024 * 1024
    reconstructed = package._reconstruct_v3_instance_rows(report)
    assert reconstructed is not None
    assert len(reconstructed) == 20_675
    assert len(package._conditional_refutation_index(reconstructed)) == 11_078


def test_target_only_projection_preserves_all_expanded_nonpass_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An under-cap report must not trade actionable failures for a receipt."""

    from verifier.runtime import manifest_gate

    repeated_details = "x" * ((package.TARGET_REPORT_BYTES + 4096) // 2)
    rows = [
        {
            "object_id": "failed-subject",
            "coordinate": "OBJECT-3.1",
            "case_kind": "POSITIVE",
            "status": "FAIL",
            "blockers": ["PACKAGE_INSTANCE_CHECK_REFUTED"],
            "reason": "The concrete package check refuted this instance.",
            "details": repeated_details,
        },
        {
            "object_id": "unknown-subject",
            "coordinate": "OBJECT-3.2",
            "case_kind": "BOUNDARY",
            "status": "UNKNOWN",
            "blockers": ["PACKAGE_INSTANCE_CHECK_UNAVAILABLE"],
            "reason": "The concrete package check did not establish a result.",
            "details": repeated_details,
        },
    ]
    before_rows = deepcopy(rows)
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": namespace_contracts.kind_denominators(),
        "status": "FAIL",
        "blockers": ["PACKAGE_INSTANCE_CHECK_REFUTED"],
        "findings": [],
        "obligation_instances": rows,
    }
    source_bytes = len(binding.canonical_bytes(report))
    assert package.TARGET_REPORT_BYTES < source_bytes < package.MAX_REPORT_BYTES
    monkeypatch.setattr(manifest_gate, "package_findings", lambda _report: [])

    sealed = package._seal(report)

    assert sealed["schema_version"] == package.EXTENSIBLE_REPORT_SCHEMA
    assert "PACKAGE_REPORT_CAPACITY_EXHAUSTED" not in sealed["blockers"]
    assert sealed["obligation_instances"] == before_rows
    assert "obligation_instance_projection" not in sealed
    assert len(binding.canonical_bytes(sealed)) <= package.MAX_REPORT_BYTES


def test_target_only_projection_cannot_grow_under_cap_report_past_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A target optimization must not replace an already admissible report."""

    from verifier.runtime import manifest_gate

    row = {
        "object_id": "subject",
        "object_digest": PIN,
        "coordinate": "OBJECT-3.1",
        "tier": 3,
        "proposition_digest": PIN,
        "instance_digest": PIN,
        "object_kind": "OBJECT",
        "verifier_id": "verifier",
        "checking_mechanism": "tests.synthetic",
        "scope": "finite_subject",
        "reason": "The exact repository subject needs a bounded check.",
        "repository_realization": {"explanation": "Fresh replay passed."},
        "applicability": {
            "status": "PASS", "classification": "NECESSARY",
            "assessment_required": True, "reason": "Always necessary.",
        },
        "selected_package_check": {
            "status": "PASS", "reason": "Fresh replay passed.",
        },
        "checker_status": "PASS", "status": "PASS", "blockers": [],
        "native_specimen_is_instance_evidence": False,
        "package_graph_replay_is_instance_evidence": True,
        "declared_kind": "OBJECT", "specializations": [],
        "kind_requirement": {"kind": "OBJECT", "declared": True},
    }
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": namespace_contracts.kind_denominators(),
        "status": "PASS",
        "blockers": [],
        "findings": [],
        "obligation_instances": [row],
        "padding": "",
    }
    # Leave enough room for the final report digest, but less than the table
    # envelope added by projecting a single unique PASS row.
    target_bytes = package.MAX_REPORT_BYTES - 1024
    base_bytes = len(binding.canonical_bytes(report))
    report["padding"] = "x" * (target_bytes - base_bytes)
    source_bytes = binding.canonical_bytes(report)
    assert len(source_bytes) == target_bytes
    before_row = deepcopy(row)
    before_padding = report["padding"]
    monkeypatch.setattr(manifest_gate, "package_findings", lambda _report: [])

    sealed = package._seal(report)

    assert sealed["schema_version"] == package.EXTENSIBLE_REPORT_SCHEMA
    assert "PACKAGE_REPORT_CAPACITY_EXHAUSTED" not in sealed["blockers"]
    assert sealed["obligation_instances"] == [before_row]
    assert sealed["padding"] == before_padding
    assert "obligation_instance_projection" not in sealed
    assert len(binding.canonical_bytes(sealed)) <= package.MAX_REPORT_BYTES


def test_whole_report_capacity_forces_pass_projection_before_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sub-threshold row ledger must not make the aggregate report UNKNOWN."""

    common = {
        "object_digest": PIN,
        "coordinate": "OBJECT-1.1",
        "tier": 1,
        "proposition_digest": PIN,
        "instance_digest": PIN,
        "object_kind": "OBJECT",
        "verifier_id": "verifier",
        "checking_mechanism": "tests.synthetic",
        "scope": "finite_subject",
        "reason": "The exact repository subject needs a bounded check.",
        "repository_realization": {
            "explanation": "Replay the exact selected source."
        },
        "applicability": {
            "status": "PASS",
            "classification": "NECESSARY",
            "assessment_required": True,
            "reason": "Always necessary.",
        },
        "selected_package_check": {
            "status": "PASS",
            "reason": "Fresh replay passed.",
            "repeated_evidence": "current-source-evidence" * 256,
        },
        "checker_status": "PASS",
        "status": "PASS",
        "blockers": [],
        "native_specimen_is_instance_evidence": False,
        "package_graph_replay_is_instance_evidence": True,
        "declared_kind": "OBJECT",
        "specializations": [],
        "kind_requirement": {"kind": "OBJECT", "declared": True},
    }
    report = package.assess_package_polish(2, Path("."), cancelled=True)
    report.pop("report_digest")
    report.update(
        schema_version=package.EXTENSIBLE_REPORT_SCHEMA,
        status="PASS",
        blockers=[],
        obligation_instances=[
            {**deepcopy(common), "object_id": f"subject-{index}"}
            for index in range(64)
        ],
    )
    normalized_instance_digests = {}
    for row in report["obligation_instances"]:
        committed = deepcopy(row)
        committed["selected_package_check"] = \
            package._selected_check_reference(
                committed["selected_package_check"]
            )
        normalized_instance_digests[row["object_id"]] = \
            binding.value_digest(committed)
    # Keep the section-local threshold deliberately above the ledger. The only
    # reason to project must be the complete report's independent byte bound.
    monkeypatch.setattr(package, "MAX_INLINE_OBLIGATION_ROWS_BYTES", 10**9)
    # If check compaction runs before the forced row projection, the retained
    # complete-instance digest will bind an intermediate row and this assertion
    # will refute the ordering.
    monkeypatch.setattr(package, "MAX_INLINE_INSTANCE_PAYLOAD_BYTES", 1)
    monkeypatch.setattr(package, "MAX_INLINE_SELECTED_CHECK_BYTES", 1)

    projected = deepcopy(report)
    assert package._attach_successful_instance_projection(
        projected, force=True
    )
    projected = package._seal(projected)
    projected_bytes = len(binding.canonical_bytes(projected))
    unprojected_bytes = len(binding.canonical_bytes(report))
    assert projected_bytes < unprojected_bytes
    monkeypatch.setattr(
        package,
        "MAX_REPORT_BYTES",
        (projected_bytes + unprojected_bytes) // 2,
    )

    sealed = package._seal(deepcopy(report))

    assert sealed["schema_version"] == package.EXTENSIBLE_REPORT_SCHEMA
    assert "PACKAGE_REPORT_CAPACITY_EXHAUSTED" not in sealed["blockers"]
    assert sealed["obligation_instance_projection"]["pass_reference_count"] == 64
    assert len(sealed["pass_instance_definitions"]) == 2
    assert {
        definition["definition_kind"]
        for definition in sealed["pass_instance_definitions"]
    } == {"SEMANTIC", "KIND_REQUIREMENT"}
    assert {
        row["object_id"]: row["repository_realization"][
            "complete_instance_digest"
        ]
        for row in sealed["obligation_instances"]
    } == normalized_instance_digests
    assert len(binding.canonical_bytes(sealed)) <= package.MAX_REPORT_BYTES


def test_contract_coverage_reference_keeps_every_key_and_actionable_nonpass() -> None:
    passed = {
        "object_id": "ledger", "object_digest": PIN, "kind": "LEDGER",
        "kind_requirement": {"kind": "LEDGER", "reasons": ["Declared ledger."]},
        "finite_check_status": "PASS",
        "clauses": [{"coordinate": "LEDGER-1.1", "status": "PASS",
                     "evidence": "current source binding " * 512}],
        "residual_requirements": [], "status": "PASS",
    }
    unknown = {
        "object_id": "market", "object_digest": PIN, "kind": "MARKET",
        "kind_requirement": {"kind": "MARKET", "reasons": ["Declared market."]},
        "finite_check_status": "UNKNOWN", "clauses": [],
        "residual_requirements": [{"status": "UNKNOWN"}], "status": "UNKNOWN",
    }
    body = {
        "schema_version": "verifier-package-contract-coverage-1", "through_tier": 2,
        "registry_digest": PIN, "collection_digest": PIN, "source_census_digest": PIN,
        "verifier_id": "verifier", "expected_instance_count": 1,
        "observed_instance_count": 1, "denominator_status": "PASS",
        "finite_check_status": "UNKNOWN", "status": "UNKNOWN",
        "normative_coverage": "NOT_ESTABLISHED", "contracts": [passed, unknown],
        "findings": [], "claim_boundary": "Bounded aggregation.",
    }
    full = {**body, "assessment_digest": binding.value_digest(body)}

    reference = package._contract_coverage_reference(full)

    assert reference["assessment_digest"] == full["assessment_digest"]
    assert reference["contract_count"] == 2
    assert reference["pass_contract_count"] == 1
    assert reference["nonpass_contract_count"] == 1
    assert reference["contracts"] == [{
        "object_id": "market",
        "object_digest": PIN,
        "kind": "MARKET",
        "status": "UNKNOWN",
        "finite_check_status": "UNKNOWN",
        "profile_status": None,
        "clause_count": 0,
        "clauses_digest": binding.value_digest([]),
        "nonpass_clause_count": 0,
        "nonpass_clauses": [],
        "residual_requirements": [{"status": "UNKNOWN"}],
        "kind_requirement_digest": binding.value_digest(
            unknown["kind_requirement"]
        ),
        "contract_digest": binding.value_digest(unknown),
    }]
    assert reference["pass_contract_references"][0]["object_id"] == "ledger"
    assert reference["pass_contract_references"][0]["contract_digest"] == binding.value_digest(passed)
    assert len(binding.canonical_bytes(reference)) < len(binding.canonical_bytes(full))


def test_contract_coverage_reference_retains_nonpass_clauses_and_digests_passes() -> None:
    failing_clause = {
        "coordinate": "MARKET-1.1", "closure_status": "FAIL",
        "status": "FAIL", "rerun_argv": ["vstd", "gate"],
    }
    passing_clause = {
        "coordinate": "MARKET-1.2", "closure_status": "PASS",
        "status": "PASS", "evidence": "large successful evidence " * 128,
    }
    contract = {
        "object_id": "market", "object_digest": PIN, "kind": "MARKET",
        "kind_requirement": {"kind": "MARKET", "reasons": ["Declared market."]},
        "finite_check_status": "FAIL", "profile_status": "FAIL",
        "clauses": [failing_clause, passing_clause],
        "residual_requirements": [{"status": "UNKNOWN"}], "status": "FAIL",
    }
    body = {
        "schema_version": "verifier-package-contract-coverage-1", "through_tier": 1,
        "registry_digest": PIN, "collection_digest": PIN,
        "source_census_digest": PIN, "verifier_id": "verifier",
        "expected_instance_count": 2, "observed_instance_count": 2,
        "denominator_status": "PASS", "finite_check_status": "FAIL",
        "status": "FAIL", "normative_coverage": "NOT_ESTABLISHED",
        "contracts": [contract], "findings": [],
        "claim_boundary": "Bounded aggregation.",
    }
    full = {**body, "assessment_digest": binding.value_digest(body)}

    reference = package._contract_coverage_reference(full)
    retained = reference["contracts"][0]

    assert retained["nonpass_clauses"] == [failing_clause]
    assert retained["nonpass_clause_count"] == 1
    assert retained["clause_count"] == 2
    assert retained["clauses_digest"] == binding.value_digest(
        [failing_clause, passing_clause]
    )
    assert retained["contract_digest"] == binding.value_digest(contract)
    assert passing_clause not in retained["nonpass_clauses"]


def test_large_contract_coverage_reference_factors_repeated_nonpass_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contracts = []
    for index in range(12):
        object_id = f"market-{index}"
        contracts.append({
            "object_id": object_id,
            "object_digest": binding.value_digest({"object_id": object_id}),
            "kind": "MARKET",
            "kind_requirement": {
                "kind": "MARKET", "reasons": ["Declared market."],
            },
            "finite_check_status": "UNKNOWN",
            "profile_status": "UNKNOWN",
            "clauses": [{
                "coordinate": "MARKET-1.1",
                "closure_status": "UNKNOWN",
                "status": "UNKNOWN",
                "object_id": object_id,
                "rerun_argv": ["vstd", "gate", "--object", object_id],
            }],
            "residual_requirements": [{
                "status": "UNKNOWN",
                "object_id": object_id,
                "next_action": ["vstd", "polish", "--object", object_id],
                "explanation": "x" * 128,
            }],
            "status": "UNKNOWN",
        })
    body = {
        "schema_version": "verifier-package-contract-coverage-1",
        "through_tier": 1,
        "registry_digest": PIN,
        "collection_digest": PIN,
        "source_census_digest": PIN,
        "verifier_id": "verifier",
        "expected_instance_count": 12,
        "observed_instance_count": 12,
        "denominator_status": "PASS",
        "finite_check_status": "UNKNOWN",
        "status": "UNKNOWN",
        "normative_coverage": "NOT_ESTABLISHED",
        "contracts": contracts,
        "findings": [],
        "claim_boundary": "Bounded aggregation.",
    }
    full = {**body, "assessment_digest": binding.value_digest(body)}
    monkeypatch.setattr(package, "MAX_INLINE_CONTRACT_COVERAGE_BYTES", 1)

    reference = package._contract_coverage_reference(full)

    assert reference["schema_version"] == (
        "verifier-package-contract-coverage-reference-2"
    )
    assert reference["contract_count"] == len(contracts)
    assert reference["nonpass_contract_count"] == len(contracts)
    assert reference["nonpass_definition_count"] == 1
    assert len(reference["contracts"]) == len(contracts)
    assert reference["contract_reference_field_order"][-1] == (
        "nonpass_definition_index"
    )
    assert {row[-1] for row in reference["contracts"]} == {0}
    definition = reference["nonpass_definitions"][0]
    assert definition["definition_digest"] == binding.value_digest({
        key: value for key, value in definition.items()
        if key != "definition_digest"
    })
    assert definition["object_id_paths"]
    for source, retained in zip(contracts, reference["contracts"]):
        assert retained[0] == source["object_id"]
        assert retained[4] == binding.value_digest(source)
    assert len(binding.canonical_bytes(reference)) < len(binding.canonical_bytes(full))


def test_default_tier3_is_package_scoped_even_when_cancelled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["polish", "3", "--cancelled", "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "verifier-manifest-package-polish-1"
    assert report["claim_scope"] == "MANIFEST_PACKAGE_GRAPH"
    assert report["requested_tier"] == 3
    assert report["manifest"]["path"] == "objects.vstd"
    assert report["polished"] is False


def test_default_tier3_missing_root_manifest_does_not_fall_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["polish", "3", "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == (
        package.self_polish_tiers.POLISH_REFRESH_BLOCKED_SCHEMA
    )
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["MANIFEST_REFRESH_TARGET_UNSAFE"]
    assert report["polished"] is False
    assert report["claim_boundary"].startswith(
        "The root manifest refresh did not complete"
    )


@pytest.fixture
def declared_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict, list]:
    """Use real manifest parsing, graph/facet replay and installed obligation join.

    Only repository census and expensive cumulative diagnostics are isolated;
    real source and installed-command execution are separate acceptance gates.
    """
    manifest = package.package_manifest.retained_contract(json.loads((ROOT / "objects.vstd").read_bytes()))
    (tmp_path / "objects.vstd").write_bytes(binding.canonical_bytes(manifest) + b"\n")
    (tmp_path / "reasons.vstd").write_bytes((ROOT / "reasons.vstd").read_bytes())
    manifest_digest = binding.bytes_digest((tmp_path / "objects.vstd").read_bytes())
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "CURRENT",
            "before_digest": manifest_digest,
            "after_digest": manifest_digest,
            "backup_digest": None,
            "source_census_digest": PIN,
            "migration_mechanism_digest": PIN,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    coordinate = {"source_head": manifest["repository"]["revision"], "source_tree": "2" * 40,
                  "source_manifest_digest": PIN, "source_worktree_status_digest": PIN}
    monkeypatch.setattr(package.self_polish_estate, "_git_coordinate", lambda root: {
        "repository": manifest["repository"]["remote"], "revision": manifest["repository"]["revision"]})
    monkeypatch.setattr(package.self_polish_statics, "_capture_coordinate", lambda root: coordinate)
    monkeypatch.setattr(package.self_polish_tiers, "_post_replay_source_recapture", lambda *args: {"status": "PASS"})
    provider_path = tmp_path / "src/verifier/runtime/tier_zero_reasons.py"
    provider_path.parent.mkdir(parents=True)
    provider_path.write_bytes((ROOT / "src/verifier/runtime/tier_zero_reasons.py").read_bytes())
    reasons = package.tier_zero_reasons.installed_reason_ledger(ROOT)
    monkeypatch.setattr(package.tier_zero_reasons, "installed_reason_ledger", lambda root: deepcopy(reasons))
    calls = []

    def native(tier: int, root: Path) -> dict:
        calls.append((tier, root))
        prerequisites = {}
        zero_body = {
            "status": "PASS",
            "manifest_digest": binding.bytes_digest(
                (root / "objects.vstd").read_bytes()
            ),
            "obligation_count": 9,
            "obligation_status_counts": {
                "PASS": 9, "FAIL": 0, "UNKNOWN": 0,
            },
            "obligations": [
                {
                    "coordinate": f"VSTD-T0.{index}",
                    "status": "PASS",
                    "assessment_reason": "Synthetic repository admission passed.",
                }
                for index in range(1, 10)
            ],
        }
        prerequisites["0"] = {
            **zero_body, "report_digest": binding.value_digest(zero_body),
        }
        for depth in range(1, min(tier, 2) + 1):
            prior_body = {
                "schema_version": package.self_polish_tiers.REPORT_SCHEMA,
                "tier": depth,
                "status": "PASS",
                "source_coordinate": coordinate,
                "source_coordinate_digest": binding.value_digest(coordinate),
                "post_replay_full_source_recapture": "PASS",
            }
            prerequisites[str(depth)] = {
                **prior_body,
                "report_digest": binding.value_digest(prior_body),
            }
        complete_replay = (
            {
                "status": "PASS",
                "blockers": [],
                "receipt_digest": "sha256:" + "b" * 64,
            }
            if tier == 3 else None
        )
        execution = {
            str(depth): package._native_execution_record(
                depth,
                execution_status="EXECUTED",
                status="PASS",
                reason=f"Synthetic native Tier {depth} execution passed.",
                evidence_digest=(
                    prerequisites[str(depth)]["report_digest"]
                    if depth <= 2
                    else complete_replay["receipt_digest"]
                ),
            )
            for depth in range(tier + 1)
        }
        body = {
            "status": "PASS",
            "source_coordinate": coordinate,
            "source_coordinate_digest": binding.value_digest(coordinate),
            "post_replay_full_source_recapture": "PASS",
            "prerequisites": prerequisites,
            "tier_execution": execution,
            "claim_scope": "SOURCE_NATIVE_DIAGNOSTICS_NOT_PACKAGE_INSTANCES",
        }
        if tier == 3:
            body["complete_tier_evidence_replay"] = complete_replay
        return {**body, "report_digest": binding.value_digest(body)}

    monkeypatch.setattr(package, "_run_native_diagnostics", native)
    return tmp_path, manifest, calls


def test_tier3_native_execution_prefix_binds_complete_replay(
        declared_package: tuple) -> None:
    import jsonschema

    root, _, _ = declared_package
    diagnostic = package._run_native_diagnostics(3, root)
    manifest_digest = binding.bytes_digest((root / "objects.vstd").read_bytes())
    assert package._native_execution_prefix_complete(
        diagnostic,
        requested_tier=3,
        source_coordinate_digest=diagnostic["source_coordinate_digest"],
        manifest_digest=manifest_digest,
    )

    replay = diagnostic["complete_tier_evidence_replay"]
    reference = package._native_diagnostic_reference(diagnostic)
    assert reference["complete_tier_evidence_replay"] == {
        "status": "PASS",
        "evidence_digest": replay["receipt_digest"],
        "receipt_digest": replay["receipt_digest"],
        "transport": "DIGEST_BOUND_REFERENCE",
    }
    package_schema = json.loads((
        ROOT
        / "src/verifier/schemas/verifier-manifest-package-polish-2.schema.json"
    ).read_bytes())
    native_schema = {
        "$schema": package_schema["$schema"],
        "$defs": package_schema["$defs"],
        "$ref": "#/$defs/cumulativeNativeDiagnostics",
    }
    jsonschema.Draft202012Validator(native_schema).validate(reference)

    forged = deepcopy(diagnostic)
    forged.pop("report_digest")
    forged_record = forged["tier_execution"]["3"]
    forged_record["evidence_digest"] = "sha256:" + "f" * 64
    forged_record["execution_record_digest"] = binding.value_digest({
        key: value for key, value in forged_record.items()
        if key != "execution_record_digest"
    })
    forged["report_digest"] = binding.value_digest(forged)
    assert not package._native_execution_prefix_complete(
        forged,
        requested_tier=3,
        source_coordinate_digest=forged["source_coordinate_digest"],
        manifest_digest=manifest_digest,
    )

    value_bound = deepcopy(diagnostic)
    value_bound.pop("report_digest")
    value_bound_replay = value_bound["complete_tier_evidence_replay"]
    value_bound_replay.pop("receipt_digest")
    value_bound_digest = binding.value_digest(value_bound_replay)
    value_bound_record = value_bound["tier_execution"]["3"]
    value_bound_record["evidence_digest"] = value_bound_digest
    value_bound_record["execution_record_digest"] = binding.value_digest({
        key: value for key, value in value_bound_record.items()
        if key != "execution_record_digest"
    })
    value_bound["report_digest"] = binding.value_digest(value_bound)
    assert package._native_execution_prefix_complete(
        value_bound,
        requested_tier=3,
        source_coordinate_digest=value_bound["source_coordinate_digest"],
        manifest_digest=manifest_digest,
    )
    assert package._native_diagnostic_reference(value_bound)[
        "complete_tier_evidence_replay"
    ] == {
        "status": "PASS",
        "evidence_digest": value_bound_digest,
        "value_digest": value_bound_digest,
        "transport": "DIGEST_BOUND_REFERENCE",
    }

    not_run = deepcopy(diagnostic)
    not_run.pop("report_digest")
    blocking = {
        "tier": 3,
        "tier_name": "STATICS",
        "required_status": "PASS",
        "observed_status": "UNKNOWN",
        "report_digest": None,
        "blockers": ["STATICS_ASSESSMENT_UNAVAILABLE"],
    }
    not_run["tier_execution"]["3"] = package._native_execution_record(
        3,
        execution_status="NOT_RUN",
        status="UNKNOWN",
        reason="Tier 3 did not produce an admissible replay receipt.",
        blocking_prerequisite=blocking,
    )
    not_run["status"] = "UNKNOWN"
    not_run["report_digest"] = binding.value_digest(not_run)
    assert not package._native_execution_prefix_complete(
        not_run,
        requested_tier=3,
        source_coordinate_digest=not_run["source_coordinate_digest"],
        manifest_digest=manifest_digest,
    )
    not_run.pop("report_digest")
    not_run["complete_tier_evidence_replay"] = None
    not_run["report_digest"] = binding.value_digest(not_run)
    assert package._native_execution_prefix_complete(
        not_run,
        requested_tier=3,
        source_coordinate_digest=not_run["source_coordinate_digest"],
        manifest_digest=manifest_digest,
    )
    jsonschema.Draft202012Validator(native_schema).validate(
        package._native_diagnostic_reference(not_run)
    )


@pytest.mark.parametrize(
    "tier,core_baseline,specialized_coordinates",
    # The core baseline counts every installed route for the legacy 26-object core,
    # including the base OBJECT source-representation route each tier adds
    # (OBJECT-1.90, then OBJECT-2.90), so tier 1 holds one more row and tier 2 two more.
    [
        (1, 46, ("LEDGER-1.1", "LEDGER-1.2")),
        (
            2,
            84,
            ("LEDGER-1.1", "LEDGER-1.2", "LEDGER-2.1", "LEDGER-2.2"),
        ),
    ],
)
def test_additive_manifest_preserves_instances_and_exposes_new_kind_gaps(
    declared_package,
    tier,
    core_baseline,
    specialized_coordinates,
):
    import subprocess
    from verifier.runtime import namespace_contracts
    root, retained, _ = declared_package
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "history.py").write_text("pass\n", encoding="utf-8")
    declarations = [{**item.to_dict(), "specializations": [], "surfaces": [], "reason": "Test role",
                     "classification": {}, "obligations": {}}
                    for item in package.tier_zero_manifest._namespace_objects(retained["objects"])]
    declarations.append({"object_id": "history", "kind": "LEDGER", "specializations": [],
        "payload": {}, "operands": {}, "surfaces": ["file:history.py"],
        "reason": "Explicit history role", "classification": {}, "obligations": {}})
    next(row for row in declarations if row["kind"] == "GRAPH")["operands"]["members"].append("history")
    document = {**retained, "schema_version": package.package_manifest.SCHEMA, "namespace": {
        "schema_version": "verifier-objects-manifest-2", "objects": declarations, "extensions": [],
        "registry_digest": namespace_contracts.registry_document(namespace_contracts.namespace_registry())["digest"]}}
    (root / "objects.vstd").write_bytes(binding.canonical_bytes(document) + b"\n")
    report = package.assess_package_polish(tier, root)
    import jsonschema
    schema = json.loads((ROOT / "src/verifier/schemas/verifier-manifest-package-polish-2.schema.json").read_bytes())
    jsonschema.Draft202012Validator(schema).validate(report)
    assert report["schema_version"] == package.EXTENSIBLE_REPORT_SCHEMA
    assert report["status"] == "UNKNOWN", report["blockers"]
    assert (
        "Portable unsigned report hashes establish internal consistency and "
        "accidental-corruption detection only; source replay or a trusted "
        "signature is required for authority."
    ) in report["claim_boundary"]
    commitment = report["verifier_execution"][
        "obligation_denominator_commitment"
    ]
    selected_index = [{
        "object_id": row["object_id"],
        "object_kind": row["object_kind"],
        "coordinate": row["coordinate"],
        "tier": row["tier"],
        "instance_digest": row["instance_digest"],
    } for row in report["obligation_instances"]]
    selected_index.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    ))
    assert commitment["status"] == "COMMITTED"
    assert commitment["selected_instance_count"] == len(
        report["obligation_instances"]
    )
    assert commitment["selected_instance_index_digest"] == \
        binding.value_digest(selected_index)
    assert commitment["commitment_digest"] == binding.value_digest({
        key: value for key, value in commitment.items()
        if key != "commitment_digest"
    })
    assert report["package_graph"]["object_count"] == 27
    # This retained-contract fixture declares the legacy 26-object core; the
    # complete 38-kind catalog denominator is exercised by separate tests.
    assert len([row for row in report["obligation_instances"] if row["object_id"] != "history"]) == core_baseline
    inherited = [row for row in report["obligation_instances"] if row["object_id"] == "history" and row["object_kind"] == "OBJECT"]
    assert inherited and all(row["object_kind"] == "OBJECT" and row["declared_kind"] == "LEDGER" for row in inherited)
    specialized = [row for row in report["obligation_instances"] if row["object_id"] == "history" and row["object_kind"] == "LEDGER"]
    # The LEDGER role makes every registered finite route part of the visible
    # denominator. This unrelated source does not inherit Verifier's installed
    # ledger implementation or its PASS evidence, so each route remains an
    # explicit applicability/evidence gap rather than disappearing.
    assert tuple(sorted(row["coordinate"] for row in specialized)) == \
        specialized_coordinates
    assert all(
        row["status"] == "UNKNOWN"
        and row["checker_status"] == "NOT_RUN"
        and row["selected_package_check"] is None
        and row["applicability"]["classification"] == "UNDETERMINED"
        and row["blockers"] == [
            "PACKAGE_INSTANCE_EVIDENCE_MISSING",
            "PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED",
        ]
        for row in specialized
    )
    assert report["refinement_coverage"] == [{"object_id": "history", "kind": "LEDGER", "through_tier": tier,
        "status": "UNKNOWN", "reason": namespace_contracts.namespace_registry()["LEDGER"].reason,
        "blocker": "PACKAGE_REFINEMENT_HIGHER_TIER_CONTRACT_NOT_ESTABLISHED", "base_obligations_inherited": True,
        "kind_requirement": {"kind": "LEDGER", "declared": True, "necessity": "NECESSARY",
            "reasons": ["Manifest declares LEDGER."],
            "source_census_digest": report["kind_requirements"]["source_census_digest"]}}]


@pytest.mark.parametrize("tier,count", [(1, 45), (2, 82), (3, 113)])
def test_root_command_consumes_manifest_graph_and_cumulative_instances(declared_package: tuple, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tier: int, count: int) -> None:
    root, manifest, calls = declared_package
    monkeypatch.chdir(root)
    assert main(["polish", str(tier), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["claim_scope"] == "MANIFEST_PACKAGE_GRAPH"
    assert report["package_graph"]["declarations"] == manifest["objects"]
    assert report["package_graph"]["manifest_digest"] == binding.bytes_digest((root / "objects.vstd").read_bytes())
    records = {r["object_id"]: r for r in report["package_graph"]["objects"]}
    assert len(records) == 26
    for declaration in manifest["objects"]:
        record = records[declaration["object_id"]]
        assert record["kind"] == declaration["object_kind"]
        assert record["operands"] == declaration["edges"]
        assert record["payload"]["representation_role"] == declaration["role"]
    assert report["verifier_execution"]["object_id"] == "verifier-core-self"
    assert report["verifier_execution"]["subject_id"] == "verifier-core-self"
    assert report["verifier_execution"]["verified_graph_id"] == "vstd-package-graph"
    assert report["verifier_execution"]["self_polish"]["aggregate_verifier_id"] \
        == "verifier-core-self"
    assert report["verifier_execution"]["self_polish"]["verified_graph_id"] \
        == "vstd-package-graph"
    assert report["verifier_execution"]["self_polish"]["aggregate_result_is_member_evidence"] \
        is False
    assert report["verifier_execution"]["requested_tier"] == tier
    assert calls == [(tier, root)]
    assert len(report["obligation_instances"]) == count
    assert len({r["instance_digest"] for r in report["obligation_instances"]}) == count
    assert report["native_diagnostics"]["status"] == "PASS"
    assert report["status"] == "UNKNOWN"  # Retained v1 semantics stay unchanged.
    assert all(r["status"] == "UNKNOWN" and r["applicability"]["assessment_required"]
               and not r["native_specimen_is_instance_evidence"] and r["reason"].strip()
               for r in report["obligation_instances"])
    assert sum(r["checker_status"] == "PASS" for r in report["obligation_instances"]) == 27
    assert report["post_replay_manifest_recapture"] == report["post_replay_source_recapture"] == "PASS"
    assert report["report_digest"] == binding.value_digest({k: v for k, v in report.items() if k != "report_digest"})


def test_package_polish_selects_only_root_reasons_vstd(
    declared_package: tuple,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The package reason authority is the one root ledger, not Python prose.

    ``objects.vstd`` remains the compiled registry and package subject.  Removing
    the historical Python reason provider must not make the assessment mechanism
    unavailable when the authoritative root ``reasons.vstd`` is present.  The
    report must bind those exact bytes so no fixture, generated ledger, or source
    module can be substituted silently.
    """

    root, _manifest, _calls = declared_package
    selected_reasons = ROOT / "reasons.vstd"
    (root / "reasons.vstd").write_bytes(selected_reasons.read_bytes())
    (root / "src/verifier/runtime/tier_zero_reasons.py").unlink()

    def legacy_provider_used(_root: Path) -> dict:
        raise AssertionError(
            "package polish consulted the legacy Python reason ledger instead "
            "of the sole root reasons.vstd"
        )

    monkeypatch.setattr(
        package.tier_zero_reasons,
        "installed_reason_ledger",
        legacy_provider_used,
    )

    report = package.assess_package_polish(1, root)

    assert report.get("reason_authority") == {
        "schema_version": "verifier-package-root-reason-authority-1",
        "path": "reasons.vstd",
        "sha256": binding.bytes_digest(selected_reasons.read_bytes()),
        "authored_input_count": 1,
        "objects_registry_path": "objects.vstd",
        "only_authored_reason_input": True,
    }, report["blockers"]
    assert "PACKAGE_SOURCE_OR_EVIDENCE_UNAVAILABLE" not in report["blockers"]
    assert not any("REASON_PROVIDER" in blocker for blocker in report["blockers"])


@pytest.mark.parametrize("mutation,blocker,status", [
    ("removed_object", "TIER_ZERO_OBJECT_DENOMINATOR_DIFFERS", "FAIL"),
    ("dangling_edge", "TIER_ZERO_OBJECT_GRAPH_DIFFERS", "FAIL"),
    ("non_verifier_owner", "PACKAGE_POLISH_OWNER_NOT_VERIFIER", "FAIL"),
    ("unknown_owner", "PACKAGE_VERIFIER_ASSIGNMENT_UNRESOLVED", "UNKNOWN"),
    ("missing_reason", "TIER_ZERO_SURFACE_RULE_INVALID", "FAIL"),
])
def test_no_template_or_specimen_fallback_for_invalid_declaration(declared_package: tuple, mutation: str, blocker: str, status: str) -> None:
    root, manifest, calls = declared_package
    if mutation == "removed_object":
        manifest["objects"].pop()
    elif mutation == "dangling_edge":
        next(r for r in manifest["objects"] if r["object_kind"] == "GRAPH")["edges"]["members"].append("undeclared")
    else:
        for rule in manifest["surface_rules"]:
            if rule["category"] in {"installed_route", "installed_mechanism"}:
                if mutation == "non_verifier_owner":
                    rule["owner_object_id"] = "vstd-data"
                elif mutation == "unknown_owner":
                    rule.update(disposition="UNRESOLVED", owner_object_id=None)
                else:
                    rule["reason"] = ""
    (root / "objects.vstd").write_bytes(binding.canonical_bytes(manifest) + b"\n")
    report = package.assess_package_polish(3, root)
    assert report["status"] == status
    assert blocker in report["blockers"]
    assert not calls
    assert report["native_diagnostics"] is None


def test_manifest_change_during_execution_is_a_refutation(declared_package: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    root, manifest, _ = declared_package
    original = package._run_native_diagnostics

    def changed(tier: int, selected: Path) -> dict:
        result = original(tier, selected)
        manifest["objects"].pop()
        (selected / "objects.vstd").write_bytes(binding.canonical_bytes(manifest) + b"\n")
        return result

    monkeypatch.setattr(package, "_run_native_diagnostics", changed)
    report = package.assess_package_polish(3, root)
    assert report["status"] == "FAIL"
    assert "PACKAGE_MANIFEST_CHANGED_DURING_REPLAY" in report["blockers"]


@pytest.mark.parametrize("field,code", [("manifest", "PACKAGE_DIAGNOSTIC_MANIFEST_DIFFERS"), ("source", "PACKAGE_DIAGNOSTIC_SOURCE_DIFFERS")])
def test_unrelated_native_pass_is_rejected(declared_package: tuple, monkeypatch: pytest.MonkeyPatch, field: str, code: str) -> None:
    root, _, _ = declared_package
    original = package._run_native_diagnostics

    def unrelated(tier: int, selected: Path) -> dict:
        result = original(tier, selected)
        result.pop("report_digest")
        if field == "manifest":
            result["prerequisites"]["0"]["manifest_digest"] = PIN
        else:
            result["source_coordinate_digest"] = PIN
        return {**result, "report_digest": binding.value_digest(result)}

    monkeypatch.setattr(package, "_run_native_diagnostics", unrelated)
    report = package.assess_package_polish(3, root)
    assert report["status"] == "FAIL" and code in report["blockers"]


@pytest.mark.parametrize("status", ["FAIL", "UNKNOWN"])
def test_native_failure_or_outage_cannot_produce_package_pass(declared_package: tuple, monkeypatch: pytest.MonkeyPatch, status: str) -> None:
    root, _, _ = declared_package
    valid = package._run_native_diagnostics(3, root)
    diagnostic = deepcopy(valid)
    diagnostic.pop("report_digest")
    if status == "FAIL":
        replay = diagnostic["complete_tier_evidence_replay"]
        replay.update(status="FAIL", blockers=["STATICS_REPLAY_REFUTED"])
        diagnostic["tier_execution"]["3"] = package._native_execution_record(
            3,
            execution_status="EXECUTED",
            status="FAIL",
            reason="Fresh Tier 3 STATICS replay was refuted.",
            evidence_digest=replay["receipt_digest"],
        )
    else:
        blocking = {
            "tier": 3,
            "tier_name": "STATICS",
            "required_status": "PASS",
            "observed_status": "UNKNOWN",
            "report_digest": None,
            "blockers": ["STATICS_ASSESSMENT_UNAVAILABLE"],
        }
        diagnostic["complete_tier_evidence_replay"] = None
        diagnostic["tier_execution"]["3"] = package._native_execution_record(
            3,
            execution_status="NOT_RUN",
            status="UNKNOWN",
            reason="Fresh Tier 3 STATICS replay was unavailable.",
            blocking_prerequisite=blocking,
        )
    diagnostic["status"] = status
    diagnostic["report_digest"] = binding.value_digest(diagnostic)
    monkeypatch.setattr(package, "_run_native_diagnostics", lambda *args: diagnostic)
    report = package.assess_package_polish(3, root)
    assert report["status"] == status
    assert "PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS" in report["blockers"]


def test_missing_manifest_does_not_search_ancestor(declared_package: tuple) -> None:
    root, _, calls = declared_package
    child = root / "child"
    child.mkdir()
    report = package.assess_package_polish(3, child)
    assert report["blockers"] == ["PACKAGE_MANIFEST_MISSING"] and not calls


@pytest.mark.parametrize("status,exit_code", [("UNKNOWN", 2), ("FAIL", 1)])
def test_output_capacity_never_changes_scope(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
    exit_code: int,
) -> None:
    actual = package.assess_package_polish
    calls = []

    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "CURRENT",
            "before_digest": PIN,
            "after_digest": PIN,
            "backup_digest": None,
            "source_census_digest": PIN,
            "migration_mechanism_digest": PIN,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )

    def assessment(tier: int, root: str, *, cancelled: bool = False) -> dict:
        calls.append(cancelled)
        result = actual(tier, root, cancelled=True)
        result.pop("report_digest")
        result["status"] = status
        result["report_digest"] = binding.value_digest(result)
        return result

    monkeypatch.setattr(package, "assess_package_polish", assessment)
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", 1)
    assert main(["polish", "3", "--json"]) == exit_code
    report = json.loads(capsys.readouterr().out)
    assert calls == [False]
    assert report["schema_version"] == package.CAPACITY_REPORT_SCHEMA
    assert report["status"] == status
    assert report["claim_scope"] == "MANIFEST_PACKAGE_GRAPH"
    assert report["blockers"] == [
        "PACKAGE_POLISH_CANCELLED", "PACKAGE_REPORT_CAPACITY_EXHAUSTED",
    ]


def test_schema_invalid_pass_is_rejected_before_capacity_projection(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    actual = package.assess_package_polish
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "CURRENT",
            "before_digest": PIN,
            "after_digest": PIN,
            "backup_digest": None,
            "source_census_digest": PIN,
            "migration_mechanism_digest": PIN,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )

    def invalid_pass(*_args: object, **_kwargs: object) -> dict:
        result = actual(3, Path("."), cancelled=True)
        result.pop("report_digest")
        result["status"] = "PASS"
        result["report_digest"] = binding.value_digest(result)
        return result

    monkeypatch.setattr(package, "assess_package_polish", invalid_pass)
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", 1)

    assert main(["polish", "3", "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == (
        "verifier-manifest-package-polish-publication-rejected-1"
    )
    assert report["status"] == "UNKNOWN"
    assert report["source_report_status"] == "PASS"
    assert report["blockers"] == ["PACKAGE_POLISH_REPORT_SCHEMA_INVALID"]


def test_package_report_schema_accepts_real_declared_graph_and_refuses_false_pass(declared_package: tuple) -> None:
    import jsonschema

    schema = json.loads((ROOT / "src/verifier/schemas/verifier-manifest-package-polish-1.schema.json").read_bytes())
    validator = jsonschema.Draft202012Validator(schema)
    jsonschema.Draft202012Validator.check_schema(schema)
    report = package.assess_package_polish(3, declared_package[0])
    validator.validate(report)
    validator.validate(package.assess_package_polish(3, declared_package[0] / "missing"))
    without_findings = deepcopy(report)
    without_findings.pop("findings")
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(without_findings)
    blank_reason = deepcopy(report)
    blank_reason["findings"][0]["reason"] = "   "
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(blank_reason)
    for field, value in [("status", "PASS"), ("polished", True), ("package_graph", {})]:
        altered = {**report, field: value}
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(altered)


def test_seal_resource_failure_retains_reason_bearing_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Diagnostic resource exhaustion must remain actionable and digest-bound."""

    from verifier.runtime import manifest_gate

    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": namespace_contracts.kind_denominators(),
        "status": "UNKNOWN",
        "blockers": [],
        "findings": [{
            "scope": "repository",
            "object_id": None,
            "obligation_id": None,
            "gate_id": "existing-gate",
            "status": "UNKNOWN",
            "code": "EXISTING_UNCERTAINTY",
            "reason": "The existing uncertainty has not been resolved.",
            "explanation": "The existing uncertainty has not been resolved.",
            "next_action": "Resolve the existing uncertainty.",
            "rerun_argv": None,
        }],
        "obligation_instances": [],
    }

    def unavailable(_report: dict) -> list[dict]:
        raise MemoryError

    monkeypatch.setattr(manifest_gate, "package_findings", unavailable)
    sealed = package._seal(report)

    assert sealed["status"] == "UNKNOWN"
    assert sealed["blockers"] == ["PACKAGE_FINDINGS_UNAVAILABLE"]
    assert len(sealed["findings"]) == 1
    finding = sealed["findings"][0]
    assert finding["code"] == "PACKAGE_FINDINGS_UNAVAILABLE"
    assert finding["status"] == "UNKNOWN"
    assert finding["reason"].strip()
    assert finding["next_action"].strip()
    body = {key: value for key, value in sealed.items() if key != "report_digest"}
    assert sealed["report_digest"] == binding.value_digest(body)


def test_explicit_root_is_used_instead_of_working_directory(declared_package: tuple, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    root, _, calls = declared_package
    unrelated = root / "unrelated"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)
    assert main(["polish", "3", "--source-root", str(root), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["package_graph"]["object_count"] == 26
    assert calls == [(3, root)]


@pytest.mark.parametrize("raw,code", [
    (b'{"a":1,"a":2}\n', "TIER_ZERO_MANIFEST_DUPLICATE_KEY"),
    (b'{', "TIER_ZERO_MANIFEST_INVALID_JSON"),
    (b'{ "a": 1}\n', "TIER_ZERO_MANIFEST_NOT_CANONICAL"),
])
def test_malformed_manifest_is_fail_not_missing_or_fallback(tmp_path: Path, raw: bytes, code: str) -> None:
    (tmp_path / "objects.vstd").write_bytes(raw)
    report = package.assess_package_polish(3, tmp_path)
    assert report["status"] == "FAIL" and code in report["blockers"]
    assert report["package_graph"] is None and report["native_diagnostics"] is None


def test_source_drift_is_failure_even_when_diagnostics_are_unavailable(declared_package: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    root, _, _ = declared_package

    def unavailable(*args: object) -> dict:
        raise OSError("synthetic unavailable")

    monkeypatch.setattr(package, "_run_native_diagnostics", unavailable)
    monkeypatch.setattr(package.self_polish_tiers, "_post_replay_source_recapture", lambda *args: {"status": "FAIL"})
    report = package.assess_package_polish(3, root)
    assert report["status"] == "FAIL"
    assert "PACKAGE_ASSESSMENT_UNAVAILABLE" in report["blockers"]
    assert "PACKAGE_SOURCE_RECAPTURE_NOT_PASS" in report["blockers"]


def test_observed_facet_failure_survives_later_outage(declared_package: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    root, _, _ = declared_package
    original = package.package_self_polish._native_facets_replay

    def failed(*args: object) -> dict:
        result = original(*args)
        result["status"] = "FAIL"
        result["results"][0]["typed_facets"]["status"] = "FAIL"
        return result

    def unavailable(*args: object) -> dict:
        raise OSError("synthetic unavailable")

    monkeypatch.setattr(package.package_self_polish, "_native_facets_replay", failed)
    monkeypatch.setattr(package, "_run_native_diagnostics", unavailable)
    report = package.assess_package_polish(3, root)
    assert report["status"] == "FAIL"
    assert "PACKAGE_FACET_REPLAY_FAILED" in report["blockers"]
    assert any(r["status"] == "FAIL" for r in report["obligation_instances"])


def test_post_graph_exception_closes_v2_cumulative_execution_ledgers(
        declared_package: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    import jsonschema
    from verifier.runtime import namespace_contracts

    root, retained, _ = declared_package
    declarations = [{
        **item.to_dict(),
        "specializations": [],
        "surfaces": [],
        "reason": "Exact retained test role.",
        "classification": {},
        "obligations": {},
    } for item in package.tier_zero_manifest._namespace_objects(
        retained["objects"]
    )]
    document = {
        **retained,
        "schema_version": package.package_manifest.SCHEMA,
        "namespace": {
            "schema_version": "verifier-objects-manifest-2",
            "objects": declarations,
            "extensions": [],
            "registry_digest": namespace_contracts.registry_document(
                namespace_contracts.namespace_registry()
            )["digest"],
        },
    }
    (root / "objects.vstd").write_bytes(binding.canonical_bytes(document) + b"\n")

    def fail_after_graph(*_args: object, **_kwargs: object) -> dict:
        raise RuntimeError("SYNTHETIC_POST_GRAPH_EXCEPTION")

    monkeypatch.setattr(
        package.package_self_polish, "_native_facets_replay", fail_after_graph,
    )
    report = package.assess_package_polish(3, root)

    schema = json.loads((
        ROOT / "src/verifier/schemas/verifier-manifest-package-polish-2.schema.json"
    ).read_bytes())
    jsonschema.Draft202012Validator(schema).validate(report)
    assert report["status"] == "FAIL"
    assert "SYNTHETIC_POST_GRAPH_EXCEPTION" in report["blockers"]
    assert [row["tier"] for row in report["tier_results"]] == [1, 2, 3]
    assert all(row["execution_status"] == "NOT_RUN"
               for row in report["tier_results"])
    assert set(report["native_diagnostics"]["tier_execution"]) == {
        "0", "1", "2", "3",
    }
    assert all(
        row["execution_status"] == "NOT_RUN"
        for row in report["native_diagnostics"]["tier_execution"].values()
    )


def test_instance_exception_does_not_publish_precommitted_denominator(
        declared_package: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """An interrupted evaluation cannot expose a preflight as a receipt."""

    import jsonschema
    import subprocess
    from verifier.runtime import namespace_contracts

    root, retained, _ = declared_package
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    declarations = [{
        **item.to_dict(),
        "specializations": [],
        "surfaces": [],
        "reason": "Exact retained test role.",
        "classification": {},
        "obligations": {},
    } for item in package.tier_zero_manifest._namespace_objects(
        retained["objects"]
    )]
    document = {
        **retained,
        "schema_version": package.package_manifest.SCHEMA,
        "namespace": {
            "schema_version": "verifier-objects-manifest-2",
            "objects": declarations,
            "extensions": [],
            "registry_digest": namespace_contracts.registry_document(
                namespace_contracts.namespace_registry()
            )["digest"],
        },
    }
    (root / "objects.vstd").write_bytes(
        binding.canonical_bytes(document) + b"\n"
    )
    original_evaluate = package.InstanceEvidence.evaluate
    original_instances = package._instance_obligations
    evaluate_calls = 0
    interrupted_commitment: dict = {}

    def interrupted_evaluate(self, item, route):
        nonlocal evaluate_calls
        evaluate_calls += 1
        if evaluate_calls == 2:
            raise RuntimeError(
                "SYNTHETIC_SECOND_INSTANCE_EVALUATION_EXCEPTION"
            )
        return original_evaluate(self, item, route)

    def capture_precommit(*args, **kwargs):
        commitment = kwargs["selection_commitment"]
        try:
            return original_instances(*args, **kwargs)
        except RuntimeError:
            interrupted_commitment.update(deepcopy(commitment))
            raise

    monkeypatch.setattr(
        package.InstanceEvidence, "evaluate", interrupted_evaluate,
    )
    monkeypatch.setattr(package, "_instance_obligations", capture_precommit)

    report = package.assess_package_polish(1, root)

    schema = json.loads((
        ROOT / "src/verifier/schemas/verifier-manifest-package-polish-2.schema.json"
    ).read_bytes())
    jsonschema.Draft202012Validator(schema).validate(report)
    assert report["schema_version"] == package.EXTENSIBLE_REPORT_SCHEMA
    assert evaluate_calls == 2, (
        report["blockers"], interrupted_commitment,
    )
    assert interrupted_commitment["status"] == "PRECOMMITTED"
    assert interrupted_commitment["selected_instance_count"] > 1
    assert "commitment_digest" not in interrupted_commitment
    assert report["status"] == "FAIL"
    assert "SYNTHETIC_SECOND_INSTANCE_EVALUATION_EXCEPTION" in \
        report["blockers"]
    assert "obligation_denominator_commitment" not in \
        report["verifier_execution"]


def test_unbound_native_options_are_not_silently_ignored(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["polish", "2", "--tier1-report", "unselected.json", "--json"])
    assert stopped.value.code == 2
    assert "require --native-specimens" in capsys.readouterr().err


def test_unselected_reason_provider_is_not_silently_replaced(declared_package: tuple) -> None:
    root, manifest, calls = declared_package
    manifest["obligation_reason_provider"] = {"selection_status": "NOT_SELECTED", "path": None, "sha256": None}
    (root / "objects.vstd").write_bytes(binding.canonical_bytes(manifest) + b"\n")
    report = package.assess_package_polish(3, root)
    assert report["status"] == "UNKNOWN"
    assert "PACKAGE_REASON_PROVIDER_NOT_SELECTED" in report["blockers"]
    assert report["obligation_instances"] == [] and not calls


def test_wrong_reason_provider_bytes_are_refuted(declared_package: tuple) -> None:
    root, _, calls = declared_package
    (root / "src/verifier/runtime/tier_zero_reasons.py").write_bytes(b"substituted\n")
    report = package.assess_package_polish(3, root)
    assert report["status"] == "FAIL"
    assert "PACKAGE_REASON_PROVIDER_DIGEST_DIFFERS" in report["blockers"]
    assert not calls


@pytest.mark.parametrize(("checker_status", "expected_status", "expected_blocker"), [
    ("PASS", "UNKNOWN", None),
    ("FAIL", "FAIL", "PACKAGE_HARNESS_APPLICABILITY_SOURCE_DRIFT"),
])
@pytest.mark.parametrize("tier", [1, 2, 3])
def test_self_harness_static_checker_is_nested_but_never_promotes_instances(
        declared_package: tuple, monkeypatch: pytest.MonkeyPatch, checker_status: str,
        expected_status: str, expected_blocker: str | None, tier: int) -> None:
    import subprocess
    from verifier.runtime import namespace_contracts
    from verifier.runtime import package_harness_applicability as harness

    root, retained, _ = declared_package
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    checker = root / "src/verifier/runtime/package_harness_applicability.py"
    checker.parent.mkdir(parents=True, exist_ok=True)
    checker.write_text("PROFILE = 'fixture'\n", encoding="utf-8")
    declarations = [{**item.to_dict(), "specializations": [], "surfaces": [],
                     "reason": "Test role", "classification": {}, "obligations": {}}
                    for item in package.tier_zero_manifest._namespace_objects(retained["objects"])]
    harness_object = next(row for row in declarations if row["kind"] == "HARNESS")
    harness_object["surfaces"] = [harness.SELECTION_SURFACE]
    document = {**retained, "schema_version": package.package_manifest.SCHEMA, "namespace": {
        "schema_version": "verifier-objects-manifest-2", "objects": declarations, "extensions": [],
        "registry_digest": namespace_contracts.registry_document(
            namespace_contracts.namespace_registry())["digest"]}}
    (root / "objects.vstd").write_bytes(binding.canonical_bytes(document) + b"\n")
    finding = ([] if checker_status == "PASS" else
               [{"code": "DIRECT_LAUNCH_SOURCE_CHANGED", "launch_id": "changed"}])
    monkeypatch.setattr(harness, "assess_repository", lambda *args, **kwargs: {
        "status": "PASS" if checker_status == "PASS" else "REFUTED",
        "findings": finding, "claim_boundary": harness.CLAIM_BOUNDARY})
    report = package.assess_package_polish(tier, root)
    nested = report["kind_requirements"]["harness_applicability"]
    assert nested["selection_status"] == "SELECTED"
    assert nested["status"] == checker_status
    assert report["status"] == expected_status
    if expected_blocker is None:
        assert not any(code.startswith("PACKAGE_HARNESS_APPLICABILITY")
                       for code in report["blockers"])
    else:
        assert expected_blocker in report["blockers"]
    selected = [row for row in report["obligation_instances"]
                if row["object_id"] == harness_object["object_id"]]
    assert selected
    assert any(row["status"] == "PASS" and row["package_graph_replay_is_instance_evidence"]
               for row in selected)
    assert all(row["status"] != "PASS" for row in selected
               if not row["package_graph_replay_is_instance_evidence"])
    assert nested["execution_established"] is False
    assert nested["confinement_established"] is False


@pytest.mark.parametrize("code", [
    "CANDIDATE_SOURCE_MUTATED",
    "SOURCE_COORDINATE_MUTATED",
    "SOURCE_COORDINATE_DIFFERS",
])
def test_live_source_drift_during_native_diagnostics_is_unknown_with_rerun(
    declared_package: tuple, monkeypatch: pytest.MonkeyPatch, code: str,
) -> None:
    """Changing active source makes currency UNKNOWN, not a refuted contract."""
    root, _, _ = declared_package

    def drifted(tier: int, selected: Path) -> dict:
        raise package.self_polish_estate.EstateError(code)

    monkeypatch.setattr(package, "_run_native_diagnostics", drifted)
    report = package.assess_package_polish(1, root)

    assert report["status"] == "UNKNOWN"
    assert code in report["blockers"]
    finding = next(row for row in report["findings"] if row["code"] == code)
    assert finding["status"] == "UNKNOWN"
    assert "unchanged" in finding["next_action"]
    assert "vstd polish 1 --json" in finding["next_action"]
    # Drift is retryable, so the finding carries the exact root rerun.
    assert finding["rerun_argv"] == ["vstd", "polish", "1", "--json"]
    assert package_polish_schema_validation.validate_package_polish_report(
        report
    ).valid


def test_genuine_estate_contract_failure_remains_fail(
    declared_package: tuple, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: a non-drift estate contract refutation keeps its FAIL verdict."""
    root, _, _ = declared_package

    def refuted(tier: int, selected: Path) -> dict:
        raise package.self_polish_estate.EstateError("PYTHON_SOURCE_INVALID")

    monkeypatch.setattr(package, "_run_native_diagnostics", refuted)
    report = package.assess_package_polish(1, root)

    assert report["status"] == "FAIL"
    assert "PYTHON_SOURCE_INVALID" in report["blockers"]


def test_conditional_refutation_ledger_survives_early_check_compaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Early transport compaction never rebinds the committed conditional ledger.

    The denominator commitment digests each ``NOT_REQUIRED`` row's complete
    check when it is made. A later recomputation from compacted rows must name
    the same evidence, so a conditional non-trigger keeps its complete check
    (it is smaller than its own reference anyway) while an ordinary PASS check
    is still factored into a digest-bound reference.
    """
    route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "OBJECT-1.2"
    )
    body = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
        "object_id": "source-object",
        "object_digest": PIN,
        "collection_digest": "sha256:" + "b" * 64,
        "applicability_established": True,
        "applicability_classification": "CONDITION_NOT_MET",
        "fulfillment_required": False,
        "native_coordinate": route["coordinate"],
        "conditional_coordinate": route["coordinate"],
        "adaptation_obligation_id": "OBJECT-1.90-source-representation-facets",
        "adaptation_result_digest": "sha256:" + "c" * 64,
        "condition": route["applicability"]["condition"],
        "applicability_digest": route["applicability_digest"],
        "condition_status": "NOT_TRIGGERED",
        "reason": "The exact source representation does not select this variant.",
        "large_observation": "current-source" * 512,
    }
    conditional_check = {**body, "result_digest": binding.value_digest(body)}
    ordinary_check = {
        "status": "PASS", "reason": "Ordinary bulky observation.",
        "large_observation": "ordinary-source" * 512,
    }

    def row(check: dict, checker_status: str, object_id: str) -> dict:
        return {
            "object_id": object_id,
            "object_kind": route["object_kind"],
            "coordinate": route["coordinate"],
            "tier": route["tier"],
            "instance_digest": PIN,
            "status": "PASS",
            "checker_status": checker_status,
            "blockers": [],
            "selected_package_check": check,
            "repository_realization": {"explanation": "Source adaptation passed."},
        }

    conditional = row(conditional_check, "NOT_REQUIRED", "source-object")
    ordinary = row(ordinary_check, "PASS", "ordinary-object")
    committed = package._conditional_refutation_index([conditional])
    monkeypatch.setattr(package, "MAX_INLINE_INSTANCE_PAYLOAD_BYTES", 1)
    monkeypatch.setattr(package, "MAX_INLINE_SELECTED_CHECK_BYTES", 1)

    package._compact_successful_instance_checks([conditional, ordinary])

    assert package._conditional_refutation_index([conditional]) == committed
    assert conditional["selected_package_check"] == conditional_check
    assert "full_check_digest" in ordinary["selected_package_check"]
