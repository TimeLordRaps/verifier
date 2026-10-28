"""Focused regressions for cumulative human package-polish output."""

from __future__ import annotations

import json

from verifier.runtime import namespace_classification
from verifier.runtime import package_manifest_refresh
from verifier.runtime import package_polish
from verifier.runtime import self_polish_tiers


def _run_human_package_polish(monkeypatch, tmp_path, report):
    digest = "sha256:" + "1" * 64
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "CURRENT",
            "before_digest": digest,
            "after_digest": digest,
            "backup_digest": None,
            "source_census_digest": "sha256:" + "2" * 64,
            "migration_mechanism_digest": "sha256:" + "3" * 64,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: report,
    )
    return self_polish_tiers.handle_self_polish_tier_argv([
        "3", "--source-root", str(tmp_path), "--manifest-refresh", "check",
    ])


def test_tier3_refresh_blocker_human_output_retains_all_not_run_tiers(
        monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "REFRESH_REQUIRED",
            "blockers": ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )

    def unexpected(*_args, **_kwargs):
        raise AssertionError("stale package assessor must not run")

    monkeypatch.setattr(
        package_polish, "assess_package_polish", unexpected,
    )

    exit_code = self_polish_tiers.handle_self_polish_tier_argv([
        "3", "--source-root", str(tmp_path), "--manifest-refresh", "check",
    ])
    output = capsys.readouterr().out

    assert exit_code == 2
    assert "package denominator=NOT_RETAINED" in output
    for depth in (1, 2, 3):
        assert f"package tier {depth}: execution=NOT_RUN" in output
    for depth in (0, 1, 2, 3):
        assert f"native tier {depth}" in output
    assert output.count("execution=NOT_RUN") >= 7
    assert "MANIFEST_REFRESH_REQUIRED_READ_ONLY" in output
    assert "refresh did not complete" in output


def test_tier3_human_output_exposes_every_native_tier_and_exact_rerun(
        monkeypatch, tmp_path, capsys) -> None:
    obligation_id = "SIM-2.4-fresh-execution-resource-accounting"
    rerun = [
        "vstd", "gate", "--object", "sim-main", "--obligation",
        obligation_id,
    ]
    report = {
        "schema_version": package_polish.REPORT_SCHEMA,
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS"],
        "package_graph": {"object_count": 461},
        "obligation_instances": [],
        "tier_results": [
            {
                "tier": 1, "instance_count": 5,
                "status_counts": {"PASS": 5}, "status": "PASS",
                "checker_status_counts": {"PASS": 5},
            },
            {
                "tier": 2, "instance_count": 3,
                "status_counts": {"UNKNOWN": 3}, "status": "UNKNOWN",
                "checker_status_counts": {"NOT_RUN": 3},
            },
            {
                "tier": 3, "instance_count": 2,
                "status_counts": {"UNKNOWN": 2}, "status": "UNKNOWN",
                "checker_status_counts": {"NOT_RUN": 2},
            },
        ],
        "native_diagnostics": {
            "status": "UNKNOWN",
            "tier_execution": {
                "0": {
                    "tier": 0, "tier_name": "ADMISSION",
                    "execution_status": "EXECUTED", "status": "PASS",
                },
                "1": {
                    "tier": 1, "tier_name": "FACETS",
                    "execution_status": "EXECUTED", "status": "PASS",
                },
                "2": {
                    "tier": 2, "tier_name": "DYNAMICS",
                    "execution_status": "EXECUTED", "status": "UNKNOWN",
                    "reason": "Fresh resource evidence was not established.",
                },
                "3": {
                    "tier": 3, "tier_name": "STATICS",
                    "execution_status": "NOT_RUN", "status": "UNKNOWN",
                    "reason": "Tier 2 did not pass.",
                    "blocking_prerequisite": {
                        "tier": 2, "status": "UNKNOWN",
                    },
                },
            },
            "prerequisites": {
                "0": {"status": "PASS"},
                "1": {"status": "PASS"},
                "2": {
                    "status": "UNKNOWN",
                    "blockers": ["TIER2_FRESH_EVIDENCE_NOT_ESTABLISHED"],
                    "nonpass_records": [{
                        "status": "UNKNOWN",
                        "object_id": "sim-main",
                        "obligation_id": obligation_id,
                        "gate_id": "fresh-execution-resource",
                        "coordinate": "SIM-2.4",
                        "path": "$.prerequisites.2.obligations[3]",
                        "reason": "Measured fresh execution was unavailable.",
                        "blockers": ["SIM_RESOURCE_EXECUTION_NOT_ESTABLISHED"],
                        "rerun_argv": rerun,
                    }],
                },
            },
        },
        "findings": [],
    }

    assert _run_human_package_polish(monkeypatch, tmp_path, report) == 2
    output = capsys.readouterr().out

    assert "package tier 1: execution=EXECUTED; result=PASS; instances=5" in output
    assert "package tier 2: execution=EXECUTED; result=UNKNOWN; instances=3" in output
    assert "package tier 3: execution=EXECUTED; result=UNKNOWN; instances=2" in output
    assert "native tier 0 ADMISSION: execution=EXECUTED; result=PASS" in output
    assert "native tier 1 FACETS: execution=EXECUTED; result=PASS" in output
    assert "native tier 2 DYNAMICS: execution=EXECUTED; result=UNKNOWN" in output
    assert "native tier 3 STATICS: execution=NOT_RUN; result=UNKNOWN" in output
    assert 'blocking_prerequisite={"status":"UNKNOWN","tier":2}' in output
    assert (
        'prerequisite_blockers=["TIER2_FRESH_EVIDENCE_NOT_ESTABLISHED"]'
    ) in output
    assert (
        "object=sim-main obligation=" + obligation_id
        + " gate=fresh-execution-resource coordinate=SIM-2.4 "
        + "path=$.prerequisites.2.obligations[3]"
    ) in output
    assert (
        'rerun_argv=["vstd","gate","--object","sim-main","--obligation","'
        + obligation_id + '"]'
    ) in output


def test_tier_zero_original_kind_focus_survives_human_cumulative_output(
        capsys) -> None:
    obligation_id = "VSTD-T0.2-object-denominator-closure"
    reason = (
        "The original-kind applicability cell for object vstd-simulation and "
        "kind MODEL is not source-closed."
    )
    next_action = (
        "Audit this exact object/kind against its owned current source, then "
        "bind the source-audited decision."
    )
    rerun = [
        "vstd", "gate", "--object", "vstd-simulation",
        "--obligation", obligation_id,
    ]
    native_record = {
        "path": "$.prerequisites.0.findings[0]",
        "status": "UNKNOWN",
        "object_id": "vstd-simulation",
        "object_kind": "SIM",
        "classification_kind": "MODEL",
        "obligation_id": obligation_id,
        "gate_id": "object-inventory",
        "coordinate": "VSTD-T0.2",
        "reason": reason,
        "next_action": next_action,
        "rerun_argv": rerun,
        "blockers": [
            "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
            "vstd-simulation:MODEL"
        ],
    }
    self_polish_tiers._print_native_nonpass_record(native_record, tier=0)
    output = capsys.readouterr().out

    assert "object=vstd-simulation" in output
    assert "object_kind=SIM" in output
    assert "classification_kind=MODEL" in output
    assert "gate=object-inventory" in output
    assert "obligation=" + obligation_id in output
    assert "reason=" + reason in output
    assert "Next: " + next_action in output
    assert 'rerun_argv=["vstd","gate","--object","vstd-simulation"' in output


def test_numeric_polish_zero_json_preserves_exact_original_kind_finding(
        monkeypatch, tmp_path, capsys) -> None:
    digest = "sha256:" + "1" * 64
    obligation_id = "VSTD-T0.2-object-denominator-closure"
    reason = (
        "The original-kind applicability cell for object vstd-simulation and "
        "kind MODEL is not source-closed."
    )
    next_action = "Audit the exact vstd-simulation:MODEL source decision."
    finding = {
        "scope": "object",
        "object_id": "vstd-simulation",
        "object_kind": "SIM",
        "classification_kind": "MODEL",
        "coordinate": "VSTD-T0.2",
        "obligation_id": obligation_id,
        "gate_id": "object-inventory",
        "status": "UNKNOWN",
        "code": (
            "PACKAGE_ORIGINAL_KIND_CATALOG_UNRESOLVED:"
            "vstd-simulation:MODEL"
        ),
        "reason": reason,
        "explanation": reason,
        "next_action": next_action,
        "rerun_argv": [
            "vstd", "gate", "--object", "vstd-simulation",
            "--obligation", obligation_id,
        ],
    }
    report = {
        "schema_version": "verifier-tier-zero-package-admission-report-4",
        "status": "UNKNOWN",
        "obligation_count": 9,
        "obligations": [],
        "blockers": [finding["code"]],
        "findings": [finding],
        "tier_1_plus_status": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
        "report_digest": digest,
    }
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "CURRENT",
            "before_digest": digest,
            "after_digest": digest,
            "backup_digest": None,
            "source_census_digest": digest,
            "migration_mechanism_digest": digest,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(
        package_polish.tier_zero,
        "assess_tier_zero",
        lambda *_args, **_kwargs: report,
    )

    exit_code = self_polish_tiers.handle_self_polish_tier_argv([
        "0", "--source-root", str(tmp_path), "--manifest-refresh", "check",
        "--json",
    ])
    selected = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    [actual] = selected["findings"]
    for field in (
        "gate_id", "object_id", "object_kind", "classification_kind",
        "obligation_id", "reason", "next_action", "rerun_argv",
    ):
        assert actual[field] == finding[field]


def test_capacity_not_retained_human_output_is_explicitly_incomplete(
        monkeypatch, tmp_path, capsys) -> None:
    report = {
        "schema_version": package_polish.CAPACITY_REPORT_SCHEMA,
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_REPORT_CAPACITY_EXHAUSTED"],
        "package_graph": None,
        "package_graph_reference": {"object_count": 461},
        "obligation_instances": [],
        "obligation_index": {"instance_count": 0, "entries": []},
        "denominator_status": "NOT_RETAINED",
        "native_diagnostics": None,
        "findings": [],
    }

    assert _run_human_package_polish(monkeypatch, tmp_path, report) == 2
    output = capsys.readouterr().out

    assert "package denominator=NOT_RETAINED" in output
    assert "cumulative report not complete" in output
    for depth in range(4):
        assert (
            f"native tier {depth}: execution=NOT_RETAINED; result=UNKNOWN"
        ) in output
    assert "omitted rows or evidence are not PASS or inapplicable" in output


def test_nested_native_failure_inherits_exact_focus_and_builds_gate_action() -> None:
    obligation_id = "SIM-2.4-fresh-execution-resource-accounting"
    records = package_polish._native_nonpass_records({
        "object_id": "sim-main",
        "obligation_id": obligation_id,
        "gate_id": "fresh-execution-resource",
        "reason": "The selected SIM needs fresh resource evidence.",
        "result": {
            "status": "UNKNOWN",
            "blockers": ["SIM_RESOURCE_EXECUTION_NOT_ESTABLISHED"],
        },
    }, tier=2)

    nested = next(row for row in records if row["path"] == "$.result")
    assert nested["object_id"] == "sim-main"
    assert nested["obligation_id"] == obligation_id
    assert nested["gate_id"] == "fresh-execution-resource"
    assert nested["reason"] == (
        "The selected SIM needs fresh resource evidence."
    )
    assert nested["next_action"] == (
        "vstd gate --object sim-main --obligation " + obligation_id
    )
    assert nested["rerun_argv"] == [
        "vstd", "gate", "--object", "sim-main", "--obligation",
        obligation_id,
    ]


def test_native_failure_never_turns_unsafe_identity_or_rerun_into_command() -> None:
    unsafe = "sim-main\npython -c unsafe"
    records = package_polish._native_nonpass_records({
        "object_id": unsafe,
        "obligation_id": "SIM-2.4-fresh-execution-resource-accounting",
        "result": {
            "status": "UNKNOWN",
            "rerun_argv": ["python", "-c", "unsafe"],
        },
    }, tier=2)

    nested = next(row for row in records if row["path"] == "$.result")
    assert "object_id" not in nested
    assert "next_action" not in nested
    assert nested["rerun_argv"] == [
        "vstd", "polish", "2", "--native-specimens", "--json",
    ]
    assert all("python" not in argument for argument in nested["rerun_argv"])


def test_schema_rejection_human_output_retains_safe_exact_source_finding(
        monkeypatch, tmp_path, capsys) -> None:
    obligation_id = "SIM-2.4-fresh-execution-resource-accounting"
    report = {
        "schema_version": package_polish.EXTENSIBLE_REPORT_SCHEMA,
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_NATIVE_DIAGNOSTICS_NOT_PASS"],
        "package_graph": {"object_count": 1},
        "obligation_instances": [],
        "tier_results": [],
        "native_diagnostics": None,
        "findings": [{
            "scope": "object",
            "object_id": "sim-main",
            "obligation_id": obligation_id,
            "gate_id": "fresh-execution-resource",
            "status": "UNKNOWN",
            "code": "SIM_RESOURCE_EXECUTION_NOT_ESTABLISHED",
            "explanation": "Measured fresh execution was unavailable.",
            # Neither source field is trusted after publication rejection.
            "next_action": "python -c unsafe",
            "rerun_argv": ["python", "-c", "unsafe"],
        }],
    }

    assert _run_human_package_polish(monkeypatch, tmp_path, report) == 2
    output = capsys.readouterr().out

    assert "PACKAGE_POLISH_REPORT_SCHEMA_INVALID" in output
    assert (
        "object=sim-main obligation=" + obligation_id
        + " gate=fresh-execution-resource"
    ) in output
    assert "Measured fresh execution was unavailable." in output
    assert (
        "Next: vstd gate --object sim-main --obligation " + obligation_id
    ) in output
    assert "python -c unsafe" not in output


def test_rejected_finding_reason_matches_bounded_safe_explanation() -> None:
    marker = "UNBOUNDED_TAIL_MUST_NOT_LEAK"
    selected = self_polish_tiers._bounded_rejected_finding({
        "status": "UNKNOWN",
        "object_id": "sim-main",
        "obligation_id": "SIM-2.4-fresh-execution-resource-accounting",
        "gate_id": "fresh-execution-resource",
        "explanation": "measured\n" + "x" * 4096 + marker,
        "next_action": "python -c unsafe",
        "rerun_argv": ["python", "-c", "unsafe"],
    })

    assert selected is not None
    assert selected["reason"] == selected["explanation"]
    assert "\\n" in selected["reason"]
    assert "\n" not in selected["reason"]
    assert marker not in selected["reason"]
    assert selected["next_action"] == (
        "vstd gate --object sim-main --obligation "
        "SIM-2.4-fresh-execution-resource-accounting"
    )
    assert all("python" not in value for value in selected["rerun_argv"])



def _many_instance_findings(count: int) -> list[dict]:
    return [
        {
            "scope": "object", "object_id": f"object-{index:04d}", "object_kind": "SENSOR",
            "coordinate": "SENSOR-1.1", "obligation_id": "SENSOR-1.1-step",
            "obligation_name": "Step", "semantic_version": "v1", "gate_id": "applicability",
            "status": "UNKNOWN", "code": "PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED",
            "explanation": "No object-specific necessity reason is established.",
            "reason": "No object-specific necessity reason is established.",
            "next_action": "Supply source-bound applicability evidence.",
            "rerun_argv": ["vstd", "gate", "--object", f"object-{index:04d}",
                           "--obligation", "SENSOR-1.1-step"],
        }
        for index in range(count)
    ]


def _plain_report(**overrides) -> dict:
    report = {
        "schema_version": package_polish.REPORT_SCHEMA,
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED"],
        "package_graph": {"object_count": 461},
        "obligation_instances": [],
        "tier_results": [],
        "native_diagnostics": None,
        "findings": [],
    }
    report.update(overrides)
    return report


def test_package_polish_human_output_groups_a_long_finding_list(
        capsys) -> None:
    report = _plain_report(findings=_many_instance_findings(900))

    self_polish_tiers._print_package_polish_summary(report, 3)
    output = capsys.readouterr().out

    assert output.count("PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED") <= 3
    assert "[UNKNOWN] 900x PACKAGE_INSTANCE_APPLICABILITY_NOT_ESTABLISHED" in output
    assert "objects=900" in output
    assert "Next: Supply source-bound applicability evidence." in output
    assert "vstd gate --object object-0000 --obligation SENSOR-1.1-step" in output
    assert output.count("object=object-") == 0


def test_package_polish_human_output_keeps_a_short_finding_list_in_full(
        capsys) -> None:
    report = _plain_report(findings=_many_instance_findings(3))

    self_polish_tiers._print_package_polish_summary(report, 3)
    output = capsys.readouterr().out

    for index in range(3):
        assert f"object=object-{index:04d} obligation=SENSOR-1.1-step" in output
    assert "Next actions:" not in output


def _native_report(records: list[dict]) -> dict:
    return _plain_report(native_diagnostics={
        "status": "UNKNOWN",
        "tier_execution": {"0": {
            "tier": 0, "tier_name": "ADMISSION", "execution_status": "EXECUTED",
            "status": "UNKNOWN",
        }},
        "prerequisites": {"0": {"status": "UNKNOWN", "nonpass_records": records}},
    })


def _native_records(count: int) -> list[dict]:
    return [
        {
            "status": "UNKNOWN", "object_id": f"object-{index:04d}",
            "obligation_id": "VSTD-T0.2-namespace-admission", "gate_id": "namespace-admission",
            "coordinate": "VSTD-T0.2", "path": f"$.prerequisites.0.obligations[{index}]",
            "reason": "A classification question is unresolved.",
            "rerun_argv": ["vstd", "gate", "--object", f"object-{index:04d}",
                           "--obligation", "VSTD-T0.2-namespace-admission"],
        }
        for index in range(count)
    ]


def test_package_polish_human_output_groups_a_long_native_record_list(
        capsys) -> None:
    report = _native_report(_native_records(700))

    self_polish_tiers._print_package_polish_summary(report, 3)
    output = capsys.readouterr().out

    assert output.count("native tier 0 nonpass") <= 4
    assert "700x" in output
    assert "gate=namespace-admission" in output
    command = "vstd gate --object object-0000 --obligation "
    assert command in output
    printed = output.split(command, 1)[1].split()[0]
    assert {"obligation_id": printed} == {"obligation_id": "VSTD-T0.2-namespace-admission"}


def test_package_polish_human_output_keeps_a_short_native_record_list_in_full(
        capsys) -> None:
    report = _native_report(_native_records(2))

    self_polish_tiers._print_package_polish_summary(report, 3)
    output = capsys.readouterr().out

    assert output.count("[UNKNOWN] native tier 0 nonpass") == 2


def _long_blockers() -> list[str]:
    adopted = [
        f"PACKAGE_SEMANTIC_REVIEW_UNADOPTED:vstd-controller:KIND-{index:02d}"
        for index in range(40)
    ]
    unresolved = [
        f"PACKAGE_SEMANTIC_REVIEW_UNRESOLVED:vstd-crosswalk-{index // 4}:KIND-{index % 4}"
        for index in range(20)
    ]
    plain = ["NAMESPACE_CLASSIFICATION_UNRESOLVED", "NAMESPACE_LABEL_CONTRADICTS_SOURCE"]
    return sorted(adopted + unresolved + plain)


def _blocked_native_report(blockers: list[str]) -> dict:
    anchor = {
        "blockers": blockers, "observed_status": "FAIL", "required_status": "PASS",
        "tier": 0, "tier_name": "ADMISSION", "report_digest": "sha256:" + "d" * 64,
    }
    dependent = {
        "tier": 1, "tier_name": "FACETS", "execution_status": "NOT_RUN",
        "status": "UNKNOWN", "reason": "Tier 1 was not executed because Tier 0 FAIL.",
        "blocking_prerequisite": anchor,
    }
    return _plain_report(native_diagnostics={
        "status": "FAIL",
        "tier_execution": {
            "0": {"tier": 0, "tier_name": "ADMISSION", "execution_status": "EXECUTED",
                  "status": "FAIL", "reason": "Tier 0 was executed."},
            "1": dependent,
            "2": {**dependent, "tier": 2, "tier_name": "DYNAMICS"},
            "3": {**dependent, "tier": 3, "tier_name": "STATICS"},
        },
        "prerequisites": {"0": {"status": "FAIL", "blockers": blockers}},
    })


def test_a_long_blocker_list_is_grouped_once_not_repeated_for_every_tier(capsys) -> None:
    report = _blocked_native_report(_long_blockers())

    self_polish_tiers._print_package_polish_summary(report, 3)
    output = capsys.readouterr().out

    # Every group is named with its size, and no individual blocker is spelled out.
    assert "40x PACKAGE_SEMANTIC_REVIEW_UNADOPTED" in output
    assert "20x PACKAGE_SEMANTIC_REVIEW_UNRESOLVED" in output
    assert "NAMESPACE_CLASSIFICATION_UNRESOLVED" in output
    assert "vstd-controller" in output
    assert "KIND-17" not in output
    # The dependent tiers point back at the one listing instead of copying it.
    assert output.count("PACKAGE_SEMANTIC_REVIEW_UNADOPTED") == 1
    assert "same blockers as native tier 0" in output
    assert len(output) < 3000


def test_a_short_blocker_list_is_still_printed_in_full(capsys) -> None:
    blockers = ["NAMESPACE_AGENCY_BINDING_UNRESOLVED", "NAMESPACE_CLASSIFICATION_UNRESOLVED"]
    report = _blocked_native_report(blockers)

    self_polish_tiers._print_package_polish_summary(report, 3)
    output = capsys.readouterr().out

    assert "  prerequisite_blockers=" + json.dumps(
        blockers, sort_keys=True, separators=(",", ":")
    ) in output
    assert output.count("NAMESPACE_AGENCY_BINDING_UNRESOLVED") >= 2
    assert "same blockers as" not in output


def _admission_finding(object_id: str, *, status: str = "UNKNOWN",
                       code: str = "NAMESPACE_CLASSIFICATION_UNRESOLVED") -> dict:
    # The installed constructor, so the fixture has the real shape: no ``scope`` key.
    return namespace_classification.finding(
        code, status, "VSTD-T0.2",
        object_id + ": Provide a repository-specific reason and current source evidence.",
        "Record APPLIES or an evidenced DOES_NOT_APPLY reason for this kind.",
        object_id=object_id, obligation_id="VSTD-T0.2-namespace-admission")


def _run_human_tier_zero(monkeypatch, tmp_path, capsys, findings: list[dict]) -> str:
    digest = "sha256:" + "1" * 64
    obligations = [
        {"coordinate": "VSTD-T0.1", "name": "Canonical manifest admission",
         "status": "PASS", "blockers": []},
        {"coordinate": "VSTD-T0.2", "name": "Object denominator closure", "status": "FAIL",
         "blockers": sorted({row["code"] for row in findings})},
    ]
    report = {
        "schema_version": "verifier-tier-zero-package-admission-report-4",
        "status": "FAIL", "obligation_count": 2, "obligations": obligations,
        "blockers": sorted({code for row in obligations for code in row["blockers"]}),
        "findings": findings, "tier_1_plus_status": "NOT_ESTABLISHED", "polished": False,
        "release_authorized": False, "deployment_authorized": False, "report_digest": digest,
    }
    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA, "status": "CURRENT",
            "before_digest": digest, "after_digest": digest, "backup_digest": None,
            "source_census_digest": digest, "migration_mechanism_digest": digest,
            "refresh_is_admission": False, "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(package_polish.tier_zero, "assess_tier_zero", lambda *_a, **_k: report)
    exit_code = self_polish_tiers.handle_self_polish_tier_argv(
        ["0", "--source-root", str(tmp_path), "--manifest-refresh", "check"])
    assert exit_code == 1
    return capsys.readouterr().out


def test_tier_zero_human_output_states_each_obligation_and_groups_a_long_finding_list(
        monkeypatch, tmp_path, capsys) -> None:
    findings = [_admission_finding(f"vstd-object-{index:03d}") for index in range(400)]
    findings.append(_admission_finding(
        "vstd-domain-grounding-specimen", status="FAIL", code="NAMESPACE_LABEL_CONTRADICTS_SOURCE"))

    output = _run_human_tier_zero(monkeypatch, tmp_path, capsys, findings)

    # Where admission stands: one line per obligation, in order.
    assert "VSTD-T0.1 PASS Canonical manifest admission" in output
    assert "VSTD-T0.2 FAIL Object denominator closure" in output
    assert output.index("VSTD-T0.1 PASS") < output.index("VSTD-T0.2 FAIL")
    # What to do next: the refutation first, the open cells as one counted group.
    assert "400x NAMESPACE_CLASSIFICATION_UNRESOLVED" in output
    assert output.index("NAMESPACE_LABEL_CONTRADICTS_SOURCE") < output.index("400x")
    assert "object=vstd-domain-grounding-specimen" in output
    assert "vstd-object-399" not in output
    assert len(output) < 4000


def test_tier_zero_human_output_keeps_a_short_finding_list_in_full(
        monkeypatch, tmp_path, capsys) -> None:
    findings = [_admission_finding(f"vstd-object-{index}") for index in range(3)]

    output = _run_human_tier_zero(monkeypatch, tmp_path, capsys, findings)

    assert "VSTD-T0.2 FAIL Object denominator closure" in output
    for index in range(3):
        assert f"object=vstd-object-{index} " in output
