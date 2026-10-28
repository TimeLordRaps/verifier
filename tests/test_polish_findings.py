"""Observational report controls, including false-fix and false-regression attacks.

Terminology: command-line interface (CLI); JavaScript Object Notation (JSON).
Fixtures are carried diagnostics, not authenticated executions or certificates.
"""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.runtime import polish_findings as reports


def attempt(state: str, execution: str = "EXECUTED") -> dict:
    rows = [{"path": "demo.py", "sha256": "sha256:" + "2" * 64, "size_bytes": 12}]
    binding = {"policy_sha256": "sha256:" + "1" * 64,
               "source": {"files": rows, "sha256": reports._digest(canonical_bytes(rows))},
               "implementation": {"mechanisms": {name: "sha256:" + "3" * 64 for name in reports._WORKFLOW_MECHANISMS},
                                  "python_version": "3.12.8", "platform": "win32", "interpreter_sha256": "sha256:" + "4" * 64}}
    return {"schema_version": "verifier-polish-workflow-report-1", "status": state,
        "polished": False, "binding": binding, "binding_digest": reports._digest(canonical_bytes(binding)),
        "stages": [{"id": "quality", "required": True, "selected": True,
                    "status": state, "execution_status": execution}],
        "findings": [{"code": "STAGE_BLOCKED", "stage": "quality", "status": state}] if state != "PASS" else []}


def project(value: dict, previous: dict | None = None, history: tuple[dict, ...] = ()) -> dict:
    return reports.project_reports(canonical_bytes(value), previous_bytes=canonical_bytes(previous) if previous else None,
                                   history_bytes=[canonical_bytes(row) for row in history])


def test_stable_ids_preserve_every_occurrence_and_input_pointer() -> None:
    first = attempt("FAIL")
    first["findings"] += [{"code": "OTHER", "status": "FAIL", "path": "demo.py"}]
    changed = deepcopy(first)
    changed["findings"].reverse()
    changed["binding"]["source"]["files"][0]["sha256"] = "sha256:" + "3" * 64
    before, after = project(first), project(changed)
    assert {row["finding_id"] for row in before["findings"]} == {row["finding_id"] for row in after["findings"]}
    assert all(o["input_digest"] == after["inputs"][-1]["sha256"] and o["pointer"].startswith("/")
               for row in after["findings"] for o in row["occurrences"] if "diagnostic_emitter" not in o["source_anchor"])
    assert all(o["input_digest"] == after["diagnostic_selection"]["selection_digest"]
               for row in after["findings"] for o in row["occurrences"] if "diagnostic_emitter" in o["source_anchor"])


@pytest.mark.parametrize("control", ["NOT_RUN", "NOT_SELECTED", "OMITTED", "POLICY_CHANGED", "MECHANISM_CHANGED"])
def test_disappearing_failure_is_not_fixed_by_unrun_deselection_or_changed_scope(control: str) -> None:
    previous = attempt("FAIL")
    current = attempt("PASS")
    if control == "OMITTED":
        current["stages"] = []
    elif control == "POLICY_CHANGED":
        current["binding"]["policy_sha256"] = "sha256:" + "4" * 64
    elif control == "MECHANISM_CHANGED":
        current["binding"]["implementation"] = {"checker": "changed"}
    else:
        current["stages"][0]["execution_status"] = control
        if control == "NOT_SELECTED":
            current["stages"][0].update(status="NOT_SELECTED", selected=False)
    result = project(current, previous)
    assert result["delta"]["fixed"] == []
    assert result["delta"]["unobserved"]
    assert result["polished"] == "NOT_ASSESSED" and result["authentication"] == "NOT_ESTABLISHED"


def test_explicit_same_scope_executed_pass_observation_can_be_fixed() -> None:
    result = project(attempt("PASS"), attempt("FAIL"))
    assert result["delta"]["comparison"] == "COMPARABLE_OBSERVATIONS"
    assert result["delta"]["fixed"]
    assert any(row["code"] == "POLISHED_ARTIFACT_NOT_ESTABLISHED" for row in result["findings"])


def test_conflicting_occurrence_prevents_false_fixed() -> None:
    current = attempt("PASS")
    current["stages"].append({**current["stages"][0], "status": "UNKNOWN"})
    result = project(current, attempt("FAIL"))
    assert result["delta"]["fixed"] == []
    assert any(row["code"] == "CHECK_UNKNOWN" for row in result["findings"])


def test_regression_requires_prior_pass_and_unknown_to_fail_is_new_refutation() -> None:
    assert project(attempt("FAIL"), attempt("UNKNOWN"))["delta"]["regressed"] == []
    result = project(attempt("FAIL"), attempt("UNKNOWN"), (attempt("PASS"),))
    assert result["delta"]["regressed"]
    assert result["chronology"] == "CALLER_SELECTED_ORDER"


def test_open_required_slots_remain_visible_beside_declared_coverage_pass() -> None:
    report = {"schema_version": "verifier-polish-requirements-assessment-1", "status": "UNKNOWN",
        "declared_coverage": "PASS", "polished": False, "open_required_slots": [{"object_id": "verifier", "tier": 4}],
        "inventory_authentication": "NOT_ESTABLISHED", "objective_inventory_closure": "NOT_ESTABLISHED",
        "native_assessment": {"schema_version": "verifier-polish-assessment-2", "status": "UNKNOWN",
            "objectives": [{"object_id": "verifier", "coordinate": "VERIFIER-2.1", "status": "UNKNOWN",
                            "reason": "NATIVE_REPLAY_UNAVAILABLE"}], "remaining_gates": ["PUBLIC_CHECKABILITY_FOR_EVERY_REQUIRED_OBJECTIVE"]}}
    result = project(report)
    codes = {row["code"] for row in result["findings"]}
    assert {"OPEN_REQUIRED_SLOT", "INVENTORY_AUTHENTICATION", "NATIVE_REPLAY_UNAVAILABLE",
            "PUBLIC_CHECKABILITY_FOR_EVERY_REQUIRED_OBJECTIVE"} <= codes
    rendered = reports.render_findings(result)
    assert "Next:" in rendered and "input_digest" in rendered and "verifier" in rendered


@pytest.mark.parametrize("raw", [b'{"schema_version":"unknown"}', b'{"schema_version":"verifier-quality-report-1","status":"PASS","status":"FAIL"}',
                                 b'{"schema_version":"verifier-quality-report-1","value":NaN}'])
def test_unsupported_duplicate_or_nonfinite_reports_are_refused(raw: bytes) -> None:
    with pytest.raises(ValueError):
        reports.project_reports(raw)


def test_tampered_carried_digest_and_history_bounds_are_refused() -> None:
    value = attempt("FAIL")
    value["report_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="digest differs"):
        project(value)
    with pytest.raises(ValueError, match="bound"):
        reports.project_reports(canonical_bytes(attempt("FAIL")), history_bytes=[b"{}"] * 17)


def test_cli_readonly_report_has_json_and_complete_human_findings(tmp_path, capsys) -> None:
    from verifier.runtime.public_cli import main, POLISH_SUBCOMMANDS
    source = tmp_path / "report.json"
    raw = canonical_bytes(attempt("FAIL", "NOT_RUN"))
    source.write_bytes(raw)
    assert "report" in POLISH_SUBCOMMANDS
    assert main(["polish", "report", str(source), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == reports.SCHEMA
    assert main(["polish", "report", str(source)]) == 1
    shown = capsys.readouterr().out
    assert "STAGE_BLOCKED" in shown and "NOT_RUN" in shown and "Next:" in shown
    assert source.read_bytes() == raw


@pytest.mark.parametrize("pin", ["", {}, [], "sha256:wrong", None])
def test_empty_or_invalid_requirement_pin_cannot_clear_old_failure(pin) -> None:
    before, after = attempt("FAIL"), attempt("PASS")
    before["binding"]["policy_sha256"] = after["binding"]["policy_sha256"] = pin
    result = project(after, before)
    assert result["delta"]["comparison"] == "INCOMPARABLE_SCOPE"
    assert result["delta"]["fixed"] == []


@pytest.mark.parametrize("mode", ["missing", "empty", "duplicate"])
def test_ambiguous_check_identity_cannot_clear_old_failure(mode: str) -> None:
    before, after = attempt("FAIL"), attempt("PASS")
    for row in (before, after):
        if mode == "missing":
            row["stages"][0].pop("id")
        elif mode == "empty":
            row["stages"][0]["id"] = ""
        else:
            row["stages"].append(dict(row["stages"][0]))
    result = project(after, before)
    assert result["delta"]["comparison"] == "INCOMPARABLE_SCOPE"
    assert result["delta"]["fixed"] == []


def test_nested_native_subject_scope_cannot_disappear_or_change() -> None:
    before, after = attempt("FAIL"), attempt("PASS")
    native = {"schema_version": "verifier-polish-assessment-2", "status": "UNKNOWN",
              "objectives": [{"object_id": "subject", "object_kind": "OBJECT", "coordinate": "OBJECT-1.1",
                              "semantic_version": "verifier-current-object-obligations-1", "status": "UNKNOWN"}]}
    before["native_assessment"] = deepcopy(native)
    after["native_assessment"] = deepcopy(native)
    after["native_assessment"]["objectives"][0]["object_id"] = "foreign-subject"
    result = project(after, before)
    assert result["delta"]["comparison"] == "INCOMPARABLE_SCOPE" and not result["delta"]["fixed"]


def test_line_and_free_text_reason_changes_preserve_finding_identity() -> None:
    before = attempt("FAIL")
    before["findings"] = [{"status": "FAIL", "reason": "Specific old detail", "line": 2, "path": "demo.py"}]
    after = deepcopy(before)
    after["findings"][0].update(reason="Updated exact detail", line=5)
    first, second = project(before), project(after)
    assert {row["finding_id"] for row in first["findings"]} == {row["finding_id"] for row in second["findings"]}
    assert any(o["source_anchor"]["declared_line"] == 5 for row in second["findings"] for o in row["occurrences"])


def test_actual_compilation_report_definition_pin_and_public_hold_are_visible() -> None:
    report = {"schema_version": "verifier-prdel-compilation-report-1", "status": "UNKNOWN",
              "definition_digest": "sha256:" + "1" * 64, "public_checkability": "NOT_ESTABLISHED"}
    result = project(report)
    assert result["comparison_scope"]["pins"]["definition_digest"] == report["definition_digest"]
    assert any(row["code"] == "PUBLIC_CHECKABILITY" for row in result["findings"])


def test_terminal_control_text_is_escaped_and_descendant_details_are_not_duplicated() -> None:
    report = attempt("FAIL")
    report["stages"][0]["id"] = "quality\x1b[2J\nforged"
    report["findings"][0].update(code="bad\x1b[2J\nforged", stage="quality\x1b[2J\nforged")
    report["quality"] = {"schema_version": "verifier-quality-report-1", "status": "FAIL",
                         "findings": [{"code": "CHILD", "status": "FAIL", "detail": "x" * 1000}]}
    result = project(report)
    shown = reports.render_findings(result)
    assert "\x1b" not in shown and "\\u001b" in shown
    assert all("quality" not in o["detail"] if isinstance(o["detail"], dict) else True
               for row in result["findings"] for o in row["occurrences"])


def test_output_bound_refuses_instead_of_silently_truncating(monkeypatch) -> None:
    monkeypatch.setattr(reports, "MAX_OUTPUT_BYTES", 512)
    with pytest.raises(ValueError, match="output bound"):
        project(attempt("FAIL"))


@pytest.mark.parametrize("change", ["policy", "source_paths", "profile"])
def test_incomparable_scope_has_no_remaining_fixed_or_regressed_matching(change: str) -> None:
    before, after = attempt("FAIL"), attempt("FAIL")
    if change == "source_paths":
        after["binding"]["source"]["files"][0]["path"] = "different.py"
    else:
        after["binding"]["policy_sha256" if change == "policy" else "quality_profile_sha256"] = "sha256:" + "5" * 64
    after["binding"]["source"]["sha256"] = reports._digest(canonical_bytes(after["binding"]["source"]["files"]))
    after["binding_digest"] = reports._digest(canonical_bytes(after["binding"]))
    result = project(after, before, (attempt("PASS"),))
    assert result["delta"]["comparison"] == "INCOMPARABLE_SCOPE"
    assert not any(result["delta"][key] for key in ("remaining", "fixed", "regressed"))
    assert set(result["delta"]["new"]) == {row["finding_id"] for row in result["findings"]}
    assert set(result["delta"]["unobserved"]) == {row["finding_id"] for row in project(before)["findings"]
                                                if not row["locus"].get("selection") and row["code"] != "TIME_NOT_ASSESSED"}


@pytest.mark.parametrize("change", ["source_hash_missing", "source_hash_invalid", "source_size_missing",
                                    "source_commitment_wrong", "evaluator_missing", "evaluator_hash_missing",
                                    "interpreter_missing", "binding_digest_wrong"])
def test_incomplete_source_or_evaluator_binding_cannot_clear_failure(change: str) -> None:
    before, after = attempt("FAIL"), attempt("PASS")
    binding = after["binding"]
    row = binding["source"]["files"][0]
    if change == "source_hash_missing":
        row.pop("sha256")
    elif change == "source_hash_invalid":
        row["sha256"] = "sha256:bad"
    elif change == "source_size_missing":
        row.pop("size_bytes")
    elif change == "source_commitment_wrong":
        binding["source"]["sha256"] = "sha256:" + "0" * 64
    elif change == "evaluator_missing":
        binding.pop("implementation")
    elif change == "evaluator_hash_missing":
        binding["implementation"]["mechanisms"].pop("polish_workflow.py")
    elif change == "interpreter_missing":
        binding["implementation"].pop("interpreter_sha256")
    else:
        after["binding_digest"] = "sha256:" + "0" * 64
    if change != "source_commitment_wrong":
        binding["source"]["sha256"] = reports._digest(canonical_bytes(binding["source"]["files"]))
    if change != "binding_digest_wrong":
        after["binding_digest"] = reports._digest(canonical_bytes(binding))
    result = project(after, before)
    assert not result["delta"]["fixed"] and result["delta"]["comparison"] == "INCOMPARABLE_SCOPE"
    assert result["inputs"][-1]["binding_validation"]["status"] == "NOT_ESTABLISHED"


def test_changed_candidate_valid_bindings_allow_observed_fix_and_retain_both_hashes() -> None:
    before, after = attempt("FAIL"), attempt("PASS")
    source = after["binding"]["source"]
    source["files"][0].update(sha256="sha256:" + "7" * 64, size_bytes=13)
    source["sha256"] = reports._digest(canonical_bytes(source["files"]))
    after["binding_digest"] = reports._digest(canonical_bytes(after["binding"]))
    result = project(after, before)
    assert result["delta"]["comparison"] == "COMPARABLE_OBSERVATIONS" and result["delta"]["fixed"]
    assert [row["carried_binding"]["binding"]["source"]["files"][0]["sha256"] for row in result["inputs"]] == [
        "sha256:" + "2" * 64, "sha256:" + "7" * 64]
    assert result["authentication"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("state,execution", [("UNKNOWN", "EXECUTED"), ("PASS", "NOT_RUN"), ("NOT_SELECTED", "NOT_SELECTED")])
def test_uncertain_or_unexecuted_current_observation_cannot_fix(state: str, execution: str) -> None:
    assert not project(attempt(state, execution), attempt("FAIL"))["delta"]["fixed"]


@pytest.mark.parametrize("raw,code", [(b"Status: OPEN\nExact contradictory claims remain.\n", "TIME_OPEN"),
    (b"Status: CLEAR\nStatus: OPEN\n", "TIME_STATUS_INVALID"), (b"No status\n", "TIME_STATUS_INVALID"),
    (b"Status: CLEAR \n", "TIME_STATUS_INVALID")])
def test_time_contradiction_and_ambiguous_status_never_clear_diagnostics(raw: bytes, code: str) -> None:
    result = reports.project_reports(canonical_bytes(attempt("PASS")), time_bytes=raw)
    assert result["diagnostic_status"] == "FAIL" and result["reported_status"] == "PASS"
    assert any(row["code"] == code for row in result["findings"])
    assert result["diagnostic_selection"]["time"]["text"].encode() == raw
    assert result["diagnostic_selection"]["time"]["sha256"] == reports._digest(raw)


def test_time_clear_is_only_carried_status_and_absent_time_remains_unassessed() -> None:
    clear = reports.project_reports(canonical_bytes(attempt("PASS")), time_bytes=b"Status: CLEAR\n")
    assert clear["diagnostic_selection"]["time"]["status"] == "CLEAR"
    assert clear["polished"] == "NOT_ASSESSED" and clear["authentication"] == "NOT_ESTABLISHED"
    assert any(row["code"] == "TIME_NOT_ASSESSED" for row in project(attempt("PASS"))["findings"])


def test_explicit_missing_family_is_unmet_and_history_cannot_supply_current_family() -> None:
    current = attempt("PASS")
    current["binding"]["quality_profile_sha256"] = "sha256:" + "6" * 64
    current["binding_digest"] = reports._digest(canonical_bytes(current["binding"]))
    sources = [{"path": "demo.py", "size_bytes": 12, "digest": "sha256:" + "2" * 64}]
    quality = {"schema_version": "verifier-quality-report-1", "status": "PASS", "stages": [],
               "sources": sources, "source_digest": reports._digest(canonical_bytes(sources)),
               "profile_digest": current["binding"]["quality_profile_sha256"]}
    result = reports.project_reports(canonical_bytes(current), history_bytes=[canonical_bytes(quality)],
        required_report_contracts=[quality["schema_version"]], time_bytes=b"Status: CLEAR\n")
    assert result["diagnostic_status"] == "FAIL"
    assert any(row["code"] == "REQUIRED_REPORT_FAMILY_MISSING" for row in result["findings"])
    observed = reports.project_reports(canonical_bytes(current), related_bytes=[canonical_bytes(quality)],
        required_report_contracts=[quality["schema_version"]], time_bytes=b"Status: CLEAR\n")
    assert not any(row["code"] == "REQUIRED_REPORT_FAMILY_MISSING" for row in observed["findings"])
    assert observed["diagnostic_selection"]["global_completeness"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("mode", ["missing_binding", "foreign_source", "foreign_profile"])
def test_foreign_or_unbound_related_family_cannot_fulfil_current_candidate_stage(mode: str) -> None:
    current = attempt("PASS")
    current["binding"]["quality_profile_sha256"] = "sha256:" + "6" * 64
    current["binding_digest"] = reports._digest(canonical_bytes(current["binding"]))
    sources = [{"path": "demo.py", "size_bytes": 12, "digest": "sha256:" + "2" * 64}]
    quality = {"schema_version": "verifier-quality-report-1", "status": "PASS",
               "stages": [{"id": "lint", "required": True, "selected": True, "status": "PASS", "execution_status": "EXECUTED"}],
               "sources": sources, "source_digest": reports._digest(canonical_bytes(sources)), "profile_digest": "sha256:" + "6" * 64}
    if mode == "missing_binding":
        quality.pop("sources")
    elif mode == "foreign_source":
        quality["sources"][0]["digest"] = "sha256:" + "8" * 64
        quality["source_digest"] = reports._digest(canonical_bytes(quality["sources"]))
    else:
        quality["profile_digest"] = "sha256:" + "9" * 64
    result = reports.project_reports(canonical_bytes(current), related_bytes=[canonical_bytes(quality)],
        required_report_contracts=[quality["schema_version"]], required_stages=[quality["schema_version"] + ":lint"])
    assert {"REQUIRED_REPORT_FAMILY_MISSING", "REQUIRED_STAGE_NOT_RUN"} <= {row["code"] for row in result["findings"]}
    assert result["inputs"][-1]["candidate_association"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("mode", ["omitted", "deselected", "not_run", "unknown", "not_required"])
def test_explicit_required_stage_must_have_required_executed_pass(mode: str) -> None:
    value = attempt("PASS")
    if mode == "omitted":
        value["stages"] = []
    elif mode == "deselected":
        value["stages"][0].update(selected=False, status="NOT_SELECTED", execution_status="NOT_SELECTED")
    elif mode == "not_run":
        value["stages"][0]["execution_status"] = "NOT_RUN"
    elif mode == "unknown":
        value["stages"][0]["status"] = "UNKNOWN"
    else:
        value["stages"][0]["required"] = False
    result = reports.project_reports(canonical_bytes(value), required_stages=[value["schema_version"] + ":quality"])
    assert result["diagnostic_status"] == "FAIL"
    assert any(row["code"] in {"REQUIRED_STAGE_NOT_RUN", "REQUIRED_STAGE_UNMET"} for row in result["findings"])


def test_required_stage_contract_qualification_prevents_foreign_family_substitution() -> None:
    result = reports.project_reports(canonical_bytes(attempt("PASS")),
        required_stages=["verifier-quality-report-1:quality"])
    assert any(row["code"] == "REQUIRED_STAGE_NOT_RUN" for row in result["findings"])


def test_projection_digest_is_exact_module_byte_identity() -> None:
    from pathlib import Path
    assert project(attempt("FAIL"))["projection_mechanism_digest"] == reports._digest(Path(reports.__file__).read_bytes())


@pytest.mark.parametrize("mode", ["foreign_source", "foreign_profile", "missing_binding"])
def test_embedded_foreign_family_cannot_bypass_candidate_association(mode: str) -> None:
    value = attempt("PASS")
    value["binding"]["quality_profile_sha256"] = "sha256:" + "6" * 64
    value["binding_digest"] = reports._digest(canonical_bytes(value["binding"]))
    sources = [{"path": "demo.py", "size_bytes": 12, "digest": "sha256:" + "2" * 64}]
    quality = {"schema_version": "verifier-quality-report-1", "status": "PASS",
        "profile_digest": "sha256:" + "6" * 64, "sources": sources,
        "source_digest": reports._digest(canonical_bytes(sources)),
        "stages": [{"id": "lint", "required": True, "status": "PASS", "execution_status": "EXECUTED"}]}
    if mode == "foreign_source":
        quality["sources"][0]["digest"] = "sha256:" + "8" * 64
        quality["source_digest"] = reports._digest(canonical_bytes(quality["sources"]))
    elif mode == "foreign_profile":
        quality["profile_digest"] = "sha256:" + "9" * 64
    else:
        quality.pop("sources")
    value["quality"] = quality
    raw = canonical_bytes(value)
    result = reports.project_reports(raw, required_report_contracts=[quality["schema_version"]],
                                   required_stages=[quality["schema_version"] + ":lint"])
    assert {"REQUIRED_REPORT_FAMILY_MISSING", "REQUIRED_STAGE_NOT_RUN"} <= {row["code"] for row in result["findings"]}
    assert result["diagnostic_selection"]["unassociated_embedded_reports"] == [{"schema_version": quality["schema_version"],
        "input_digest": reports._digest(raw), "pointer": "/quality", "candidate_association": "NOT_ESTABLISHED"}]


def test_exact_embedded_candidate_and_profile_can_supply_finite_observations() -> None:
    value = attempt("PASS")
    value["binding"]["quality_profile_sha256"] = "sha256:" + "6" * 64
    value["binding_digest"] = reports._digest(canonical_bytes(value["binding"]))
    sources = [{"path": "demo.py", "size_bytes": 12, "digest": "sha256:" + "2" * 64}]
    value["quality"] = {"schema_version": "verifier-quality-report-1", "status": "PASS",
        "profile_digest": "sha256:" + "6" * 64, "sources": sources, "source_digest": reports._digest(canonical_bytes(sources)),
        "stages": [{"id": "lint", "required": True, "status": "PASS", "execution_status": "EXECUTED"}]}
    result = reports.project_reports(canonical_bytes(value), required_report_contracts=[value["quality"]["schema_version"]],
                                    required_stages=[value["quality"]["schema_version"] + ":lint"])
    assert not result["diagnostic_selection"]["unassociated_embedded_reports"]
    assert not any(row["code"] in {"REQUIRED_REPORT_FAMILY_MISSING", "REQUIRED_STAGE_NOT_RUN", "REQUIRED_STAGE_UNMET"} for row in result["findings"])
    assert result["polished"] == "NOT_ASSESSED" and result["diagnostic_selection"]["global_completeness"] == "NOT_ESTABLISHED"


def test_cli_explicit_selection_and_time_leave_native_pass_separate(tmp_path, capsys) -> None:
    from verifier.runtime.public_cli import main
    source, time = tmp_path / "report.json", tmp_path / "TIME.md"
    source.write_bytes(canonical_bytes(attempt("PASS")))
    time.write_bytes(b"Status: OPEN\nPinned contradictory claims.\n")
    assert main(["polish", "report", str(source), "--time", str(time), "--required-report-contract",
                 "verifier-quality-report-1", "--required-stage", "verifier-polish-workflow-report-1:missing", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["reported_status"] == "PASS" and report["diagnostic_status"] == "FAIL"
    assert {"TIME_OPEN", "REQUIRED_REPORT_FAMILY_MISSING", "REQUIRED_STAGE_NOT_RUN"} <= {row["code"] for row in report["findings"]}


def test_actual_evaluator_revision_change_remains_incomparable_with_valid_bindings() -> None:
    before, after = attempt("FAIL"), attempt("PASS")
    after["binding"]["implementation"]["mechanisms"]["polish_workflow.py"] = "sha256:" + "9" * 64
    after["binding_digest"] = reports._digest(canonical_bytes(after["binding"]))
    result = project(after, before)
    assert all(row["binding_validation"]["status"] == "VALID_CARRIED_BINDING" for row in result["inputs"])
    assert result["delta"]["comparison"] == "INCOMPARABLE_SCOPE" and not result["delta"]["fixed"]


@pytest.mark.parametrize("mode", ["missing_source_digest", "missing_evaluator_identity", "wrong_candidate"])
def test_embedded_pass_with_incomplete_comparison_binding_cannot_clear_previous_failure(mode: str) -> None:
    before, after = attempt("FAIL"), attempt("PASS")
    for value, state in ((before,"FAIL"),(after,"PASS")):
        value["binding"]["quality_profile_sha256"] = "sha256:" + "6" * 64
        value["binding_digest"] = reports._digest(canonical_bytes(value["binding"]))
        sources = [{"path":"demo.py","size_bytes":12,"digest":"sha256:" + "2" * 64}]
        value["quality"] = {"schema_version":"verifier-quality-report-1","status":state,
            "profile_digest":"sha256:" + "6" * 64,"sources":sources,"source_digest":reports._digest(canonical_bytes(sources)),
            "stages":[{"id":"lint","selected":True,"required":True,"status":state,"execution_status":"EXECUTED"}]}
    if mode == "missing_source_digest":
        after["quality"]["sources"][0].pop("digest")
    elif mode == "wrong_candidate":
        after["quality"]["sources"][0]["digest"] = "sha256:" + "9" * 64
        after["quality"]["source_digest"] = reports._digest(canonical_bytes(after["quality"]["sources"]))
    result = project(after,before)
    assert all(row["binding_validation"]["status"] == "VALID_CARRIED_BINDING" for row in result["inputs"])
    assert not any(result["delta"][key] for key in ("fixed","remaining","regressed"))
    assert result["delta"]["comparison"] == "INCOMPARABLE_SCOPE" and result["delta"]["unobserved"]
    assert not result["inputs"][-1]["embedded_comparison_bindings"]


def test_related_scopes_are_observable_without_cross_attempt_matching() -> None:
    before, current, foreign = attempt("FAIL"), attempt("PASS"), attempt("FAIL")
    foreign["binding"]["policy_sha256"] = "sha256:" + "9" * 64
    foreign["binding_digest"] = reports._digest(canonical_bytes(foreign["binding"]))
    result = reports.project_reports(canonical_bytes(current), previous_bytes=canonical_bytes(before),
                                    related_bytes=[canonical_bytes(foreign)])
    assert result["delta"]["comparison"] == "INCOMPARABLE_SCOPE"
    assert not any(result["delta"][key] for key in ("remaining", "fixed", "regressed"))
    assert any(o["input_digest"] == reports._digest(canonical_bytes(foreign)) for row in result["findings"] for o in row["occurrences"])


def test_required_stage_observation_retains_exact_report_digest_and_pointer() -> None:
    value = attempt("PASS", "NOT_RUN")
    raw = canonical_bytes(value)
    result = reports.project_reports(raw, required_stages=[value["schema_version"] + ":quality"])
    occurrence = next(row for row in result["findings"] if row["code"] == "REQUIRED_STAGE_UNMET")["occurrences"][0]
    assert occurrence["detail"]["observations"] == [{"input_digest": reports._digest(raw),
                                                      "pointer": "/stages/0", "observation": value["stages"][0]}]


def test_report_root_occurrence_uses_empty_json_pointer() -> None:
    value = {"schema_version": "verifier-quality-report-1", "status": "FAIL"}
    occurrence = next(row for row in project(value)["findings"] if row["code"] == "CHECK_FAIL")["occurrences"][0]
    assert occurrence["pointer"] == ""


def test_release_source_binding_pass_keeps_application_and_replay_holds_visible() -> None:
    value={"schema_version":"verifier-release-source-binding-assessment-1","status":"UNKNOWN","binding_status":"PASS",
           "application_profile":"UNADOPTED","full_application_status":"UNKNOWN","polished":False,
           "source_inventory_completeness":"NOT_ESTABLISHED","selector_authority":"NOT_ESTABLISHED",
           "public_surface_completeness":"NOT_ESTABLISHED","actual_execution":"NOT_ESTABLISHED","native_objective_replay":"NOT_RUN"}
    result=project(value)
    assert {"APPLICATION_PROFILE_UNADOPTED","FULL_APPLICATION_STATUS","SOURCE_INVENTORY_COMPLETENESS",
            "SELECTOR_AUTHORITY","PUBLIC_SURFACE_COMPLETENESS","ACTUAL_EXECUTION","NATIVE_OBJECTIVE_REPLAY"} <= {row["code"] for row in result["findings"]}
    assert result["reported_status"] == "UNKNOWN" and result["polished"] == "NOT_ASSESSED"


@pytest.mark.parametrize("json_output", [True, False])
def test_cli_rendering_bound_refusal_is_structured_and_caught(tmp_path, monkeypatch, capsys, json_output: bool) -> None:
    from verifier.runtime.public_cli import main
    source = tmp_path / "report.json"
    source.write_bytes(canonical_bytes(attempt("FAIL")))
    original = reports.project_reports
    def small(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr(reports, "MAX_OUTPUT_BYTES", len(canonical_bytes(result)) + 128)
        return result
    monkeypatch.setattr(reports, "project_reports", small)
    if not json_output:
        monkeypatch.setattr(reports, "render_findings", lambda _: (_ for _ in ()).throw(ValueError("rendered report output bound exceeded")))
    assert main(["polish", "report", str(source), *(["--json"] if json_output else [])]) == 1
    shown = capsys.readouterr().out
    assert "INVALID_OR_UNAVAILABLE_REPORT" in shown and "Traceback" not in shown
