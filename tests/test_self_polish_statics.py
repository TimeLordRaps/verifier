"""Fail-closed public Statics promotion and native replay regression gates."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from verifier.runtime.public_cli import main
from verifier.runtime import core_obligation_union as binding
from verifier.runtime import self_polish_statics as statics
from verifier.runtime import self_polish_tiers as tiers
from verifier.domains.contracts import graph_statics

ROOT = Path(__file__).resolve().parents[1]
PIN = "sha256:" + "a" * 64


def _tier3_membership():
    registry, cases = statics._registry()
    row = deepcopy(registry["memberships"][0])
    return row, cases[row["obligation_id"]]


def _reseal_evidence(evidence):
    evidence["evidence_digest"] = binding.value_digest({
        key: value for key, value in evidence.items()
        if key != "evidence_digest"
    })
    return evidence


_GRAPH = "GRAPH:GRAPH-3.1"
_ACTOR = "ACTOR:ACTOR-3.3"
_MODEL_HARDWARE = "MODEL:MODEL-3.2"
_KEEP = {_GRAPH, _ACTOR, _MODEL_HARDWARE}


def _membership(result, obligation_id):
    return next(row for row in result["memberships"] if row["obligation_id"] == obligation_id)


def _statuses(result):
    return {row["obligation_id"]: row["status"] for row in result["memberships"]}


def _wrap_checker(monkeypatch, suffix, transform):
    """Let transform see one native checker's honest result, or raise in its place."""
    resolve = statics.native._resolve_mechanism

    def wrapped(root, dotted):
        function, path, digest = resolve(root, dotted)
        if not dotted.endswith(suffix):
            return function, path, digest
        original = function

        def checked(*args, **kwargs):
            return transform(original(*args, **kwargs))

        return checked, path, digest

    monkeypatch.setattr(statics.native, "_resolve_mechanism", wrapped)


def _replay_subset(monkeypatch, keep, *, review=None):
    """Replay only the kept memberships; the cases and digests stay the installed ones."""
    registry, cases = statics._registry()
    subset = deepcopy(registry)
    subset["memberships"] = [row for row in registry["memberships"] if row["obligation_id"] in keep]
    monkeypatch.setattr(statics, "_registry", lambda: (subset, cases))
    if review is not None:
        monkeypatch.setattr(statics.specimens, "installed_source_review", lambda: review)
    return statics.replay_statics(ROOT, source_coordinate_digest=PIN)


def _synthetic_retained_graph_review():
    """Exercise retained-UNKNOWN mechanics without keeping live Graph stale."""
    review = statics.specimens.installed_source_review()
    selected = statics.specimens.installed_case_inputs()[_GRAPH]
    row = review[_GRAPH]
    row.update({
        "disposition": "RETAIN_UNKNOWN",
        "change_class": ["TEST_SYNTHETIC_DRIFT"],
        "prior_mechanism_digest": selected["policy"]["mechanism_digest"],
        "reviewed_mechanism_digest": PIN,
        "retained_case_digest": binding.value_digest(selected),
    })
    return review


def test_public_tier3_help_names_fresh_prerequisites(capsys):
    with pytest.raises(SystemExit) as stopped:
        main(["polish", "3", "--help"])
    assert stopped.value.code == 0
    text = " ".join(capsys.readouterr().out.split()).lower()
    assert "statics" in text
    assert "fresh" in text and "0" in text and "1" in text and "2" in text
    assert "--source-root" in text
    assert "--cancelled" in text


def test_native_statics_exact_routes_controls_reasons_and_boundaries():
    # Current-tree state: all 31 reviewed triads execute. MODEL:MODEL-3.7
    # replays genuinely: its selected MODEL-3.4 and TRAIN-1.5 children carry
    # live nested pins in the installed fixture.
    result = statics.replay_statics(ROOT, source_coordinate_digest=PIN)
    assert result["status"] == "PASS", result["blockers"]
    assert result["blockers"] == []
    assert result["membership_count"] == 31
    assert result["case_count"] == 93
    assert result["reasoned_route_count"] == 31
    assert len({row["object_kind"] for row in result["memberships"]}) == 26
    assert result["full_application_status"] == "UNKNOWN"
    assert result["release_authorized"] is False
    statuses = {row["obligation_id"]: row["status"] for row in result["memberships"]}
    assert sum(status == "PASS" for status in statuses.values()) == 31
    assert statuses["GRAPH:GRAPH-3.1"] == "PASS"
    assert statuses["MODEL:MODEL-3.7"] == "PASS"
    for row in result["memberships"]:
        assert row["applicability"]["mode"] == "CONDITIONAL"
        assert row["reason"]["classification"] == "NECESSARY"
        assert row["reason"]["condition_status"] == "TRIGGERED"
        assert row["reason"]["fulfillment_required"] is True
        assert row["reason"]["applicability_declaration"] == row["applicability"]
        assert row["reason"]["applicability_digest"] == row["applicability_digest"]
        assert row["reason"]["condition_evidence_digest"].startswith("sha256:")
        assert row["reason"]["necessity_reason"].strip()
        assert row["reason"]["applicability_reason"].strip()
        assert row["retention"] is None
        assert row["status"] == "PASS"
        assert [case["native_status"] for case in row["cases"]] == ["PASS", "FAIL", "UNKNOWN"]
        assert all(case["status"] == "PASS" for case in row["cases"])
    sim = next(row for row in result["memberships"] if row["obligation_id"] == "SIM:SIM-3.4")
    assert sim["cases"][0]["native_result"]["physical_law_truth"] == "NOT_ESTABLISHED"
    assert "physical" in sim["reason"]["scope_limit"]


def test_native_statics_evaluates_conditional_trigger_from_bound_selection():
    row, selected = _tier3_membership()
    assert row["applicability"]["mode"] == "CONDITIONAL"
    evidence = statics._native_applicability_evidence(
        row, selected, source_coordinate_digest=PIN,
    )
    assessment = statics._assess_membership_applicability(row, evidence)
    assert assessment == {
        "status": "PASS",
        "classification": "NECESSARY",
        "condition_status": "TRIGGERED",
        "fulfillment_required": True,
        "reason": evidence["reason"],
        "declaration": row["applicability"],
        "applicability_digest": row["applicability_digest"],
        "condition_evidence_digest": evidence["evidence_digest"],
    }


def test_conditional_non_trigger_requires_source_bound_adaptation_and_reason():
    row, selected = _tier3_membership()
    evidence = statics._native_applicability_evidence(
        row, selected, source_coordinate_digest=PIN,
    )
    evidence.update({
        "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
        "condition_status": "NOT_TRIGGERED",
        "classification": "CONDITION_NOT_MET",
        "reason": (
            "The exact source-owned representation selected the necessary Tier-3 "
            "source adaptation instead of this retained runtime-domain variant."
        ),
        "selected_input_digest": None,
        "adaptation_obligation_id": (
            f"{row['object_kind']}-3.90-source-representation-statics"
        ),
        "adaptation_result_digest": PIN,
    })
    assessment = statics._assess_membership_applicability(
        row, _reseal_evidence(evidence),
    )
    assert assessment["status"] == "PASS"
    assert assessment["classification"] == "CONDITION_NOT_MET"
    assert assessment["condition_status"] == "NOT_TRIGGERED"
    assert assessment["fulfillment_required"] is False
    assert assessment["reason"] == evidence["reason"]


@pytest.mark.parametrize("evidence", [None, {}, {"condition_status": "UNKNOWN"}])
def test_missing_conditional_evidence_is_unknown_and_never_exempts(evidence):
    row, _ = _tier3_membership()
    assessment = statics._assess_membership_applicability(row, evidence)
    assert assessment["status"] == "UNKNOWN"
    assert assessment["classification"] == "UNDETERMINED"
    assert assessment["condition_status"] == "UNKNOWN"
    assert assessment["fulfillment_required"] is True


def test_object_relabel_cannot_bypass_native_membership_identity():
    row, selected = _tier3_membership()
    evidence = statics._native_applicability_evidence(
        row, selected, source_coordinate_digest=PIN,
    )
    row["object_kind"] = "OBJECT"
    row["obligation_id"] = f"OBJECT:{row['coordinate']}"
    evidence.update(object_kind="OBJECT", obligation_id=row["obligation_id"])
    assessment = statics._assess_membership_applicability(
        row, _reseal_evidence(evidence),
    )
    assert assessment["status"] == "FAIL"
    assert assessment["classification"] == "UNDETERMINED"
    assert assessment["fulfillment_required"] is True
    assert "identity" in assessment["reason"].lower()


def test_contradictory_conditional_classification_fails_closed():
    row, selected = _tier3_membership()
    evidence = statics._native_applicability_evidence(
        row, selected, source_coordinate_digest=PIN,
    )
    evidence["classification"] = "CONDITION_NOT_MET"
    assessment = statics._assess_membership_applicability(
        row, _reseal_evidence(evidence),
    )
    assert assessment["status"] == "FAIL"
    assert assessment["classification"] == "UNDETERMINED"
    assert assessment["fulfillment_required"] is True
    assert "contradicts" in assessment["reason"]


@pytest.mark.parametrize("mutation,code", [
    ("reason_missing", "STATICS_NECESSITY_REASON_COVERAGE_DIFFERS"),
    ("reason_empty", "STATICS_NECESSITY_REASON_COVERAGE_DIFFERS"),
    ("case_missing", "STATICS_CASE_DENOMINATOR_DIFFERS"),
    ("case_extra", "STATICS_CASE_DENOMINATOR_DIFFERS"),
    ("request_substituted", "STATICS_REQUEST_BINDING_DIFFERS"),
    ("policy_substituted", "STATICS_REQUEST_BINDING_DIFFERS"),
    ("adapter_substituted", "STATICS_CASE_BINDING_DIFFERS"),
    ("catalog_substituted", "STATICS_OBJECTIVE_BINDING_DIFFERS"),
    ("applicability_missing", "STATICS_APPLICABILITY_DECLARATION_MISSING"),
    ("applicability_digest", "STATICS_APPLICABILITY_DECLARATION_INVALID"),
    ("applicability_reason", "STATICS_APPLICABILITY_REASON_MISSING"),
    ("applicability_extra", "STATICS_APPLICABILITY_DECLARATION_DENOMINATOR_DIFFERS"),
])
def test_registry_rejects_missing_or_substituted_selection(monkeypatch, mutation, code):
    cases = statics.specimens.installed_case_inputs()
    declarations = statics.core_tier_progression.installed_core_route_declarations()
    first = next(iter(cases))
    reasons = dict(statics._NECESSITY)
    if mutation == "reason_missing":
        reasons.pop(next(iter(reasons)))
    elif mutation == "reason_empty":
        reasons[next(iter(reasons))] = " "
    elif mutation == "case_missing":
        cases.pop(first)
    elif mutation == "case_extra":
        cases["OTHER:OTHER-3.1"] = deepcopy(cases[first])
    elif mutation == "request_substituted":
        cases[first]["request"]["proposition_digest"] = PIN
    elif mutation == "policy_substituted":
        cases[first]["policy"]["mechanism_digest"] = PIN
    elif mutation == "adapter_substituted":
        cases[first]["unknown_adapter"] = "HYPER_CLOSURE_OPERATION_BUDGET"
    elif mutation == "catalog_substituted":
        catalog = deepcopy(statics.polish.polish_catalog())
        next(r for r in catalog["routes"] if r["objective"] == "SIM-3.4")["scope"] = "physical_truth"
        monkeypatch.setattr(statics.polish, "polish_catalog", lambda: catalog)
    elif mutation == "applicability_missing":
        declarations.pop(next(key for key in declarations if key[1] == 3))
    elif mutation == "applicability_digest":
        first_key = next(key for key in declarations if key[1] == 3)
        declarations[first_key]["applicability_digest"] = PIN
    elif mutation == "applicability_reason":
        first_key = next(key for key in declarations if key[1] == 3)
        declarations[first_key]["reason"] = " "
    elif mutation == "applicability_extra":
        first_key = next(key for key in declarations if key[1] == 3)
        declarations[("OBJECT", 3, "OBJECT-3.99")] = deepcopy(
            declarations[first_key]
        )
    monkeypatch.setattr(statics, "_NECESSITY", reasons)
    monkeypatch.setattr(statics.specimens, "installed_case_inputs", lambda: cases)
    monkeypatch.setattr(
        statics.core_tier_progression,
        "installed_core_route_declarations",
        lambda: declarations,
    )
    with pytest.raises(statics.native.NativeReplayError, match=code):
        statics._registry()


@pytest.mark.parametrize("pin", [None, True, "a" * 64, "sha256:" + "A" * 64])
def test_replay_rejects_invalid_source_pin(pin):
    result = statics.replay_statics(ROOT, source_coordinate_digest=pin)
    assert result["status"] == "FAIL"
    assert result["memberships"] == []
    assert "STATICS_SOURCE_PIN_INVALID" in result["blockers"]


def test_replay_refuses_different_selected_source(tmp_path):
    result = statics.replay_statics(tmp_path, source_coordinate_digest=PIN)
    assert result["status"] == "FAIL"
    assert "STATICS_INSTALLED_SOURCE_DIFFERS" in result["blockers"]


@pytest.mark.parametrize("outcome", ["UNKNOWN", "FAIL"])
def test_positive_unavailable_or_refuted_never_becomes_control_pass(monkeypatch, outcome):
    _wrap_checker(monkeypatch, "recheck_model_hardware_certificate",
                  lambda result: {**result, "status": outcome} if result["status"] == "PASS" else result)
    result = statics.replay_statics(ROOT, source_coordinate_digest=PIN)
    member = _membership(result, "MODEL:MODEL-3.2")
    assert member["status"] == outcome
    assert [case["status"] for case in member["cases"]] == [outcome, "PASS", "PASS"]
    assert f"MODEL:MODEL-3.2:POSITIVE:{outcome}" in result["blockers"]
    # MODEL-3.7 is a genuine PASS, so only the injected outcome and the retained
    # GRAPH-3.1 UNKNOWN decide the aggregate: FAIL dominates, otherwise UNKNOWN.
    assert result["status"] == ("FAIL" if outcome == "FAIL" else "UNKNOWN")
    assert "MODEL:MODEL-3.7:POSITIVE:FAIL" not in result["blockers"]


@pytest.mark.parametrize("outage", [False, True])
def test_wrong_negative_is_failure_even_when_later_source_check_unavailable(monkeypatch, outage):
    resolve = statics.native._resolve_mechanism

    def wrapped(root, dotted):
        function, path, digest = resolve(root, dotted)
        if dotted.endswith("recheck_actor_decision_record_certificate"):
            original = function

            def function(*args, **kwargs):
                result = original(*args, **kwargs)
                return {**result, "status": "PASS"} if result["status"] == "FAIL" else result
        return function, path, digest

    monkeypatch.setattr(statics.native, "_resolve_mechanism", wrapped)
    if outage:
        before = statics._package_source_binding
        count = 0

        def binding_then_outage(root):
            nonlocal count
            count += 1
            if count > 1:
                raise OSError("synthetic outage")
            return before(root)

        monkeypatch.setattr(statics, "_package_source_binding", binding_then_outage)
    result = statics.replay_statics(ROOT, source_coordinate_digest=PIN)
    assert result["status"] == "FAIL"
    assert "ACTOR:ACTOR-3.3:NEGATIVE:FAIL" in result["blockers"]


def test_cancelled_does_not_execute_or_claim_prerequisites(monkeypatch):
    monkeypatch.setattr(statics, "_capture_coordinate", lambda *_: pytest.fail("must not execute"))
    result = tiers.assess_self_polish_tier(3, source_root=ROOT, cancelled=True)
    assert result["status"] == "UNKNOWN"
    assert result["prerequisites"] == {}
    assert result["selected_depth"] == 0
    assert result["blockers"] == ["STATICS_CANCELLED"]


def test_tier3_rejects_caller_prerequisite_verdict():
    with pytest.raises(ValueError, match="all prerequisites are fresh"):
        tiers.assess_self_polish_tier(3, source_root=ROOT, tier1_report_bytes=b'{"status":"PASS"}')


def _fake_prerequisites(monkeypatch, *, failure_tier=None, failure_status="FAIL", recapture="PASS"):
    coordinate = {"source_head": "1" * 40, "source_tree": "2" * 40,
                  "source_worktree_status_digest": PIN, "source_manifest_digest": PIN}
    monkeypatch.setattr(statics, "_capture_coordinate", lambda root: coordinate)
    monkeypatch.setattr(statics, "mechanism_digest", lambda: PIN)
    calls = []

    def run(tier, **kwargs):
        calls.append(tier)
        status = failure_status if tier == failure_tier else "PASS"
        return statics._seal({"status": status, "selected_tier_status": status,
            "whole_tier_conformance": status, "polished": False, "release_authorized": False,
            "source_coordinate": coordinate, "source_coordinate_digest": binding.value_digest(coordinate),
            "post_replay_full_source_recapture": "PASS", "repository_package_estate_closure": "PASS",
            "blockers": [] if status == "PASS" else ["SYNTHETIC_PREREQUISITE"]}, "report_digest")

    monkeypatch.setattr(statics.tier_zero, "assess_tier_zero", lambda root: run(0))
    monkeypatch.setattr(tiers, "assess_self_polish_tier", run)
    monkeypatch.setattr(tiers, "_post_replay_source_recapture", lambda *args: {"status": recapture})
    return calls


@pytest.mark.parametrize("tier", [0, 1, 2])
@pytest.mark.parametrize("status", ["FAIL", "UNKNOWN"])
def test_fresh_prerequisite_failure_blocks_statics(monkeypatch, tier, status):
    calls = _fake_prerequisites(monkeypatch, failure_tier=tier, failure_status=status)
    monkeypatch.setattr(statics, "replay_statics", lambda *a, **k: pytest.fail("must not replay"))
    result = statics.assess_self_polish_statics(ROOT)
    assert result["status"] == result["selected_tier_status"] == status
    assert calls == list(range(tier + 1))
    assert result["selected_depth"] < 3
    assert f"TIER{tier}_FRESH_PASS_REQUIRED" in result["blockers"]
    assert set(result["tier_execution"]) == {"0", "1", "2", "3"}
    for executed_tier in range(tier + 1):
        record = result["tier_execution"][str(executed_tier)]
        assert record["execution_status"] == "EXECUTED"
        assert record["status"] == (status if executed_tier == tier else "PASS")
        assert record["evidence_digest"] == result["prerequisites"][str(executed_tier)]["report_digest"]
        assert record["blocking_prerequisite"] is None
        assert record["execution_record_digest"] == binding.value_digest({
            key: value for key, value in record.items()
            if key != "execution_record_digest"
        })
    for skipped_tier in range(tier + 1, 4):
        record = result["tier_execution"][str(skipped_tier)]
        assert record["execution_status"] == "NOT_RUN"
        assert record["status"] == "UNKNOWN"
        assert record["evidence_digest"] is None
        assert record["blocking_prerequisite"] == {
            "tier": tier,
            "tier_name": statics._TIER_NAMES[tier],
            "required_status": "PASS",
            "observed_status": status,
            "report_digest": result["prerequisites"][str(tier)]["report_digest"],
            "blockers": ["SYNTHETIC_PREREQUISITE"],
        }
        assert f"Tier {tier}" in record["reason"]
        assert status in record["reason"]
        assert record["execution_record_digest"] == binding.value_digest({
            key: value for key, value in record.items()
            if key != "execution_record_digest"
        })
    assert result["complete_tier_evidence_replay"] is None


@pytest.mark.parametrize("failed_tier", [0, 1])
def test_prerequisite_exception_retains_complete_fail_closed_execution_ledger(
        monkeypatch, failed_tier):
    calls = _fake_prerequisites(monkeypatch)

    if failed_tier == 0:
        class SyntheticUnexpected(Exception):
            pass

        def fail_tier_zero(_root):
            calls.append(0)
            raise SyntheticUnexpected("must not escape the fail-closed report")

        monkeypatch.setattr(statics.tier_zero, "assess_tier_zero", fail_tier_zero)
        expected_blocker = "STATICS_ASSESSMENT_UNEXPECTED_EXCEPTION"
        expected_exception_type = "SyntheticUnexpected"
    else:
        original = tiers.assess_self_polish_tier

        def fail_tier_one(tier, **kwargs):
            if tier == 1:
                calls.append(1)
                raise RuntimeError("SYNTHETIC_TIER1_EXCEPTION")
            return original(tier, **kwargs)

        monkeypatch.setattr(tiers, "assess_self_polish_tier", fail_tier_one)
        expected_blocker = "SYNTHETIC_TIER1_EXCEPTION"
        expected_exception_type = "RuntimeError"

    monkeypatch.setattr(statics, "replay_statics",
                        lambda *a, **k: pytest.fail("must not replay"))
    result = statics.assess_self_polish_statics(ROOT)

    assert result["status"] == result["selected_tier_status"] == "FAIL"
    assert result["blockers"] == [expected_blocker]
    assert calls == list(range(failed_tier + 1))
    assert set(result["tier_execution"]) == {"0", "1", "2", "3"}
    for tier in range(failed_tier):
        record = result["tier_execution"][str(tier)]
        assert record["execution_status"] == "EXECUTED"
        assert record["status"] == "PASS"
        assert record["evidence_digest"] == result["prerequisites"][str(tier)]["report_digest"]
        assert record["blocking_prerequisite"] is None
    expected_stage = f"TIER{failed_tier}_{statics._TIER_NAMES[failed_tier]}_ASSESSMENT"
    for tier in range(failed_tier, 4):
        record = result["tier_execution"][str(tier)]
        assert record["execution_status"] == "NOT_RUN"
        assert record["status"] == "UNKNOWN"
        assert record["evidence_digest"] is None
        assert record["blocking_prerequisite"] == {
            "tier": failed_tier,
            "tier_name": statics._TIER_NAMES[failed_tier],
            "required_status": "PASS",
            "observed_status": "UNKNOWN",
            "report_digest": None,
            "blockers": [expected_blocker],
            "failure_stage": expected_stage,
            "exception_type": expected_exception_type,
        }
        assert expected_stage in record["reason"]
        assert record["execution_record_digest"] == binding.value_digest({
            key: value for key, value in record.items()
            if key != "execution_record_digest"
        })
    assert result["complete_tier_evidence_replay"] is None
    assert result["report_digest"] == binding.value_digest({
        key: value for key, value in result.items() if key != "report_digest"
    })


@pytest.mark.parametrize("recapture,expected", [("PASS", "PASS"), ("FAIL", "FAIL"), ("NOT_ESTABLISHED", "UNKNOWN")])
def test_final_source_recapture_is_required(monkeypatch, recapture, expected):
    calls = _fake_prerequisites(monkeypatch, recapture=recapture)
    monkeypatch.setattr(statics, "replay_statics", lambda *a, **k: {"status": "PASS", "blockers": []})
    result = statics.assess_self_polish_statics(ROOT)
    assert calls == [0, 1, 2]
    assert set(result["tier_execution"]) == {"0", "1", "2", "3"}
    assert all(record["execution_status"] == "EXECUTED"
               for record in result["tier_execution"].values())
    assert result["status"] == expected
    assert result["selected_depth"] == (3 if expected == "PASS" else 2)
    assert result["full_application_status"] == "UNKNOWN"
    assert result["application_authority"]["obligation"]["condition_status"] == "NOT_TRIGGERED"
    assert result["release_authorized"] is result["polished"] is False


@pytest.mark.parametrize("status,exit_code", [("PASS", 2), ("FAIL", 1), ("UNKNOWN", 2)])
def test_cli_report_capacity_preserves_failure(monkeypatch, capsys, status, exit_code):
    monkeypatch.setattr(tiers, "assess_self_polish_tier", lambda *a, **k: {"status": status})
    monkeypatch.setattr(statics, "MAX_REPORT_BYTES", 1)
    assert main(["polish", "3", "--native-specimens", "--json"]) == exit_code
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == ("FAIL" if status == "FAIL" else "UNKNOWN")
    assert result["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert result["blockers"] == ["STATICS_REPORT_CAPACITY_EXHAUSTED"]


@pytest.mark.parametrize("outcome", ["UNKNOWN", "FAIL"])
def test_isolated_positive_outcome_sets_exact_aggregate(monkeypatch, outcome):
    _wrap_checker(monkeypatch, "recheck_model_hardware_certificate",
                  lambda result: {**result, "status": outcome} if result["status"] == "PASS" else result)
    result = _replay_subset(monkeypatch, {_MODEL_HARDWARE})
    assert result["status"] == outcome
    assert result["blockers"] == [f"MODEL:MODEL-3.2:POSITIVE:{outcome}"]


def test_unknown_only_aggregate_is_exact_unknown(monkeypatch):
    _wrap_checker(monkeypatch, "recheck_model_hardware_certificate",
                  lambda result: {**result, "status": "UNKNOWN"} if result["status"] == "PASS" else result)
    result = _replay_subset(monkeypatch, _KEEP)
    assert result["status"] == "UNKNOWN"
    assert _statuses(result) == {_ACTOR: "PASS", _GRAPH: "PASS", _MODEL_HARDWARE: "UNKNOWN"}
    assert result["blockers"] == ["MODEL:MODEL-3.2:POSITIVE:UNKNOWN"]
    assert "FAIL" not in {case["status"] for row in result["memberships"] for case in row["cases"]}


def test_fail_only_aggregate_is_exact_fail_for_a_stale_unretained_pin(monkeypatch):
    monkeypatch.setattr(graph_statics, "mechanism_digest", lambda: PIN)
    result = _replay_subset(monkeypatch, _KEEP)
    assert result["status"] == "FAIL"
    assert _statuses(result) == {_ACTOR: "PASS", _GRAPH: "FAIL", _MODEL_HARDWARE: "PASS"}
    assert result["blockers"] == [
        "GRAPH:GRAPH-3.1:NEGATIVE:FAIL",
        "GRAPH:GRAPH-3.1:POSITIVE:FAIL",
        "GRAPH:GRAPH-3.1:UNKNOWN:FAIL",
        "STATICS_NATIVE_CASE_CONTRACT_REJECTED",
    ]
    graph = _membership(result, _GRAPH)
    assert all(case["exception_type"] == "GraphStaticsError"
               and case["contract_detail"] == "policy differs from installed mechanism"
               and case["native_status"] == "NOT_EXECUTED"
               for case in graph["cases"])
    assert "UNKNOWN" not in {case["status"] for row in result["memberships"] for case in row["cases"]}


def test_fail_dominates_unknown_and_keeps_both_exact_blockers(monkeypatch):
    monkeypatch.setattr(graph_statics, "mechanism_digest", lambda: PIN)
    _wrap_checker(monkeypatch, "recheck_model_hardware_certificate",
                  lambda result: {**result, "status": "UNKNOWN"} if result["status"] == "PASS" else result)
    result = _replay_subset(monkeypatch, _KEEP)
    assert result["status"] == "FAIL"
    assert _statuses(result) == {_ACTOR: "PASS", _GRAPH: "FAIL", _MODEL_HARDWARE: "UNKNOWN"}
    assert "MODEL:MODEL-3.2:POSITIVE:UNKNOWN" in result["blockers"]
    assert "GRAPH:GRAPH-3.1:POSITIVE:FAIL" in result["blockers"]


def test_multiple_unknowns_yield_a_deterministic_sorted_receipt(monkeypatch):
    _wrap_checker(monkeypatch, "recheck_actor_decision_record_certificate",
                  lambda result: {**result, "status": "UNKNOWN"} if result["status"] == "PASS" else result)
    _wrap_checker(monkeypatch, "recheck_model_hardware_certificate",
                  lambda result: {**result, "status": "UNKNOWN"} if result["status"] == "PASS" else result)
    first = _replay_subset(monkeypatch, _KEEP)
    second = statics.replay_statics(ROOT, source_coordinate_digest=PIN)
    assert first["status"] == second["status"] == "UNKNOWN"
    assert first["blockers"] == second["blockers"] == sorted(first["blockers"])
    assert first["blockers"][0] == "ACTOR:ACTOR-3.3:POSITIVE:UNKNOWN"
    assert first["receipt_digest"] == second["receipt_digest"]


def test_retained_graph_checker_is_never_invoked_even_if_it_would_pass(monkeypatch):
    registry, _ = statics._registry()
    row = next(item for item in registry["memberships"] if item["obligation_id"] == _GRAPH)
    checker_name = row["checking_mechanism"]
    module, symbol = checker_name.rsplit(".", 1)
    builder_name = module + "." + symbol.replace("recheck_", "build_", 1)
    calls = []
    resolve = statics.native._resolve_mechanism

    def wrapped(root, dotted):
        function, path, digest = resolve(root, dotted)
        if dotted not in (checker_name, builder_name):
            return function, path, digest

        def spy(*args, **kwargs):
            calls.append(dotted)
            return {"status": "PASS"} if dotted == checker_name else b"forged"

        return spy, path, digest

    monkeypatch.setattr(statics.native, "_resolve_mechanism", wrapped)
    result = _replay_subset(
        monkeypatch, {_GRAPH}, review=_synthetic_retained_graph_review(),
    )
    assert calls == []
    assert result["status"] == "UNKNOWN"
    graph = _membership(result, _GRAPH)
    assert graph["status"] == "UNKNOWN"
    assert [case["status"] for case in graph["cases"]] == ["UNKNOWN"] * 3
    assert all(case["native_result"] is None and case["native_status"] == "NOT_EXECUTED"
               for case in graph["cases"])
    assert "GRAPH:GRAPH-3.1:POSITIVE:PASS" not in result["blockers"]


@pytest.mark.parametrize("mutation,code", [
    ("digest", "STATICS_RETAINED_CASE_BINDING_DIFFERS"),
    ("prior_pin", "STATICS_RETAINED_CASE_BINDING_DIFFERS"),
    ("missing_route", "STATICS_SOURCE_REVIEW_ROUTE_MISSING"),
    ("invalid_disposition", "STATICS_SOURCE_REVIEW_DISPOSITION_INVALID"),
])
def test_retained_review_corruption_is_typed_fail_not_unknown(monkeypatch, mutation, code):
    review = _synthetic_retained_graph_review()
    if mutation == "digest":
        review["GRAPH:GRAPH-3.1"]["retained_case_digest"] = PIN
    elif mutation == "prior_pin":
        review["GRAPH:GRAPH-3.1"]["prior_mechanism_digest"] = PIN
    elif mutation == "missing_route":
        review.pop("GRAPH:GRAPH-3.1")
    else:
        review["GRAPH:GRAPH-3.1"]["disposition"] = "MAYBE"
    result = _replay_subset(monkeypatch, {_GRAPH}, review=review)
    graph = _membership(result, _GRAPH)
    assert result["status"] == graph["status"] == "FAIL"
    assert [case["contract_code"] for case in graph["cases"]] == [code] * 3
    assert result["blockers"] == sorted([
        "GRAPH:GRAPH-3.1:NEGATIVE:FAIL", "GRAPH:GRAPH-3.1:POSITIVE:FAIL",
        "GRAPH:GRAPH-3.1:UNKNOWN:FAIL", code,
    ])


@pytest.mark.parametrize("replacement", [None, {"status": "MAYBE"}])
def test_invalid_checker_shape_is_a_typed_positive_fail(monkeypatch, replacement):
    _wrap_checker(monkeypatch, "recheck_actor_decision_record_certificate",
                  lambda result: replacement if result["status"] == "PASS" else result)
    result = _replay_subset(monkeypatch, {_ACTOR})
    actor = _membership(result, _ACTOR)
    assert result["status"] == "FAIL"
    assert [case["status"] for case in actor["cases"]] == ["FAIL", "PASS", "PASS"]
    assert actor["cases"][0]["contract_code"] == "STATICS_NATIVE_OUTCOME_INVALID"
    assert result["blockers"] == ["ACTOR:ACTOR-3.3:POSITIVE:FAIL", "STATICS_NATIVE_OUTCOME_INVALID"]


@pytest.mark.parametrize("error,code,exception_type", [
    (ValueError("free text rejection"), "STATICS_NATIVE_CASE_CONTRACT_REJECTED", "ValueError"),
    (statics.native.NativeReplayError("SYNTHETIC_CHECKER_CONTRACT"),
     "SYNTHETIC_CHECKER_CONTRACT", "NativeReplayError"),
])
def test_checker_exception_fails_only_that_polarity_and_keeps_others(
        monkeypatch, error, code, exception_type):
    def raise_on_pass(result):
        if result["status"] == "PASS":
            raise error
        return result

    _wrap_checker(monkeypatch, "recheck_actor_decision_record_certificate", raise_on_pass)
    result = _replay_subset(monkeypatch, {_ACTOR, _MODEL_HARDWARE})
    actor = _membership(result, _ACTOR)
    assert result["status"] == "FAIL"
    assert result["blockers"] == sorted(["ACTOR:ACTOR-3.3:POSITIVE:FAIL", code])
    assert actor["cases"][0]["exception_type"] == exception_type
    assert actor["cases"][0]["contract_detail"] == str(error)
    assert _statuses(result)[_MODEL_HARDWARE] == "PASS"


@pytest.mark.parametrize("statuses,expected", [
    ([], "UNKNOWN"),
    (["PASS"], "PASS"),
    (["PASS", "PASS"], "PASS"),
    (["UNKNOWN"], "UNKNOWN"),
    (["PASS", "UNKNOWN"], "UNKNOWN"),
    (["FAIL"], "FAIL"),
    (["UNKNOWN", "FAIL"], "FAIL"),
    (["FAIL", "UNKNOWN", "PASS"], "FAIL"),
])
def test_aggregate_join_is_fail_dominant_and_never_passes_unknown(statuses, expected):
    assert statics._join(statuses) == expected
