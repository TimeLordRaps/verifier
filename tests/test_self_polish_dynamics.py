"""Source-native Dynamics progression; no historical resource truth by fiat."""
from __future__ import annotations

import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest

from verifier.runtime import self_polish_dynamics as dynamics
from verifier.runtime import core_obligation_union as binding


ROOT = Path(__file__).parents[1]
PIN = "sha256:" + "1" * 64


def assess(**options):
    selected = dict(source_coordinate_digest=PIN, subject_id="verifier-core-self",
                    prior_report_digest="sha256:" + "2" * 64)
    selected.update(options)
    return dynamics.assess_native_dynamics(ROOT, **selected)


@pytest.fixture(scope="module")
def actual():
    return assess()


def test_source_native_dynamics_progression_is_available() -> None:
    assert importlib.util.find_spec("verifier.runtime.self_polish_dynamics") is not None


def test_actual_cumulative_replay_uses_explicit_fresh_variant(actual):
    assert actual["status"] == actual["selected_target_status"] == "PASS"
    assert actual["selected_depth"] == 2
    assert [r["direct_status"] for r in actual["tiers"]] == ["PASS", "PASS"]
    assert [len(r["required_routes"]) for r in actual["tiers"]] == [45, 37]
    assert [r["case_count"] for r in actual["native_assessments"].values()] == [135, 111]
    assert actual["native_replay"] == "EXECUTED"
    assert actual["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert actual["polished"] is actual["release_authorized"] is False
    resource = next(r for r in actual["native_assessments"]["2"]["memberships"] if r["obligation_id"] == "SIM:SIM-2.4")
    assert resource["membership"]["semantic_version"] == dynamics.native.sim_resource_fresh.SEMANTIC_VERSION
    result = resource["cases"][0]["fresh_execution_result"]
    assert result["historical_metric_correspondence"] == "NOT_ESTABLISHED"
    assert result["observation"]["source_recheck"] == "PASS"
    assert actual["blockers"] == []


def test_every_dynamics_reason_binds_its_exact_route_and_replay(actual):
    reasons = actual["dynamics_reasons"]
    assert reasons["status"] == "PASS"
    assert reasons["fulfillment_status"] == "PASS"
    assert reasons["reasoned_route_count"] == 37
    assert sum(r["fulfillment_status"] == "PASS" for r in reasons["entries"]) == 37
    replay = actual["native_assessments"]["2"]
    members = {r["obligation_id"]: r for r in replay["memberships"]}
    for row in reasons["entries"]:
        assert row["classification"] == "NECESSARY"
        assert row["necessity_reason"] and row["applicability_reason"] and row["fulfillment_reason"]
        assert row["evidence"]["source_coordinate_digest"] == PIN
        assert row["evidence"]["membership_replay_digest"] == members[row["obligation_id"]]["native_replay_digest"]
    resource = next(r for r in reasons["entries"] if r["obligation_id"] == "SIM:SIM-2.4")
    assert resource["fulfillment_status"] == "PASS"
    assert "fabricated numbers" in resource["necessity_reason"]
    assert "Historical signed-record claims remain UNKNOWN" in resource["applicability_reason"]


@pytest.mark.parametrize("which", ["report", "reasons"])
def test_exact_assessment_digests(actual, which):
    value = deepcopy(actual if which == "report" else actual["dynamics_reasons"])
    pin = value.pop("assessment_digest")
    assert binding.value_digest(value) == pin


def test_cancel_never_replays(monkeypatch):
    monkeypatch.setattr(dynamics, "_replay", lambda *a: pytest.fail("cancelled replay ran"))
    value = assess(cancelled=True)
    assert value["status"] == "UNKNOWN"
    assert value["native_replay"] == "NOT_RUN"
    assert value["blockers"] == ["DYNAMICS_PROGRESSION_CANCELLED"]
    assert len(value["tiers"]) == 2


@pytest.mark.parametrize("options", [
    {"source_coordinate_digest": "missing"}, {"prior_report_digest": None},
    {"subject_id": ""}, {"cancelled": 1},
])
def test_invalid_selection_cannot_replay(monkeypatch, options):
    monkeypatch.setattr(dynamics, "_replay", lambda *a: pytest.fail("invalid replay ran"))
    value = assess(**options)
    assert value["status"] == "FAIL"
    assert value["blockers"] == ["DYNAMICS_SELECTION_INVALID"]


@pytest.mark.parametrize("first_status,expected", [("PASS", "UNKNOWN"), ("FAIL", "FAIL")])
def test_later_unavailability_cannot_erase_earlier_failure(monkeypatch, actual, first_status, expected):
    def replay(tier, *args):
        if tier == 2:
            raise OSError("injected unavailable checker")
        result = deepcopy(actual["native_assessments"]["1"])
        result["status"] = first_status
        return result
    monkeypatch.setattr(dynamics, "_replay", replay)
    value = assess()
    assert value["status"] == value["selected_target_status"] == expected
    assert len(value["tiers"]) == 2
    assert "DYNAMICS_PROGRESSION_UNAVAILABLE" in value["blockers"]


@pytest.mark.parametrize("mutation", ["missing", "blank", "extra"])
def test_reason_coverage_cannot_be_removed_or_widened(monkeypatch, actual, mutation):
    reasons = dict(dynamics._NECESSITY)
    if mutation == "missing":
        reasons.pop("SIM-2.4")
    elif mutation == "blank":
        reasons["SIM-2.4"] = " "
    else:
        reasons["SIM-2.99"] = "not an installed route"
    monkeypatch.setattr(dynamics, "_NECESSITY", reasons)
    monkeypatch.setattr(dynamics, "_replay", lambda tier, *a: deepcopy(actual["native_assessments"][str(tier)]))
    result = assess()
    assert result["status"] == "FAIL"
    assert "DYNAMICS_NECESSITY_REASON_COVERAGE_DIFFERS" in result["blockers"]
    assert result["selected_depth"] < 2


def test_fresh_replay_does_not_accept_a_caller_verdict():
    with pytest.raises(TypeError):
        assess(native_assessments={"2": {"status": "PASS"}})


def test_repeated_execution_preserves_both_observations(actual):
    first = actual["native_assessments"]["2"]
    second = dynamics._replay(2, ROOT, PIN)
    assert first != second
    assert dynamics.native.same_execution_selection(first, second)
    changed = deepcopy(second)
    changed["source_coordinate_digest"] = "sha256:" + "0" * 64
    changed.pop("receipt_digest")
    changed["receipt_digest"] = binding.value_digest(changed)
    assert not dynamics.native.same_execution_selection(first, changed)


def test_legacy_profile_is_not_silently_upgraded(actual):
    selected = dynamics.native.installed_native_replay_registry()
    historical = next(row for row in selected["tiers"]["2"] if row["obligation_id"] == "SIM:SIM-2.4")
    fresh = next(row for row in actual["native_assessments"]["2"]["memberships"] if row["obligation_id"] == "SIM:SIM-2.4")
    assert historical["semantic_version"] != fresh["membership"]["semantic_version"]
    assert historical["proposition_digest"] != fresh["membership"]["proposition_digest"]
    assert selected["sim_resource_variant"] is None
