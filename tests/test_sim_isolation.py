"""Finite simulation (SIM) isolation against retained virtual HARDWARE records.

These tests check the bounded computational model, not physical host containment.
"""
from __future__ import annotations

from copy import deepcopy

import pytest

import verifier.domains.common as common_module
from verifier.domains.common import Refuted, digest
import verifier.domains.contracts.sim_isolation as isolation_module
from verifier.domains.contracts.sim_isolation import assess_sim_isolation, recheck_sim_isolation


def model() -> dict:
    return {
        "schema_version": "verifier-sim-isolation-evidence-1",
        "sim_id": "sim:finite-room",
        "initial_state": "idle",
        "virtual_hardware": [
            {"id": "virtual:cpu", "kind": "compute"},
            {"id": "virtual:store", "kind": "storage"},
        ],
        "states": [
            {"id": "idle", "partition": "inside", "capabilities": ["virtual:cpu", "virtual:store"]},
            {"id": "busy", "partition": "inside", "capabilities": ["virtual:cpu", "virtual:store"]},
            {"id": "host", "partition": "outside", "capabilities": ["physical:network"]},
        ],
        "actions": ["step"],
        "transitions": [
            {"source": "idle", "action": "step", "outcomes": [
                {"target": "busy", "effects": [{"kind": "internal_write", "target": "virtual:cpu"}]},
            ]},
            {"source": "busy", "action": "step", "outcomes": [
                {"target": "idle", "effects": [
                    {"kind": "receipt_record", "target": "virtual:store"},
                    {"kind": "data_record", "target": "virtual:store"},
                ]},
            ]},
        ],
    }


def binding(evidence: dict, *, max_operations: int = 1000, max_items: int = 64) -> dict:
    return {"sim_id": evidence["sim_id"], "evidence_digest": digest(evidence),
            "max_operations": max_operations, "max_items": max_items}


def assess(evidence: dict, *, max_operations: int = 1000, max_items: int = 64) -> dict:
    return assess_sim_isolation(evidence, expected_binding=binding(
        evidence, max_operations=max_operations, max_items=max_items))


def test_complete_cyclic_model_and_inert_receipt_export_replay() -> None:
    evidence = model()
    selected = binding(evidence)
    result = assess_sim_isolation(evidence, expected_binding=selected)
    assert result["status"] == "PASS", result
    assert result["reachable_states"] == 2
    assert result["checked_outcomes"] == 2
    assert result["unreachable_states"] == 1
    assert result["scope"] == "finite_declared_transition_model"
    assert result["physical_host_containment"] == "NOT_ESTABLISHED"
    assert result["authority"] == "NOT_ESTABLISHED"
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["evidence_digest"] == selected["evidence_digest"]
    assert result["assessment_digest"] == digest({k: v for k, v in result.items()
                                                  if k != "assessment_digest"})
    assert recheck_sim_isolation(result, evidence, expected_binding=selected) == result


def test_missing_pair_is_unknown_even_with_all_retained_states() -> None:
    evidence = model()
    evidence["transitions"].pop()
    result = assess(evidence)
    assert result["status"] == "UNKNOWN", result
    assert result["missing_pairs"] == [{"state": "busy", "action": "step"}]


def test_empty_outcome_is_unknown() -> None:
    evidence = model()
    evidence["transitions"][1]["outcomes"] = []
    assert assess(evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("change,reason", [
    ("outside_state", "outside"),
    ("external_actuation", "external"),
    ("outside_write", "outside"),
    ("external_export", "external"),
    ("capability_acquire", "acquisition"),
    ("new_capability", "capability"),
    ("initial_outside_capability", "capability"),
    ("unheld_virtual_target", "capability"),
    ("receipt_on_compute", "storage"),
])
def test_explicit_boundary_escape_fails_even_after_rebinding(change: str, reason: str) -> None:
    evidence = model()
    outcome = evidence["transitions"][0]["outcomes"][0]
    if change == "outside_state":
        outcome["target"] = "host"
    elif change == "new_capability":
        evidence["states"][1]["capabilities"].append("virtual:new")
    elif change == "initial_outside_capability":
        evidence["states"][0]["capabilities"].append("physical:network")
    elif change == "unheld_virtual_target":
        evidence["states"][0]["capabilities"].remove("virtual:cpu")
        evidence["states"][1]["capabilities"].remove("virtual:cpu")
    elif change == "receipt_on_compute":
        outcome["effects"] = [{"kind": "receipt_record", "target": "virtual:cpu"}]
    else:
        outcome["effects"] = [{"kind": change, "target": "physical:network"}]
    result = assess(evidence)
    assert result["status"] == "FAIL", result
    assert reason in result["reason"].lower(), result


@pytest.mark.parametrize("change", [
    "duplicate_state", "duplicate_hardware", "duplicate_action", "duplicate_pair",
    "dangling_source", "dangling_target", "unknown_action", "unknown_effect",
    "negative_limit", "boolean_limit", "extra_field",
])
def test_malformed_or_unsupported_boundaries_do_not_pass(change: str) -> None:
    evidence = model()
    selected = binding(evidence)
    if change == "duplicate_state":
        evidence["states"].append(deepcopy(evidence["states"][0]))
    elif change == "duplicate_hardware":
        evidence["virtual_hardware"].append(deepcopy(evidence["virtual_hardware"][0]))
    elif change == "duplicate_action":
        evidence["actions"].append("step")
    elif change == "duplicate_pair":
        evidence["transitions"].append(deepcopy(evidence["transitions"][0]))
    elif change == "dangling_source":
        evidence["transitions"][0]["source"] = "missing"
    elif change == "dangling_target":
        evidence["transitions"][0]["outcomes"][0]["target"] = "missing"
    elif change == "unknown_action":
        evidence["transitions"][0]["action"] = "unknown"
    elif change == "unknown_effect":
        evidence["transitions"][0]["outcomes"][0]["effects"][0]["kind"] = "magic"
    elif change == "negative_limit":
        selected["max_operations"] = -1
    elif change == "boolean_limit":
        selected["max_items"] = True
    elif change == "extra_field":
        evidence["states"][0]["unexpected"] = "ignored?"
    if change not in ("negative_limit", "boolean_limit"):
        selected = binding(evidence)
    try:
        result = assess_sim_isolation(evidence, expected_binding=selected)
    except Refuted:
        return
    assert result["status"] != "PASS", result


def test_budget_exhaustion_is_unknown_and_bound() -> None:
    result = assess(model(), max_operations=5)
    assert result["status"] == "UNKNOWN", result
    assert "budget" in result["reason"].lower() or "bound" in result["reason"].lower()


def test_oversized_string_is_rejected_before_canonical_serialization(monkeypatch) -> None:
    evidence = model()
    selected = binding(evidence)
    evidence["sim_id"] = "x" * (1024 * 1024 + 1)
    original = isolation_module.canonical_bytes

    def guarded(value):
        if value is evidence:
            raise AssertionError("oversized evidence was serialized before the byte gate")
        return original(value)

    monkeypatch.setattr(isolation_module, "canonical_bytes", guarded)
    result = assess_sim_isolation(evidence, expected_binding=selected)
    assert result["status"] == "UNKNOWN", result
    assert "byte" in result["reason"].lower()


def test_every_nondeterministic_outcome_is_checked() -> None:
    evidence = model()
    evidence["transitions"][0]["outcomes"].append(
        {"target": "idle", "effects": []})
    assert assess(evidence)["checked_outcomes"] == 3
    evidence["transitions"][0]["outcomes"][1]["target"] = "host"
    assert assess(evidence)["status"] == "FAIL"


def test_explicit_escape_overrides_another_missing_pair() -> None:
    evidence = model()
    evidence["transitions"][0]["outcomes"][0]["effects"] = [
        {"kind": "external_export", "target": "physical:network"}]
    evidence["transitions"].pop()
    assert assess(evidence)["status"] == "FAIL"


def test_recheck_rejects_forged_result_and_stale_evidence_binding() -> None:
    evidence = model()
    selected = binding(evidence)
    original = assess_sim_isolation(evidence, expected_binding=selected)
    forged = deepcopy(original)
    forged["checked_outcomes"] = 999
    forged["assessment_digest"] = digest({k: v for k, v in forged.items()
                                          if k != "assessment_digest"})
    with pytest.raises(Refuted):
        recheck_sim_isolation(forged, evidence, expected_binding=selected)
    changed_budget = dict(selected, max_operations=selected["max_operations"] + 1)
    assert digest(changed_budget) != original["binding_digest"]
    with pytest.raises(Refuted):
        recheck_sim_isolation(original, evidence, expected_binding=changed_budget)
    changed = deepcopy(evidence)
    changed["transitions"][0]["outcomes"][0]["target"] = "host"
    assert assess_sim_isolation(changed, expected_binding=selected)["status"] == "FAIL"
    with pytest.raises(Refuted):
        recheck_sim_isolation(original, changed, expected_binding=selected)
    with pytest.raises(Refuted, match="malformed retained assessment"):
        recheck_sim_isolation({"status": float("nan")}, evidence, expected_binding=selected)


def test_recheck_rejects_oversized_assessment_before_serialization(monkeypatch) -> None:
    evidence = model()
    selected = binding(evidence)
    forged = assess_sim_isolation(evidence, expected_binding=selected)
    forged["reason"] = "x" * (2 * 1024 * 1024 + 1)
    original = common_module.canonical_bytes

    def guarded(value):
        if value is forged:
            raise AssertionError("oversized assessment was serialized")
        return original(value)

    monkeypatch.setattr(common_module, "canonical_bytes", guarded)
    with pytest.raises(Refuted, match="malformed retained assessment"):
        recheck_sim_isolation(forged, evidence, expected_binding=selected)


def test_selected_sim_identity_is_bounded_before_binding_digest() -> None:
    evidence = model()
    selected = binding(evidence)
    selected["sim_id"] = "s" * 257
    with pytest.raises(Refuted, match="simulation identity bound"):
        assess_sim_isolation(evidence, expected_binding=selected)


def test_missing_pair_diagnostics_have_a_byte_bound() -> None:
    evidence = model()
    long_id = "i" * 100_000
    evidence["initial_state"] = long_id
    evidence["states"][0]["id"] = long_id
    evidence["transitions"] = []
    evidence["actions"] = ["a", "b", "c", "d"]
    result = assess(evidence, max_operations=10000)
    assert result["status"] == "UNKNOWN", result
    assert "missing transition list bound" in result["reason"]


def test_result_does_not_upgrade_existing_domain_certificate() -> None:
    result = assess(model())
    assert "domain_depth" not in result
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"


def test_mutation_after_canonical_capture_cannot_change_checked_inventory(monkeypatch) -> None:
    evidence = model()
    selected = binding(evidence)
    original = isolation_module.canonical_bytes

    def mutate_after_capture(value):
        captured = original(value)
        if value is evidence:
            evidence["virtual_hardware"][0]["kind"] = "storage"
        return captured

    monkeypatch.setattr(isolation_module, "canonical_bytes", mutate_after_capture)
    result = assess_sim_isolation(evidence, expected_binding=selected)
    assert result["status"] == "PASS", result
    assert result["virtual_hardware"] == [
        {"id": "virtual:cpu", "kind": "compute"},
        {"id": "virtual:store", "kind": "storage"},
    ]


def test_selected_binding_mutation_after_capture_does_not_rebind_result(monkeypatch) -> None:
    evidence = model()
    selected = binding(evidence)
    original_selected = dict(selected)
    original = isolation_module.canonical_bytes

    def mutate_after_capture(value):
        captured = original(value)
        if value is evidence:
            selected["max_operations"] += 1
        return captured

    monkeypatch.setattr(isolation_module, "canonical_bytes", mutate_after_capture)
    result = assess_sim_isolation(evidence, expected_binding=selected)
    assert result["status"] == "PASS", result
    assert result["binding_digest"] == digest(original_selected)
