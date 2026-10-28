"""Verifier Standard (VSTD) selected objective-profile closure controls.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
The profiles here are synthetic test inventories, not normative objective lists.
Counts are dimensionless. Encoded transport and output limits are in bytes.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, assess_composition, composition_digest
from verifier.runtime import polish_inventory


SEMANTIC = "verifier-current-object-obligations-1"
LIMITS = {"objects": 256, "profile_objectives": 8192,
          "expanded_objectives": 32768, "rule_operations": 1000000,
          "composition_operations": 1000000, "output_bytes": 8388608}


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism() -> Any:
    return polish_inventory


def fixture(*, payload: dict[str, Any] | None = None, child: bool = False) -> tuple[dict[str, Any], dict[str, Any], list[NamespaceObject]]:
    root = NamespaceObject.create("root", "OBJECT", payload if payload is not None else {
        "signals": {"enabled": True, "count": 3, "explicit_null": None},
        "private_witness": "fixture-private-value-do-not-echo"})
    objects = [root]
    if child:
        objects.append(NamespaceObject.create("child", "OBJECT", {"signals": {"enabled": False}}))
    tiers = [{"tier": tier, "objectives": [{"semantic_version": SEMANTIC,
        "coordinate": f"OBJECT-{tier}.1", "proposition": f"Synthetic test inventory item {tier}",
        "applicability_rule": {"op": "always"}}]} for tier in range(1, 10)]
    tiers[0]["objectives"].append({"semantic_version": SEMANTIC,
        "coordinate": "OBJECT-1.2", "proposition": "Synthetic optional test inventory item",
        "applicability_rule": {"op": "equals", "path": ["payload", "signals", "enabled"], "value": True}})
    profile = {"schema_version": "verifier-polish-objective-profile-1",
        "profile_id": "synthetic-nine-tier-test-inventory", "revision": "test-1",
        "kinds": [{"kind": "OBJECT", "tiers": tiers}]}
    collection = {"schema_version": "verifier-polish-object-collection-1",
                  "objects": [item.to_dict() for item in objects]}
    return profile, collection, objects


def request(profile: dict[str, Any], collection: dict[str, Any], objects: list[NamespaceObject], *, limits: dict[str, int] | None=None) -> dict[str, Any]:
    return {"schema_version": "verifier-polish-inventory-request-1", "root_id": "root",
        "profile_digest": digest(canonical_bytes(profile)),
        "collection_bytes_digest": digest(canonical_bytes(collection)),
        "collection_digest": composition_digest(objects),
        "mechanism_digest": mechanism().mechanism_digest(),
        "limits": deepcopy(LIMITS if limits is None else limits)}


def plan(profile: dict[str, Any], selection: dict[str, Any], *, enabled: str="REQUIRED", child: bool=False) -> dict[str, Any]:
    rows = [{"object_id": "root", "semantic_version": SEMANTIC,
             "coordinate": f"OBJECT-{tier}.1", "applicability": "REQUIRED"}
            for tier in range(1, 10)]
    rows.insert(1, {"object_id": "root", "semantic_version": SEMANTIC,
        "coordinate": "OBJECT-1.2", "applicability": enabled})
    if child:
        extra = [{**row, "object_id": "child"} for row in rows]
        extra[1]["applicability"] = "NOT_APPLICABLE"
        rows = extra + rows
    return {"schema_version": "verifier-polish-objective-plan-1",
        "profile_digest": selection["profile_digest"],
        "collection_digest": selection["collection_digest"],
        "request_digest": digest(canonical_bytes(selection)), "requirements": rows}


def assess(profile: dict[str, Any], collection: dict[str, Any], selection: dict[str, Any], proposed: dict[str, Any]) -> dict[str, Any]:
    return mechanism().assess_objective_inventory(canonical_bytes(proposed),
        profile_bytes=canonical_bytes(profile), collection_bytes=canonical_bytes(collection),
        request_bytes=canonical_bytes(selection))


def selected(*, payload: dict[str, Any]=None, child: bool=False) -> tuple[dict[str, Any], dict[str, Any], list[NamespaceObject], dict[str, Any]]:
    profile, collection, objects = fixture(payload=payload, child=child)
    selection = request(profile, collection, objects)
    return profile, collection, objects, selection


def rule_selection(rule: dict[str, Any], expected: str="REQUIRED", *, payload: dict[str, Any]=None) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    profile, collection, objects = fixture(payload=payload)
    profile["kinds"][0]["tiers"][0]["objectives"][1]["applicability_rule"] = rule
    selection = request(profile, collection, objects)
    return profile, collection, selection, plan(profile, selection, enabled=expected)


def test_existing_namespace_fixture_has_independent_finite_composition_pass() -> None:
    _, _, objects = fixture(child=True)
    assert assess_composition(objects, expected_digest=composition_digest(objects)).verdict.value == "PASS"


def test_existing_namespace_fixture_binds_changed_payload() -> None:
    _, _, objects = fixture()
    original = composition_digest(objects)
    changed = NamespaceObject.create("root", "OBJECT", {"signals": {"enabled": False}})
    assert assess_composition([changed], expected_digest=original).verdict.value == "FAIL"


def test_synthetic_profile_retains_nine_nonempty_general_tiers() -> None:
    profile, _, _ = fixture()
    tiers = profile["kinds"][0]["tiers"]
    assert [row["tier"] for row in tiers] == list(range(1, 10))
    assert all(any(item["applicability_rule"] == {"op": "always"}
                   for item in row["objectives"]) for row in tiers)


def test_synthetic_objective_count_is_independent_of_tier_count() -> None:
    profile, _, _ = fixture()
    assert sum(len(row["objectives"]) for row in profile["kinds"][0]["tiers"]) == 10


def test_profile_transport_digest_is_exact_bytes() -> None:
    profile, _, _ = fixture()
    assert digest(canonical_bytes(profile)) != digest(json.dumps(profile, indent=2).encode("utf-8"))


def test_complete_selected_profile_plan_passes_only_its_exact_proposition() -> None:
    profile, collection, _, selection = selected()
    report = assess(profile, collection, selection, plan(profile, selection))
    assert report["status"] == "PASS"
    assert report["profile_plan_coverage"] == "PASS"
    assert report["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert report["authority_status"] == "NOT_ESTABLISHED"
    assert report["public_checkability"] == "NOT_ESTABLISHED"
    assert report["polished"] is False
    assert report["resource_usage"]["expanded_objectives"] == 10
    assert "fixture-private-value-do-not-echo" not in json.dumps(report)


def test_builder_agrees_with_independently_written_plan() -> None:
    profile, collection, _, selection = selected(child=True)
    result = mechanism().build_objective_inventory_plan(profile_bytes=canonical_bytes(profile),
        collection_bytes=canonical_bytes(collection), request_bytes=canonical_bytes(selection))
    assert result == canonical_bytes(plan(profile, selection, child=True))


@pytest.mark.parametrize("tier", range(1, 10))
def test_omitting_any_declared_unconditional_objective_is_refuted(tier: int) -> None:
    profile, collection, _, selection = selected()
    proposed = plan(profile, selection)
    proposed["requirements"] = [row for row in proposed["requirements"]
                                if row["coordinate"] != f"OBJECT-{tier}.1"]
    assert assess(profile, collection, selection, proposed)["status"] == "FAIL"


def test_second_objective_in_one_tier_cannot_be_hidden_by_complete_tier_rows() -> None:
    profile, collection, _, selection = selected()
    proposed = plan(profile, selection)
    proposed["requirements"].pop(1)
    assert assess(profile, collection, selection, proposed)["status"] == "FAIL"


def test_every_nonroot_supplied_object_requires_its_own_profile_plan() -> None:
    profile, collection, _, selection = selected(child=True)
    proposed = plan(profile, selection, child=True)
    proposed["requirements"] = [row for row in proposed["requirements"] if row["object_id"] == "root"]
    assert assess(profile, collection, selection, proposed)["status"] == "FAIL"


@pytest.mark.parametrize("mutation", ["duplicate", "extra", "subject", "coordinate", "semantic", "waiver"])
def test_plan_substitution_is_refuted(mutation: str) -> None:
    profile, collection, _, selection = selected()
    proposed = plan(profile, selection)
    if mutation == "duplicate":
        proposed["requirements"].append(deepcopy(proposed["requirements"][0]))
    elif mutation == "extra":
        proposed["requirements"].append({**proposed["requirements"][0], "coordinate": "OBJECT-1.99"})
    elif mutation == "subject":
        proposed["requirements"][0]["object_id"] = "other"
    elif mutation == "coordinate":
        proposed["requirements"][0]["coordinate"] = "SIM-1.1"
    elif mutation == "semantic":
        proposed["requirements"][0]["semantic_version"] = "legacy-unselected"
    else:
        proposed["requirements"][0]["applicability"] = "NOT_APPLICABLE"
    assert assess(profile, collection, selection, proposed)["status"] == "FAIL"


@pytest.mark.parametrize("mutation", ["empty-tier", "duplicate-tier", "boolean-tier", "missing-tier", "conditional-only", "duplicate-objective", "wrong-kind", "extra-profile-field"])
def test_invalid_profile_cannot_close_a_plan(mutation: str) -> None:
    profile, collection, objects = fixture()
    tiers = profile["kinds"][0]["tiers"]
    if mutation == "empty-tier":
        tiers[1]["objectives"] = []
    elif mutation == "duplicate-tier":
        tiers[1]["tier"] = 1
    elif mutation == "boolean-tier":
        tiers[0]["tier"] = True
    elif mutation == "missing-tier":
        tiers.pop()
    elif mutation == "conditional-only":
        tiers[1]["objectives"][0]["applicability_rule"] = {"op": "equals", "path": ["payload", "absent"], "value": True}
    elif mutation == "duplicate-objective":
        tiers[0]["objectives"].append(deepcopy(tiers[0]["objectives"][0]))
    elif mutation == "wrong-kind":
        tiers[0]["objectives"][0]["coordinate"] = "SIM-1.1"
    else:
        profile["complete"] = True
    selection = request(profile, collection, objects)
    assert assess(profile, collection, selection, plan(profile, selection))["status"] == "FAIL"


@pytest.mark.parametrize("rule,expected", [
    ({"op": "present", "path": ["payload", "signals", "explicit_null"]}, "REQUIRED"),
    ({"op": "present", "path": ["payload", "missing"]}, "NOT_APPLICABLE"),
    ({"op": "equals", "path": ["payload", "signals", "enabled"], "value": 1}, "NOT_APPLICABLE"),
    ({"op": "equals", "path": ["payload", "signals", "count"], "value": 3.0}, "NOT_APPLICABLE"),
    ({"op": "integer_range", "path": ["payload", "signals", "count"], "minimum": 2, "maximum": 4}, "REQUIRED"),
    ({"op": "integer_range", "path": ["payload", "signals", "count"], "minimum": 4, "maximum": 7}, "NOT_APPLICABLE"),
    ({"op": "not", "rule": {"op": "present", "path": ["payload", "missing"]}}, "REQUIRED"),
    ({"op": "equals", "path": ["payload", "signals", "explicit_null"], "value": None}, "REQUIRED"),
])
def test_rules_are_typed_and_bind_only_the_retained_record(rule: dict[str, Any], expected: str) -> None:
    profile, collection, selection, proposed = rule_selection(rule, expected)
    report = assess(profile, collection, selection, proposed)
    assert report["status"] == "PASS"
    assert report["authority_status"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("rule", [
    {"op": "equals", "path": ["payload", "missing"], "value": True},
    {"op": "integer_range", "path": ["payload", "signals", "enabled"], "minimum": 0, "maximum": 1},
    {"op": "integer_range", "path": ["payload", "missing"], "minimum": 0, "maximum": 1},
])
def test_missing_or_inadmissibly_typed_rule_observation_stays_unknown(rule: dict[str, Any]) -> None:
    profile, collection, selection, proposed = rule_selection(rule, "UNKNOWN")
    report = assess(profile, collection, selection, proposed)
    assert report["status"] == "UNKNOWN"
    assert report["profile_plan_coverage"] == "PASS"
    assert report["unresolved_applicability"] == 1


@pytest.mark.parametrize("operator,known,expected", [("all", False, "NOT_APPLICABLE"), ("any", True, "REQUIRED")])
def test_three_valued_compounds_keep_decisive_known_observations(operator: str, known: bool, expected: str) -> None:
    known_rule = {"op": "present", "path": ["payload", "signals"] if known else ["payload", "missing"]}
    unknown_rule = {"op": "equals", "path": ["payload", "unobserved"], "value": True}
    for children in ([known_rule, unknown_rule], [unknown_rule, known_rule]):
        args = rule_selection({"op": operator, "rules": children}, expected)
        assert assess(*args)["status"] == "PASS"


@pytest.mark.parametrize("rule", [
    {"op": "run", "command": "never-execute"},
    {"op": "equals", "path": ["payload"], "value": {}, "status": "PASS"},
    {"op": "present", "path": [True]},
    {"op": "integer_range", "path": ["payload", "signals", "count"], "minimum": True, "maximum": 3},
    {"op": "integer_range", "path": ["payload", "signals", "count"], "minimum": 4, "maximum": 3},
    {"op": "all", "rules": []},
    {"op": "any", "rules": [{"op": "always"}, {"op": "unknown-hidden-operator"}]},
])
def test_invalid_rules_cannot_hide_in_unselected_or_decisive_branches(rule: dict[str, Any]) -> None:
    args = rule_selection(rule)
    assert assess(*args)["status"] == "FAIL"


def test_admitted_budget_exhaustion_is_unknown_without_fabricated_plan_closure() -> None:
    profile, collection, objects = fixture()
    limits = {**LIMITS, "rule_operations": 1}
    selection = request(profile, collection, objects, limits=limits)
    report = assess(profile, collection, selection, plan(profile, selection))
    assert report["status"] == "UNKNOWN"
    assert report["reason"] == "RESOURCE_LIMIT_EXCEEDED"
    assert report["exhausted_resource"] == "rule_operations"
    assert report["polished"] is False


@pytest.mark.parametrize("field", list(LIMITS))
def test_boolean_resource_selection_is_not_an_integer(field: str) -> None:
    profile, collection, objects = fixture()
    selection = request(profile, collection, objects, limits={**LIMITS, field: True})
    assert assess(profile, collection, selection, plan(profile, selection))["status"] == "FAIL"


@pytest.mark.parametrize("field", ["profile_digest", "collection_bytes_digest", "collection_digest", "mechanism_digest"])
def test_external_selection_substitution_is_refuted(field: str) -> None:
    profile, collection, _, selection = selected()
    selection[field] = "sha256:" + "0" * 64
    assert assess(profile, collection, selection, plan(profile, selection))["status"] == "FAIL"


def test_profile_replacement_cannot_supply_its_own_authority() -> None:
    profile, collection, _, selection = selected()
    profile["kinds"][0]["tiers"][0]["objectives"].pop()
    proposed = plan(profile, selection)
    proposed["requirements"].pop(1)
    assert assess(profile, collection, selection, proposed)["status"] == "FAIL"


def test_duplicate_transport_key_is_rejected_without_echo() -> None:
    profile, collection, _, selection = selected()
    proposed = canonical_bytes(plan(profile, selection))
    raw = b'{"schema_version":"duplicate",' + proposed[1:]
    report = mechanism().assess_objective_inventory(raw, profile_bytes=canonical_bytes(profile),
        collection_bytes=canonical_bytes(collection), request_bytes=canonical_bytes(selection))
    assert report["status"] == "FAIL"
    assert "fixture-private-value-do-not-echo" not in json.dumps(report)


def test_unprofiled_supplied_kind_is_unknown_and_not_inferred_from_generic_profile() -> None:
    profile, collection, objects = fixture()
    other = NamespaceObject.create("hardware", "HARDWARE", {"declared": "fixture"})
    objects.append(other)
    collection["objects"].append(other.to_dict())
    selection = request(profile, collection, objects)
    report = assess(profile, collection, selection, plan(profile, selection))
    assert report["status"] == "UNKNOWN"
    assert report["unprofiled_kinds"] == ["HARDWARE"]


def test_known_omission_is_not_masked_by_an_unprofiled_kind() -> None:
    profile, collection, objects = fixture()
    other = NamespaceObject.create("hardware", "HARDWARE", {})
    objects.append(other)
    collection["objects"].append(other.to_dict())
    selection = request(profile, collection, objects)
    proposed = plan(profile, selection)
    proposed["requirements"].pop(0)
    assert assess(profile, collection, selection, proposed)["status"] == "FAIL"


def test_rechecker_recomputes_and_rejects_rehashed_forged_promotion() -> None:
    profile, collection, _, selection = selected()
    proposed = plan(profile, selection)
    report = assess(profile, collection, selection, proposed)
    inputs = {"plan_bytes": canonical_bytes(proposed), "profile_bytes": canonical_bytes(profile),
        "collection_bytes": canonical_bytes(collection), "request_bytes": canonical_bytes(selection)}
    replay = mechanism().recheck_objective_inventory(canonical_bytes(report), **inputs)
    assert replay["status"] == "PASS"
    assert replay["replay_status"] == "REPRODUCED"
    forged = {**report, "polished": True}
    forged.pop("assessment_digest")
    forged["assessment_digest"] = digest(canonical_bytes(forged))
    rejected = mechanism().recheck_objective_inventory(canonical_bytes(forged), **inputs)
    assert rejected["status"] == "FAIL"
    assert rejected["replay_status"] == "REJECTED"


def test_collection_record_permutation_preserves_plan_semantics_with_exact_new_selection() -> None:
    profile, collection, objects, selection = selected(child=True)
    first = assess(profile, collection, selection, plan(profile, selection, child=True))
    collection["objects"].reverse()
    second_selection = request(profile, collection, objects)
    second = assess(profile, collection, second_selection, plan(profile, second_selection, child=True))
    assert first["status"] == second["status"] == "PASS"
    assert first["collection_digest"] == second["collection_digest"]
    assert first["collection_bytes_digest"] != second["collection_bytes_digest"]


def test_capacity_unknown_receipt_cannot_be_replayed_for_a_different_external_request() -> None:
    profile, collection, objects = fixture()
    first = request(profile, collection, objects, limits={**LIMITS, "rule_operations": 1})
    second = request(profile, collection, objects, limits={**LIMITS, "rule_operations": 2})
    first_report = assess(profile, collection, first, plan(profile, first))
    assert first_report["status"] == "UNKNOWN"
    replay = mechanism().recheck_objective_inventory(canonical_bytes(first_report),
        plan_bytes=canonical_bytes(plan(profile, second)), profile_bytes=canonical_bytes(profile),
        collection_bytes=canonical_bytes(collection), request_bytes=canonical_bytes(second))
    assert replay["replay_status"] == "REJECTED"
    assert replay["status"] == "FAIL"


def test_refuted_plan_receipt_cannot_be_replayed_for_different_refuted_input() -> None:
    profile, collection, _, selection = selected()
    first = plan(profile, selection)
    second = plan(profile, selection)
    first["requirements"][0]["coordinate"] = "OBJECT-1.98"
    second["requirements"][0]["coordinate"] = "OBJECT-1.99"
    first_report = assess(profile, collection, selection, first)
    assert first_report["status"] == "FAIL"
    replay = mechanism().recheck_objective_inventory(canonical_bytes(first_report),
        plan_bytes=canonical_bytes(second), profile_bytes=canonical_bytes(profile),
        collection_bytes=canonical_bytes(collection), request_bytes=canonical_bytes(selection))
    assert replay["replay_status"] == "REJECTED"


def test_synthetic_fixture_preserves_explicit_empty_payload() -> None:
    _, collection, objects = fixture(payload={})
    assert collection["objects"][0]["payload"] == {}
    assert objects[0].payload == {}


@pytest.mark.parametrize("operator,first,second,expected", [
    ("all", "T", "T", "T"), ("all", "T", "F", "F"), ("all", "T", "U", "U"),
    ("all", "F", "T", "F"), ("all", "F", "F", "F"), ("all", "F", "U", "F"),
    ("all", "U", "T", "U"), ("all", "U", "F", "F"), ("all", "U", "U", "U"),
    ("any", "T", "T", "T"), ("any", "T", "F", "T"), ("any", "T", "U", "T"),
    ("any", "F", "T", "T"), ("any", "F", "F", "F"), ("any", "F", "U", "U"),
    ("any", "U", "T", "T"), ("any", "U", "F", "U"), ("any", "U", "U", "U"),
])
def test_compound_rules_reproduce_the_full_independent_three_valued_table(operator: str, first: str, second: str, expected: str) -> None:
    observations = {"T": {"op": "always"}, "F": {"op": "present", "path": ["payload", "absent"]},
        "U": {"op": "equals", "path": ["payload", "absent"], "value": None}}
    applicability = {"T": "REQUIRED", "F": "NOT_APPLICABLE", "U": "UNKNOWN"}[expected]
    args = rule_selection({"op": operator, "rules": [observations[first], observations[second]]}, applicability)
    report = assess(*args)
    assert report["status"] == ("UNKNOWN" if expected == "U" else "PASS")


@pytest.mark.parametrize("payload,literal,expected", [
    ({"values": [{"value": True}]}, [{"value": 1}], "NOT_APPLICABLE"),
    ({"value": -0.0}, 0.0, "NOT_APPLICABLE"),
    ({"value": {"x": [True, None, 3.0]}}, {"x": [True, None, 3.0]}, "REQUIRED"),
])
def test_nested_equality_and_float_zero_follow_typed_canonical_semantics(payload: dict[str, Any], literal: Any, expected: str) -> None:
    name = "values" if "values" in payload else "value"
    args = rule_selection({"op": "equals", "path": ["payload", name], "value": literal}, expected, payload=payload)
    assert assess(*args)["status"] == "PASS"


def test_array_index_path_observes_retained_value_and_preserves_missing_index_unknown() -> None:
    good = rule_selection({"op": "equals", "path": ["payload", "values", 0], "value": 7},
        "REQUIRED", payload={"values": [7]})
    missing = rule_selection({"op": "equals", "path": ["payload", "values", 1], "value": 7},
        "UNKNOWN", payload={"values": [7]})
    assert assess(*good)["status"] == "PASS"
    assert assess(*missing)["status"] == "UNKNOWN"


@pytest.mark.parametrize("depth,expected", [(16, "PASS"), (17, "FAIL")])
def test_rule_depth_boundary_is_refutable(depth: int, expected: str) -> None:
    rule = {"op": "always"}
    for _ in range(depth):
        rule = {"op": "not", "rule": rule}
    args = rule_selection(rule, "REQUIRED" if depth % 2 == 0 else "NOT_APPLICABLE")
    assert assess(*args)["status"] == expected


@pytest.mark.parametrize("nodes,expected", [(512, "PASS"), (513, "FAIL")])
def test_rule_node_boundary_is_refutable(nodes: int, expected: str) -> None:
    groups = [{"op": "all", "rules": [{"op": "always"} for _ in range(7)]} for _ in range(63)]
    groups.append({"op": "all", "rules": [{"op": "always"} for _ in range(nodes - 506)]})
    args = rule_selection({"op": "all", "rules": groups})
    assert assess(*args)["status"] == expected


@pytest.mark.parametrize("resource", ["objects", "profile_objectives", "expanded_objectives", "composition_operations", "output_bytes"])
def test_each_selected_capacity_remains_a_distinct_unknown_gate(resource: str) -> None:
    profile, collection, objects = fixture(child=True)
    limits = {**LIMITS, resource: 4096 if resource == "output_bytes" else 1}
    selection = request(profile, collection, objects, limits=limits)
    report = assess(profile, collection, selection, plan(profile, selection, child=True))
    assert report["status"] == "UNKNOWN"
    assert report["reason"] == "RESOURCE_LIMIT_EXCEEDED"
    assert report["exhausted_resource"] == resource


@pytest.mark.parametrize("raw", [bytearray(b"{}"), memoryview(b"{}"), "{}", b"x" * (8388608 + 1)],
    ids=["mutable-bytearray", "memoryview", "string", "over-bound-bytes"])
def test_nonretained_transport_diagnostic_cannot_be_admitted_as_replayable(raw: Any) -> None:
    profile, collection, _, selection = selected()
    inputs = {"plan_bytes": raw, "profile_bytes": canonical_bytes(profile),
        "collection_bytes": canonical_bytes(collection), "request_bytes": canonical_bytes(selection)}
    report = mechanism().assess_objective_inventory(**inputs)
    assert report["status"] == "FAIL"
    assert report["replayable"] is False
    assert mechanism().recheck_objective_inventory(canonical_bytes(report), **inputs)["replay_status"] == "REJECTED"


def test_hostile_bytes_subclass_is_rejected_before_invoking_its_methods() -> None:
    class Hostile(bytes):
        def __len__(self: Hostile) -> int:
            raise AssertionError("caller-controlled length method must not execute")

    profile, collection, _, selection = selected()
    report = mechanism().assess_objective_inventory(Hostile(b"{}"),
        profile_bytes=canonical_bytes(profile), collection_bytes=canonical_bytes(collection),
        request_bytes=canonical_bytes(selection))
    assert report["status"] == "FAIL"
    assert report["replayable"] is False


def test_reordered_profile_rows_recompile_to_the_same_selected_plan_order() -> None:
    profile, collection, objects = fixture(child=True)
    profile["kinds"][0]["tiers"].reverse()
    profile["kinds"][0]["tiers"][-1]["objectives"].reverse()
    selection = request(profile, collection, objects)
    assert mechanism().build_objective_inventory_plan(profile_bytes=canonical_bytes(profile),
        collection_bytes=canonical_bytes(collection), request_bytes=canonical_bytes(selection)) == canonical_bytes(plan(profile, selection, child=True))


def test_omission_does_not_silently_reorder_the_declared_plan() -> None:
    profile, collection, _, selection = selected()
    proposed = plan(profile, selection)
    proposed["requirements"].reverse()
    assert assess(profile, collection, selection, proposed)["status"] == "FAIL"


def test_builder_preserves_unknown_rules_and_refuses_partial_capacity() -> None:
    profile, collection, selection, proposed = rule_selection({"op": "equals", "path": ["payload", "absent"], "value": True}, "UNKNOWN")
    assert mechanism().build_objective_inventory_plan(profile_bytes=canonical_bytes(profile),
        collection_bytes=canonical_bytes(collection), request_bytes=canonical_bytes(selection)) == canonical_bytes(proposed)
    selection["limits"]["rule_operations"] = 1
    with pytest.raises(mechanism().InventoryUnavailable):
        mechanism().build_objective_inventory_plan(profile_bytes=canonical_bytes(profile),
            collection_bytes=canonical_bytes(collection), request_bytes=canonical_bytes(selection))


@pytest.mark.parametrize("transport", ["profile", "collection"])
def test_builder_refuses_fixed_transport_overflow_before_hashing_that_input(transport: str) -> None:
    import sys

    profile, collection, _, selection = selected()
    module = mechanism()
    oversized = b" " * (module.TRANSPORT_BYTES[transport] + 1)
    profile_raw = oversized if transport == "profile" else canonical_bytes(profile)
    collection_raw = oversized if transport == "collection" else canonical_bytes(collection)
    selection["profile_digest" if transport == "profile" else "collection_bytes_digest"] = digest(oversized)
    observed_hash_calls: list[bool] = []
    previous_profiler = sys.getprofile()

    def observe(frame: Any, event: str, argument: Any) -> None:
        if event == "call" and frame.f_code is module._digest.__code__:
            if frame.f_locals.get("raw") is oversized:
                observed_hash_calls.append(True)

    try:
        sys.setprofile(observe)
        with pytest.raises(ValueError):
            module.build_objective_inventory_plan(profile_bytes=profile_raw,
                collection_bytes=collection_raw, request_bytes=canonical_bytes(selection))
    finally:
        sys.setprofile(previous_profiler)
    assert observed_hash_calls == [], "inadmissible raw transport entered the real hashing function"



def test_wrapper_source_mutation_rejects_stale_inventory_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    profile, collection, objects = fixture()
    chosen = request(profile, collection, objects)
    selected = plan(profile, chosen)
    gate = mechanism()
    inputs = {"profile_bytes": canonical_bytes(profile), "collection_bytes": canonical_bytes(collection),
              "request_bytes": canonical_bytes(chosen)}
    report = gate.assess_objective_inventory(canonical_bytes(selected), **inputs)
    assert report["status"] == "PASS" and report["polished"] is False
    target, original = Path(gate.__file__), Path.read_bytes

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged wrapper source\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert gate.mechanism_digest() != chosen["mechanism_digest"]
    replay = gate.recheck_objective_inventory(canonical_bytes(report), plan_bytes=canonical_bytes(selected), **inputs)
    assert replay["status"] == "FAIL" and replay["replay_status"] == "REJECTED"
    assert replay["polished"] is False
