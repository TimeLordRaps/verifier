"""Independent controls for Pull Request Domain Explanation Language (PRDEL).

These inert evidence fixtures do not execute a retained command or establish a
Verifier Standard (VSTD) certificate. The abstract syntax tree (AST) intersections
remain potential impact notices, never demonstrated runtime conflicts.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from verifier.runtime.prdel_coverage import (
    LAYERS,
    assess_coverage,
    preventative_obligations,
)


def _binding(head: str = "b") -> dict:
    return {
        "base": "a" * 40,
        "head": head * 40,
        "source_digest": "c" * 64,
        "requirements_digest": "d" * 64,
    }


def _required() -> list[dict]:
    return [
        {
            "id": "source:1",
            "kind": "source",
            "path": "module.py",
            "question": "How does the changed behavior satisfy its requirement?",
        }
    ]


def _receipts(status: str = "PASS") -> list[dict]:
    return [
        {
            "id": "result:" + layer,
            **_binding(),
            "kind": "test_result",
            "obligation_ids": ["source:1"],
            "layer": layer,
            "status": status,
            "command": "python -m pytest tests/test_behavior.py",
            "result_digest": "e" * 64,
        }
        for layer in LAYERS
    ]


def _records(status: str = "EXECUTED") -> list[dict]:
    return [
        {
            "id": "source:1",
            "coverage": {
                layer: {
                    "status": status,
                    "evidence_ids": ["result:" + layer] if status == "EXECUTED" else [],
                    "reason": (
                        "Retained test result."
                        if status == "EXECUTED"
                        else "Execution unavailable."
                    ),
                }
                for layer in LAYERS
            },
        }
    ]


def _codes(result: dict) -> set[str]:
    return {finding["code"] for finding in result["findings"]}


def test_corresponding_reported_pass_is_not_execution_or_semantic_clearance() -> None:
    result = assess_coverage(_required(), _records(), _receipts(), _binding())
    assert result["structural_status"] == "PASS"
    assert result["verdict"] == "UNKNOWN"
    assert (
        result["execution_authentication"]
        == result["semantic_clearance"]
        == "NOT_ESTABLISHED"
    )
    assert result["execution_status"] == "EXECUTED_REPORTED"
    assert _codes(result) == {"EXECUTION_NOT_ESTABLISHED"}
    for layer in LAYERS:
        assert result["layers"][layer]["verdict"] == "UNKNOWN"
        assert result["layers"][layer]["execution_status"] == "EXECUTED_REPORTED"
        assert result["layers"][layer]["obligations"][0]["recorded_verdict"] == "PASS"


@pytest.mark.parametrize(
    "field", ["base", "head", "source_digest", "requirements_digest"]
)
def test_each_stale_binding_fails_closed(field: str) -> None:
    receipts = _receipts()
    receipts[0][field] = "f" * len(receipts[0][field])
    result = assess_coverage(_required(), _records(), receipts, _binding())
    assert result["verdict"] == "FAIL"
    assert "STALE_EVIDENCE" in _codes(result)


def test_unrelated_obligation_evidence_does_not_cover_changed_behavior() -> None:
    required = _required() + [{**_required()[0], "id": "source:other"}]
    receipts = _receipts()
    receipts[0]["obligation_ids"] = ["source:other"]
    result = assess_coverage(required, _records(), receipts, _binding())
    assert result["verdict"] == "FAIL"
    assert "IRRELEVANT_EVIDENCE" in _codes(result)
    assert "MISSING_LAYER_COVERAGE" in _codes(result)


def test_layers_require_independent_relevant_evidence() -> None:
    receipts = _receipts()
    receipts[0]["layer"] = "unit"
    result = assess_coverage(_required(), _records(), receipts, _binding())
    assert "IRRELEVANT_EVIDENCE" in _codes(result)
    assert result["layers"]["base"]["verdict"] == "FAIL"


@pytest.mark.parametrize("status", ["UNRUN", "NOT_RUN"])
def test_unrun_fails_required_evidence_obligation_without_refuting_source_behavior(
    status: str,
) -> None:
    unrun = assess_coverage(_required(), _records(status), [], _binding())
    failed = assess_coverage(_required(), _records(), _receipts("FAIL"), _binding())
    assert unrun["verdict"] == "FAIL"
    assert unrun["execution_status"] == "NOT_RUN"
    assert unrun["failure_scope"] == "SELECTED_EVIDENCE_AND_COVERAGE_OBLIGATIONS"
    assert _codes(unrun) == {"UNRUN_LAYER"}
    for layer in LAYERS:
        summary = unrun["layers"][layer]
        assert summary["verdict"] == "FAIL"
        assert summary["execution_status"] == "NOT_RUN"
        assert summary["obligations"][0]["recorded_verdict"] == "UNKNOWN"
    assert all(
        finding["verdict"] == "FAIL" and finding["execution_status"] == "NOT_RUN"
        for finding in unrun["findings"]
    )
    assert failed["verdict"] == "FAIL"
    assert failed["execution_status"] == "EXECUTED_REPORTED"
    assert _codes(failed) == {"REPORTED_TEST_FAILURE"}


def test_missing_required_layer_records_fail_completeness_with_not_run() -> None:
    result = assess_coverage(
        _required(), [{"id": "source:1", "coverage": {}}], [], _binding()
    )
    assert result["verdict"] == "FAIL"
    assert result["execution_status"] == "NOT_RUN"
    assert _codes(result) == {"MISSING_LAYER_COVERAGE"}
    assert set(result["layers"]) == set(LAYERS)
    assert all(
        summary["verdict"] == "FAIL" and summary["execution_status"] == "NOT_RUN"
        for summary in result["layers"].values()
    )


def test_reported_unknown_result_remains_unresolved_evaluation() -> None:
    result = assess_coverage(_required(), _records(), _receipts("UNKNOWN"), _binding())
    assert result["verdict"] == "UNKNOWN"
    assert result["execution_status"] == "EXECUTED_REPORTED"
    assert _codes(result) == {"UNKNOWN_TEST_RESULT"}
    assert all(
        summary["verdict"] == "UNKNOWN"
        and summary["execution_status"] == "EXECUTED_REPORTED"
        for summary in result["layers"].values()
    )


@pytest.mark.parametrize("layer", LAYERS)
def test_failed_retained_result_cannot_hide_behind_empty_explanation_coverage(
    layer: str,
) -> None:
    records = [{"id": "source:1", "coverage": {}}]
    failed = next(receipt for receipt in _receipts("FAIL") if receipt["layer"] == layer)
    result = assess_coverage(_required(), records, [failed], _binding())
    assert result["verdict"] == "FAIL"
    assert result["layers"][layer]["verdict"] == "FAIL"
    disposition = next(
        finding
        for finding in result["findings"]
        if finding["code"] == "REPORTED_TEST_FAILURE"
    )
    assert disposition["evidence_id"] == failed["id"]
    assert disposition["obligation_ids"] == ["source:1"]
    assert (
        result["layers"][layer]["obligations"][0]["execution_status"]
        == "EXECUTED_REPORTED"
    )


def test_nonrequired_layer_preserves_retained_failed_result() -> None:
    required = _required()
    required[0].update(
        required_layers=["base"],
        applicability_reasons={
            layer: "Only narrative documentation changed."
            for layer in LAYERS
            if layer != "base"
        },
    )
    failed = next(
        receipt for receipt in _receipts("FAIL") if receipt["layer"] == "unit"
    )
    result = assess_coverage(
        required, [{"id": "source:1", "coverage": {}}], [failed], _binding()
    )
    assert result["verdict"] == "FAIL"
    assert result["layers"]["unit"]["verdict"] == "FAIL"
    entry = result["layers"]["unit"]["obligations"][0]
    assert entry["applicability"] == "EXTERNALLY_SELECTED_NOT_REQUIRED"
    assert entry["recorded_verdict"] == entry["verdict"] == "FAIL"


def test_selected_pass_cannot_overwrite_omitted_failure() -> None:
    evidence = _receipts()
    failed = {**evidence[0], "id": "omitted-failure", "status": "FAIL"}
    result = assess_coverage(_required(), _records(), evidence + [failed], _binding())
    base = result["layers"]["base"]["obligations"][0]
    assert result["verdict"] == "FAIL"
    assert base["verdict"] == base["recorded_verdict"] == "FAIL"
    assert set(base["evidence_ids"]) == {"result:base", "omitted-failure"}


@pytest.mark.parametrize("size", [40, 64])
def test_exact_supported_commit_identifier_lengths(size: int) -> None:
    binding = {**_binding(), "base": "a" * size, "head": "b" * size}
    evidence = [{**receipt, **binding} for receipt in _receipts()]
    result = assess_coverage(_required(), _records(), evidence, binding)
    assert result["structural_status"] == "PASS"
    assert result["verdict"] == "UNKNOWN"


@pytest.mark.parametrize("size", [0, 39, 41, 63, 65])
def test_unsupported_commit_identifier_lengths_fail_closed(size: int) -> None:
    binding = {**_binding(), "head": "b" * size}
    result = assess_coverage(_required(), _records(), _receipts(), binding)
    assert result["verdict"] == "FAIL"
    assert "INVALID_INPUT" in _codes(result)


def test_self_reported_not_applicable_cannot_waive_required_layers() -> None:
    result = assess_coverage(_required(), _records("NOT_APPLICABLE"), [], _binding())
    assert result["verdict"] == "FAIL"
    assert result["execution_status"] == "NOT_RUN"
    assert _codes(result) == {"SELF_REPORTED_WAIVER"}
    assert all(
        result["layers"][layer]["verdict"] == "FAIL"
        and result["layers"][layer]["execution_status"] == "NOT_RUN"
        for layer in LAYERS
    )


def test_generated_applicability_can_close_the_named_policy_predicate() -> None:
    required = _required()
    required[0]["required_layers"] = ["base"]
    required[0]["applicability_reasons"] = {
        layer: "Only narrative documentation changed; no executable source changed."
        for layer in LAYERS
        if layer != "base"
    }
    records = _records()
    records[0]["coverage"] = {"base": records[0]["coverage"]["base"]}
    result = assess_coverage(required, records, [_receipts()[0]], _binding())
    assert result["verdict"] == "UNKNOWN"
    assert result["layers"]["base"]["verdict"] == "UNKNOWN"
    for layer in LAYERS[1:]:
        assert result["layers"][layer]["verdict"] == "PASS"
        assert result["layers"][layer]["execution_status"] == "NOT_REQUIRED"
        assert (
            result["layers"][layer]["obligations"][0]["applicability"]
            == "EXTERNALLY_SELECTED_NOT_REQUIRED"
        )


def test_missing_generated_applicability_reason_remains_in_denominator() -> None:
    required = _required()
    required[0]["required_layers"] = ["base"]
    result = assess_coverage(required, _records(), _receipts(), _binding())
    assert "MISSING_APPLICABILITY_REASON" in _codes(result)
    assert result["layers"]["integration"]["verdict"] == "FAIL"
    assert result["layers"]["integration"]["execution_status"] == "NOT_RUN"
    assert result["verdict"] == "FAIL"


def test_generated_base_assessed_elsewhere_does_not_require_carried_receipt() -> None:
    required = _required()
    required[0].update(
        required_layers=[],
        applicability_reasons={
            layer: (
                "Base assessed by current deterministic source predicates."
                if layer == "base"
                else "Exact selected source changes are narrative documentation."
            )
            for layer in LAYERS
        },
    )
    result = assess_coverage(
        required, [{"id": "source:1", "coverage": {}}], [], _binding()
    )
    assert result["findings"] == []
    assert result["execution_status"] == "NOT_REQUIRED"
    assert all(
        summary["verdict"] == "PASS" and summary["execution_status"] == "NOT_REQUIRED"
        for summary in result["layers"].values()
    )
    assert result["semantic_clearance"] == "NOT_ESTABLISHED"


def test_one_unrun_layer_blocks_aggregate_with_other_reported_results_preserved() -> (
    None
):
    records = _records()
    records[0]["coverage"]["integration"] = {
        "status": "UNRUN",
        "evidence_ids": [],
        "reason": "No retained integration run.",
    }
    result = assess_coverage(_required(), records, _receipts(), _binding())
    assert result["verdict"] == "FAIL"
    assert result["execution_status"] == "NOT_RUN"
    assert result["layers"]["integration"]["verdict"] == "FAIL"
    assert result["layers"]["unit"]["verdict"] == "UNKNOWN"
    assert result["layers"]["unit"]["execution_status"] == "EXECUTED_REPORTED"


@pytest.mark.parametrize("collection", ["required", "records", "evidence"])
def test_duplicate_identities_are_rejected(collection: str) -> None:
    arguments = {
        "required": _required(),
        "records": _records(),
        "evidence": _receipts(),
    }
    arguments[collection].append(deepcopy(arguments[collection][0]))
    result = assess_coverage(**arguments, binding=_binding())
    assert result["verdict"] == "FAIL"
    assert "DUPLICATE_" + {
        "required": "OBLIGATION",
        "records": "RECORD",
        "evidence": "EVIDENCE",
    }[collection] in _codes(result)


@pytest.mark.parametrize(
    "fault",
    [
        "empty_command",
        "invalid_digest",
        "unknown_outcome",
        "unknown_obligation",
        "extra_layer_field",
    ],
)
def test_malformed_receipts_and_records_are_rejected(fault: str) -> None:
    receipts, records = _receipts(), _records()
    if fault == "empty_command":
        receipts[0]["command"] = ""
    elif fault == "invalid_digest":
        receipts[0]["result_digest"] = "anything"
    elif fault == "unknown_outcome":
        receipts[0]["status"] = "GREEN"
    elif fault == "unknown_obligation":
        receipts[0]["obligation_ids"] = ["source:unknown"]
    else:
        records[0]["coverage"]["base"]["trust_me"] = True
    result = assess_coverage(_required(), records, receipts, _binding())
    assert result["verdict"] == "FAIL"


def test_predicate_selection_cannot_self_authenticate() -> None:
    required, receipts = _required(), _receipts()
    receipts[0].update(
        kind="deterministic_predicate_result", predicate_id="changed-paths-represented"
    )
    unselected = assess_coverage(required, _records(), receipts, _binding())
    assert "UNSELECTED_PREDICATE" in _codes(unselected)
    required[0]["deterministic_predicates"] = {"base": ["changed-paths-represented"]}
    selected = assess_coverage(required, _records(), receipts, _binding())
    assert selected["verdict"] == "UNKNOWN"
    assert selected["layers"]["base"]["obligations"][0]["recorded_verdict"] == "PASS"


@pytest.mark.parametrize(
    "selection",
    [
        {"unknown": ["predicate"]},
        {"base": "predicate"},
        {"base": ["predicate", "predicate"]},
    ],
)
def test_invalid_generated_predicate_selection_cannot_be_ignored(
    selection: dict,
) -> None:
    required = _required()
    required[0]["deterministic_predicates"] = selection
    result = assess_coverage(required, _records(), _receipts(), _binding())
    assert result["verdict"] == "FAIL"
    assert "INVALID_PREDICATE_SELECTION" in _codes(result)


def test_contradictory_source_reference_aliases_are_rejected() -> None:
    required = _required()
    required[0].update(
        source_obligations=["source:1"], affected_source_ids=["source:different"]
    )
    result = assess_coverage(required, _records(), _receipts(), _binding())
    assert result["verdict"] == "FAIL"
    assert "AMBIGUOUS_SOURCE_REFERENCES" in _codes(result)


def test_frontier_cannot_be_closed_by_a_reported_green_test() -> None:
    required = _required()
    required[0]["kind"] = "frontier"
    result = assess_coverage(required, _records(), _receipts(), _binding())
    assert result["verdict"] == "UNKNOWN"
    assert result["execution_status"] == "UNRESOLVED"
    assert _codes(result) == {"ANALYSIS_FRONTIER"}


def test_assessment_bound_keeps_unexamined_inputs_unknown_and_unchanged() -> None:
    arguments = {
        "required": _required(),
        "records": _records(),
        "evidence": _receipts(),
        "binding": _binding(),
    }
    original = deepcopy(arguments)
    result = assess_coverage(**arguments, max_operations=2)
    assert result["verdict"] == "UNKNOWN"
    assert result["bounds"] == {"max_operations": 2, "operations": 2, "complete": False}
    assert "BOUND_EXHAUSTED" in _codes(result)
    assert arguments == original
    assert set(result["layers"]) == set(LAYERS)
    assert all(layer["verdict"] == "UNKNOWN" for layer in result["layers"].values())
    assert result["execution_status"] == "UNRESOLVED"
    assert all(
        layer["execution_status"] == "UNRESOLVED" for layer in result["layers"].values()
    )


def test_known_failed_receipt_survives_later_bound_exhaustion() -> None:
    evidence = [
        next(receipt for receipt in _receipts("FAIL") if receipt["layer"] == "unit")
    ]
    result = assess_coverage(
        _required(),
        [{"id": "source:1", "coverage": {}}],
        evidence,
        _binding(),
        max_operations=9,
    )
    assert not result["bounds"]["complete"]
    assert _codes(result) == {"REPORTED_TEST_FAILURE", "BOUND_EXHAUSTED"}
    assert result["verdict"] == "FAIL"
    assert set(result["layers"]) == set(LAYERS)
    assert result["layers"]["unit"]["verdict"] == "FAIL"
    assert result["layers"]["unit"]["execution_status"] == "EXECUTED_REPORTED"
    assert result["layers"]["base"]["verdict"] == "UNKNOWN"
    assert result["layers"]["base"]["execution_status"] == "UNRESOLVED"


@pytest.mark.parametrize("bound,expected", [(6, "UNKNOWN"), (7, "FAIL")])
def test_partial_coverage_keeps_missing_and_unvisited_obligations(
    bound: int, expected: str
) -> None:
    required = [
        {
            **_required()[0],
            "id": "source:" + str(index),
            "required_layers": ["unit"],
            "applicability_reasons": {
                layer: "Excluded by the exact selected source policy."
                for layer in LAYERS
                if layer != "unit"
            },
        }
        for index in (1, 2)
    ]
    result = assess_coverage(required, [], [], _binding(), max_operations=bound)
    assert not result["bounds"]["complete"]
    assert result["bounds"]["operations"] == bound
    assert result["verdict"] == expected
    assert result["layers"]["base"]["verdict"] == "PASS"
    assert result["layers"]["base"]["execution_status"] == "NOT_REQUIRED"
    unit = result["layers"]["unit"]
    if expected == "FAIL":
        assert _codes(result) == {"MISSING_LAYER_COVERAGE", "BOUND_EXHAUSTED"}
        assert result["execution_status"] == "NOT_RUN"
        assert unit["verdict"] == "FAIL" and unit["execution_status"] == "NOT_RUN"
        assert len(unit["obligations"]) == 1
        reached = unit["obligations"][0]
        assert reached["obligation_id"] == "source:1"
        assert reached["verdict"] == "FAIL" and reached["execution_status"] == "NOT_RUN"
    else:
        assert _codes(result) == {"BOUND_EXHAUSTED"}
        assert result["execution_status"] == "UNRESOLVED"
        assert unit["verdict"] == "UNKNOWN" and unit["execution_status"] == "UNRESOLVED"
        assert unit["obligations"] == []
    for layer in ("integration", "regression", "preventative"):
        assert result["layers"][layer] == {
            "verdict": "UNKNOWN",
            "execution_status": "UNRESOLVED",
            "obligations": [],
        }


def _graph(head: str, *, path: str = "module.py", changed: bool = True) -> dict:
    return {
        "binding": _binding(head),
        "nodes": [
            {
                "id": "producer",
                "path": path,
                "symbol": "produce",
                "node_kind": "function",
                "side": "after",
                "changed": changed,
                "source_obligations": ["source:1"],
            },
            {
                "id": "consumer",
                "path": "consumer.py",
                "symbol": "consume",
                "node_kind": "function",
                "side": "after",
                "changed": False,
                "source_obligations": ["source:1"],
            },
        ],
        "edges": [
            {
                "id": "call:1",
                "source": "producer",
                "target": "consumer",
                "relationship": "calls",
                "evidence_state": "resolved_relationship",
                "side": "after",
            }
        ],
        "frontier": [],
    }


def test_branch_intersections_emit_reproducible_undelivered_potential_notices() -> None:
    current, other = _graph("b"), _graph("f")
    first = preventative_obligations(current, [other])
    second = preventative_obligations(deepcopy(current), [deepcopy(other)])
    assert first == second
    assert first["verdict"] == "UNKNOWN"
    assert first["bounds"]["complete"]
    assert first["notices"]
    for notice in first["notices"]:
        assert notice["classification"] == "POTENTIAL"
        assert notice["status"] == "UNKNOWN"
        assert notice["delivery"] == "NOT_SENT" and notice["owner"] is None
        assert notice["source_binding"] == current["binding"]
        assert notice["target_binding"] == other["binding"]
        assert (
            notice["question"] and notice["test_obligation"]["layer"] == "preventative"
        )
    assert {notice["rule"] for notice in first["notices"]} >= {
        "SOURCE_PATH_INTERSECTION",
        "SYMBOL_INTERSECTION",
        "PRODUCER_CONSUMER_COMPATIBILITY",
        "ADDED_REMOVED_RELATIONSHIP",
    }


def test_impacted_unchanged_consumers_stay_in_notice_coverage() -> None:
    result = preventative_obligations(_graph("b"), [_graph("f", path="different.py")])
    assert any(notice["path"] == "consumer.py" for notice in result["notices"])


def test_real_ast_graph_shape_preserves_affected_unchanged_consumers() -> None:
    from verifier.runtime.prdel_graph import build_impact_graph

    before = {
        "producer.py": b"def produce(value):\n    return value\n",
        ("consumer.py"): (
            b"from producer import produce\ndef consume(value):\n    "
            b"return produce(value)\n"
        ),
    }
    current = build_impact_graph(
        before,
        {**before, "producer.py": b"def produce(value):\n    return value + 1\n"},
        [
            {
                "id": "change:1",
                "path": "producer.py",
                "old_range": [2, 2],
                "new_range": [2, 2],
            }
        ],
    )
    target = build_impact_graph(
        before,
        {**before, "producer.py": b"def produce(value):\n    return value - 1\n"},
        [
            {
                "id": "change:2",
                "path": "producer.py",
                "old_range": [2, 2],
                "new_range": [2, 2],
            }
        ],
    )
    current["binding"], target["binding"] = _binding("b"), _binding("f")
    result = preventative_obligations(current, [target])
    assert "INVALID_GRAPH_NODE" not in _codes(result)
    assert "INVALID_GRAPH_EDGE" not in _codes(result)
    assert any(notice["path"] == "consumer.py" for notice in result["notices"])
    assert all(notice["classification"] == "POTENTIAL" for notice in result["notices"])


@pytest.mark.parametrize(
    "field,rule",
    [
        ("signature", "SIGNATURE_COMPATIBILITY"),
        ("schema", "SCHEMA_COMPATIBILITY"),
        ("config_keys", "CONFIGURATION_INTERACTION"),
        ("shared_state", "SHARED_STATE_INTERACTION"),
        ("ordering", "ORDERING_INTERACTION"),
        ("invariants", "INVARIANT_COMPATIBILITY"),
    ],
)
def test_hazard_rules_require_directly_represented_facts(field: str, rule: str) -> None:
    graph = _graph("b")
    plain = preventative_obligations(graph, [_graph("f")])
    assert rule not in {notice["rule"] for notice in plain["notices"]}
    graph["nodes"][0][field] = ["explicit declared fact"]
    represented = preventative_obligations(graph, [_graph("f")])
    assert rule in {notice["rule"] for notice in represented["notices"]}


def test_missing_branch_inventory_and_dynamic_frontiers_remain_unresolved() -> None:
    graph = _graph("b")
    graph["frontier"] = [
        {
            "id": "dynamic:1",
            "question": "Which runtime target receives this reflective call?",
        }
    ]
    result = preventative_obligations(graph, [])
    assert result["verdict"] == "UNKNOWN"
    assert _codes(result) == {
        "BRANCH_INVENTORY_NOT_ESTABLISHED",
        "UNRESOLVED_GRAPH_FRONTIER",
    }


def test_invalid_or_duplicate_branch_graphs_cannot_silently_disappear() -> None:
    unbound = _graph("f")
    del unbound["binding"]
    result = preventative_obligations(_graph("b"), [unbound])
    assert "UNBOUND_GRAPH" in _codes(result)
    duplicated = preventative_obligations(_graph("b"), [_graph("f"), _graph("f")])
    assert duplicated["verdict"] == "FAIL"
    assert "DUPLICATE_BRANCH_GRAPH" in _codes(duplicated)


def test_preventative_bound_retains_unknown_and_does_not_mutate_graphs() -> None:
    current, other = _graph("b"), _graph("f")
    original = deepcopy((current, other))
    result = preventative_obligations(current, [other], max_operations=3)
    assert result["verdict"] == "UNKNOWN"
    assert not result["bounds"]["complete"]
    assert result["bounds"]["operations"] == 3
    assert "BOUND_EXHAUSTED" in _codes(result)
    assert (current, other) == original
