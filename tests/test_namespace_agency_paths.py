"""Refute false agency bindings without physical or financial execution.

Verifier Standard (VSTD) checks actual declaration paths, not test deployments.
"""
from __future__ import annotations

from copy import deepcopy

import pytest

from test_namespace_consequence_graph import (
    fixture,
    graph_assessment,
    graph_observation,
    save,
)
from verifier.runtime.namespace_admission import assess, assess_gate
from verifier.runtime import namespace_consequences
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.namespace_classification import assess_classification


def _edge(document: dict, source: str, target: str) -> None:
    edge = deepcopy(document["consequence_graph"]["edges"][0])
    edge.update(source=source, relation="influences", target=target)
    document["consequence_graph"]["edges"].append(edge)


@pytest.mark.parametrize("harnesses", [[], ["missing"], ["data"], ["harness", "data"]])
def test_financial_agency_requires_its_actual_governing_harness(tmp_path, harnesses):
    document = fixture(tmp_path)
    graph = document["consequence_graph"]
    graph["effects"] = [row for row in graph["effects"] if row["domain"] == "REAL_FINANCIAL"]
    # A typed ACTUATOR endpoint demands ROBOT whether or not its effect row is declared, so
    # isolate financial agency by also dropping the control and actuation path.
    graph["edges"] = [row for row in graph["edges"] if row["relation"] not in {"controls", "actuates"}]
    agent = next(row for row in document["objects"] if row["object_id"] == "agent")
    agent["operands"]["harness"] = harnesses
    result = graph_assessment(document)
    assert result["status"] == "UNKNOWN"
    findings = [row for row in result["findings"] if row["code"] == "NAMESPACE_AGENCY_HARNESS_UNRESOLVED"]
    assert {row["object_id"] for row in findings} == {"agent", "bot"}
    assert all(row["obligation_id"] == "FINBOT-0.1-agent-and-financial-authority" for row in findings)


def test_cross_root_applies_demands_harness_without_satisfying_harness_role(
    tmp_path,
):
    document = fixture(tmp_path)
    evidence = document["consequence_graph"]["effects"][0]["evidence"]
    harness = next(
        row for row in document["objects"] if row["object_id"] == "harness"
    )
    harness["kind"] = "DATA"
    harness["classification"]["HARNESS"] = {
        "status": "APPLIES",
        "reason": namespace_consequences.compiled_role_reason(
            "harness", "HARNESS"
        ),
        "evidence": evidence,
    }

    consequences = graph_assessment(document)
    findings = [
        row
        for row in consequences["findings"]
        if row["code"] == "NAMESPACE_AGENCY_HARNESS_UNRESOLVED"
    ]
    assert {row["object_id"] for row in findings} == {"agent", "bot"}

    classified = assess_classification(
        document["objects"],
        namespace_registry(),
        graph_observation(document),
        consequence_kinds=consequences["required_kinds"],
    )
    selected = next(
        row for row in classified["objects"] if row["object_id"] == "harness"
    )
    assert "HARNESS" in selected["effective_kinds"]
    assert "HARNESS" in selected["necessary_kinds"]


def test_cross_root_harness_demand_agrees_across_independent_reconcilers(
    tmp_path,
):
    document = fixture(tmp_path)
    evidence = document["consequence_graph"]["effects"][0]["evidence"]
    harness = next(
        row for row in document["objects"] if row["object_id"] == "harness"
    )
    harness["kind"] = "DATA"
    harness["classification"]["HARNESS"] = {
        "status": "APPLIES",
        "reason": namespace_consequences.compiled_role_reason(
            "harness", "HARNESS"
        ),
        "evidence": evidence,
    }
    save(tmp_path, document)

    report = assess(tmp_path)
    assert report["independent_reconciliation"]["status"] == "PASS"
    findings = [
        row
        for row in report["consequence_graph"]["findings"]
        if row["code"] == "NAMESPACE_AGENCY_HARNESS_UNRESOLVED"
    ]
    assert {row["object_id"] for row in findings} == {"agent", "bot"}


def test_cross_root_bot_applies_cannot_create_implicit_embodiment(tmp_path):
    document = fixture(tmp_path)
    evidence = document["consequence_graph"]["effects"][0]["evidence"]
    bot = next(row for row in document["objects"] if row["object_id"] == "bot")
    bot["kind"] = "DATA"
    bot["classification"]["BOT"] = {
        "status": "APPLIES",
        "reason": namespace_consequences.compiled_role_reason("bot", "BOT"),
        "evidence": evidence,
    }
    _edge(document, "bot", "agent")

    consequences = graph_assessment(document)
    assert set(consequences["reachable_effects"]["bot"]) == {
        "REAL_FINANCIAL",
        "REAL_PHYSICAL",
    }
    assert consequences["required_kinds"]["bot"] == ["FINBOT", "ROBOT"]
    assert any(
        row["code"] == "NAMESPACE_AGENCY_BINDING_UNRESOLVED"
        and row["object_id"] == "bot"
        for row in consequences["findings"]
    )

    classified = assess_classification(
        document["objects"],
        namespace_registry(),
        graph_observation(document),
        consequence_kinds=consequences["required_kinds"],
    )
    selected = next(
        row for row in classified["objects"] if row["object_id"] == "bot"
    )
    assert "BOT" in selected["effective_kinds"]
    assert "BOT" in selected["necessary_kinds"]


def test_cross_root_bot_demand_agrees_across_independent_reconcilers(tmp_path):
    document = fixture(tmp_path)
    evidence = document["consequence_graph"]["effects"][0]["evidence"]
    bot = next(row for row in document["objects"] if row["object_id"] == "bot")
    bot["kind"] = "DATA"
    bot["operands"] = {}
    bot["classification"]["BOT"] = {
        "status": "APPLIES",
        "reason": namespace_consequences.compiled_role_reason("bot", "BOT"),
        "evidence": evidence,
    }
    _edge(document, "bot", "agent")
    save(tmp_path, document)

    report = assess(tmp_path)
    assert report["independent_reconciliation"]["status"] == "PASS"
    assert set(report["consequence_graph"]["reachable_effects"]["bot"]) == {
        "REAL_FINANCIAL",
        "REAL_PHYSICAL",
    }
    assert report["consequence_graph"]["required_kinds"]["bot"] == [
        "FINBOT",
        "ROBOT",
    ]
    assert any(
        row["code"] == "NAMESPACE_AGENCY_BINDING_UNRESOLVED"
        and row["object_id"] == "bot"
        for row in report["consequence_graph"]["findings"]
    )


def test_duplicate_harnesses_are_already_rejected_by_manifest_shape(tmp_path):
    document = fixture(tmp_path)
    next(row for row in document["objects"] if row["object_id"] == "agent")["operands"]["harness"] *= 2
    with pytest.raises(ValueError, match="NAMESPACE_OPERANDS_INVALID"):
        graph_assessment(document)


@pytest.mark.parametrize("target,obligation", [
    ("actuator", "ROBOT-0.1-agent-to-actuator-binding"),
    ("ledger", "FINBOT-0.1-agent-and-financial-authority"),
])
@pytest.mark.parametrize("form", ["direct", "indirect", "cycle", "self_effect"])
def test_one_agent_path_cannot_cover_a_wrappers_other_effects(tmp_path, target, obligation, form):
    document = fixture(tmp_path)
    if form == "self_effect":
        effect = deepcopy(document["consequence_graph"]["effects"][0 if target == "actuator" else 1])
        effect["object_id"] = "bot"
        document["consequence_graph"]["effects"].append(effect)
    elif form == "direct":
        _edge(document, "bot", target)
    else:
        _edge(document, "bot", "data")
        _edge(document, "data", target)
        if form == "cycle":
            _edge(document, "data", "bot")
    result = graph_assessment(document)
    assert result["status"] == "UNKNOWN"
    assert any(row["code"] == "NAMESPACE_AGENCY_EFFECT_BYPASS" and row["object_id"] == "bot"
               and row["obligation_id"] == obligation for row in result["findings"])
    assert result["required_kinds"]["bot"]  # Never prune the consequence requirements.


def test_indirect_wrapper_path_through_actual_agent_remains_admissible(tmp_path):
    document = fixture(tmp_path)
    _edge(document, "bot", "data")
    _edge(document, "data", "agent")
    _edge(document, "agent", "data")  # Cycles do not by themselves refute the binding.
    result = graph_assessment(document)
    assert result["status"] == "PASS"
    assert result["external_confinement_status"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("target", ["actuator", "ledger"])
def test_explicit_non_bot_embodiment_has_the_same_no_bypass_rule(tmp_path, target):
    document = fixture(tmp_path)
    row = next(row for row in document["objects"] if row["object_id"] == "bot")
    row.update(kind="OBJECT", operands={}, specializations=["ROBOT", "FINBOT"])
    edge = deepcopy(document["consequence_graph"]["edges"][0])
    edge.update(source="bot", relation="embodies", target="agent")
    document["consequence_graph"]["edges"].append(edge)
    assert graph_assessment(document)["status"] == "PASS"
    _edge(document, "bot", target)
    assert any(row["code"] == "NAMESPACE_AGENCY_EFFECT_BYPASS" for row in graph_assessment(document)["findings"])


def test_bypass_is_visible_in_admission_and_exact_obligation_gate(tmp_path):
    document = fixture(tmp_path)
    _edge(document, "bot", "ledger")
    save(tmp_path, document)
    report = assess(tmp_path)
    assert report["independent_reconciliation"]["status"] == "PASS"
    obligation = "FINBOT-0.1-agent-and-financial-authority"
    finding = next(row for row in report["findings"] if row["code"] == "NAMESPACE_AGENCY_EFFECT_BYPASS")
    assert finding["rerun_argv"] == ["vstd", "gate", "--object", "bot", "--obligation", obligation]
    selected = assess_gate("bot", obligation, tmp_path)
    assert selected["status"] != "PASS"
    assert any(row["code"] == finding["code"] for row in selected["findings"])
