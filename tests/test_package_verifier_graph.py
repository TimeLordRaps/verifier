"""Recursive package self-polish graph tests."""
from __future__ import annotations

import copy

import pytest

from verifier.core import namespace
from verifier.runtime import core_obligation_union as binding
from verifier.runtime import package_verifier_graph as graph


def _objects():
    aggregate = namespace.NamespaceObject.create(
        "aggregate", "VERIFIER", {"representation_role": "polish-system"}
    )
    checker = namespace.NamespaceObject.create(
        "policy-checker", "DATA", {"representation_role": "member-checker"}
    )
    package_graph = namespace.NamespaceObject.create(
        "package-graph", "GRAPH", {"element_kind": "OBJECT"},
        {"members": ["aggregate", "policy-checker"]},
    )
    return aggregate, checker, package_graph


def _document(classification: str = "APPLIES") -> dict:
    return {
        "namespace": {
            "objects": [
                {
                    "object_id": "aggregate",
                    "kind": "VERIFIER",
                    "surfaces": [
                        "file:src/verifier/runtime/package_polish.py",
                        "python:src/pkg/aggregate.py:check",
                    ],
                    "classification": {"VERIFIER": {"status": "APPLIES"}},
                },
                {
                    "object_id": "policy-checker",
                    "kind": "DATA",
                    "surfaces": ["python:src/pkg/checker.py:check"],
                    "classification": {
                        "VERIFIER": {"status": classification}
                    },
                },
                {
                    "object_id": "package-graph",
                    "kind": "GRAPH",
                    "surfaces": [],
                    "classification": {},
                },
            ]
        }
    }


def _row(
    *,
    subject: str,
    mechanism: str,
    tier: int,
    status: str,
) -> dict:
    body = {
        "object_id": subject,
        "object_kind": "VERIFIER" if subject == "aggregate" else "DATA",
        "coordinate": f"POLICY-{tier}.1",
        "tier": tier,
        "checking_mechanism": mechanism,
        "status": status,
    }
    return {**body, "instance_digest": binding.value_digest(body)}


def _compile(rows: list[dict], *, classification: str = "APPLIES") -> dict:
    objects = _objects()
    return graph.compile_self_polish_graph(
        document=_document(classification),
        objects=objects,
        obligation_rows=rows,
        aggregate_verifier=objects[0],
        package_graph_id="package-graph",
        package_graph_digest=namespace.composition_digest(objects),
        requested_tier=max(row["tier"] for row in rows),
    )


def test_aggregate_verifier_represents_member_verifiers_and_polishes_itself() -> None:
    rows = [
        _row(
            subject="aggregate", mechanism="pkg.aggregate.check",
            tier=1, status="PASS",
        ),
        _row(
            subject="policy-checker", mechanism="pkg.checker.check",
            tier=1, status="PASS",
        ),
    ]
    result = _compile(rows)

    assert result["status"] == "PASS"
    assert result["aggregate_verifier_id"] == "aggregate"
    assert result["aggregate_subject_kind"] == "VERIFIER"
    assert result["verified_graph_id"] == "package-graph"
    assert result["aggregate_result_is_member_evidence"] is False
    assert result["self_application_authority"] == "NOT_ESTABLISHED"
    assert {
        row["verifier_id"] for row in result["member_verifiers"]
    } == {"aggregate", "policy-checker"}
    assert {
        subject
        for row in result["member_verifiers"]
        for subject in row["subject_objects"]
    } == {"aggregate", "policy-checker"}
    assert sum(
        len(row["obligation_instances"])
        for row in result["member_verifiers"]
    ) == len(rows)
    assert next(
        row for row in result["polish_system_subjects"]
        if row["object_id"] == "aggregate"
    )["status"] == "PASS"
    assert result["graph_digest"] == binding.value_digest({
        key: value for key, value in result.items() if key != "graph_digest"
    })
    graph.validate_self_polish_graph(
        result,
        aggregate_verifier_id="aggregate",
        aggregate_verifier_digest=_objects()[0].digest,
        package_graph_id="package-graph",
        package_graph_digest=namespace.composition_digest(_objects()),
        requested_tier=1,
        obligation_rows=rows,
    )


def test_unresolved_member_verifier_classification_keeps_graph_unknown() -> None:
    result = _compile([
        _row(
            subject="aggregate", mechanism="pkg.checker.check",
            tier=1, status="PASS",
        )
    ], classification="UNRESOLVED")

    assert result["status"] == "UNKNOWN"
    assert "PACKAGE_MEMBER_VERIFIER_OBLIGATIONS_NOT_PASS" in result["blockers"]
    assert result["member_verifiers"][0]["blockers"] == [
        "MEMBER_VERIFIER_CLASSIFICATION_NOT_ESTABLISHED"
    ]


def test_tier_results_are_cumulative_without_borrowing_later_unknowns() -> None:
    result = _compile([
        _row(
            subject="aggregate", mechanism="pkg.aggregate.check",
            tier=1, status="PASS",
        ),
        _row(
            subject="policy-checker", mechanism="pkg.checker.check",
            tier=2, status="UNKNOWN",
        ),
    ])

    assert [row["status"] for row in result["tier_results"]] == [
        "PASS", "UNKNOWN"
    ]
    assert result["status"] == "UNKNOWN"


def test_aggregate_result_cannot_turn_an_unknown_member_into_pass() -> None:
    result = _compile([
        _row(
            subject="aggregate", mechanism="pkg.aggregate.check",
            tier=1, status="PASS",
        ),
        _row(
            subject="policy-checker", mechanism="pkg.checker.check",
            tier=1, status="UNKNOWN",
        ),
    ])

    assert result["aggregate_result_is_member_evidence"] is False
    assert result["status"] == "UNKNOWN"
    assert result["member_status_counts"] == {"PASS": 1, "UNKNOWN": 1}


def test_rechecker_rejects_rehashed_aggregate_result_as_member_evidence() -> None:
    result = _compile([
        _row(
            subject="aggregate", mechanism="pkg.aggregate.check",
            tier=1, status="PASS",
        )
    ])
    mutant = copy.deepcopy(result)
    mutant["aggregate_result_is_member_evidence"] = True
    mutant["graph_digest"] = binding.value_digest({
        key: value for key, value in mutant.items() if key != "graph_digest"
    })

    with pytest.raises(
        graph.VerifierGraphError,
        match="PACKAGE_SELF_POLISH_GRAPH_BINDING_DIFFERS",
    ):
        graph.validate_self_polish_graph(
            mutant,
            aggregate_verifier_id="aggregate",
            aggregate_verifier_digest=_objects()[0].digest,
            package_graph_id="package-graph",
            package_graph_digest=namespace.composition_digest(_objects()),
            requested_tier=1,
        )


def test_rechecker_rejects_rehashed_member_status_substitution() -> None:
    result = _compile([
        _row(
            subject="aggregate", mechanism="pkg.aggregate.check",
            tier=1, status="UNKNOWN",
        )
    ])
    mutant = copy.deepcopy(result)
    member = mutant["member_verifiers"][0]
    member["status"] = "PASS"
    member["blockers"] = []
    member["member_digest"] = binding.value_digest({
        key: value for key, value in member.items() if key != "member_digest"
    })
    mutant["member_status_counts"] = {"PASS": 1}
    mutant["member_verifier_digest"] = binding.value_digest(
        mutant["member_verifiers"]
    )
    mutant["edges"][0]["member_digest"] = member["member_digest"]
    mutant["edge_digest"] = binding.value_digest(mutant["edges"])
    mutant["status"] = "PASS"
    mutant["blockers"] = []
    mutant["graph_digest"] = binding.value_digest({
        key: value for key, value in mutant.items() if key != "graph_digest"
    })

    with pytest.raises(
        graph.VerifierGraphError,
        match="PACKAGE_SELF_POLISH_GRAPH_MEMBER_STATUS_DIFFERS",
    ):
        graph.validate_self_polish_graph(
            mutant,
            aggregate_verifier_id="aggregate",
            aggregate_verifier_digest=_objects()[0].digest,
            package_graph_id="package-graph",
            package_graph_digest=namespace.composition_digest(_objects()),
            requested_tier=1,
        )
