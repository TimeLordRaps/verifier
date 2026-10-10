"""Counterexamples for native role-class and collective-graph checks."""

import pytest

from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains import role, collective


def _role():
    events = [
        {"position": 0, "event": "take", "bearer_id": "bearer:a", "bearer_class": "human"},
        {"position": 1, "event": "handover", "leaving": "bearer:a", "taking": "bearer:b", "bearer_class": "human"},
    ]
    artifact = {"role_class_id": "role:reviewer", "coordinate": "org:1", "authority": ["review"],
                "qualifications": ["trained"], "bearer_limit": 1,
                "admissible_bearer_classes": ["human"], "occupancy_events_digest": digest(events),
                "current_occupants": ["bearer:b"]}
    return artifact, {"occupancy_events": events}


def test_role_facets_are_a_class_not_an_occupant():
    artifact, inputs = _role()
    assert role.evaluate("facets", artifact, inputs, Budget(500))["role_class_id"] == "role:reviewer"
    artifact["bearer_limit"] = None
    with pytest.raises(Refuted):
        role.evaluate("facets", artifact, inputs, Budget(500))


def test_role_occupancy_replays_atomic_handover_and_refutes_digest_tamper():
    artifact, inputs = _role()
    observed = role.evaluate("occupancy", artifact, inputs, Budget(500))
    assert observed["declared_occupants_after_trace"] == ["bearer:b"]
    assert observed["live_occupancy"] == "NOT_ESTABLISHED"
    inputs["occupancy_events"][1]["taking"] = "bearer:c"
    with pytest.raises(Refuted):
        role.evaluate("occupancy", artifact, inputs, Budget(500))


def test_role_unknown_when_occupancy_evidence_absent():
    artifact, _ = _role()
    with pytest.raises(Unavailable):
        role.evaluate("occupancy", artifact, {}, Budget(500))


def test_role_replay_rejects_overcapacity_even_if_summary_agrees():
    artifact, inputs = _role()
    inputs["occupancy_events"] = [
        {"position": 0, "event": "take", "bearer_id": "bearer:a", "bearer_class": "human"},
        {"position": 1, "event": "take", "bearer_id": "bearer:b", "bearer_class": "human"},
    ]
    artifact["occupancy_events_digest"] = digest(inputs["occupancy_events"])
    artifact["current_occupants"] = ["bearer:a", "bearer:b"]
    with pytest.raises(Refuted, match="limit exceeded"):
        role.evaluate("occupancy", artifact, inputs, Budget(500))


def test_role_replay_rejects_non_atomic_handover_and_forged_summary():
    artifact, inputs = _role()
    inputs["occupancy_events"][1] = {"position": 1, "event": "leave", "bearer_id": "bearer:a"}
    artifact["occupancy_events_digest"] = digest(inputs["occupancy_events"])
    with pytest.raises(Refuted, match="current occupants"):
        role.evaluate("occupancy", artifact, inputs, Budget(500))


def _collective():
    roles = ["role:reviewer", "role:approver"]
    edges = [{"source": "role:reviewer", "target": "role:approver", "relation": "reports-to"}]
    artifact = {"collective_id": "collective:1", "coordinate": "org:1", "role_classes": roles,
                "relation_types": ["reports-to", "delegates-to", "must-countersign"],
                "inside": roles, "outside": [], "decision_classes": ["release"],
                "role_graph_digest": digest(edges)}
    return artifact, {"role_graph": edges}


def _collective_decisions():
    artifact, inputs = _collective()
    role_decisions = [
        {"position": 0, "decision_id": "rd:1", "role_class_id": "role:reviewer",
         "decision_class": "release", "bearer_id": "bearer:a"},
        {"position": 1, "decision_id": "rd:2", "role_class_id": "role:approver",
         "decision_class": "release", "bearer_id": "bearer:b"},
    ]
    collective_decisions = [{"decision_id": "cd:1", "decision_class": "release",
                             "component_decision_ids": ["rd:1", "rd:2"]}]
    artifact["role_decisions_digest"] = digest(role_decisions)
    artifact["collective_decisions_digest"] = digest(collective_decisions)
    artifact["assembly_policy"] = {"release": {"required_roles": ["role:reviewer", "role:approver"]}}
    inputs["role_decisions"] = role_decisions
    inputs["collective_decisions"] = collective_decisions
    return artifact, inputs


def test_collective_graph_has_typed_edges_and_no_occupants():
    artifact, inputs = _collective()
    assert collective.evaluate("graph", artifact, inputs, Budget(500))["role_classes"] == 2
    inputs["role_graph"][0]["relation"] = ""
    with pytest.raises(Refuted):
        collective.evaluate("graph", artifact, inputs, Budget(500))


def test_collective_graph_does_not_establish_authority_or_person_identity():
    artifact, inputs = _collective()
    with pytest.raises(Unavailable):
        collective.evaluate("authority", artifact, inputs, Budget(500))
    with pytest.raises(Unavailable):
        collective.evaluate("persons", artifact, inputs, Budget(500))


def test_collective_unknown_when_graph_evidence_absent():
    artifact, _ = _collective()
    with pytest.raises(Unavailable):
        collective.evaluate("graph", artifact, {}, Budget(500))


def test_collective_graph_rejects_undeclared_endpoint_even_with_matching_digest():
    artifact, inputs = _collective()
    inputs["role_graph"][0]["target"] = "role:ghost"
    artifact["role_graph_digest"] = digest(inputs["role_graph"])
    with pytest.raises(Refuted, match="undeclared role class"):
        collective.evaluate("graph", artifact, inputs, Budget(500))


def test_collective_graph_rejects_boundary_substitution():
    artifact, inputs = _collective()
    artifact["inside"] = ["role:reviewer"]
    artifact["outside"] = ["role:approver"]
    with pytest.raises(Refuted, match="boundary differs"):
        collective.evaluate("graph", artifact, inputs, Budget(500))


def test_collective_decision_assembly_replays_bounded_role_trace():
    artifact, inputs = _collective_decisions()
    result = collective.evaluate("decisions", artifact, inputs, Budget(500))
    assert result["collective_decisions_replayed"] == 1
    assert result["person_or_authority_established"] is False


def test_collective_decision_rejects_split_role_trace():
    artifact, inputs = _collective_decisions()
    inputs["collective_decisions"].append({"decision_id": "cd:2", "decision_class": "release",
                                          "component_decision_ids": ["rd:1", "rd:2"]})
    artifact["collective_decisions_digest"] = digest(inputs["collective_decisions"])
    with pytest.raises(Refuted, match="reused"):
        collective.evaluate("decisions", artifact, inputs, Budget(500))


def test_collective_decision_rejects_missing_required_role():
    artifact, inputs = _collective_decisions()
    inputs["collective_decisions"][0]["component_decision_ids"] = ["rd:1"]
    artifact["collective_decisions_digest"] = digest(inputs["collective_decisions"])
    with pytest.raises(Refuted, match="assembly policy"):
        collective.evaluate("decisions", artifact, inputs, Budget(500))


def test_collective_quorum_remains_unknown_without_independent_occupancy():
    artifact, inputs = _collective_decisions()
    with pytest.raises(Unavailable, match="independent"):
        collective.evaluate("quorum", artifact, inputs, Budget(500))


def test_collective_two_roles_same_declared_bearer_never_prove_person_quorum():
    artifact, inputs = _collective_decisions()
    inputs["role_decisions"][1]["bearer_id"] = "bearer:a"
    artifact["role_decisions_digest"] = digest(inputs["role_decisions"])
    result = collective.evaluate("decisions", artifact, inputs, Budget(500))
    assert result["person_or_authority_established"] is False
    with pytest.raises(Unavailable, match="independent"):
        collective.evaluate("quorum", artifact, inputs, Budget(500))


def test_collective_quorum_refutes_tampered_trace_before_unknown():
    artifact, inputs = _collective_decisions()
    inputs["role_decisions"][0]["role_class_id"] = "role:ghost"
    with pytest.raises(Refuted, match="trace differs"):
        collective.evaluate("quorum", artifact, inputs, Budget(500))


def test_collective_rejects_duplicate_and_extra_role_decisions_in_assembly():
    artifact, inputs = _collective_decisions()
    inputs["role_decisions"].append({"position": 2, "decision_id": "rd:3",
                                    "role_class_id": "role:reviewer", "decision_class": "release",
                                    "bearer_id": "bearer:c"})
    artifact["role_decisions_digest"] = digest(inputs["role_decisions"])
    inputs["collective_decisions"][0]["component_decision_ids"].append("rd:3")
    artifact["collective_decisions_digest"] = digest(inputs["collective_decisions"])
    with pytest.raises(Refuted, match="assembly policy"):
        collective.evaluate("decisions", artifact, inputs, Budget(500))
    inputs["role_decisions"][2]["decision_id"] = "rd:1"
    artifact["role_decisions_digest"] = digest(inputs["role_decisions"])
    with pytest.raises(Refuted, match="duplicate role decision"):
        collective.evaluate("decisions", artifact, inputs, Budget(500))


def test_collective_decision_unknown_when_retained_trace_absent():
    artifact, inputs = _collective_decisions()
    del inputs["collective_decisions"]
    with pytest.raises(Unavailable, match="required evidence absent"):
        collective.evaluate("decisions", artifact, inputs, Budget(500))


def test_collective_decision_rejects_noncontiguous_position():
    artifact, inputs = _collective_decisions()
    inputs["role_decisions"][1]["position"] = 9
    artifact["role_decisions_digest"] = digest(inputs["role_decisions"])
    with pytest.raises(Refuted, match="not contiguous"):
        collective.evaluate("decisions", artifact, inputs, Budget(500))
