"""Refute unsupported Verifier Standard (VSTD) identity-role claims."""
from __future__ import annotations

import importlib

import pytest

from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import Refuted, digest


def checker():
    return importlib.import_module("verifier.domains.contracts.identity_occupancy")


def specimen(kind: str = "AGENT"):
    make = NamespaceObject.create
    scope = "simulation:sim" if kind == "BOT" else "team:research"
    evidence = {
        "schema_version": "verifier-namespace-identity-evidence-1",
        "identity_id": "identity", "actor_id": "actor", "role_id": "role",
        "collective_id": "collective", "representation_id": kind.lower(),
        "actor_kind": kind, "root_human_id": "human", "scope": scope,
        "evidence_ref": digest("retained-but-unresolved-record"),
    }
    objects = [make(name, object_kind, payload) for name, object_kind, payload in (
        ("data", "DATA", {}), ("verifier", "VERIFIER", {}), ("arch", "ARCH", {}),
        ("time", "TIME", {}), ("space", "SPACE", {}), ("meaning", "OBJECT", {}),
        ("env", "ENV", {}), ("hardware", "HARDWARE", {}), ("harness", "HARNESS", {}),
        ("human", "HUMAN", {}),
        ("role", "ROLE", {"admitted_scopes": ["team:research", "simulation:sim"]}),
    )]
    objects += [
        make("collective", "COLLECTIVE", {}, {"roles": ["role"]}),
        make("event", "EVENT", {}, {"time": ["time"], "space": ["space"], "meaning": ["meaning"]}),
        make("bench", "BENCH", {}, {"verifier": ["verifier"], "data": ["data"]}),
        make("train", "TRAIN", {}, {"data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"]}),
        make("model", "MODEL", {}, {"train": ["train"], "data": ["data"], "events": ["event"],
             "bench": ["bench"], "arch": ["arch"], "env": ["env"], "hardware": ["hardware"]}),
        make("agent", "AGENT", {}, {"model": ["model"], "harness": ["harness"], "env": ["env"]}),
        make("sim", "SIM", {}, {"data": ["data"], "verifier": ["verifier"],
                                "objects": ["meaning"], "env": ["env"]}),
        make("bot", "BOT", {}, {"agent": ["agent"], "sim": ["sim"], "env": ["env"]}),
        make("actor", "ACTOR", {}, {"representation": [kind.lower()], "root_human": ["human"]}),
        make("identity", "IDENTITY", {"scope": scope, "binding_evidence_digest": digest(evidence)},
             {"actor": ["actor"], "role": ["role"]}),
    ]
    return objects, evidence


def assess(objects, evidence, **kwargs):
    return checker().assess_identity_occupancy(
        objects, identity_id="identity", collective_id="collective",
        expected_digest=composition_digest(objects),
        expected_evidence_digest=digest(evidence), evidence=evidence, **kwargs,
    )


def rebind_identity(objects, evidence):
    make = NamespaceObject.create
    index = next(i for i, item in enumerate(objects) if item.object_id == "identity")
    objects[index] = make("identity", "IDENTITY",
                          {"scope": evidence["scope"], "binding_evidence_digest": digest(evidence)},
                          {"actor": ["actor"], "role": ["role"]})


@pytest.mark.parametrize("kind", ["HUMAN", "AGENT", "BOT"])
def test_current_actor_kinds_have_exact_declared_role_binding(kind):
    objects, evidence = specimen(kind)
    result = assess(objects, evidence)
    assert result["status"] == "PASS"
    assert result["scope"] == "declared_actor_role_binding"
    assert result["actor_kind"] == kind
    assert result["root_human_id"] == "human"
    assert result["role_id"] == "role"
    assert result["human_authenticity"] == "NOT_ESTABLISHED"
    assert result["role_authority"] == "NOT_ESTABLISHED"
    assert result["evidence_ref_resolution"] == "NOT_ESTABLISHED"
    assert result["privacy"] == "NOT_ESTABLISHED"
    assert result["consent"] == "NOT_ESTABLISHED"
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"


def test_missing_selection_or_scope_declaration_is_unknown():
    objects, evidence = specimen()
    module = checker()
    missing = module.assess_identity_occupancy(
        objects, identity_id="identity", collective_id="collective",
        expected_digest=None, expected_evidence_digest=digest(evidence), evidence=evidence)
    assert missing["status"] == "UNKNOWN"
    index = next(i for i, item in enumerate(objects) if item.object_id == "role")
    objects[index] = NamespaceObject.create("role", "ROLE", {})
    assert assess(objects, evidence)["status"] == "UNKNOWN"


def test_malformed_expected_evidence_digest_fails_without_exception():
    objects, evidence = specimen()
    result = checker().assess_identity_occupancy(
        objects, identity_id="identity", collective_id="collective",
        expected_digest=composition_digest(objects),
        expected_evidence_digest={"attacker": "object"}, evidence=evidence)
    assert result["status"] == "FAIL"
    assert result["selected_evidence_digest"] is None


def test_unsupported_version_is_unknown_only_when_selected_bytes_match():
    objects, evidence = specimen()
    selected = digest(evidence)
    evidence["schema_version"] = "verifier-namespace-identity-evidence-2"
    module = checker()
    contradictory = module.assess_identity_occupancy(
        objects, identity_id="identity", collective_id="collective",
        expected_digest=composition_digest(objects),
        expected_evidence_digest=selected, evidence=evidence)
    assert contradictory["status"] == "FAIL"
    rebind_identity(objects, evidence)
    unsupported = assess(objects, evidence)
    assert unsupported["status"] == "UNKNOWN"


def test_changed_evidence_or_collection_is_not_a_pass():
    objects, evidence = specimen()
    selected = digest(evidence)
    evidence["role_id"] = "substituted"
    result = checker().assess_identity_occupancy(
        objects, identity_id="identity", collective_id="collective",
        expected_digest=composition_digest(objects),
        expected_evidence_digest=selected, evidence=evidence)
    assert result["status"] == "FAIL"
    original_collection = composition_digest(objects)
    objects[0] = NamespaceObject.create("data", "DATA", {"changed": True})
    result = checker().assess_identity_occupancy(
        objects, identity_id="identity", collective_id="collective",
        expected_digest=original_collection,
        expected_evidence_digest=digest(evidence), evidence=evidence)
    assert result["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [
    ("identity_id", "other"), ("actor_id", "other"),
    ("collective_id", "other"), ("scope", "team:other"),
    ("actor_kind", "BOT"), ("root_human_id", "other"),
    ("role_id", "other"), ("representation_id", "human"),
])
def test_rebound_false_relation_is_refuted(field, value):
    objects, evidence = specimen("AGENT")
    evidence[field] = value
    rebind_identity(objects, evidence)
    assert assess(objects, evidence)["status"] == "FAIL"


def test_malformed_retained_evidence_locator_fails_even_when_hash_bound():
    objects, evidence = specimen()
    evidence["evidence_ref"] = "unresolved"
    rebind_identity(objects, evidence)
    assert assess(objects, evidence)["status"] == "FAIL"


def test_blank_scope_cannot_pass_from_mutually_blank_declarations():
    objects, evidence = specimen()
    evidence["scope"] = " "
    index = next(i for i, item in enumerate(objects) if item.object_id == "role")
    objects[index] = NamespaceObject.create("role", "ROLE", {"admitted_scopes": [" "]})
    rebind_identity(objects, evidence)
    assert assess(objects, evidence)["status"] == "FAIL"


def test_blank_role_scope_invalidates_mixed_admission_list():
    objects, evidence = specimen()
    index = next(i for i, item in enumerate(objects) if item.object_id == "role")
    objects[index] = NamespaceObject.create(
        "role", "ROLE", {"admitted_scopes": ["team:research", " "]})
    assert assess(objects, evidence)["status"] == "FAIL"


def test_role_must_belong_to_selected_collective():
    objects, evidence = specimen()
    objects.append(NamespaceObject.create("other-role", "ROLE", {"admitted_scopes": ["team:research"]}))
    index = next(i for i, item in enumerate(objects) if item.object_id == "collective")
    objects[index] = NamespaceObject.create("collective", "COLLECTIVE", {}, {"roles": ["other-role"]})
    assert assess(objects, evidence)["status"] == "FAIL"


def test_explicitly_typed_role_graph_preserves_one_role_binding():
    objects, evidence = specimen()
    objects.append(NamespaceObject.create("role-graph", "GRAPH", {"element_kind": "ROLE"},
                                          {"members": ["role"]}))
    for name, kind, payload, operands in (
        ("collective", "COLLECTIVE", {}, {"roles": ["role-graph"]}),
        ("identity", "IDENTITY", {"scope": evidence["scope"],
                                   "binding_evidence_digest": digest(evidence)},
         {"actor": ["actor"], "role": ["role-graph"]}),
    ):
        index = next(i for i, item in enumerate(objects) if item.object_id == name)
        objects[index] = NamespaceObject.create(name, kind, payload, operands)
    assert assess(objects, evidence)["status"] == "PASS"


def test_bot_cannot_take_unbounded_scope_even_with_rebound_evidence():
    objects, evidence = specimen("BOT")
    evidence["scope"] = "team:research"
    rebind_identity(objects, evidence)
    assert assess(objects, evidence)["status"] == "FAIL"


def test_bot_identity_selects_one_of_several_bound_simulations():
    objects, evidence = specimen("BOT")
    make = NamespaceObject.create
    objects.append(make("sim-2", "SIM", {}, {"data": ["data"], "verifier": ["verifier"],
                                             "objects": ["meaning"], "env": ["env"]}))
    index = next(i for i, item in enumerate(objects) if item.object_id == "bot")
    objects[index] = make("bot", "BOT", {}, {"agent": ["agent"],
                                                "sim": ["sim", "sim-2"], "env": ["env"]})
    assert assess(objects, evidence)["status"] == "PASS"


def test_recheck_replays_instead_of_trusting_a_rehashed_status():
    objects, evidence = specimen()
    module = checker()
    assessment = assess(objects, evidence)
    forged = {**assessment, "role_authority": "ESTABLISHED"}
    forged["assessment_digest"] = digest({k: v for k, v in forged.items() if k != "assessment_digest"})
    with pytest.raises(Refuted):
        module.recheck_identity_occupancy(
            forged, objects, identity_id="identity", collective_id="collective",
            expected_digest=composition_digest(objects),
            expected_evidence_digest=digest(evidence), evidence=evidence)


def test_caller_mutation_after_composition_cannot_change_checked_relation(monkeypatch):
    objects, evidence = specimen()
    index = next(i for i, item in enumerate(objects) if item.object_id == "collective")
    good = objects[index]
    objects.append(NamespaceObject.create("other-role", "ROLE", {"admitted_scopes": ["team:research"]}))
    objects[index] = NamespaceObject.create("collective", "COLLECTIVE", {}, {"roles": ["other-role"]})
    commitment = composition_digest(objects)
    module = checker()
    original = module.assess_composition

    def swap_after_check(submitted, **kwargs):
        result = original(submitted, **kwargs)
        objects[index] = good
        return result

    monkeypatch.setattr(module, "assess_composition", swap_after_check)
    result = module.assess_identity_occupancy(
        objects, identity_id="identity", collective_id="collective",
        expected_digest=commitment, expected_evidence_digest=digest(evidence), evidence=evidence)
    assert result["status"] == "FAIL"


def test_evidence_mutation_during_hash_cannot_change_checked_relation(monkeypatch):
    objects, evidence = specimen()
    evidence["actor_kind"] = "BOT"
    rebind_identity(objects, evidence)
    selected = digest(evidence)
    module = checker()
    original = module.digest

    def swap_after_hash(value):
        observed = original(value)
        if value is evidence:
            evidence["actor_kind"] = "AGENT"
        return observed

    monkeypatch.setattr(module, "digest", swap_after_hash)
    result = module.assess_identity_occupancy(
        objects, identity_id="identity", collective_id="collective",
        expected_digest=composition_digest(objects),
        expected_evidence_digest=selected, evidence=evidence)
    assert result["status"] == "FAIL"
