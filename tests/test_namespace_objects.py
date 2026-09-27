"""Refutable structural gates for the maintainer's object hierarchy."""
from __future__ import annotations

from dataclasses import replace
import importlib

import pytest


def namespace():
    return importlib.import_module("verifier.core.namespace")


def test_exact_names_and_general_meta_tier_meanings():
    module = namespace()
    assert {kind.value for kind in module.ObjectKind} == {
        "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
        "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
        "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS",
        "AGENT", "SIM", "BOT", "TOKEN",
    }
    assert {tier.value: tier.name for tier in module.MetaTier} == {
        1: "FACETS", 2: "DYNAMICS", 3: "STATICS", 4: "CLOSURE",
        5: "INDEPENDENCE", 6: "PRIVACY", 7: "CONSENT", 8: "GOVERNANCE",
    }
    coordinate = module.ObjectCoordinate.parse("SIM-3.6")
    assert coordinate.object_kind.value == "SIM"
    assert coordinate.tier.value == 3
    assert coordinate.objective == 6
    assert str(coordinate) == "SIM-3.6"


@pytest.mark.parametrize("value", ["SIM-0.1", "SIM-9.1", "SIM-3.0", "SIM-3.m",
                                      "SIM-03.1", "SIM-3.01", "VSTD-1.1", "ABSENT-1.1"])
def test_coordinate_rejects_unknown_and_legacy_names(value):
    with pytest.raises(ValueError):
        namespace().ObjectCoordinate.parse(value)


def test_object_payload_and_operands_are_immutable_and_content_bound():
    module = namespace()
    payload = {"tensor": [1, 2]}
    item = module.NamespaceObject.create("architecture", "ARCH", payload)
    original = item.digest
    payload["tensor"][0] = 8
    item.payload["tensor"][1] = 9
    assert item.payload == {"tensor": [1, 2]}
    assert item.digest == original
    assert module.NamespaceObject.create("architecture", "ARCH", {"tensor": [2, 1]}).digest != original
    with pytest.raises(ValueError):
        module.NamespaceObject.create("architecture", "ARCH", {1: "coerced key"})
    with pytest.raises(ValueError):
        module.NamespaceObject.create("architecture", "ARCH", {"bad": float("nan")})
    with pytest.raises(ValueError):
        replace(item, payload_bytes=b'{"duplicate":1,"duplicate":2}')


def specimen():
    make = namespace().NamespaceObject.create
    objects = [make(name, kind, {}) for name, kind in (
        ("data", "DATA"), ("verifier", "VERIFIER"), ("arch", "ARCH"),
        ("time", "TIME"), ("space", "SPACE"), ("meaning", "OBJECT"),
        ("env", "ENV"), ("hardware", "HARDWARE"), ("harness", "HARNESS"),
        ("human", "HUMAN"), ("role", "ROLE"),
    )]
    objects += [
        make("event", "EVENT", {}, {"time": ["time"], "space": ["space"], "meaning": ["meaning"]}),
        make("bench", "BENCH", {}, {"verifier": ["verifier"], "data": ["data"]}),
        make("train", "TRAIN", {}, {"data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"]}),
        make("model", "MODEL", {}, {"train": ["train"], "data": ["data"], "events": ["event"],
             "bench": ["bench"], "arch": ["arch"], "env": ["env"], "hardware": ["hardware"]}),
        make("agent", "AGENT", {}, {"model": ["model"], "harness": ["harness"], "env": ["env"]}),
        make("actor", "ACTOR", {}, {"representation": ["agent"], "root_human": ["human"]}),
        make("identity", "IDENTITY", {}, {"actor": ["actor"], "role": ["role"]}),
    ]
    return objects


def assess(objects, **kwargs):
    module = namespace()
    return module.assess_composition(objects, expected_digest=module.composition_digest(objects), **kwargs)


def test_full_composition_is_order_independent_and_bounded_structural_only():
    objects = specimen()
    result = assess(objects)
    assert result.verdict.value == "PASS"
    assert result.collection_digest == namespace().composition_digest(list(reversed(objects)))
    assert result.object_profile_conformance == "NOT_ESTABLISHED"
    assert result.scope == "finite typed object composition"
    assert assess(objects, max_objects=2).verdict.value == "UNKNOWN"


def test_typed_nested_graph_can_replace_an_environment_but_not_an_architecture():
    module = namespace()
    objects = specimen()
    make = module.NamespaceObject.create
    objects.extend([make("envs", "GRAPH", {"element_kind": "ENV"}, {"members": ["env"]}),
                    make("nested", "GRAPH", {"element_kind": "ENV"}, {"members": ["envs"]})])
    pos = next(i for i, obj in enumerate(objects) if obj.object_id == "agent")
    objects[pos] = make("agent", "AGENT", {}, {"model": ["model"], "harness": ["harness"], "env": ["nested"]})
    assert assess(objects).verdict.value == "PASS"
    objects[-2] = make("envs", "GRAPH", {"element_kind": "ENV"}, {"members": ["arch"]})
    assert assess(objects).verdict.value == "FAIL"


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "cycle", "unbound", "wrong_kind", "extra_slot", "harness_model"])
def test_structural_counterexamples(mutation):
    module = namespace()
    make = module.NamespaceObject.create
    objects = specimen()
    if mutation == "missing":
        objects = [item for item in objects if item.object_id != "human"]
    elif mutation == "duplicate":
        objects.append(objects[0])
    elif mutation == "cycle":
        objects.extend([make("a", "HYPER", {}, {"x": ["b"]}), make("b", "HYPER", {}, {"x": ["a"]})])
    elif mutation == "unbound":
        result = module.assess_composition(objects, expected_digest="sha256:" + "0" * 64)
        assert result.verdict.value == "FAIL"
        return
    elif mutation == "wrong_kind":
        objects[-1] = make("identity", "IDENTITY", {}, {"actor": ["role"], "role": ["role"]})
    elif mutation == "extra_slot":
        objects[-1] = make("identity", "IDENTITY", {}, {"actor": ["actor"], "role": ["role"], "extra": ["human"]})
    else:
        index = next(i for i, item in enumerate(objects) if item.object_id == "harness")
        objects[index] = make("harness", "HARNESS", {}, {"model": ["model"]})
    assert assess(objects).verdict.value == "FAIL"


def test_actor_root_is_explicit_even_when_its_representation_is_human():
    make = namespace().NamespaceObject.create
    objects = [make("human", "HUMAN", {}), make("another", "HUMAN", {}),
               make("actor", "ACTOR", {}, {"representation": ["human"], "root_human": ["another"]})]
    assert assess(objects).verdict.value == "FAIL"
    objects[-1] = make("actor", "ACTOR", {}, {"representation": ["human"], "root_human": ["human"]})
    assert assess(objects).verdict.value == "PASS"


def test_no_evidence_binding_cannot_establish_a_composition():
    result = namespace().assess_composition(specimen(), expected_digest=None)
    assert result.verdict.value == "UNKNOWN"


def test_generic_graph_does_not_silently_acquire_an_environment_type():
    module = namespace()
    make = module.NamespaceObject.create
    objects = specimen()
    objects.append(make("untyped", "GRAPH", {"element_kind": "OBJECT"}, {"members": ["env"]}))
    index = next(i for i, item in enumerate(objects) if item.object_id == "agent")
    objects[index] = make("agent", "AGENT", {}, {"model": ["model"], "harness": ["harness"], "env": ["untyped"]})
    assert assess(objects).verdict.value == "FAIL"


def test_total_payload_and_operation_limits_remain_unknown():
    objects = specimen()
    assert assess(objects, max_payload_bytes=1).verdict.value == "UNKNOWN"
    assert assess(objects, max_operations=1).verdict.value == "UNKNOWN"


def test_aggregate_reference_bound_is_checked_before_canonicalization(monkeypatch):
    module = namespace()
    objects = specimen()
    commitment = module.composition_digest(objects)

    def forbidden_hash(_objects):
        raise AssertionError("checker hashed objects before applying its input bounds")

    monkeypatch.setattr(module, "composition_digest", forbidden_hash)
    assert module.assess_composition(objects, expected_digest=commitment,
                                    max_operations=1).verdict.value == "UNKNOWN"
    assert module.assess_composition(objects, expected_digest=commitment,
                                    max_reference_bytes=1).verdict.value == "UNKNOWN"


def ownership_specimen(actor_kind, realm):
    from verifier.domains.common import digest
    make = namespace().NamespaceObject.create
    objects = specimen()
    evidence = {
        "schema_version": "verifier-sim-isolation-evidence-1", "sim_id": "sim",
        "initial_state": "s", "virtual_hardware": [{"id": "memory", "kind": "memory"}],
        "states": [{"id": "s", "partition": "inside", "capabilities": ["memory"]}],
        "actions": ["step"], "transitions": [{"source": "s", "action": "step", "outcomes": [
            {"target": "s", "effects": [{"kind": "internal_write", "target": "memory"}]}]}],
    }
    binding = {"sim_id": "sim", "evidence_digest": digest(evidence), "max_operations": 20000, "max_items": 1000}
    payload = {"realm": realm}
    if realm == "virtual":
        payload.update(simulation_id="sim", resource_id="memory", resource_kind="memory")
    objects += [
        make("owned", "HARDWARE", payload),
        make("sim", "SIM", {"isolation_evidence_digest": digest(evidence)},
             {"data": ["data"], "verifier": ["verifier"], "objects": ["owned"], "env": ["env"]}),
        make("bot", "BOT", {}, {"agent": ["agent"], "sim": ["sim"], "env": ["env"]}),
        make("owner", "OWNER", {}, {"actor": ["actor"], "object": ["owned"]}),
    ]
    index = next(i for i, item in enumerate(objects) if item.object_id == "actor")
    objects[index] = make("actor", "ACTOR", {}, {"representation": [actor_kind.lower()], "root_human": ["human"]})
    return objects, evidence, binding


def ownership(objects, evidence=None, binding=None):
    module = importlib.import_module("verifier.domains.contracts.accountability")
    return module.assess_hardware_ownership(
        objects, owner_id="owner", expected_digest=namespace().composition_digest(objects),
        isolation_evidence=evidence, isolation_binding=binding)


@pytest.mark.parametrize("kind,realm,expected", [
    ("HUMAN", "physical", "PASS"), ("HUMAN", "virtual", "PASS"),
    ("AGENT", "physical", "FAIL"), ("AGENT", "virtual", "FAIL"),
    ("BOT", "physical", "FAIL"), ("BOT", "virtual", "PASS"),
])
def test_hardware_ownership_kind_rule(kind, realm, expected):
    objects, evidence, binding = ownership_specimen(kind, realm)
    result = ownership(objects, evidence, binding)
    assert result["status"] == expected
    assert result["authority"] == "NOT_ESTABLISHED"
    assert result["physical_host_containment"] == "NOT_ESTABLISHED"


def test_bot_virtual_ownership_requires_replayed_isolation_and_exact_hardware():
    objects, evidence, binding = ownership_specimen("BOT", "virtual")
    assert ownership(objects)["status"] == "UNKNOWN"
    evidence["transitions"][0]["outcomes"][0]["effects"][0]["kind"] = "outside_write"
    assert ownership(objects, evidence, binding)["status"] == "FAIL"


@pytest.mark.parametrize("mutation", ["other_sim", "other_resource_kind", "not_in_sim", "sim_digest", "missing_sim_digest"])
def test_isolation_cannot_be_reused_for_a_different_ownership_coordinate(mutation):
    make = namespace().NamespaceObject.create
    objects, evidence, binding = ownership_specimen("BOT", "virtual")
    hardware_index = next(i for i, item in enumerate(objects) if item.object_id == "owned")
    sim_index = next(i for i, item in enumerate(objects) if item.object_id == "sim")
    hardware_payload = objects[hardware_index].payload
    sim_payload = objects[sim_index].payload
    if mutation == "other_sim":
        hardware_payload["simulation_id"] = "other"
    elif mutation == "other_resource_kind":
        hardware_payload["resource_kind"] = "compute"
    elif mutation == "sim_digest":
        sim_payload["isolation_evidence_digest"] = "sha256:" + "0" * 64
    elif mutation == "missing_sim_digest":
        sim_payload = {}
    sim_operands = dict(objects[sim_index].operands)
    if mutation == "not_in_sim":
        sim_operands["objects"] = ["data"]
    objects[sim_index] = make("sim", "SIM", sim_payload, sim_operands)
    objects[hardware_index] = make("owned", "HARDWARE", hardware_payload)
    expected = "UNKNOWN" if mutation == "missing_sim_digest" else "FAIL"
    assert ownership(objects, evidence, binding)["status"] == expected


def test_mutating_callers_evidence_after_replay_cannot_supply_a_new_resource(monkeypatch):
    from verifier.domains.contracts import accountability as checker
    module = namespace()
    objects, evidence, binding = ownership_specimen("BOT", "virtual")
    index = next(i for i, item in enumerate(objects) if item.object_id == "owned")
    payload = objects[index].payload
    payload["resource_id"] = "substituted"
    objects[index] = module.NamespaceObject.create("owned", "HARDWARE", payload)
    real = checker.assess_sim_isolation

    def mutate_after_replay(submitted, *, expected_binding):
        result = real(submitted, expected_binding=expected_binding)
        evidence["virtual_hardware"][0]["id"] = "substituted"
        return result

    monkeypatch.setattr(checker, "assess_sim_isolation", mutate_after_replay)
    result = checker.assess_hardware_ownership(objects, owner_id="owner",
        expected_digest=module.composition_digest(objects), isolation_evidence=evidence,
        isolation_binding=binding)
    assert result["status"] == "FAIL"


def test_hardware_ownership_replay_rejects_rehashed_forged_verdict():
    from verifier.domains.contracts import accountability as checker
    from verifier.domains.common import Refuted, digest
    objects, evidence, binding = ownership_specimen("AGENT", "physical")
    commitment = namespace().composition_digest(objects)
    assessment = ownership(objects, evidence, binding)
    assert checker.recheck_hardware_ownership(assessment, objects, owner_id="owner",
        expected_digest=commitment, isolation_evidence=evidence, isolation_binding=binding) == assessment
    assessment["status"] = "PASS"
    assessment.pop("assessment_digest")
    assessment["assessment_digest"] = digest(assessment)
    with pytest.raises(Refuted):
        checker.recheck_hardware_ownership(assessment, objects, owner_id="owner",
            expected_digest=commitment, isolation_evidence=evidence, isolation_binding=binding)


def test_undeclared_virtual_resource_cannot_be_owned_by_a_bot():
    objects, evidence, binding = ownership_specimen("BOT", "virtual")
    index = next(i for i, item in enumerate(objects) if item.object_id == "owned")
    objects[index] = namespace().NamespaceObject.create("owned", "HARDWARE", {
        "realm": "virtual", "simulation_id": "sim", "resource_id": "not_declared", "resource_kind": "memory"})
    assert ownership(objects, evidence, binding)["status"] == "FAIL"


def test_collection_cannot_change_after_its_commitment_is_checked(monkeypatch):
    from verifier.core import namespace as checker
    objects = specimen()
    index = next(i for i, item in enumerate(objects) if item.object_id == "identity")
    good = objects[index]
    objects[index] = checker.NamespaceObject.create("identity", "IDENTITY", {},
        {"actor": ["role"], "role": ["role"]})
    commitment = checker.composition_digest(objects)
    real = checker.composition_digest

    def mutate_after_hash(submitted):
        result = real(submitted)
        objects[index] = good
        return result

    monkeypatch.setattr(checker, "composition_digest", mutate_after_hash)
    assert checker.assess_composition(objects, expected_digest=commitment).verdict.value == "FAIL"


def test_owner_cannot_change_after_composition_replay(monkeypatch):
    from verifier.core import namespace
    from verifier.domains.contracts import accountability as checker
    objects, evidence, binding = ownership_specimen("AGENT", "physical")
    index = next(i for i, item in enumerate(objects) if item.object_id == "actor")
    commitment = namespace.composition_digest(objects)
    real = checker.assess_composition

    def mutate_after_composition(submitted, **kwargs):
        result = real(submitted, **kwargs)
        objects[index] = namespace.NamespaceObject.create("actor", "ACTOR", {},
            {"representation": ["human"], "root_human": ["human"]})
        return result

    monkeypatch.setattr(checker, "assess_composition", mutate_after_composition)
    result = checker.assess_hardware_ownership(objects, owner_id="owner", expected_digest=commitment,
        isolation_evidence=evidence, isolation_binding=binding)
    assert result["status"] == "FAIL"
