"""Finite authority correspondence checks for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) fixtures contain inert declared models only.
Passing member floors is intentionally weaker than transition correspondence.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from verifier.interoperability.network import (
    AUTHORITY_AXIOM_AGENCY, AuthorityState, AuthorityTransition,
    assess_composition, canonical_bytes, digest_bytes,
)
from test_artifact_network import _replace_authority_model
from test_silo_composition_receipt import _members, _valid_composite
import verifier.interoperability.network as network


def _fixture(tmp_path: Path, *, omit: str | None = None) -> tuple[dict, dict, tuple]:
    first, second, _ = _members(tmp_path)
    members = tuple(sorted((first, second), key=lambda pair: pair[0].canonical_digest()))
    composite, store = _valid_composite(tmp_path, members[0][0], members[1][0])
    base = network._load_authority_model(composite, store)
    transitions = (
        AuthorityTransition("t00", "s00", "s10", "ANY_ACTOR", "SETTLE"),
        AuthorityTransition("t01", "s01", "s11", "ANY_ACTOR", "SETTLE"),
        AuthorityTransition("t10", "s00", "s01", "ANY_ACTOR", "SETTLE"),
        AuthorityTransition("t11", "s10", "s11", "ANY_ACTOR", "SETTLE"),
    )
    transitions = tuple(item for item in transitions if item.transition_id != omit)
    model = replace(
        base, initial_state_ids=("s00",), state_universe=("s00", "s01", "s10", "s11"),
        states=tuple(AuthorityState(name, AUTHORITY_AXIOM_AGENCY, ()) for name in ("s00", "s01", "s10", "s11")),
        transitions=transitions, transition_universe=tuple(item.transition_id for item in transitions),
    )
    composite = _replace_authority_model(store, composite, model)
    pairs = (*members, (composite, store))
    evidence = {}
    selections = []
    for commit, selected_store in pairs:
        model_record = next(entry.object_record for entry in commit.census if entry.path == commit.authority_model_path)
        commit_bytes = canonical_bytes(commit.to_dict())
        evidence[digest_bytes(commit_bytes)] = commit_bytes
        evidence[model_record.object_digest] = selected_store.read_object(model_record)
        selections.append({"commit_digest": commit.canonical_digest(), "authority_model_path": commit.authority_model_path, "authority_model_digest": model_record.object_digest})
    declaration = {
        "schema_version": "VSTD-FINITE-AUTHORITY-COMPOSITION-0.1",
        "profile_digest": "sha256:" + "0" * 64,
        "members": selections[:-1], "composite": selections[-1],
        "state_bindings": [
            {"composite_state_id": "s00", "member_state_ids": ["initial", "initial"]},
            {"composite_state_id": "s01", "member_state_ids": ["initial", "steady"]},
            {"composite_state_id": "s10", "member_state_ids": ["steady", "initial"]},
            {"composite_state_id": "s11", "member_state_ids": ["steady", "steady"]},
        ],
        "transition_bindings": [
            {"composite_transition_id": item.transition_id, "member_index": 0 if item.transition_id < "t10" else 1, "member_transition_id": "settle"}
            for item in transitions
        ],
    }
    return declaration, evidence, pairs


def test_omitted_transition_passes_existing_floors_but_not_correspondence(tmp_path: Path) -> None:
    declaration, evidence, pairs = _fixture(tmp_path, omit="t01")
    old = assess_composition(tuple(pair[0] for pair in pairs[:-1]), tuple(pair[1] for pair in pairs[:-1]), composite_commit=pairs[-1][0], composite_store=pairs[-1][1])
    assert old["authority_axiom_agency"] == "PRESERVED"
    from verifier.interoperability.authority_composition import assess_authority_composition, authority_composition_profile_digest
    declaration["profile_digest"] = authority_composition_profile_digest()
    result = assess_authority_composition(canonical_bytes(declaration), evidence)
    assert result["transition_correspondence"] == "MISMATCH"
    assert result["agency_preservation"] == "UNKNOWN"
    assert all(item["agency_preservation"] == "PRESERVED" for item in result["model_results"])


def _assess(declaration: dict, evidence: dict) -> dict:
    from verifier.interoperability.authority_composition import assess_authority_composition, authority_composition_profile_digest
    declaration["profile_digest"] = authority_composition_profile_digest()
    return assess_authority_composition(canonical_bytes(declaration), evidence)


def _model_value(declaration: dict, evidence: dict, index: int = -1) -> dict:
    selection = declaration["composite"] if index == -1 else declaration["members"][index]
    return json.loads(evidence[selection["authority_model_digest"]])


def _rebind_model(declaration: dict, evidence: dict, value: dict, index: int = -1, *, size_delta: int = 0) -> None:
    selection = declaration["composite"] if index == -1 else declaration["members"][index]
    payload = canonical_bytes(value)
    commit = json.loads(evidence[selection["commit_digest"]])
    entry = next(item for item in commit["census"] if item["path"] == selection["authority_model_path"])
    record = entry["object"]
    record["object_digest"] = digest_bytes(payload)
    record["size_bytes"] = len(payload) + size_delta
    commit_bytes = canonical_bytes(commit)
    selection["commit_digest"] = digest_bytes(commit_bytes)
    selection["authority_model_digest"] = digest_bytes(payload)
    evidence[selection["commit_digest"]] = commit_bytes
    evidence[selection["authority_model_digest"]] = payload
    if index != -1:
        previous = list(declaration["members"])
        declaration["members"] = sorted(previous, key=lambda item: item["commit_digest"])
        indices = [previous.index(item) for item in declaration["members"]]
        for binding in declaration["state_bindings"]:
            binding["member_state_ids"] = [binding["member_state_ids"][i] for i in indices]
        for binding in declaration["transition_bindings"]:
            binding["member_index"] = indices.index(binding["member_index"])


def test_exact_product_passes_without_silo_axis_promotion(tmp_path: Path) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    before = dict(evidence)
    result = _assess(declaration, evidence)
    assert result["coordinate_binding"] == "BOUND"
    assert result["transition_correspondence"] == "MATCHED"
    assert result["agency_preservation"] == result["local_addition_preservation"] == "PRESERVED"
    assert result["counts"] == {"product_states": 4, "generated_transitions": 4}
    assert result["declaration_digest"] == digest_bytes(canonical_bytes(declaration))
    assert "GENERAL_COMPOSED_AGENCY_NOT_ESTABLISHED" in result["residual_obligations"]
    assert not {"self_derivability", "completeness", "silo_grounding", "result"} & result.keys()
    assert evidence == before
    assert _assess(declaration, dict(reversed(list(evidence.items())))) == result


@pytest.mark.parametrize("mutation", ["action", "target", "extra", "initial", "missing_state", "missing_binding"])
def test_known_relation_mutations_are_mismatch(tmp_path: Path, mutation: str) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    model = _model_value(declaration, evidence)
    if mutation == "action":
        model["transitions"][0]["action"] = "DIFFERENT"
    elif mutation == "target":
        model["transitions"][0]["target_state_id"] = "s11"
    elif mutation == "extra":
        model["transitions"].append({**model["transitions"][0], "transition_id": "t99"})
        model["transition_universe"].append("t99")
        declaration["transition_bindings"].append({"composite_transition_id": "t99", "member_index": 0, "member_transition_id": "settle"})
    elif mutation == "initial":
        model["initial_state_ids"].append("s01")
    elif mutation == "missing_state":
        declaration["state_bindings"].pop()
    else:
        declaration["transition_bindings"].pop()
    _rebind_model(declaration, evidence, model)
    assert _assess(declaration, evidence)["transition_correspondence"] == "MISMATCH"


@pytest.mark.parametrize("mutation", ["duplicate_state", "duplicate_tuple", "bad_state", "bad_member_state", "bad_transition", "bad_member_transition", "bool_index", "float_index", "negative_index", "extra_field", "unsorted_members"])
def test_malformed_bindings_are_invalid(tmp_path: Path, mutation: str) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    if mutation == "duplicate_state":
        declaration["state_bindings"].append(declaration["state_bindings"][-1])
    elif mutation == "duplicate_tuple":
        declaration["state_bindings"][1]["member_state_ids"] = declaration["state_bindings"][0]["member_state_ids"]
    elif mutation == "bad_state":
        declaration["state_bindings"][-1]["composite_state_id"] = "unknown"
    elif mutation == "bad_member_state":
        declaration["state_bindings"][-1]["member_state_ids"][0] = "unknown"
    elif mutation == "bad_transition":
        declaration["transition_bindings"][-1]["composite_transition_id"] = "unknown"
    elif mutation == "bad_member_transition":
        declaration["transition_bindings"][-1]["member_transition_id"] = "unknown"
    elif mutation in {"bool_index", "float_index", "negative_index"}:
        declaration["transition_bindings"][0]["member_index"] = {"bool_index": True, "float_index": 0.0, "negative_index": -1}[mutation]
    elif mutation == "extra_field":
        declaration["approved"] = True
    else:
        declaration["members"].reverse()
    from verifier.interoperability.authority_composition import assess_authority_composition
    # The native canonical codec correctly refuses floats and negative integers
    # too; raw compact encoding lets the checker itself observe those negatives.
    raw = json.dumps(declaration, sort_keys=True, separators=(",", ":")).encode()
    result = assess_authority_composition(raw, evidence)
    if mutation in {"bad_state", "bad_member_state", "bad_transition", "bad_member_transition"}:
        result = _assess(declaration, evidence)
    assert result["transition_correspondence"] == "INVALID"


@pytest.mark.parametrize("mutation", ["missing", "wrong_bytes", "wrong_type", "wrong_size", "bad_census_role", "bad_commit", "unsupported_schema"])
def test_evidence_classes_are_not_conflated(tmp_path: Path, mutation: str) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    selection = declaration["composite"]
    if mutation == "missing":
        evidence.pop(selection["authority_model_digest"])
    elif mutation == "wrong_bytes":
        evidence[selection["authority_model_digest"]] = b"substituted"
    elif mutation == "wrong_type":
        evidence[selection["authority_model_digest"]] = None
    elif mutation == "wrong_size":
        _rebind_model(declaration, evidence, _model_value(declaration, evidence), size_delta=1)
    elif mutation == "bad_census_role":
        commit = json.loads(evidence[selection["commit_digest"]])
        next(item for item in commit["census"] if item["path"] == selection["authority_model_path"])["object"]["artifact_kind"] = "opaque"
        payload = canonical_bytes(commit)
        selection["commit_digest"] = digest_bytes(payload)
        evidence[selection["commit_digest"]] = payload
    elif mutation == "bad_commit":
        evidence[selection["commit_digest"]] = b"{}"
    else:
        model = _model_value(declaration, evidence)
        model["schema_version"] = "UNSUPPORTED-1"
        _rebind_model(declaration, evidence, model)
    result = _assess(declaration, evidence)
    expected = "UNKNOWN" if mutation in {"missing", "unsupported_schema"} else "INVALID"
    assert result["coordinate_binding"] == expected
    assert result["transition_correspondence"] == expected
    assert result["agency_preservation"] == "UNKNOWN"


@pytest.mark.parametrize("other_gap", ["missing_member", "open", "budget", "unsupported_profile"])
def test_reachable_floor_violation_survives_positive_gaps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, other_gap: str) -> None:
    import verifier.interoperability.authority_composition as module
    declaration, evidence, _ = _fixture(tmp_path)
    model = _model_value(declaration, evidence)
    model["states"][-1]["ground_actions"].remove("EXIT_COMPOSITION")
    if other_gap == "open":
        model["closure_status"] = "OPEN"
    _rebind_model(declaration, evidence, model)
    if other_gap == "missing_member":
        evidence.pop(declaration["members"][0]["commit_digest"])
    if other_gap == "budget":
        monkeypatch.setattr(module, "MAX_PRODUCT_STATES", 3)
        declaration["state_bindings"] = declaration["state_bindings"][:3]
    if other_gap == "unsupported_profile":
        result = module.assess_authority_composition(canonical_bytes(declaration), evidence)
    else:
        result = _assess(declaration, evidence)
    assert result["agency_preservation"] == "VIOLATED"
    assert result["model_results"][-1]["agency_preservation"] == "VIOLATED"
    assert "REACHABLE_GROUND_ACTION_REMOVED" in result["reason_codes"]


def test_unreachable_hostile_state_is_not_a_reachable_counterexample(tmp_path: Path) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    model = _model_value(declaration, evidence)
    model["states"].append({"state_id": "unreachable", "ground_actions": [], "local_authority_additions": []})
    model["state_universe"].append("unreachable")
    _rebind_model(declaration, evidence, model)
    result = _assess(declaration, evidence)
    assert result["agency_preservation"] == "UNKNOWN"
    assert result["model_results"][-1]["agency_preservation"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["closure_status", "residual_obligations", "actor_scope", "ground_extension", "bad_endpoint", "bad_universe"])
def test_declared_model_support_is_checked(tmp_path: Path, field: str) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    model = _model_value(declaration, evidence)
    if field == "closure_status":
        model[field] = "OPEN"
    elif field == "residual_obligations":
        model[field] = ["unresolved"]
    elif field == "actor_scope":
        model["transitions"][0][field] = "UNSUPPORTED_ACTOR"
    elif field == "ground_extension":
        model["states"][0]["ground_actions"].append("ZZZ_LOCAL")
    elif field == "bad_endpoint":
        model["transitions"][0]["target_state_id"] = "unknown"
    else:
        model["transition_universe"].pop()
    _rebind_model(declaration, evidence, model)
    result = _assess(declaration, evidence)
    assert result["agency_preservation"] == "UNKNOWN"
    if field in {"bad_endpoint", "bad_universe"}:
        assert result["transition_correspondence"] == "INVALID"
    elif field != "ground_extension":
        assert result["transition_correspondence"] == "UNKNOWN"


@pytest.mark.parametrize("budget", ["MAX_PRODUCT_STATES", "MAX_GENERATED_TRANSITIONS"])
def test_expansion_budget_is_checked_before_cartesian_allocation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, budget: str) -> None:
    import verifier.interoperability.authority_composition as module
    declaration, evidence, _ = _fixture(tmp_path)
    monkeypatch.setattr(module, budget, 3)
    # Binding list admission has the same bound; keep the admitted mapping short
    # so this test reaches the separately enforced expansion guard.
    declaration["state_bindings"] = declaration["state_bindings"][:3]
    declaration["transition_bindings"] = declaration["transition_bindings"][:3]
    def forbidden(*args: object) -> None:
        raise AssertionError("Cartesian allocation occurred before its bound")
    monkeypatch.setattr(module.itertools, "product", forbidden)
    result = _assess(declaration, evidence)
    assert result["transition_correspondence"] == "UNKNOWN"
    assert "COMPOSITION_EXPANSION_LIMIT" in result["reason_codes"]


def test_custom_input_hooks_are_never_executed(tmp_path: Path) -> None:
    from verifier.interoperability.authority_composition import assess_authority_composition
    class Hostile(dict):
        def items(self) -> None:
            raise AssertionError("untrusted callback")
    class Key:
        def __hash__(self) -> int:
            return 1
        def __str__(self) -> str:
            raise AssertionError("untrusted conversion")
    declaration, evidence, _ = _fixture(tmp_path)
    result = assess_authority_composition(canonical_bytes(declaration), Hostile(evidence))
    assert result["coordinate_binding"] == "UNKNOWN"
    result = assess_authority_composition(canonical_bytes(declaration), {Key(): b"data"})
    assert result["coordinate_binding"] == "UNKNOWN"


@pytest.mark.parametrize("wire", [b"{}", b'{"schema_version":"x","schema_version":"y"}', b'{ "schema_version":"x"}', b'[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]'])
def test_wire_admission_is_strict_and_bounded(wire: bytes) -> None:
    from verifier.interoperability.authority_composition import assess_authority_composition
    result = assess_authority_composition(wire, {})
    assert result["coordinate_binding"] == ("UNKNOWN" if wire.startswith(b"[[") else "INVALID")
    assert result["model_results"] == []


@pytest.mark.parametrize("propagation,missing_peer", [("COMPOSITION_PRESERVED", False), ("COMPOSITION_PRESERVED", True), ("LOCAL_ONLY", False)])
def test_local_additions_have_exact_propagation_meaning(tmp_path: Path, propagation: str, missing_peer: bool) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    peer = declaration["members"][1]
    model = _model_value(declaration, evidence, 0)
    model["states"][0]["local_authority_additions"] = [{"actor_scope": "ANY_ACTOR", "action": "INSPECT_EXTRA", "propagation": propagation}]
    _rebind_model(declaration, evidence, model, 0)
    if missing_peer:
        evidence.pop(peer["commit_digest"])
    result = _assess(declaration, evidence)
    assert result["local_addition_preservation"] == ("VIOLATED" if propagation == "COMPOSITION_PRESERVED" else "PRESERVED")
    if propagation == "COMPOSITION_PRESERVED":
        composite = _model_value(declaration, evidence)
        for state in composite["states"]:
            state["local_authority_additions"] = model["states"][0]["local_authority_additions"]
        _rebind_model(declaration, evidence, composite)
        assert _assess(declaration, evidence)["local_addition_preservation"] == ("UNKNOWN" if missing_peer else "PRESERVED")


def test_self_loops_retain_member_edge_multiplicity(tmp_path: Path) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    for selection in list(declaration["members"]):
        index = declaration["members"].index(selection)
        model = _model_value(declaration, evidence, index)
        model["state_universe"] = ["initial"]
        model["states"] = model["states"][:1]
        model["transitions"][0]["target_state_id"] = "initial"
        _rebind_model(declaration, evidence, model, index)
    composite = _model_value(declaration, evidence)
    composite["state_universe"] = ["s00"]
    composite["states"] = composite["states"][:1]
    composite["transition_universe"] = ["t00", "t10"]
    composite["transitions"] = [item for item in composite["transitions"] if item["transition_id"] in {"t00", "t10"}]
    for item in composite["transitions"]:
        item["target_state_id"] = "s00"
    _rebind_model(declaration, evidence, composite)
    declaration["state_bindings"] = declaration["state_bindings"][:1]
    declaration["transition_bindings"] = [{"composite_transition_id": name, "member_index": index, "member_transition_id": "settle"} for index, name in enumerate(("t00", "t10"))]
    result = _assess(declaration, evidence)
    assert result["transition_correspondence"] == "MATCHED"
    assert result["counts"] == {"product_states": 1, "generated_transitions": 2}
    declaration["transition_bindings"][1]["member_index"] = 0
    assert _assess(declaration, evidence)["transition_correspondence"] == "MISMATCH"


def test_empty_transition_product_is_valid_for_initial_singletons(tmp_path: Path) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    for selection in list(declaration["members"]):
        index = declaration["members"].index(selection)
        model = _model_value(declaration, evidence, index)
        model.update(state_universe=["initial"], states=model["states"][:1], transitions=[], transition_universe=[])
        _rebind_model(declaration, evidence, model, index)
    composite = _model_value(declaration, evidence)
    composite.update(state_universe=["s00"], states=composite["states"][:1], transitions=[], transition_universe=[])
    _rebind_model(declaration, evidence, composite)
    declaration["state_bindings"] = declaration["state_bindings"][:1]
    declaration["transition_bindings"] = []
    result = _assess(declaration, evidence)
    assert result["transition_correspondence"] == "MATCHED"
    assert result["counts"]["generated_transitions"] == 0


@pytest.mark.parametrize("mutation", ["reduced", "extended", "wrong_digest", "wrong_version"])
def test_canonical_agency_declaration_cannot_be_replaced(tmp_path: Path, mutation: str) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    selection = declaration["composite"]
    commit = json.loads(evidence[selection["commit_digest"]])
    if mutation == "reduced":
        commit["authority_axiom_agency"].pop()
    elif mutation == "extended":
        commit["authority_axiom_agency"].append("ZZZ_NEW_ACTION")
    elif mutation == "wrong_version":
        commit["authority_axiom_agency_version"] = "UNSUPPORTED-1"
    commit["authority_axiom_agency_digest"] = network.authority_axiom_agency_digest(tuple(commit["authority_axiom_agency"]))
    if mutation == "wrong_digest":
        commit["authority_axiom_agency_digest"] = "sha256:" + "0" * 64
    payload = canonical_bytes(commit)
    selection["commit_digest"] = digest_bytes(payload)
    evidence[selection["commit_digest"]] = payload
    result = _assess(declaration, evidence)
    assert result["coordinate_binding"] == ("INVALID" if mutation == "wrong_digest" else "UNKNOWN")
    assert result["agency_preservation"] == "UNKNOWN"


def test_known_size_mismatch_survives_unsupported_model(tmp_path: Path) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    model = _model_value(declaration, evidence)
    model["schema_version"] = "UNSUPPORTED-1"
    _rebind_model(declaration, evidence, model, size_delta=1)
    result = _assess(declaration, evidence)
    assert result["coordinate_binding"] == "INVALID"
    assert "MODEL_CENSUS_SIZE_INVALID" in result["reason_codes"]


@pytest.mark.parametrize("kind", ["entry_count", "record_bytes", "total_bytes"])
def test_input_limits_do_not_run_unbounded_observations(tmp_path: Path, kind: str) -> None:
    import verifier.interoperability.authority_composition as module
    declaration, evidence, _ = _fixture(tmp_path)
    if kind == "entry_count":
        for index in range(module.MAX_EVIDENCE_ENTRIES + 1):
            payload = str(index).encode()
            evidence[digest_bytes(payload)] = payload
    elif kind == "record_bytes":
        evidence[declaration["composite"]["authority_model_digest"]] = b"x" * (module.MAX_RECORD_BYTES + 1)
    else:
        evidence[digest_bytes(b"large")] = b"x" * (module.MAX_EVIDENCE_BYTES + 1)
    result = _assess(declaration, evidence)
    assert result["coordinate_binding"] == "UNKNOWN"
    assert result["agency_preservation"] == "UNKNOWN"
    if kind != "record_bytes":
        assert result["model_results"] == []


@pytest.mark.parametrize("gap", ["missing_peer", "expansion_limit"])
@pytest.mark.parametrize("mutation", ["action", "source", "target", "other_coordinate"])
def test_bound_edge_mismatch_survives_unrelated_positive_gap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gap: str, mutation: str) -> None:
    import verifier.interoperability.authority_composition as module
    declaration, evidence, _ = _fixture(tmp_path)
    model = _model_value(declaration, evidence)
    transition = model["transitions"][0]
    if mutation == "action":
        transition["action"] = "DIFFERENT"
    elif mutation == "source":
        transition["source_state_id"] = "s10"
    elif mutation == "target":
        transition["target_state_id"] = "s00"
    else:
        transition["target_state_id"] = "s11"
    _rebind_model(declaration, evidence, model)
    if gap == "missing_peer":
        evidence.pop(declaration["members"][1]["commit_digest"])
    else:
        monkeypatch.setattr(module, "MAX_PRODUCT_STATES", 3)
        # Retain both endpoints of the exact edge being refuted.
        omitted = "s01" if mutation == "other_coordinate" else "s11"
        declaration["state_bindings"] = [item for item in declaration["state_bindings"] if item["composite_state_id"] != omitted]
    result = _assess(declaration, evidence)
    assert result["transition_correspondence"] == "MISMATCH"
    assert result["agency_preservation"] == "UNKNOWN"


def test_supported_reference_invalidity_survives_missing_peer(tmp_path: Path) -> None:
    declaration, evidence, _ = _fixture(tmp_path)
    evidence.pop(declaration["members"][1]["commit_digest"])
    declaration["transition_bindings"][0]["member_transition_id"] = "unknown"
    assert _assess(declaration, evidence)["transition_correspondence"] == "INVALID"


def test_actual_product_bound_precedes_allocation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import verifier.interoperability.authority_composition as module
    declaration, evidence, _ = _fixture(tmp_path)
    for selection in list(declaration["members"]):
        index = declaration["members"].index(selection)
        model = _model_value(declaration, evidence, index)
        names = ["initial", "steady", *(f"z{n:02}" for n in range(2, 17))]
        model["state_universe"] = names
        model["states"] = [{"state_id": name, "ground_actions": list(AUTHORITY_AXIOM_AGENCY), "local_authority_additions": []} for name in names]
        model["transitions"] += [{"transition_id": f"t{n:02}", "source_state_id": names[n - 1], "target_state_id": names[n], "actor_scope": "ANY_ACTOR", "action": "NEXT"} for n in range(2, 17)]
        model["transition_universe"] = [item["transition_id"] for item in model["transitions"]]
        _rebind_model(declaration, evidence, model, index)
    def forbidden(*args: object) -> None:
        raise AssertionError("289-state product must never be allocated")
    monkeypatch.setattr(module.itertools, "product", forbidden)
    result = _assess(declaration, evidence)
    assert result["transition_correspondence"] == "UNKNOWN"
    assert result["counts"]["product_states"] is None
    assert "COMPOSITION_EXPANSION_LIMIT" in result["reason_codes"]
