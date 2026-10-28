"""Finite ten-tier gate controls with actual native certificate fixtures.

directed acyclic graph (DAG); Secure Hash Algorithm 256-bit (SHA-256).
Fault injection tests replay interruption, not production checker correctness.
"""
from __future__ import annotations

from asyncio import CancelledError
from copy import deepcopy
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import MetaTier, NamespaceObject, ObjectCoordinate
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import object_facets
from verifier.runtime import tier_progression as gate
from test_certificate_dag_native_subjects import _fixture


def fixture() -> tuple[dict, dict, dict[str, bytes]]:
    bundle, policy, files = _fixture("verifier")
    checker = bundle["nodes"][0]
    checker.update(node_id="checker", claim_id="checker")
    claim = bundle["profiles"][0]["obligations"][0]
    claim["claim_id"] = "checker"
    claim["dependencies"] = [{"claim_id": "representation", "operand_role": None,
                              "object_kind": "VERIFIER", "profile_digest": None}]
    item = NamespaceObject.create(**bundle["objects"][0])
    selected = object_facets.object_facets_policy(trust_roots=("finite-selected-fixture",))
    request = object_facets.object_facets_request(item, policy=selected)
    raw = object_facets.build_object_facets_certificate(request, canonical_bytes(item.to_dict()), policy=selected)
    route = next(r for r in routes.current_object_route_catalog() if r["objective"] == "OBJECT-1.1")
    replay = routes.replay_current_object_certificate(raw, semantic_version=route["semantic_version"],
        objective="OBJECT-1.1", represented_kind="VERIFIER", expected_request=request, policy=selected)
    assert replay["computational_status"] == "PASS"
    node = {"node_id": "representation", "object_id": item.object_id, "claim_id": "representation",
        "certificate_path": "representation.json", "certificate_digest": gate.digest(raw),
        "request": request, "checker_policy": selected,
        "contract_version": replay["schema_version"].rsplit("-", 1)[1],
        "artifact_bindings": [{"path": "representation.json", "digest": gate.digest(raw)}],
        "facet_bindings": deepcopy(checker["facet_bindings"])}
    bundle["nodes"].append(node)
    bundle["profiles"][0]["obligations"].append({"claim_id": "representation",
        **{key: route[key] for key in ("semantic_version", "objective", "proposition_digest", "scope")},
        "assumptions": [], "dependencies": []})
    bundle["edges"] = [{"node_id": "checker", "prerequisite_id": "representation", "operand_role": None}]
    policy["required_roots"] = ["checker"]
    files["representation.json"] = raw
    repin(bundle, policy, files)
    return bundle, policy, files


def repin(bundle: dict, policy: dict, files: dict[str, bytes]) -> None:
    pin = gate.digest(canonical_bytes(bundle["profiles"][0]))
    policy["approved_profiles"] = [pin]
    policy["required_objects"][0]["profile_digest"] = pin
    policy["nodes"] = deepcopy(bundle["nodes"])
    policy["artifact_files_digest"] = dag.artifact_files_digest(files)


def selection(bundle: dict, policy: dict, files: dict[str, bytes], target: int = 2) -> dict:
    return {"schema_version": gate.SELECTION, "semantic_version": gate.PROFILE,
        "profile_id": "finite-test-closure", "subject": {key: policy["required_objects"][0][key]
            for key in ("object_id", "object_kind", "record_digest")}, "target_tier": target,
        "bundle_digest": gate.digest(canonical_bytes(bundle)), "policy_digest": gate.digest(canonical_bytes(policy)),
        "artifact_files_digest": dag.artifact_files_digest(files),
        "ranks": [{"node_id": "representation", "tier": 1}, {"node_id": "checker", "tier": 2}],
        "tiers": [{"tier": t, "census": "COMPLETE" if t <= 2 else "UNKNOWN",
                   "required_nodes": ["representation"] if t == 1 else ["checker"] if t == 2 else []}
                  for t in range(1, 11)]}


def assess(bundle: dict, policy: dict, files: dict[str, bytes], selected: dict | None = None,
           **options: Any) -> dict:
    raw = canonical_bytes(selected or selection(bundle, policy, files))
    inputs = {"bundle_bytes": canonical_bytes(bundle), "expected_policy_bytes": canonical_bytes(policy),
        "artifact_files": files, "expected_selection_digest": gate.digest(raw),
        "expected_mechanism_digest": gate.mechanism_digest()}
    inputs.update(options)
    return gate.assess_tier_progression(raw, **inputs)


def no_replay(*args: Any, **kwargs: Any) -> dict:
    pytest.fail("native replay must be fenced")


def test_actual_native_finite_progression_keeps_full_application_unknown() -> None:
    bundle, policy, files = fixture()
    result = assess(bundle, policy, files)
    assert result["status"] == result["selected_target_status"] == "PASS"
    assert result["selected_depth"] == 2 and result["can_advance_to"] is None
    assert result["native_assessment"]["status"] == "PASS"
    assert result["full_required_certificate_instances"] == result["full_application_status"] == "UNKNOWN"
    assert result["polished"] is False
    assert assess(bundle, policy, files, selection(bundle, policy, files, 1))["can_advance_to"] == 2


def test_new_ranks_preserve_old_namespace_meanings() -> None:
    assert [t.name for t in gate.ProgressionTier] == ["FACETS", "DYNAMICS", "STATICS", "CLOSURE",
        "INDEPENDENCE", "SECURITY", "PRIVACY", "CONSENT", "GOVERNANCE", "CORRIGIBILITY"]
    assert len(MetaTier) == 9 and MetaTier.PRIVACY.value == 6 and MetaTier.SECURITY.value == 9
    with pytest.raises(ValueError):
        ObjectCoordinate.parse("VERIFIER-10.1")


def test_upward_prerequisite_refused_without_reinterpreting_old_dag(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    assert dag.assess_certificate_dependencies(canonical_bytes(bundle), expected_policy_bytes=canonical_bytes(policy), artifact_files=files)["status"] == "PASS"
    chosen = selection(bundle, policy, files)
    chosen["ranks"][0]["tier"], chosen["ranks"][1]["tier"] = 2, 1
    chosen["tiers"][0]["required_nodes"], chosen["tiers"][1]["required_nodes"] = ["checker"], ["representation"]
    monkeypatch.setattr(dag, "assess_certificate_dependencies_preserving_faults", no_replay)
    result = assess(bundle, policy, files, chosen, cancelled=True)
    assert result["status"] == "FAIL" and "PROGRESSION_UPWARD_PREREQUISITE" in result["blockers"]


def test_same_tier_cycle_is_refused_before_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    bundle["edges"].append({"node_id": "representation", "prerequisite_id": "checker", "operand_role": None})
    repin(bundle, policy, files)
    chosen = selection(bundle, policy, files)
    chosen["ranks"][0]["tier"] = 2
    chosen["tiers"][0].update(census="UNKNOWN", required_nodes=[])
    chosen["tiers"][1]["required_nodes"] = ["representation", "checker"]
    monkeypatch.setattr(dag, "assess_certificate_dependencies_preserving_faults", no_replay)
    result = assess(bundle, policy, files, chosen, cancelled=True)
    assert result["status"] == "FAIL" and "PROGRESSION_DEPENDENCY_CYCLE" in result["blockers"]


@pytest.mark.parametrize("missing", ["profile-claim", "root"])
def test_unknown_native_closure_with_all_present_nodes_pass_cannot_unlock(missing: str) -> None:
    bundle, policy, files = fixture()
    if missing == "root":
        policy["required_roots"].append("missing-root")
    else:
        claim = deepcopy(bundle["profiles"][0]["obligations"][1])
        claim["claim_id"] = "missing-instance"
        bundle["profiles"][0]["obligations"].append(claim)
    repin(bundle, policy, files)
    result = assess(bundle, policy, files)
    assert result["native_assessment"]["status"] == "UNKNOWN"
    assert all(row["qualified_status"] == "PASS" for row in result["native_assessment"]["nodes"])
    assert result["status"] == "UNKNOWN" and result["selected_depth"] == 0 and result["can_advance_to"] is None


def test_unknown_lower_census_does_not_unlock_higher_pass() -> None:
    bundle, policy, files = fixture()
    chosen = selection(bundle, policy, files)
    chosen["tiers"][0]["census"] = "UNKNOWN"
    result = assess(bundle, policy, files, chosen)
    assert result["native_assessment"]["status"] == "PASS"
    assert result["status"] == "UNKNOWN" and result["selected_depth"] == 0


def test_missing_lower_certificate_blocks_actual_native_closure() -> None:
    bundle, policy, files = fixture()
    del files["representation.json"]
    repin(bundle, policy, files)
    result = assess(bundle, policy, files)
    assert result["status"] == "UNKNOWN" and result["can_advance_to"] is None


@pytest.mark.parametrize("cancelled", [False, True])
def test_available_artifact_contradiction_survives_missing_pin_or_cancel(cancelled: bool) -> None:
    bundle, policy, files = fixture()
    files["representation.json"] += b" "
    repin(bundle, policy, files)
    result = assess(bundle, policy, files, cancelled=cancelled, expected_mechanism_digest=None)
    assert result["status"] == "FAIL" and result["native_replay"] == "NOT_RUN"


def test_wrong_selection_pin_precedes_missing_native_inputs_and_source_io(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    raw = canonical_bytes(selection(bundle, policy, files))
    def unavailable() -> str:
        raise OSError("fault control")
    monkeypatch.setattr(gate, "mechanism_digest", unavailable)
    for native in (None, canonical_bytes(bundle)):
        result = gate.assess_tier_progression(raw, bundle_bytes=native, expected_policy_bytes=None,
            artifact_files=files, expected_selection_digest="sha256:" + "0" * 64,
            expected_mechanism_digest="sha256:" + "0" * 64)
        assert result["status"] == "FAIL" and "PROGRESSION_EXTERNAL_PIN_DIFFERS" in result["blockers"]


def test_valid_cancellation_never_runs_native(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    monkeypatch.setattr(dag, "assess_certificate_dependencies_preserving_faults", no_replay)
    result = assess(bundle, policy, files, cancelled=True)
    assert result["status"] == "UNKNOWN" and result["native_replay"] == "NOT_RUN"


def test_prior_native_refusal_survives_later_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    calls: list[str] = []
    def interrupted(raw: bytes, **kwargs: Any) -> dict:
        calls.append(kwargs["objective"])
        if len(calls) == 1:
            raise routes.CurrentObjectRouteRefusal("finite refusal control")
        raise CancelledError()
    monkeypatch.setattr(routes, "replay_current_object_certificate", interrupted)
    result = assess(bundle, policy, files)
    assert len(calls) == 2 and result["status"] == "FAIL"
    assert result["native_assessment"]["nodes"][0]["qualified_status"] == "FAIL"
    assert "DEPENDENCY_REPLAY_INTERRUPTED" in result["blockers"]
    assert result["can_advance_to"] is None


@pytest.mark.parametrize("fault", [OSError, CancelledError])
def test_first_replay_unavailable_is_unknown(fault: type[BaseException], monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    def unavailable(raw: bytes, **kwargs: Any) -> dict:
        raise fault()
    monkeypatch.setattr(routes, "replay_current_object_certificate", unavailable)
    result = assess(bundle, policy, files)
    assert result["status"] == "UNKNOWN" and result["can_advance_to"] is None


@pytest.mark.parametrize("change", ["extra-status", "empty-complete", "boolean-rank", "duplicate-rank", "clone-native"])
def test_forged_or_incomplete_selection_is_refused(change: str) -> None:
    bundle, policy, files = fixture()
    chosen = selection(bundle, policy, files)
    if change == "extra-status":
        chosen["status"] = "PASS"
    elif change == "empty-complete":
        chosen["tiers"][2]["census"] = "COMPLETE"
    elif change == "boolean-rank":
        chosen["ranks"][0]["tier"] = True
    elif change == "duplicate-rank":
        chosen["ranks"].append(deepcopy(chosen["ranks"][0]))
    else:
        bundle["nodes"][0]["request"] = deepcopy(bundle["nodes"][1]["request"])
        bundle["nodes"][0]["checker_policy"] = deepcopy(bundle["nodes"][1]["checker_policy"])
        repin(bundle, policy, files)
        chosen = selection(bundle, policy, files)
    assert assess(bundle, policy, files, chosen)["status"] == "FAIL"


def test_artifact_count_capacity_precedes_inventory_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    chosen = selection(bundle, policy, files)
    files.update({f"extra-{n}": b"" for n in range(1025)})
    original = dag.artifact_files_digest
    monkeypatch.setattr(dag, "artifact_files_digest", no_replay)
    raw = canonical_bytes(chosen)
    result = gate.assess_tier_progression(raw, bundle_bytes=canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files,
        expected_selection_digest=gate.digest(raw), expected_mechanism_digest=gate.mechanism_digest())
    assert result["status"] == "UNKNOWN" and "PROGRESSION_CAPACITY_EXHAUSTED" in result["blockers"]
    assert callable(original)


def test_report_compaction_preserves_fail_and_revokes_clearance(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    files["representation.json"] += b" "
    repin(bundle, policy, files)
    monkeypatch.setattr(gate, "MAX_REPORT_BYTES", 800)
    result = assess(bundle, policy, files)
    assert result["status"] == "FAIL" and result["report_complete"] is False
    assert result["selected_depth"] == 0 and result["can_advance_to"] is None


def test_every_same_tier_selected_instance_requires_its_own_native_certificate() -> None:
    bundle, policy, files = fixture()
    item = NamespaceObject.create(**bundle["objects"][0])
    selected = object_facets.object_facets_policy(trust_roots=("second-selected-instance",))
    request = object_facets.object_facets_request(item, policy=selected)
    raw = object_facets.build_object_facets_certificate(request, canonical_bytes(item.to_dict()), policy=selected)
    second = deepcopy(bundle["nodes"][1])
    second.update(node_id="second-instance", claim_id="second-instance", request=request,
                  checker_policy=selected, certificate_path="second.json", certificate_digest=gate.digest(raw),
                  artifact_bindings=[{"path": "second.json", "digest": gate.digest(raw)}])
    bundle["nodes"].append(second)
    claim = deepcopy(bundle["profiles"][0]["obligations"][1])
    claim["claim_id"] = "second-instance"
    bundle["profiles"][0]["obligations"].append(claim)
    bundle["profiles"][0]["obligations"][0]["dependencies"].append({"claim_id": "second-instance",
        "operand_role": None, "object_kind": "VERIFIER", "profile_digest": None})
    bundle["edges"].append({"node_id": "checker", "prerequisite_id": "second-instance", "operand_role": None})
    files["second.json"] = raw
    repin(bundle, policy, files)
    chosen = selection(bundle, policy, files)
    chosen["ranks"].append({"node_id": "second-instance", "tier": 1})
    chosen["tiers"][0]["required_nodes"].append("second-instance")
    assert assess(bundle, policy, files, chosen)["status"] == "PASS"
    del files["second.json"]
    repin(bundle, policy, files)
    chosen.update(bundle_digest=gate.digest(canonical_bytes(bundle)), policy_digest=gate.digest(canonical_bytes(policy)),
                  artifact_files_digest=dag.artifact_files_digest(files))
    result = assess(bundle, policy, files, chosen)
    assert result["status"] == "UNKNOWN" and result["selected_depth"] == 0


def test_binding_work_is_fenced_before_native_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    monkeypatch.setattr(gate, "MAX_BINDING_HASH_BYTES", 1)
    monkeypatch.setattr(dag, "assess_certificate_dependencies_preserving_faults", no_replay)
    result = assess(bundle, policy, files)
    assert result["status"] == "UNKNOWN" and "PROGRESSION_CAPACITY_EXHAUSTED" in result["blockers"]


def test_invalid_artifact_name_is_refused_before_inventory_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    chosen = selection(bundle, policy, files)
    files["../escape"] = b""
    monkeypatch.setattr(dag, "artifact_files_digest", no_replay)
    result = assess(bundle, policy, files, chosen)
    assert result["status"] == "FAIL" and result["native_replay"] == "NOT_RUN"


@pytest.mark.parametrize("change", ["payload", "duplicate"])
def test_available_namespace_refutations_precede_cancel_or_missing_pin(change: str) -> None:
    bundle, policy, files = fixture()
    if change == "duplicate":
        bundle["objects"].append(deepcopy(bundle["objects"][0]))
    else:
        bundle["objects"][0]["payload"]["altered"] = True
        item = NamespaceObject.create(**bundle["objects"][0])
        for node in bundle["nodes"]:
            node["facet_bindings"]["payload_digest"] = gate.digest(item.payload_bytes)
    repin(bundle, policy, files)
    result = assess(bundle, policy, files, cancelled=True, expected_mechanism_digest=None)
    assert result["status"] == "FAIL" and result["native_replay"] == "NOT_RUN"


def rooted_fixture() -> tuple[dict, dict, dict[str, bytes], dict]:
    """Actual two-object native dependency graph; generic finite root only."""
    bundle, policy, files = fixture()
    child = NamespaceObject.create(**bundle["objects"][0])
    root = NamespaceObject.create(object_id="selected-finite-root", kind="VERIFIER",
        payload={"scope": "finite-root-binding-control"}, operands={"checker": [child.object_id]})
    chosen_policy = object_facets.object_facets_policy(trust_roots=("finite-root-selection",))
    request = object_facets.object_facets_request(root, policy=chosen_policy)
    raw = object_facets.build_object_facets_certificate(request, canonical_bytes(root.to_dict()), policy=chosen_policy)
    route = next(r for r in routes.current_object_route_catalog() if r["objective"] == "OBJECT-1.1")
    replay = routes.replay_current_object_certificate(raw, semantic_version=route["semantic_version"],
        objective="OBJECT-1.1", represented_kind="VERIFIER", expected_request=request, policy=chosen_policy)
    assert replay["computational_status"] == "PASS"
    profile = {"schema_version": dag.PROFILE, "profile_id": "finite-root-control", "profile_version": "1",
        "object_kind": "VERIFIER", "obligations": [{"claim_id": "application",
            **{key: route[key] for key in ("semantic_version", "objective", "proposition_digest", "scope")},
            "assumptions": [], "dependencies": [{"claim_id": "checker", "operand_role": "checker",
                "object_kind": "VERIFIER", "profile_digest": policy["required_objects"][0]["profile_digest"]}]}]}
    profile_pin = gate.digest(canonical_bytes(profile))
    bundle["profiles"].append(profile)
    bundle["objects"].append(root.to_dict())
    bundle["nodes"].append({"node_id": "application", "object_id": root.object_id, "claim_id": "application",
        "certificate_path": "root.json", "certificate_digest": gate.digest(raw), "request": request,
        "checker_policy": chosen_policy, "contract_version": replay["schema_version"].rsplit("-", 1)[1],
        "artifact_bindings": [{"path": "root.json", "digest": gate.digest(raw)}],
        "facet_bindings": {"payload_digest": gate.digest(root.payload_bytes),
            "operands_digest": gate.digest(canonical_bytes(root.to_dict()["operands"]))}})
    bundle["edges"].append({"node_id": "application", "prerequisite_id": "checker", "operand_role": "checker"})
    policy["approved_profiles"].append(profile_pin)
    policy["required_objects"].append({"object_id": root.object_id, "object_kind": "VERIFIER",
        "record_digest": root.digest, "profile_digest": profile_pin})
    policy["required_roots"] = ["application"]
    policy["nodes"] = deepcopy(bundle["nodes"])
    files["root.json"] = raw
    policy["artifact_files_digest"] = dag.artifact_files_digest(files)
    chosen = selection(bundle, policy, files, 3)
    chosen["ranks"].append({"node_id": "application", "tier": 3})
    chosen["tiers"][2].update(census="COMPLETE", required_nodes=["application"])
    return bundle, policy, files, chosen


@pytest.mark.parametrize("cancelled", [False, True])
def test_subject_merely_dependency_cannot_claim_selected_root_progression(cancelled: bool,
        monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files, chosen = rooted_fixture()
    assert dag.assess_certificate_dependencies(canonical_bytes(bundle),
        expected_policy_bytes=canonical_bytes(policy), artifact_files=files)["status"] == "PASS"
    monkeypatch.setattr(dag, "assess_certificate_dependencies_preserving_faults", no_replay)
    result = assess(bundle, policy, files, chosen, cancelled=cancelled)
    assert result["status"] == "FAIL" and "PROGRESSION_SUBJECT_ROOT_DIFFERS" in result["blockers"]
    assert result["selected_depth"] == 0 and result["can_advance_to"] is None


def test_exact_subject_owned_selected_root_allows_only_finite_progression() -> None:
    bundle, policy, files, chosen = rooted_fixture()
    chosen["subject"] = {key: policy["required_objects"][1][key]
        for key in ("object_id", "object_kind", "record_digest")}
    result = assess(bundle, policy, files, chosen)
    assert result["status"] == result["native_assessment"]["status"] == "PASS"
    assert result["selected_depth"] == 3 and result["polished"] is False
    assert result["full_application_status"] == "UNKNOWN"


def test_missing_only_selected_root_preserves_native_closure_refutation() -> None:
    bundle, policy, files = fixture()
    policy["required_roots"] = ["missing-root"]
    result = assess(bundle, policy, files)
    assert result["native_assessment"]["status"] == result["status"] == "FAIL"
    assert result["selected_depth"] == 0 and result["can_advance_to"] is None


def test_missing_subject_root_with_valid_other_root_closure_remains_unknown() -> None:
    bundle, policy, files, chosen = rooted_fixture()
    policy["required_roots"].append("missing-subject-root")
    chosen["policy_digest"] = gate.digest(canonical_bytes(policy))
    result = assess(bundle, policy, files, chosen)
    assert result["native_assessment"]["status"] == result["status"] == "UNKNOWN"
    assert all(row["qualified_status"] == "PASS" for row in result["native_assessment"]["nodes"])
    assert result["selected_depth"] == 0 and result["can_advance_to"] is None


def test_empty_selected_roots_refuse_root_progression(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, policy, files = fixture()
    policy["required_roots"] = []
    monkeypatch.setattr(dag, "assess_certificate_dependencies_preserving_faults", no_replay)
    result = assess(bundle, policy, files)
    assert result["status"] == "FAIL" and "PROGRESSION_ROOT_SELECTION" in result["blockers"]
