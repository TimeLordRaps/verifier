"""Bounded structural compilation and adverse denominator tests.

The positive scope has no claim about complete application or opaque payload truth.
The explicit five source fields below are fixture goldens, not compiler output.
"""
from copy import deepcopy
from hashlib import sha256
import base64

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import application_requirements as compiler
from verifier.domains.contracts import object_facets, typed_facets


def pin(value):
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


def fixture():
    item = NamespaceObject.create("h", "HUMAN", {"opaque": 7})
    records = [item.to_dict()]
    collection = {"schema_version": "verifier-polish-object-collection-1", "objects": records}
    raw = canonical_bytes(collection)
    # Independently enumerated retained field census for this exact fixture.
    field_values = [(["object_id"], "h"), (["kind"], "HUMAN"),
        (["payload"], {"opaque": 7}), (["payload", "opaque"], 7), (["operands"], {})]
    census = [{"object_id": "h", "object_kind": "HUMAN", "record_digest": item.digest,
        "path": path, "value_digest": pin(value), "source_unit_id": "declared-source",
        "facet_id": pin(["declared-source", "h", path])} for path, value in field_values]
    census.sort(key=lambda row: row["facet_id"])
    families = compiler.installed_families(["HUMAN"])
    source = {"schema_version": compiler.SOURCE, "scope_id": "finite-structural-fixture", "revision": "1",
        "source_units": [{"unit_id": "declared-source", "language": compiler.LANGUAGE,
            "bytes_b64": base64.b64encode(raw).decode("ascii"),
            "bytes_digest": "sha256:" + sha256(raw).hexdigest()}],
        "normative_families": families, "semantic_mappings": [],
        "interaction_generators": compiler.installed_interaction_generators(),
        "census_evidence": {"source_member_census_digest": pin(census)}}
    obj_policy = object_facets.object_facets_policy(trust_roots=["fixture"])
    typed_policy = typed_facets.typed_facets_policy(trust_roots=["fixture"])
    typed_evidence = canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION, "objects": records})
    selection = {"schema_version": compiler.SELECTION,
        "application_profile_id": compiler.STRUCTURAL, "application_profile_version": "1", "root_id": "h",
        "semantic_version": compiler.SEMANTIC, "source_scope_digest": pin(source),
        "collection_bytes_digest": "sha256:" + sha256(raw).hexdigest(), "collection_digest": composition_digest([item]),
        "selectors": [], "native_intents": [
            {"object_id": "h", "coordinate": "OBJECT-1.1", "request": object_facets.object_facets_request(item, policy=obj_policy),
                "checker_policy": obj_policy},
            {"object_id": "h", "coordinate": "HUMAN-1.1", "request": typed_facets.typed_facets_request(
                object_kind="HUMAN", subject_id="h", object_digest=item.digest,
                collection_digest=composition_digest([item]), evidence_ref="sha256:" + sha256(typed_evidence).hexdigest(),
                policy=typed_policy), "checker_policy": typed_policy}]}
    policy = {"schema_version": compiler.POLICY, "mechanism_digest": compiler.mechanism_digest(),
        "source_scope_digest": pin(source), "collection_bytes_digest": "sha256:" + sha256(raw).hexdigest(),
        "selection_digest": pin(selection), "installed_rule_set_digest": pin(compiler.installed_rules()),
        "normative_family_set_digest": pin(compiler.normative_family_census()),
        "allowed_frontend_digests": [pin({"language": compiler.LANGUAGE, "source_pins": compiler._PINS})],
        "admitted_rule_digests": sorted(row["rule_digest"] for row in compiler.installed_rules()["rules"]),
        "limits": dict(compiler.CEILINGS)}
    return source, collection, selection, policy


def run_case(source, collection, selection, policy, *, reselect=True):
    source, selection, policy = deepcopy(source), deepcopy(selection), deepcopy(policy)
    if reselect:
        selection["source_scope_digest"] = pin(source)
        selection["collection_bytes_digest"] = pin(collection)
        policy.update(source_scope_digest=pin(source), collection_bytes_digest=pin(collection), selection_digest=pin(selection))
    return compiler.derive_current_application_requirements(canonical_bytes(source), canonical_bytes(collection),
        canonical_bytes(selection), expected_compiler_policy_bytes=canonical_bytes(policy))


def test_genuine_finite_structural_scope_never_full_polish():
    args = fixture()
    result = run_case(*args)
    assert result["status"] == "PASS"
    assert result["scope_kind"] == compiler.STRUCTURAL
    assert result["full_application_status"] == "UNKNOWN" and result["polished"] is False
    assert result["closure_status"] == "CLOSED_FOR_EXACT_SELECTED_FINITE_SCOPE"
    assert {tuple(row["path"]) for row in result["namespace_census"]} == {
        ("object_id",), ("kind",), ("payload",), ("payload", "opaque"), ("operands",)}
    assert {row["coordinate"] for row in result["required_objectives"]} == {"OBJECT-1.1", "HUMAN-1.1"}
    assert len(result["semantic_facet_census"]) == 5
    assert result["consumer_requirements"] == []
    assert result["scope_admission"]["authority_status"] == "NOT_EVALUATED"
    families = result["normative_family_census"]
    assert len(families) == 234 and len({(r["represented_kind"], r["tier"]) for r in families}) == 234
    assert all(r["full_family_members"] is None and r["full_family_closure"] == "UNKNOWN" for r in families)
    encoded = canonical_bytes(result)
    replay = compiler.recheck_current_application_requirements(encoded,
        expected_mechanism_digest=result["mechanism_digest"], expected_manifest_digest=result["manifest_digest"],
        source_scope_bytes=canonical_bytes(args[0]), collection_bytes=canonical_bytes(args[1]),
        selection_bytes=canonical_bytes(args[2]), expected_compiler_policy_bytes=canonical_bytes(args[3]))
    assert replay["replay_status"] == "REPRODUCED"


def test_full_application_retains_all234_unknown_not_one_certificate_per_slot():
    source, collection, selection, policy = fixture()
    selection["application_profile_id"] = compiler.FULL
    result = run_case(source, collection, selection, policy)
    assert result["status"] == "UNKNOWN" and result["full_application_status"] == "UNKNOWN"
    assert sum(row["code"] == "CURRENT_FULL_NORMATIVE_FAMILY_OPEN" for row in result["unresolved_cells"]) == 234
    assert len(result["required_objectives"]) == 2


def test_missing_native_intent_does_not_remove_requirement():
    source, collection, selection, policy = fixture()
    selection["native_intents"].pop()
    result = run_case(source, collection, selection, policy)
    assert result["status"] == "UNKNOWN" and len(result["required_objectives"]) == 2
    assert any(row["code"] == "NATIVE_INTENT_MISSING" for row in result["unresolved_cells"])


def test_source_omission_cannot_be_hidden_by_repinning():
    source, collection, selection, policy = fixture()
    changed = deepcopy(collection); changed["objects"][0]["payload"] = {}
    raw = canonical_bytes(changed)
    source["source_units"][0].update(bytes_b64=base64.b64encode(raw).decode("ascii"), bytes_digest=pin(changed))
    assert run_case(source, collection, selection, policy)["status"] == "FAIL"


def test_supplied_census_omission_is_refuted():
    source, collection, selection, policy = fixture()
    source["census_evidence"]["source_member_census_digest"] = pin([])
    assert run_case(source, collection, selection, policy)["status"] == "FAIL"


def test_unknown_payload_semantics_or_na_waiver_never_closes_full():
    source, collection, selection, policy = fixture()
    source["semantic_mappings"] = [{"property": "model_correctness", "applicability": "NOT_APPLICABLE"}]
    result = run_case(source, collection, selection, policy)
    assert result["status"] == "UNKNOWN"
    assert any(row["code"] == "APPLICATION_SEMANTIC_MAPPING_UNSUPPORTED" for row in result["unresolved_cells"])


def test_all_m_without_family_endpoint_and_subset_selector_unknown():
    source, collection, selection, policy = fixture()
    selection["selectors"] = [{"object_kind": "HUMAN", "tier": 7, "objective": "all.m"}, {"subset": ["h"]}]
    result = run_case(source, collection, selection, policy)
    assert result["status"] == "UNKNOWN"
    assert {r["code"] for r in result["unresolved_cells"]} >= {"OBJECTIVE_FAMILY_ENDPOINT_UNKNOWN", "SELECTOR_UNSUPPORTED"}


def test_bool_tier_is_malformed():
    source, collection, selection, policy = fixture()
    selection["selectors"] = [{"object_kind": "HUMAN", "tier": True, "objective": "all.m"}]
    assert run_case(source, collection, selection, policy)["status"] == "FAIL"


def test_same_label_wrong_request_subject_and_wrong_policy_fail():
    for field in ("object_id", "policy_digest"):
        source, collection, selection, policy = fixture()
        selection["native_intents"][0]["request"][field] = "other" if field == "object_id" else "sha256:" + "0" * 64
        assert run_case(source, collection, selection, policy)["status"] == "FAIL"


def test_bound_exhaustion_returns_no_completed_partial_ledger():
    source, collection, selection, policy = fixture()
    policy["limits"]["facets"] = 1
    result = run_case(source, collection, selection, policy)
    assert result["status"] == "UNKNOWN" and result["complete_bounds"] is False
    assert result["closure_certificate"] is None and result["namespace_census"] == []


def test_rehashed_forged_scope_cannot_reproduce():
    source, collection, selection, policy = fixture()
    result = run_case(source, collection, selection, policy)
    result.update(scope_kind=compiler.FULL, full_application_status="PASS")
    result["manifest_digest"] = pin({k: v for k, v in result.items() if k != "manifest_digest"})
    replay = compiler.recheck_current_application_requirements(canonical_bytes(result),
        expected_mechanism_digest=result["mechanism_digest"], expected_manifest_digest=result["manifest_digest"],
        source_scope_bytes=canonical_bytes(source), collection_bytes=canonical_bytes(collection),
        selection_bytes=canonical_bytes(selection), expected_compiler_policy_bytes=canonical_bytes(policy))
    assert replay["replay_status"] == "REJECTED"


def test_two_same_unknown_diagnostics_still_bind_different_inputs():
    source, collection, selection, policy = fixture()
    selection["selectors"] = [{"unsupported": "a"}]
    a = run_case(source, collection, selection, policy)
    selection["selectors"] = [{"unsupported": "b"}]
    b = run_case(source, collection, selection, policy)
    assert a["status"] == b["status"] == "UNKNOWN"
    assert a["unresolved_cells"] == b["unresolved_cells"]
    assert a["manifest_digest"] != b["manifest_digest"]


def test_source_mechanism_outage_is_unknown(monkeypatch):
    args = fixture()
    def unavailable():
        raise OSError("private detail must not escape")
    monkeypatch.setattr(compiler, "source_bindings", unavailable)
    result = run_case(*args)
    assert result["status"] == "UNKNOWN" and result["replayable"] is False
    assert "private detail" not in canonical_bytes(result).decode()


def test_late_known_fail_keeps_verdict_and_compacts_to_selected_output_bound():
    source, collection, selection, policy = fixture()
    policy["limits"]["output_bytes"] = 8192
    # Native intent rejection happens after the large 234-cell family census.
    selection["native_intents"][0]["request"]["object_id"] = "different-subject"
    result = run_case(source, collection, selection, policy)
    assert result["status"] == "FAIL" and result["closure_status"] == "REFUTED"
    assert result["complete_bounds"] is False and result["exhausted_resource"] == "output_bytes"
    assert len(canonical_bytes(result)) <= policy["limits"]["output_bytes"]
    assert result["closure_certificate"] is None and result["normative_family_census"] == []
    assert result["scope_admission"] == {"authority_status": "NOT_EVALUATED"}


def recheck_case(result, args, *, mechanism_digest=None, manifest_bytes=None):
    return compiler.recheck_current_application_requirements(
        canonical_bytes(result) if manifest_bytes is None else manifest_bytes,
        expected_mechanism_digest=mechanism_digest or result["mechanism_digest"],
        expected_manifest_digest=result["manifest_digest"], source_scope_bytes=canonical_bytes(args[0]),
        collection_bytes=canonical_bytes(args[1]), selection_bytes=canonical_bytes(args[2]),
        expected_compiler_policy_bytes=canonical_bytes(args[3]))


def test_previously_passing_compiler_manifest_does_not_carry_pass_through_source_outage(monkeypatch):
    args = fixture()
    result = run_case(*args)
    assert result["status"] == "PASS"
    def unavailable():
        raise OSError("private detail must not escape")
    monkeypatch.setattr(compiler, "source_bindings", unavailable)
    replay = recheck_case(result, args)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"
    assert replay["polished"] is False and replay["full_application_status"] == "UNKNOWN"
    assert replay["input_digests"] == result["input_digests"]
    assert replay["expected_manifest_digest"] == result["manifest_digest"]
    assert replay["observed_manifest_digest"] != result["manifest_digest"]
    assert "private detail" not in canonical_bytes(replay).decode()


def test_compiler_source_outage_diagnostic_replay_remains_unavailable(monkeypatch):
    args = fixture()
    selected_mechanism = compiler.mechanism_digest()
    def unavailable():
        raise OSError("source unavailable")
    monkeypatch.setattr(compiler, "source_bindings", unavailable)
    result = run_case(*args)
    assert result["status"] == "UNKNOWN" and result["replayable"] is False
    replay = recheck_case(result, args, mechanism_digest=selected_mechanism)
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"
    assert replay["input_digests"] == result["input_digests"]


@pytest.mark.parametrize("changed", [0, 1, 2, 3])
def test_changed_original_compiler_inputs_refuted_before_source_outage(changed, monkeypatch):
    args = fixture()
    result = run_case(*args)
    changed_args = deepcopy(args)
    changed_args[changed]["changed_original_input"] = True
    def unexpected():
        raise AssertionError("changed original inputs reached installed-source callback")
    monkeypatch.setattr(compiler, "source_bindings", unexpected)
    replay = recheck_case(result, changed_args)
    assert replay["status"] == "FAIL" and replay["replay_status"] == "REJECTED"


def test_compiler_rechecker_bounds_manifest_before_installed_source_callback(monkeypatch):
    args = fixture()
    result = run_case(*args)
    def unexpected():
        raise AssertionError("over-bound manifest reached installed-source callback")
    monkeypatch.setattr(compiler, "source_bindings", unexpected)
    replay = recheck_case(result, args, manifest_bytes=b" " * (8 * 1024**2 + 1))
    assert replay["status"] == "UNKNOWN" and replay["replay_status"] == "UNAVAILABLE"


def test_compiler_available_known_native_binding_fail_reproduces_fail():
    source, collection, selection, policy = fixture()
    selection["native_intents"][0]["request"]["object_id"] = "different-subject"
    policy["selection_digest"] = pin(selection)
    args = source, collection, selection, policy
    result = run_case(*args)
    assert result["status"] == "FAIL" and result["replayable"] is True
    replay = recheck_case(result, args)
    assert replay["status"] == "FAIL" and replay["replay_status"] == "REPRODUCED"


def test_compiler_unavailable_reconstruction_preserves_current_observed_fail(monkeypatch):
    args = fixture()
    result = run_case(*args)
    current = deepcopy(result)
    current.update(status="FAIL", replayable=False, closure_status="REFUTED", reason="CURRENT_KNOWN_FAILURE")
    current["manifest_digest"] = pin({key: value for key, value in current.items() if key != "manifest_digest"})
    monkeypatch.setattr(compiler, "derive_current_application_requirements", lambda *args, **kwargs: deepcopy(current))
    replay = recheck_case(result, args)
    assert replay["status"] == "FAIL" and replay["replay_status"] == "UNAVAILABLE"
    assert replay["closure_status"] == "REFUTED" and replay["polished"] is False
