"""Refutable gates for versioned current-object simulation grounding."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import hashlib
import importlib
import importlib.util
import json
import sys

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains.common import Unavailable


def _candidate():
    name = "verifier.domains.contracts.object_grounding"
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
    # The scratch candidate is intentionally outside the live package. After
    # transfer, the ordinary package import above is the production test path.
    path = Path(__file__).resolve().parents[1] / "src/verifier/domains/contracts/object_grounding.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _model():
    return {"schema_version": "verifier-sim-isolation-evidence-1", "sim_id": "sim",
        "initial_state": "idle",
        "virtual_hardware": [{"id": "cpu", "kind": "compute"}, {"id": "disk", "kind": "storage"}],
        "states": [
            {"id": "idle", "partition": "inside", "capabilities": ["cpu", "disk"]},
            {"id": "busy", "partition": "inside", "capabilities": ["cpu", "disk"]},
            {"id": "outside", "partition": "outside", "capabilities": ["host:network"]},
        ],
        "actions": ["step"],
        "transitions": [
            {"source": "idle", "action": "step", "outcomes": [
                {"target": "busy", "effects": [{"kind": "internal_write", "target": "cpu"}]},
                {"target": "idle", "effects": []},
            ]},
            {"source": "busy", "action": "step", "outcomes": [
                {"target": "idle", "effects": [{"kind": "receipt_record", "target": "disk"}]},
            ]},
        ],
    }


def _objects(iso_bytes: bytes):
    make = NamespaceObject.create
    objects = [
        make("data", "DATA", {}), make("verifier", "VERIFIER", {}),
        make("room", "OBJECT", {}), make("env", "ENV", {}),
    ]
    objects.append(make("sim", "SIM", {
        "isolation_evidence_digest": "sha256:" + hashlib.sha256(iso_bytes).hexdigest(),
    }, {"data": ["data"], "verifier": ["verifier"], "objects": ["room"], "env": ["env"]}))
    return objects


def _fixture(limits=None):
    module = _candidate()
    iso = canonical_bytes(_model())
    objects = _objects(iso)
    policy = module.current_object_policy(trust_roots=("checker-selected-local-fixture",))
    request = module.current_object_request(objects, sim_id="sim", isolation_evidence_bytes=iso,
                                            policy=policy, limits=limits)
    return module, request, objects, iso, policy


def _build(module, request, objects, iso, policy):
    return module.build_current_object_certificate(request, objects, iso, policy=policy)


def test_versioned_current_object_certificate_builder_exists() -> None:
    candidate = _candidate()
    assert callable(candidate.build_current_object_certificate)
    assert callable(candidate.recheck_current_object_certificate)


def test_positive_finite_confinement_is_independently_replayed_without_tier_promotion():
    module, request, objects, iso, policy = _fixture()
    certificate = _build(module, request, objects, iso, policy)
    carried = strict_json_loads(certificate.decode("utf-8"))
    result = module.recheck_current_object_certificate(certificate,
        expected_request=request, policy=policy)
    assert result == carried["result"]
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["isolation_status"] == "PASS"
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["sim_tier_5_conformance"] == "NOT_ESTABLISHED"
    assert result["physical_host_containment"] == "NOT_ESTABLISHED"
    assert result["authority"] == "NOT_ESTABLISHED"
    assert carried["request"]["semantic_version"] == module.SEMANTIC_VERSION
    assert carried["proposition_digest"] == module.PROPOSITION_DIGEST
    assert set(carried["evidence_payloads"]) == set(carried["evidence_refs"])


def test_legacy_coordinate_spelling_cannot_dispatch_as_current_independence():
    module, request, objects, iso, policy = _fixture()
    assert module.COORDINATE == "SIM-5.1"
    legacy = dict(request, semantic_version="verifier-domain-obligations-1")
    with pytest.raises(module.CurrentObjectGroundingError, match="semantic version"):
        _build(module, legacy, objects, iso, policy)
    unsupported = dict(request, coordinate="SIM-5.2")
    with pytest.raises(module.CurrentObjectGroundingError, match="unregistered"):
        _build(module, unsupported, objects, iso, policy)
    certificate = _build(module, request, objects, iso, policy)
    legacy_certificate = canonical_bytes({"schema_version": "verifier-domain-certification-1"})
    with pytest.raises(module.CurrentObjectGroundingError):
        module.recheck_current_object_certificate(legacy_certificate,
            expected_request=request, policy=policy)
    changed = dict(request, proposition_digest="sha256:" + "0" * 64)
    with pytest.raises(module.CurrentObjectGroundingError, match="proposition"):
        _build(module, changed, objects, iso, policy)
    with pytest.raises(module.CurrentObjectGroundingError):
        module.recheck_current_object_certificate(certificate,
            expected_request=legacy, policy=policy)


def test_complete_collection_and_selected_sim_object_substitutions_fail():
    module, request, objects, iso, policy = _fixture()
    altered = list(objects)
    altered[0] = NamespaceObject.create("data", "DATA", {"changed": True})
    result = strict_json_loads(_build(module, request, altered, iso, policy).decode())["result"]
    assert result["status"] == "FAIL"
    altered = list(objects)
    altered[-1] = NamespaceObject.create("sim", "SIM", {"isolation_evidence_digest": request["isolation_evidence_digest"], "changed": True},
        {"data": ["data"], "verifier": ["verifier"], "objects": ["room"], "env": ["env"]})
    result = strict_json_loads(_build(module, request, altered, iso, policy).decode())["result"]
    assert result["status"] == "FAIL"
    certificate = _build(module, request, objects, iso, policy)
    expected_changed = dict(request, object_digest="sha256:" + "0" * 64)
    with pytest.raises(module.CurrentObjectGroundingError):
        module.recheck_current_object_certificate(certificate,
            expected_request=expected_changed, policy=policy)


def test_isolation_evidence_substitution_and_explicit_escape_fail():
    module, request, objects, iso, policy = _fixture()
    altered = _model()
    altered["states"][1]["partition"] = "outside"
    result = strict_json_loads(_build(module, request, objects, canonical_bytes(altered), policy).decode())["result"]
    assert result["status"] == "FAIL"
    escape = _model()
    escape["transitions"][0]["outcomes"][0]["effects"] = [
        {"kind": "external_export", "target": "host:network"}]
    escape["transitions"].pop()  # Explicit refutation must dominate a missing pair.
    escaped = canonical_bytes(escape)
    new_objects = _objects(escaped)
    new_request = module.current_object_request(new_objects, sim_id="sim",
        isolation_evidence_bytes=escaped, policy=policy)
    result = strict_json_loads(_build(module, new_request, new_objects, escaped, policy).decode())["result"]
    assert result["status"] == "FAIL"


def test_missing_transition_and_unsupported_effect_remain_unknown():
    module, _, _, _, policy = _fixture()
    missing = _model()
    missing["transitions"].pop()
    for changed in (missing, _model()):
        if changed is not missing:
            changed["transitions"][0]["outcomes"][0]["effects"] = [
                {"kind": "quantum-teleport", "target": "cpu"}]
        iso = canonical_bytes(changed)
        objects = _objects(iso)
        request = module.current_object_request(objects, sim_id="sim",
            isolation_evidence_bytes=iso, policy=policy)
        result = strict_json_loads(_build(module, request, objects, iso, policy).decode())["result"]
        assert result["status"] == "UNKNOWN", result
    module, request, objects, iso, policy = _fixture()
    absent = _build(module, request, objects, None, policy)
    assert strict_json_loads(absent.decode())["result"]["status"] == "UNKNOWN"


def test_rehashed_forgery_and_external_policy_substitution_are_rejected():
    module, request, objects, iso, policy = _fixture()
    certificate = _build(module, request, objects, iso, policy)
    forged = strict_json_loads(certificate.decode())
    forged["result"]["status"] = "FAIL"
    forged["digest"] = "sha256:" + canonical_digest({k: v for k, v in forged.items() if k != "digest"})
    with pytest.raises(module.CurrentObjectGroundingError, match="does not reproduce"):
        module.recheck_current_object_certificate(canonical_bytes(forged),
            expected_request=request, policy=policy)
    new_policy = dict(policy, trust_roots=["different-external-selector"])
    with pytest.raises(module.CurrentObjectGroundingError):
        module.recheck_current_object_certificate(certificate,
            expected_request=request, policy=new_policy)
    with pytest.raises(module.CurrentObjectGroundingError):
        _build(module, request, objects, iso, new_policy)
    wrong_mechanism = dict(policy, mechanism_digest="sha256:" + "0" * 64)
    with pytest.raises(module.CurrentObjectGroundingError, match="installed"):
        _build(module, request, objects, iso, wrong_mechanism)


def test_selected_limits_and_result_are_bound_to_exact_request():
    module, request, objects, iso, policy = _fixture()
    certificate = _build(module, request, objects, iso, policy)
    new_request = deepcopy(request)
    new_request["limits"]["max_isolation_operations"] += 1
    with pytest.raises(module.CurrentObjectGroundingError, match="request"):
        module.recheck_current_object_certificate(certificate,
            expected_request=new_request, policy=policy)
    tiny = deepcopy(request)
    tiny["limits"]["max_isolation_operations"] = 1
    result = strict_json_loads(_build(module, tiny, objects, iso, policy).decode())["result"]
    assert result["status"] == "UNKNOWN"


def test_collection_snapshot_ignores_mutation_after_capture(monkeypatch):
    module, request, objects, iso, policy = _fixture()
    original = module._capture_objects
    def mutate_after_capture(items, limits):
        result = original(items, limits)
        items.append(NamespaceObject.create("late", "OBJECT", {}))
        return result
    monkeypatch.setattr(module, "_capture_objects", mutate_after_capture)
    certificate = _build(module, request, objects, iso, policy)
    assert strict_json_loads(certificate.decode())["result"]["status"] == "PASS"
    assert len(objects) == 6
    assert module.recheck_current_object_certificate(certificate,
        expected_request=request, policy=policy)["status"] == "PASS"


def test_large_collection_is_refused_before_canonical_serialization(monkeypatch):
    module, request, _, iso, policy = _fixture({**_candidate().DEFAULT_LIMITS,
        "max_collection_bytes": 1024 * 1024})
    huge = [NamespaceObject.create("one", "OBJECT", {"text": "x" * 700000}),
            NamespaceObject.create("two", "OBJECT", {"text": "y" * 700000})]
    original = module.canonical_bytes
    def guarded(value):
        if type(value) is dict and value.get("schema_version") == module.COLLECTION_VERSION:
            raise AssertionError("unbounded collection reached canonical serialization")
        return original(value)
    monkeypatch.setattr(module, "canonical_bytes", guarded)
    with pytest.raises(Unavailable, match="before serialization"):
        _build(module, request, huge, iso, policy)


def test_large_certificate_is_refused_before_json_parser(monkeypatch):
    module, request, _, _, policy = _fixture()
    def forbidden(_):
        raise AssertionError("oversized certificate reached parser")
    monkeypatch.setattr(module, "strict_json_loads", forbidden)
    with pytest.raises(module.CurrentObjectGroundingError, match="byte bound"):
        module.recheck_current_object_certificate(b"x" * (policy["max_certificate_bytes"] + 1),
            expected_request=request, policy=policy)


def test_typed_graph_substitution_and_generic_retyping_are_distinct():
    module, _, objects, iso, policy = _fixture()
    graph = NamespaceObject.create("env-graph", "GRAPH", {"element_kind": "ENV"},
        {"members": ["env"]})
    replacement = NamespaceObject.create("sim", "SIM", objects[-1].payload,
        {"data": ["data"], "verifier": ["verifier"], "objects": ["room"], "env": ["env-graph"]})
    good = [*objects[:-1], graph, replacement]
    selected = module.current_object_request(good, sim_id="sim",
        isolation_evidence_bytes=iso, policy=policy)
    assert strict_json_loads(_build(module, selected, good, iso, policy).decode())["result"]["status"] == "PASS"
    generic = NamespaceObject.create("env-graph", "GRAPH", {"element_kind": "OBJECT"},
        {"members": ["env"]})
    bad = [*objects[:-1], generic, replacement]
    selected_bad = module.current_object_request(bad, sim_id="sim",
        isolation_evidence_bytes=iso, policy=policy)
    result = strict_json_loads(_build(module, selected_bad, bad, iso, policy).decode())["result"]
    assert result["status"] == "FAIL"


@pytest.mark.parametrize("mutation", ["dangling", "duplicate", "cycle", "wrong_kind"])
def test_invalid_complete_collection_is_refuted(mutation):
    module, _, objects, iso, policy = _fixture()
    changed = list(objects)
    if mutation == "dangling":
        changed[-1] = NamespaceObject.create("sim", "SIM", objects[-1].payload,
            {"data": ["missing"], "verifier": ["verifier"], "objects": ["room"], "env": ["env"]})
    elif mutation == "duplicate":
        changed.append(objects[0])
    elif mutation == "cycle":
        changed.append(NamespaceObject.create("cycle", "GRAPH", {"element_kind": "OBJECT"},
            {"members": ["cycle"]}))
    else:
        changed[-1] = NamespaceObject.create("sim", "SIM", objects[-1].payload,
            {"data": ["env"], "verifier": ["verifier"], "objects": ["room"], "env": ["env"]})
    selected = module.current_object_request(changed, sim_id="sim",
        isolation_evidence_bytes=iso, policy=policy)
    result = strict_json_loads(_build(module, selected, changed, iso, policy).decode())["result"]
    assert result["status"] == "FAIL", result


def test_rehashed_evidence_payload_substitution_is_rejected_on_recheck():
    module, request, objects, iso, policy = _fixture()
    carried = strict_json_loads(_build(module, request, objects, iso, policy).decode())
    ref = carried["evidence_refs"][1]
    carried["evidence_payloads"][ref] = "eA=="  # Valid base64, wrong bound bytes.
    carried["digest"] = "sha256:" + canonical_digest({k: v for k, v in carried.items() if k != "digest"})
    with pytest.raises(module.CurrentObjectGroundingError, match="evidence"):
        module.recheck_current_object_certificate(canonical_bytes(carried),
            expected_request=request, policy=policy)


def test_request_selected_other_collection_is_refuted_not_promoted():
    module, request, objects, iso, policy = _fixture()
    changed = dict(request, collection_digest="sha256:" + "0" * 64)
    result = strict_json_loads(_build(module, changed, objects, iso, policy).decode())["result"]
    assert result["status"] == "FAIL"


def test_model_law_scope_does_not_infer_host_containment_or_authority():
    module, request, objects, iso, policy = _fixture()
    result = strict_json_loads(_build(module, request, objects, iso, policy).decode())["result"]
    assert result["status"] == "PASS"
    assert result["scope"] == "finite_declared_capability_effect_confinement"
    for field in ("physical_host_containment", "authority", "sim_tier_5_conformance",
                  "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"


def test_outer_objective_rejects_a_contradictory_inner_scope(monkeypatch):
    module, request, objects, iso, policy = _fixture()
    original = module.isolation_module.assess_sim_isolation
    def changed_scope(*args, **kwargs):
        assessment = original(*args, **kwargs)
        assessment["physical_host_containment"] = "ESTABLISHED"
        assessment["assessment_digest"] = module.common_module.digest({
            key: value for key, value in assessment.items() if key != "assessment_digest"})
        return assessment
    monkeypatch.setattr(module.isolation_module, "assess_sim_isolation", changed_scope)
    result = strict_json_loads(_build(module, request, objects, iso, policy).decode())["result"]
    assert result["status"] == "FAIL"
    assert "scope or binding" in result["evaluation"]["details"]


def test_normative_candidate_states_the_exact_versioned_proposition():
    module = _candidate()
    document = Path(__file__).resolve().parents[1] / "src/verifier/standard/CURRENT_OBJECT_GROUNDING.md"
    text = document.read_text(encoding="utf-8-sig")
    assert module.PROPOSITION in text
    assert module.SEMANTIC_VERSION in text
    assert "not the legacy `SIM-5.1` mainstay-binding" in text


def test_request_and_limits_use_the_values_validated_before_caller_mutation(monkeypatch):
    module, request, objects, iso, policy = _fixture()
    original_limit = request["limits"]["max_isolation_operations"]
    original_digest = module._digest
    def mutate_after_digest(value, label):
        checked = original_digest(value, label)
        if label == "policy_digest":
            request["semantic_version"] = "verifier-domain-obligations-1"
            request["limits"]["max_isolation_operations"] = 1
        return checked
    monkeypatch.setattr(module, "_digest", mutate_after_digest)
    certificate = _build(module, request, objects, iso, policy)
    carried = strict_json_loads(certificate.decode())
    assert carried["request"]["semantic_version"] == module.SEMANTIC_VERSION
    assert carried["request"]["limits"]["max_isolation_operations"] == original_limit
    assert carried["result"]["status"] == "PASS"


def test_policy_copies_validated_fields_before_source_digest_callback(monkeypatch):
    module, _, _, _, policy = _fixture()
    original_digest = policy["mechanism_digest"]
    original_roots = list(policy["trust_roots"])
    def mutate_during_source_digest():
        policy["schema_version"] = "verifier-domain-policy-1"
        policy["mechanism_digest"] = "sha256:" + "0" * 64
        policy["trust_roots"][:] = ["unselected-root"]
        return original_digest
    monkeypatch.setattr(module, "mechanism_digest", mutate_during_source_digest)
    accepted = module._policy(policy)
    assert accepted["schema_version"] == module.POLICY_VERSION
    assert accepted["mechanism_digest"] == original_digest
    assert accepted["trust_roots"] == original_roots


def test_shape_refusal_precedes_hashing_or_copying_unexpected_keys(monkeypatch):
    import builtins
    module = _candidate()
    fields = {"only"}
    value = {"first": 1, "second": 2}
    original_set = builtins.set
    def forbidden_set(*args, **kwargs):
        raise AssertionError("set conversion happened before length rejection")
    monkeypatch.setattr(builtins, "set", forbidden_set)
    try:
        try:
            module._mapping(value, fields, "bounded record")
        except module.CurrentObjectGroundingError as exc:
            assert "fields differ" in str(exc)
        else:
            raise AssertionError("oversized known-field record was accepted")
    finally:
        monkeypatch.setattr(builtins, "set", original_set)


def test_whitespace_only_policy_root_is_rejected():
    module, _, _, _, policy = _fixture()
    bad = dict(policy, trust_roots=["   "])
    with pytest.raises(module.CurrentObjectGroundingError, match="trust roots"):
        module._policy(bad)


def test_request_helper_rejects_nonplain_limits_before_iterating_them():
    module, _, objects, iso, policy = _fixture()
    class HostileLimits:
        def __iter__(self):
            raise AssertionError("arbitrary limits mapping was iterated before type and bound check")
    with pytest.raises(module.CurrentObjectGroundingError, match="limits"):
        module.current_object_request(objects, sim_id="sim", isolation_evidence_bytes=iso,
            policy=policy, limits=HostileLimits())


def test_policy_helper_rejects_large_root_source_before_copying_it():
    module = _candidate()
    class HostileRoots:
        def __len__(self):
            return 1000000
        def __iter__(self):
            raise AssertionError("large root source was iterated before bound check")
    with pytest.raises(module.CurrentObjectGroundingError, match="trust roots"):
        module.current_object_policy(trust_roots=HostileRoots())


@pytest.mark.parametrize("base", [list, tuple])
def test_collection_subclass_is_refused_before_custom_iteration(base):
    module, request, objects, iso, policy = _fixture()

    class IteratorBomb(base):
        def __iter__(self):
            raise AssertionError("caller iteration before bounded capture")

    with pytest.raises(module.CurrentObjectGroundingError, match="plain finite sequence"):
        _build(module, request, IteratorBomb(objects), iso, policy)
