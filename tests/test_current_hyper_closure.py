"""Current HYPER closure tests: finite representation, not world closure."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import base64
import hashlib
import importlib
import importlib.util
import json
import sys

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import EvidenceStore
from verifier.core.namespace import NamespaceObject, assess_composition, composition_digest
from verifier.domains.common import Refuted, Unavailable


def candidate():
    name = "verifier.domains.contracts.hyper_closure"
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
    path = Path(__file__).resolve().parents[1] / "src/verifier/domains/contracts/hyper_closure.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def specimen():
    make = NamespaceObject.create
    return [make("t", "TIME", {}), make("s", "SPACE", {}), make("meaning", "OBJECT", {}),
            make("d", "DATA", {}),
            make("e", "EVENT", {}, {"time": ["t"], "space": ["s"], "meaning": ["meaning"]}),
            make("h", "HYPER", {}, {"event": ["e"], "input": ["d"]})]


def selection(objects=None):
    module = candidate()
    objects = specimen() if objects is None else objects
    policy = module.hyper_closure_policy(trust_roots=["independent-local-policy"])
    request = module.hyper_closure_request(objects, hyper_id="h", policy=policy)
    return module, objects, request, policy


def certify(module, objects, request, policy):
    encoded = module.build_hyper_closure_certificate(request, objects, policy=policy)
    return encoded, module.recheck_hyper_closure_certificate(
        encoded, expected_request=request, policy=policy)


def rehash(value):
    value = deepcopy(value)
    value.pop("digest")
    value["digest"] = "sha256:" + canonical_digest(value)
    return canonical_bytes(value)


def test_current_hyper_closure_route_exists():
    module = candidate()
    assert callable(module.build_hyper_closure_certificate)


def test_exact_mixed_kind_cone_passes_and_replays_with_narrow_scope():
    module, objects, request, policy = selection()
    encoded, result = certify(module, objects, request, policy)
    envelope = json.loads(encoded)
    assert result["status"] == "PASS"
    assert result["scope"] == "finite_declared_hyper_operand_closure"
    assert result["evaluation"]["observations"]["members_checked"] == 6
    assert envelope["request"] == request
    assert envelope["evidence_ref"] in envelope["evidence_payloads"]
    for key in ("hyper_tier_4_conformance", "object_profile_conformance", "mathematical_closure",
                "physical_completeness", "privacy", "consent", "governance", "authority"):
        assert result[key] == "NOT_ESTABLISHED"


def test_collection_order_does_not_change_exact_certificate_bytes():
    module, objects, request, policy = selection()
    orders = [objects, list(reversed(objects)), objects[2:] + objects[:2],
              objects[1::2] + objects[::2]]
    certificates = [module.build_hyper_closure_certificate(request, order, policy=policy)
                    for order in orders]
    assert certificates.count(certificates[0]) == len(certificates)
    assert module.recheck_hyper_closure_certificate(
        certificates[0], expected_request=request, policy=policy)["status"] == "PASS"


def test_extra_unrelated_token_refutes_exact_cone_even_though_composition_passes():
    objects = specimen() + [NamespaceObject.create("unrelated", "TOKEN", {})]
    assert assess_composition(objects, expected_digest=composition_digest(objects)).verdict.value == "PASS"
    module, objects, request, policy = selection(objects)
    _encoded, result = certify(module, objects, request, policy)
    assert result["status"] == "FAIL"
    assert "unrelated" in result["evaluation"]["details"]


def rebound(module, request, objects):
    """Retain the same selected proposition but bind a modified candidate collection."""
    selected = deepcopy(request)
    captured, encoded = module._capture_collection(objects, selected["limits"])
    selected["collection_digest"] = composition_digest(captured)
    selected["evidence_ref"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    root = next((item for item in captured if item.object_id == "h"), None)
    if root is not None:
        selected["object_digest"] = root.digest
    return selected


@pytest.mark.parametrize("change", ["missing", "duplicate", "cycle", "wrong_event_kind", "wrong_graph_leaf"])
def test_refutes_missing_duplicate_cycle_or_wrong_typed_operands(change):
    module, original, request, policy = selection()
    objects = list(original)
    make = NamespaceObject.create
    if change == "missing":
        objects = [item for item in objects if item.object_id != "t"]
    elif change == "duplicate":
        objects.append(make("d", "DATA", {}))
    elif change == "cycle":
        objects[-1] = make("h", "HYPER", {}, {"self": ["h"], "event": ["e"]})
    elif change == "wrong_event_kind":
        objects[4] = make("e", "EVENT", {}, {"time": ["d"], "space": ["s"], "meaning": ["meaning"]})
    else:
        objects[5] = make("h", "HYPER", {}, {"members": ["g"]})
        objects.append(make("g", "GRAPH", {"element_kind": "DATA"}, {"members": ["t", "d"]}))
    selected = rebound(module, request, objects)
    _encoded, result = certify(module, objects, selected, policy)
    assert result["status"] == "FAIL"
    assert result["hyper_tier_4_conformance"] == "NOT_ESTABLISHED"


def test_substituted_payload_or_operand_order_changes_object_and_collection_binding():
    module, objects, request, policy = selection()
    changed = list(objects)
    changed[3] = NamespaceObject.create("d", "DATA", {"payload": "changed"})
    with pytest.raises(Refuted):
        module.build_hyper_closure_certificate(request, changed, policy=policy)
    reordered = list(objects)
    reordered[-1] = NamespaceObject.create("h", "HYPER", {}, {"members": ["d", "e"]})
    reverse_order = list(objects)
    reverse_order[-1] = NamespaceObject.create("h", "HYPER", {}, {"members": ["e", "d"]})
    first = module.hyper_closure_request(reordered, hyper_id="h", policy=policy)
    second = module.hyper_closure_request(reverse_order, hyper_id="h", policy=policy)
    assert first["object_digest"] != second["object_digest"]
    assert first["collection_digest"] != second["collection_digest"]
    assert first["cone_digest"] != second["cone_digest"]


@pytest.mark.parametrize("field", ["status", "authority", "hyper_tier_4_conformance", "cone_digest"])
def test_rehashed_result_forgery_rejected_by_full_replay(field):
    module, objects, request, policy = selection()
    encoded, _ = certify(module, objects, request, policy)
    value = json.loads(encoded)
    value["result"][field] = "PASS" if field != "status" else "FAIL"
    with pytest.raises(module.CurrentHyperClosureError):
        module.recheck_hyper_closure_certificate(rehash(value), expected_request=request, policy=policy)


@pytest.mark.parametrize("field", ["semantic_version", "coordinate", "proposition_digest", "cone_digest", "object_digest", "collection_digest", "evidence_ref"])
def test_external_request_substitution_cannot_select_another_claim(field):
    module, objects, request, policy = selection()
    encoded, _ = certify(module, objects, request, policy)
    altered = deepcopy(request)
    altered[field] = "legacy-or-other" if field in {"semantic_version", "coordinate"} else "sha256:" + "0" * 64
    with pytest.raises(module.CurrentHyperClosureError):
        module.recheck_hyper_closure_certificate(encoded, expected_request=altered, policy=policy)


def test_external_policy_substitution_and_self_selected_policy_are_rejected():
    module, objects, request, policy = selection()
    encoded, _ = certify(module, objects, request, policy)
    alternate = module.hyper_closure_policy(trust_roots=["another-root"])
    with pytest.raises(module.CurrentHyperClosureError):
        module.recheck_hyper_closure_certificate(encoded, expected_request=request, policy=alternate)
    changed = json.loads(encoded)
    changed["policy_digest"] = "sha256:" + canonical_digest(alternate)
    with pytest.raises(module.CurrentHyperClosureError):
        module.recheck_hyper_closure_certificate(rehash(changed), expected_request=request, policy=policy)
    forged_mechanism = deepcopy(policy)
    forged_mechanism["mechanism_digest"] = "sha256:" + "0" * 64
    with pytest.raises(module.CurrentHyperClosureError):
        module.build_hyper_closure_certificate(request, objects, policy=forged_mechanism)


def test_missing_or_substituted_retained_evidence_cannot_replay_pass():
    module, objects, request, policy = selection()
    encoded, _ = certify(module, objects, request, policy)
    missing = json.loads(encoded)
    missing["evidence_payloads"] = {}
    with pytest.raises(module.CurrentHyperClosureError):
        module.recheck_hyper_closure_certificate(rehash(missing), expected_request=request, policy=policy)
    substituted = json.loads(encoded)
    ref = request["evidence_ref"]
    substituted["evidence_payloads"][ref] = base64.b64encode(b"{} ").decode("ascii")
    with pytest.raises(module.CurrentHyperClosureError):
        module.recheck_hyper_closure_certificate(rehash(substituted), expected_request=request, policy=policy)


def test_absent_retained_evidence_is_replayable_unknown_not_pass():
    module, _objects, request, policy = selection()
    certificate = module._build(request, policy, EvidenceStore())
    result = module.recheck_hyper_closure_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN"
    assert result["hyper_tier_4_conformance"] == "NOT_ESTABLISHED"


def test_certificate_retains_full_private_payload_without_emission_authority():
    module = candidate()
    objects = [NamespaceObject.create("sensitive", "OBJECT", {"private": "canary-secret"}),
               NamespaceObject.create("h", "HYPER", {}, {"subject": ["sensitive"]})]
    policy = module.hyper_closure_policy(trust_roots=["independent-local-policy"])
    request = module.hyper_closure_request(objects, hyper_id="h", policy=policy)
    encoded, result = certify(module, objects, request, policy)
    payload = json.loads(encoded)["evidence_payloads"][request["evidence_ref"]]
    assert b"canary-secret" in base64.b64decode(payload)
    assert result["privacy"] == result["consent"] == result["governance"] == "NOT_ESTABLISHED"


def test_declared_graph_closure_can_include_consistent_typed_graph():
    module = candidate()
    make = NamespaceObject.create
    objects = [make("d1", "DATA", {}), make("d2", "DATA", {}),
               make("g", "GRAPH", {"element_kind": "DATA"}, {"members": ["d1", "d2"]}),
               make("h", "HYPER", {}, {"data_graph": ["g"]})]
    policy = module.hyper_closure_policy(trust_roots=["independent-local-policy"])
    request = module.hyper_closure_request(objects, hyper_id="h", policy=policy)
    _encoded, result = certify(module, objects, request, policy)
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["members_checked"] == 4


def test_missing_budget_is_unknown_with_replay_not_a_tier_pass():
    module, objects, request, policy = selection()
    limited = deepcopy(request)
    limited["limits"]["max_closure_operations"] = 1
    _encoded, result = certify(module, objects, limited, policy)
    assert result["status"] == "UNKNOWN"
    assert result["hyper_tier_4_conformance"] == "NOT_ESTABLISHED"


def test_pre_serialization_object_bound_and_reference_bound(monkeypatch):
    module, objects, request, policy = selection()
    def forbidden(_value):
        raise AssertionError("whole collection serialized before bound")
    monkeypatch.setattr(module, "canonical_bytes", forbidden)
    low_items = deepcopy(request)
    low_items["limits"]["max_objects"] = 5
    with pytest.raises(Unavailable):
        module.build_hyper_closure_certificate(low_items, objects, policy=policy)
    low_refs = deepcopy(request)
    low_refs["limits"]["max_reference_bytes"] = 1
    with pytest.raises(Unavailable):
        module.build_hyper_closure_certificate(low_refs, objects, policy=policy)


def test_escaped_reference_bytes_are_charged_before_whole_collection_serialization(monkeypatch):
    module = candidate()
    target = '"' * 100
    objects = [NamespaceObject.create(target, "OBJECT", {}),
               NamespaceObject.create("h", "HYPER", {}, {"item": [target]})]
    limits = dict(module.DEFAULT_LIMITS, max_reference_bytes=250)
    def forbidden(_value):
        raise AssertionError("whole collection serialization preceded escaped-reference budget")
    monkeypatch.setattr(module, "canonical_bytes", forbidden)
    with pytest.raises(Unavailable):
        module._capture_collection(objects, limits)


class HostileList(list):
    def __len__(self):
        raise AssertionError("hostile length called")
    def __iter__(self):
        raise AssertionError("hostile iterator called")
    def __contains__(self, _item):
        raise AssertionError("hostile membership called")
    def __eq__(self, _other):
        raise AssertionError("hostile equality called")


class HostileTuple(tuple):
    def __len__(self):
        raise AssertionError("hostile length called")
    def __iter__(self):
        raise AssertionError("hostile iterator called")
    def __contains__(self, _item):
        raise AssertionError("hostile membership called")
    def __eq__(self, _other):
        raise AssertionError("hostile equality called")


class HostileDict(dict):
    def __len__(self):
        raise AssertionError("hostile length called")
    def __iter__(self):
        raise AssertionError("hostile iterator called")
    def __contains__(self, _item):
        raise AssertionError("hostile membership called")
    def __eq__(self, _other):
        raise AssertionError("hostile equality called")


class HostileText(str):
    def __eq__(self, _other):
        raise AssertionError("hostile text equality called")


@pytest.mark.parametrize("container", [HostileList, HostileTuple])
def test_hostile_sequence_subclass_rejected_before_len_iter_or_contains(container):
    module, objects, request, policy = selection()
    with pytest.raises(module.CurrentHyperClosureError):
        module.build_hyper_closure_certificate(request, container(objects), policy=policy)
    with pytest.raises(module.CurrentHyperClosureError):
        module.hyper_closure_policy(trust_roots=container(["root"]))


def test_hostile_dict_subclass_rejected_before_len_iter_or_contains():
    module, objects, request, policy = selection()
    with pytest.raises(module.CurrentHyperClosureError):
        module.build_hyper_closure_certificate(HostileDict(request), objects, policy=policy)
    with pytest.raises(module.CurrentHyperClosureError):
        module.build_hyper_closure_certificate(request, objects, policy=HostileDict(policy))
    with pytest.raises(module.CurrentHyperClosureError):
        module.hyper_closure_request(objects, hyper_id="h", policy=policy, limits=HostileDict(request["limits"]))


@pytest.mark.parametrize("surface,field", [("request", "schema_version"),
                                           ("request", "semantic_version"),
                                           ("policy", "schema_version"),
                                           ("policy", "mechanism_id")])
def test_hostile_scalar_subclass_rejected_before_equality(surface, field):
    module, objects, request, policy = selection()
    selected = deepcopy(request)
    admitted = deepcopy(policy)
    if surface == "request":
        selected[field] = HostileText(selected[field])
    else:
        admitted[field] = HostileText(admitted[field])
    with pytest.raises(module.CurrentHyperClosureError):
        module.build_hyper_closure_certificate(selected, objects, policy=admitted)


def test_mutation_of_caller_list_after_capture_cannot_change_checked_evidence(monkeypatch):
    module, objects, request, policy = selection()
    expected_ref = request["evidence_ref"]
    actual_capture = module._capture_collection
    def mutate_after_capture(submitted, limits):
        captured, encoded = actual_capture(submitted, limits)
        objects[-1] = NamespaceObject.create("h", "HYPER", {}, {"input": ["d"]})
        return captured, encoded
    monkeypatch.setattr(module, "_capture_collection", mutate_after_capture)
    encoded, result = certify(module, objects, request, policy)
    assert result["status"] == "PASS"
    assert json.loads(encoded)["evidence_ref"] == expected_ref


def test_mutated_frozen_record_after_reference_callback_cannot_change_snapshot(monkeypatch):
    module = candidate()
    objects = list(reversed(specimen()))
    root = objects[0]
    original_bytes = module._capture_collection(objects, module.DEFAULT_LIMITS)[1]
    real = module.certificate_module.canonical_bytes
    changed = False
    def mutate_after_field_capture(value):
        nonlocal changed
        if value == "h" and not changed:
            changed = True
            object.__setattr__(root, "payload_bytes", canonical_bytes({"tampered": True}))
        return real(value)
    monkeypatch.setattr(module.certificate_module, "canonical_bytes", mutate_after_field_capture)
    _captured, encoded = module._capture_collection(objects, module.DEFAULT_LIMITS)
    assert changed
    assert encoded == original_bytes


def test_request_and_policy_are_snapshotted_before_digest_callbacks(monkeypatch):
    module, objects, request, policy = selection()
    raw_request = deepcopy(request)
    original_digest = module._digest
    def mutate_request(value, label):
        if label == "policy_digest":
            raw_request["semantic_version"] = "legacy"
            raw_request["limits"]["max_objects"] = 1
        return original_digest(value, label)
    monkeypatch.setattr(module, "_digest", mutate_request)
    encoded = module.build_hyper_closure_certificate(raw_request, objects, policy=policy)
    assert json.loads(encoded)["result"]["status"] == "PASS"
    monkeypatch.setattr(module, "_digest", original_digest)
    raw_policy = deepcopy(policy)
    original_mechanism = module.mechanism_digest
    def mutate_policy():
        raw_policy["schema_version"] = "legacy"
        raw_policy["trust_roots"].append("other")
        return original_mechanism()
    monkeypatch.setattr(module, "mechanism_digest", mutate_policy)
    encoded = module.build_hyper_closure_certificate(request, objects, policy=raw_policy)
    assert json.loads(encoded)["result"]["status"] == "PASS"


def test_whitespace_only_trust_root_rejected_and_documented_claim_is_exact():
    module = candidate()
    with pytest.raises(module.CurrentHyperClosureError):
        module.hyper_closure_policy(trust_roots=["  "])
    spec = (Path(__file__).resolve().parents[1] / "src/verifier/standard/CURRENT_HYPER_CLOSURE.md").read_text(encoding="utf-8")
    assert module.PROPOSITION in " ".join(spec.split())
    assert "Saturation" in spec and "verifier-domain-obligations-1" in spec


def test_noncanonical_certificate_and_duplicate_json_keys_rejected():
    module, objects, request, policy = selection()
    encoded, _ = certify(module, objects, request, policy)
    with pytest.raises(module.CurrentHyperClosureError):
        module.recheck_hyper_closure_certificate(encoded + b" ", expected_request=request, policy=policy)
    repeated = b'{"schema_version":1,"schema_version":2}'
    with pytest.raises(ValueError):
        module._parse_collection(repeated, request["limits"])


def test_certificate_byte_bound_is_checked_before_parser(monkeypatch):
    module, objects, request, policy = selection()
    encoded, _ = certify(module, objects, request, policy)
    narrow = deepcopy(policy)
    narrow["max_certificate_bytes"] = 1
    def forbidden(_bytes):
        raise AssertionError("certificate parser ran before byte bound")
    monkeypatch.setattr(module, "strict_json_loads", forbidden)
    with pytest.raises(module.CurrentHyperClosureError):
        module.recheck_hyper_closure_certificate(encoded, expected_request=request, policy=narrow)
