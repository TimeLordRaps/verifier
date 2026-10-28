"""Refutable gates for the current generic object representation objective.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, ObjectKind, assess_composition, composition_digest
from verifier.core.receipt import strict_json_loads
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import object_facets


def candidate():
    return object_facets


def test_current_object_facets_route_exists():
    module = candidate()
    assert callable(module.build_object_facets_certificate)
    assert callable(module.recheck_object_facets_certificate)


LITERAL_RECORD = b'{"kind":"OBJECT","object_id":"node","operands":{},"payload":{"x":1}}'
LITERAL_RECORD_DIGEST = "sha256:e97809ebe6d32449be955bbadada3ab8ece5d78bc87a55f90f0eefb2eaa3eb55"
LITERAL_PAYLOAD_DIGEST = "sha256:5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22"
LITERAL_OPERANDS_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
LITERAL_ADDRESS_DIGEST = "sha256:6a12dec37d406ca24eb49c70107314d29df1983494ddb9bdc1835b09bde40b8c"


def fixture(item=None, limits=None):
    module = candidate()
    item = item or NamespaceObject.create("node", "OBJECT", {"x": 1})
    policy = module.object_facets_policy(trust_roots=("independent-local-selector",))
    request = module.object_facets_request(item, policy=policy, limits=limits)
    record_bytes = canonical_bytes(item.to_dict())
    return module, item, policy, request, record_bytes


def _rehashed(value):
    value["digest"] = "sha256:" + canonical_digest({key: item for key, item in value.items() if key != "digest"})
    return canonical_bytes(value)


def test_literal_record_and_address_have_independent_byte_hash_oracles():
    module, item, policy, request, record_bytes = fixture()
    assert record_bytes == LITERAL_RECORD
    assert hashlib.sha256(LITERAL_RECORD).hexdigest() == LITERAL_RECORD_DIGEST.removeprefix("sha256:")
    assert item.digest == request["record_digest"] == request["evidence_ref"] == LITERAL_RECORD_DIGEST
    assert request["payload_digest"] == LITERAL_PAYLOAD_DIGEST
    assert request["operands_digest"] == LITERAL_OPERANDS_DIGEST
    assert request["address_digest"] == LITERAL_ADDRESS_DIGEST
    assert request["coordinate"] == "OBJECT-1.1"
    assert request["semantic_version"] == "verifier-current-object-obligations-1"


def test_positive_generic_object_certificate_replays_exact_bytes_without_tier_promotion():
    module, item, policy, request, record_bytes = fixture()
    selected_request, selected_policy = deepcopy(request), deepcopy(policy)
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    carried = strict_json_loads(certificate.decode("utf-8"))
    result = module.recheck_object_facets_certificate(certificate,
        expected_request=selected_request, policy=selected_policy)
    assert result == carried["result"]
    assert result["status"] == "PASS"
    assert result["scope"] == "generic_canonical_representation_and_address"
    assert result["kind_specific_tier_1_conformance"] == "NOT_ESTABLISHED"
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["issued_receipt"] == result["execution"] == result["authority"] == "NOT_ESTABLISHED"
    assert base64.b64decode(carried["evidence_payloads"][request["evidence_ref"]]) == LITERAL_RECORD
    assert carried["proposition_digest"] == module.PROPOSITION_DIGEST


def test_generic_actor_representation_does_not_establish_actor_facets_or_human_root():
    actor = NamespaceObject.create("actor", "ACTOR", {"description": "only representation"})
    module, _, policy, request, record_bytes = fixture(actor)
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    result = module.recheck_object_facets_certificate(certificate,
        expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert result["object_kind"] == "ACTOR"
    assert result["coordinate"] == "OBJECT-1.1"
    assert result["kind_specific_tier_1_conformance"] == "NOT_ESTABLISHED"
    typed = assess_composition([actor], expected_digest=composition_digest([actor]))
    assert typed.verdict.value == "FAIL"


def test_generic_operand_map_is_retained_without_claiming_reference_resolution():
    item = NamespaceObject.create("relation", "HYPER", {}, {"named": ["unbound"]})
    module, _, policy, request, record_bytes = fixture(item)
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    assert module.recheck_object_facets_certificate(certificate,
        expected_request=request, policy=policy)["status"] == "PASS"
    assert assess_composition([item], expected_digest=composition_digest([item])).verdict.value == "FAIL"


@pytest.mark.parametrize("limit_name", ["max_operations", "max_reference_bytes"])
def test_externally_selected_retained_record_budget_is_replayed_as_unknown(limit_name):
    item = NamespaceObject.create("node", "HYPER", {}, {"member": ["dangling"]})
    module, _, policy, request, encoded = fixture(item)
    selected = dict(request, limits=dict(request["limits"], **{limit_name: 1}))
    certificate = module.build_object_facets_certificate(selected, encoded, policy=policy)
    carried = strict_json_loads(certificate.decode("utf-8"))
    assert carried["result"]["status"] == "UNKNOWN"
    assert module.recheck_object_facets_certificate(certificate,
        expected_request=selected, policy=policy)["status"] == "UNKNOWN"


@pytest.mark.parametrize("selected_operations,expected_status", [(3, "PASS"), (2, "UNKNOWN")])
def test_retained_operation_budget_exact_boundary_replays(selected_operations, expected_status):
    item = NamespaceObject.create("node", "HYPER", {}, {"member": ["dangling"]})
    module, _, policy, request, encoded = fixture(item)
    assert 1 + len(item.operands) + sum(len(targets) for _, targets in item.operands) == 3
    selected = dict(request, limits=dict(request["limits"], max_operations=selected_operations))
    certificate = module.build_object_facets_certificate(selected, encoded, policy=policy)
    assert strict_json_loads(certificate.decode("utf-8"))["result"]["status"] == expected_status
    assert module.recheck_object_facets_certificate(certificate,
        expected_request=selected, policy=policy)["status"] == expected_status


@pytest.mark.parametrize("selected_reference_bytes,expected_status", [(24, "PASS"), (23, "UNKNOWN")])
def test_retained_escaped_reference_byte_budget_exact_boundary_replays(selected_reference_bytes, expected_status):
    identifier = '"' * 8
    item = NamespaceObject.create(identifier, "HYPER", {}, {"r": ["t"]})
    module, _, policy, request, encoded = fixture(item)
    assert len(canonical_bytes(identifier)) == 18  # Eight escaped quotes plus JSON quotes.
    assert len(canonical_bytes(identifier)) + len(canonical_bytes("r")) + len(canonical_bytes("t")) == 24
    selected = dict(request, limits=dict(request["limits"], max_reference_bytes=selected_reference_bytes))
    certificate = module.build_object_facets_certificate(selected, encoded, policy=policy)
    assert strict_json_loads(certificate.decode("utf-8"))["result"]["status"] == expected_status
    assert module.recheck_object_facets_certificate(certificate,
        expected_request=selected, policy=policy)["status"] == expected_status


@pytest.mark.parametrize("limit_name", ["max_operations", "max_reference_bytes"])
def test_retained_budget_exhaustion_precedes_whole_record_canonicalization(monkeypatch, limit_name):
    item = NamespaceObject.create("node", "HYPER", {}, {"member": ["dangling"]})
    module, _, policy, request, encoded = fixture(item)
    selected = dict(request, limits=dict(request["limits"], **{limit_name: 1}))
    original = module.canonical_bytes

    def trap(value):
        if type(value) is dict and set(value) == {"object_id", "kind", "payload", "operands"}:
            raise AssertionError("whole retained record canonicalized after budget exhaustion")
        return original(value)

    monkeypatch.setattr(module, "canonical_bytes", trap)
    certificate = module.build_object_facets_certificate(selected, encoded, policy=policy)
    assert strict_json_loads(certificate.decode("utf-8"))["result"]["status"] == "UNKNOWN"
    assert module.recheck_object_facets_certificate(certificate,
        expected_request=selected, policy=policy)["status"] == "UNKNOWN"


def test_payload_and_role_insertion_order_does_not_change_canonical_evidence():
    first = NamespaceObject.create("node", "HYPER", {"b": 2, "a": 1}, {"z": ["b"], "a": ["c"]})
    second = NamespaceObject.create("node", "HYPER", {"a": 1, "b": 2}, {"a": ["c"], "z": ["b"]})
    module, _, policy, request, encoded = fixture(first)
    assert canonical_bytes(second.to_dict()) == encoded
    assert module.object_facets_request(second, policy=policy) == request
    first_certificate = module.build_object_facets_certificate(request, encoded, policy=policy)
    second_certificate = module.build_object_facets_certificate(request,
        canonical_bytes(second.to_dict()), policy=policy)
    assert first_certificate == second_certificate


@pytest.mark.parametrize("identifier,role,target", [
    ("plain", "edge", "target"),
    ('"' * 8, "newline\nrole", "slash\\target"),
    ("é", "λ", "🤖"),
    ("zero\u0000inside", "r", "t"),
])
def test_record_length_precheck_matches_independent_canonical_encoding(identifier, role, target):
    module = candidate()
    item = NamespaceObject.create(identifier, "HYPER", {"number": 3}, {role: [target]})
    policy = module.object_facets_policy(trust_roots=("independent-local-selector",))
    selected = module.object_facets_request(item, policy=policy)
    independently_encoded = canonical_bytes(item.to_dict())
    assert selected["record_digest"] == "sha256:" + hashlib.sha256(independently_encoded).hexdigest()
    assert module.recheck_object_facets_certificate(
        module.build_object_facets_certificate(selected, independently_encoded, policy=policy),
        expected_request=selected, policy=policy)["status"] == "PASS"


@pytest.mark.parametrize("field,replacement", [
    ("semantic_version", "verifier-domain-obligations-1"),
    ("coordinate", "OBJECT-1.2"),
    ("proposition_digest", "sha256:" + "0" * 64),
    ("record_digest", "sha256:" + "0" * 64),
    ("payload_digest", "sha256:" + "0" * 64),
    ("operands_digest", "sha256:" + "0" * 64),
    ("address_digest", "sha256:" + "0" * 64),
])
def test_external_selection_rejects_substituted_semantics_and_facets(field, replacement):
    module, _, policy, request, record_bytes = fixture()
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    substituted = dict(request, **{field: replacement})
    with pytest.raises(module.ObjectFacetsError):
        module.recheck_object_facets_certificate(certificate,
            expected_request=substituted, policy=policy)


def test_reselected_kind_and_record_can_be_valid_but_cannot_replace_original_request():
    module, _, policy, request, record_bytes = fixture()
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    other = NamespaceObject.create("node", "DATA", {"x": 1})
    other_request = module.object_facets_request(other, policy=policy)
    with pytest.raises(module.ObjectFacetsError, match="externally selected request"):
        module.recheck_object_facets_certificate(certificate,
            expected_request=other_request, policy=policy)


@pytest.mark.parametrize("field,replacement", [
    ("status", "FAIL"),
    ("issued_receipt", "PASS"),
    ("kind_specific_tier_1_conformance", "PASS"),
    ("address_digest", "sha256:" + "0" * 64),
])
def test_rehashed_result_forgery_is_rejected_by_reexecution(field, replacement):
    module, _, policy, request, record_bytes = fixture()
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    value = strict_json_loads(certificate.decode("utf-8"))
    value["result"][field] = replacement
    forged = _rehashed(value)
    with pytest.raises(module.ObjectFacetsError, match="reproduce"):
        module.recheck_object_facets_certificate(forged,
            expected_request=request, policy=policy)


def test_external_policy_substitution_and_self_selected_policy_are_not_admitted():
    module, _, policy, request, record_bytes = fixture()
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    other = module.object_facets_policy(trust_roots=("other-local-selector",))
    with pytest.raises(module.ObjectFacetsError, match="policy"):
        module.recheck_object_facets_certificate(certificate,
            expected_request=request, policy=other)
    with pytest.raises(module.ObjectFacetsError, match="policy"):
        module.build_object_facets_certificate(request, record_bytes, policy=other)
    assert policy["trust_roots"] == ["independent-local-selector"]


def test_missing_selected_evidence_is_replayable_unknown():
    module, _, policy, request, _ = fixture()
    certificate = module.build_object_facets_certificate(request, None, policy=policy)
    carried = strict_json_loads(certificate.decode("utf-8"))
    assert carried["evidence_payloads"] == {}
    assert module.recheck_object_facets_certificate(certificate,
        expected_request=request, policy=policy)["status"] == "UNKNOWN"


@pytest.mark.parametrize("malformed", [
    b'{"object_id":"node","kind":"OBJECT","payload":{"x":1},"operands":{}}',
    b'{"kind":"OBJECT","kind":"OBJECT","object_id":"node","operands":{},"payload":{"x":1}}',
    b'{"kind":"OBJECT","object_id":"node","operands":{},"payload":{"x":1},"extra":1}',
    b'{"kind":"ABSENT","object_id":"node","operands":{},"payload":{"x":1}}',
    b'{"kind":"OBJECT","object_id":"node","operands":{},"payload":{"x":NaN}}',
    b'{"kind":"OBJECT","object_id":"node","operands":{"r":42},"payload":{"x":1}}',
    b'{"kind":"OBJECT","object_id":"node","operands":{"r":[false]},"payload":{"x":1}}',
])
def test_retained_malformed_evidence_is_fail_and_replayable(malformed):
    module, _, policy, request, _ = fixture()
    digest = "sha256:" + hashlib.sha256(malformed).hexdigest()
    selected = dict(request, record_digest=digest, evidence_ref=digest,
        address_digest="sha256:" + canonical_digest({"schema_version": module.ADDRESS_VERSION,
            "semantic_version": module.SEMANTIC_VERSION, "object_id": "node",
            "object_kind": "OBJECT", "record_digest": digest}))
    certificate = module.build_object_facets_certificate(selected, malformed, policy=policy)
    assert module.recheck_object_facets_certificate(certificate,
        expected_request=selected, policy=policy)["status"] == "FAIL"


def test_supplied_substitute_bytes_refuse_original_selection():
    module, _, policy, request, _ = fixture()
    changed = canonical_bytes(NamespaceObject.create("node", "OBJECT", {"x": 2}).to_dict())
    with pytest.raises(Refuted, match="contradict"):
        module.build_object_facets_certificate(request, changed, policy=policy)


def test_invalid_request_and_policy_shapes_refuse_before_copy_or_comparison():
    module, _, policy, request, encoded = fixture()
    with pytest.raises(module.ObjectFacetsError, match="fields"):
        module.build_object_facets_certificate(dict(request, extra=True), encoded, policy=policy)
    with pytest.raises(module.ObjectFacetsError, match="fields"):
        module.build_object_facets_certificate(request, encoded, policy=dict(policy, extra=True))
    with pytest.raises(module.ObjectFacetsError, match="trust roots"):
        module.object_facets_policy(trust_roots=(" ",))


class HostileText(str):
    def __eq__(self, other):
        raise AssertionError("hostile equality invoked")

    def __ne__(self, other):
        raise AssertionError("hostile inequality invoked")


@pytest.mark.parametrize("place,field", [
    ("request", "schema_version"), ("request", "semantic_version"),
    ("request", "coordinate"), ("request", "object_kind"),
    ("policy", "schema_version"), ("policy", "mechanism_id"),
])
def test_hostile_scalar_subclasses_refused_before_equality(place, field):
    module, _, policy, request, encoded = fixture()
    target = dict(request) if place == "request" else dict(policy)
    target[field] = HostileText(target[field])
    with pytest.raises(module.ObjectFacetsError):
        module.build_object_facets_certificate(target if place == "request" else request,
            encoded, policy=target if place == "policy" else policy)


def test_hostile_record_subclass_refused_before_field_callback():
    module, _, policy, _, _ = fixture()

    class HostileObject(NamespaceObject):
        def __getattribute__(self, field):
            if field in {"object_id", "kind", "payload_bytes", "operands"} and getattr(self, "_armed", False):
                raise AssertionError("hostile namespace-object callback invoked")
            return super().__getattribute__(field)

    item = HostileObject("node", ObjectKind.OBJECT, b"{}")
    object.__setattr__(item, "_armed", True)
    with pytest.raises(module.ObjectFacetsError, match="exact namespace object"):
        module.object_facets_request(item, policy=policy)


def test_mutated_frozen_caller_record_cannot_change_checked_snapshot(monkeypatch):
    module, item, policy, _, _ = fixture()
    original = module.canonical_bytes

    def mutate(value):
        if value == "node":
            object.__setattr__(item, "payload_bytes", b'{"x":99}')
        return original(value)

    monkeypatch.setattr(module, "canonical_bytes", mutate)
    selected = module.object_facets_request(item, policy=policy)
    assert selected["record_digest"] == LITERAL_RECORD_DIGEST
    assert item.payload == {"x": 99}


def test_expected_request_is_snapshotted_before_digest_callback(monkeypatch):
    module, _, policy, request, record_bytes = fixture()
    original = module.canonical_digest
    original_payload_digest = request["payload_digest"]

    def mutate(value):
        if type(value) is dict and value.get("schema_version") == module.ADDRESS_VERSION:
            request["payload_digest"] = "sha256:" + "0" * 64
        return original(value)

    monkeypatch.setattr(module, "canonical_digest", mutate)
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    carried = strict_json_loads(certificate.decode("utf-8"))
    assert carried["request"]["payload_digest"] == original_payload_digest
    assert carried["result"]["status"] == "PASS"


def test_policy_is_snapshotted_before_source_digest_callback(monkeypatch):
    module, _, policy, _, _ = fixture()
    original = module.mechanism_digest

    def mutate():
        policy["schema_version"] = "legacy"
        policy["trust_roots"][0] = "replacement"
        return original()

    monkeypatch.setattr(module, "mechanism_digest", mutate)
    admitted = module._policy(policy)
    assert admitted["schema_version"] == module.POLICY_VERSION
    assert admitted["trust_roots"] == ["independent-local-selector"]


def test_escaped_reference_budget_and_operation_budget_precede_whole_serialization(monkeypatch):
    module = candidate()
    item = NamespaceObject.create('"' * 100, "HYPER", {}, {"role": ["child"]})
    policy = module.object_facets_policy(trust_roots=("independent-local-selector",))
    original = module.canonical_bytes

    def trap(value):
        if type(value) is dict and set(value) == {"object_id", "kind", "payload", "operands"}:
            raise AssertionError("whole record serialized before selected budget")
        return original(value)

    monkeypatch.setattr(module, "canonical_bytes", trap)
    with pytest.raises(Unavailable, match="reference bound"):
        module.object_facets_request(item, policy=policy,
            limits=dict(module.DEFAULT_LIMITS, max_reference_bytes=150))
    with pytest.raises(Unavailable, match="operation bound"):
        module.object_facets_request(item, policy=policy,
            limits=dict(module.DEFAULT_LIMITS, max_operations=2))


def test_record_byte_bound_precedes_json_parser_and_boolean_limits_refuse():
    module, _, policy, request, _ = fixture()
    with pytest.raises(Unavailable, match="before parse"):
        module.build_object_facets_certificate(request, b"x" * (module.DEFAULT_LIMITS["max_record_bytes"] + 1), policy=policy)
    invalid = dict(request, limits=dict(request["limits"], max_operations=True))
    with pytest.raises(module.ObjectFacetsError):
        module.build_object_facets_certificate(invalid, LITERAL_RECORD, policy=policy)


def test_selected_record_byte_budget_exhausts_before_full_encoding(monkeypatch):
    module, item, policy, _, _ = fixture()
    original = module.canonical_bytes

    def trap(value):
        if type(value) is dict and set(value) == {"object_id", "kind", "payload", "operands"}:
            raise AssertionError("whole record encoded before selected byte bound")
        return original(value)

    monkeypatch.setattr(module, "canonical_bytes", trap)
    with pytest.raises(Unavailable, match="before serialization"):
        module.object_facets_request(item, policy=policy,
            limits=dict(module.DEFAULT_LIMITS, max_record_bytes=20))


def test_evidence_byte_budget_is_unknown_without_weaker_status():
    module, item, policy, _, record_bytes = fixture()
    request = module.object_facets_request(item, policy=policy,
        limits=dict(module.DEFAULT_LIMITS, max_evidence_bytes=1))
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    assert module.recheck_object_facets_certificate(certificate,
        expected_request=request, policy=policy)["status"] == "UNKNOWN"


def test_noncanonical_certificate_and_duplicate_keys_refuse_recheck():
    module, _, policy, request, record_bytes = fixture()
    certificate = module.build_object_facets_certificate(request, record_bytes, policy=policy)
    value = strict_json_loads(certificate.decode("utf-8"))
    spaced = json.dumps(value, sort_keys=True).encode("utf-8")
    with pytest.raises(module.ObjectFacetsError, match="noncanonical"):
        module.recheck_object_facets_certificate(spaced, expected_request=request, policy=policy)
    duplicate = certificate.replace(b'"digest":', b'"digest":"sha256:' + b"0" * 64 + b'","digest":', 1)
    with pytest.raises(module.ObjectFacetsError):
        module.recheck_object_facets_certificate(duplicate, expected_request=request, policy=policy)


def test_normative_spec_states_exact_proposition_and_neutral_address():
    module = candidate()
    spec = Path(module.__file__).resolve().parents[2] / "standard/CURRENT_OBJECT_FACETS.md"
    text = spec.read_text(encoding="utf-8")
    assert module.PROPOSITION in text
    assert "not an issued RECEIPT" in text
    assert "kind_specific_tier_1_conformance=NOT_ESTABLISHED" in text
