"""Adversarial checks for the signed current simulation-object capture route."""
from __future__ import annotations

import hashlib
import importlib

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectKind, composition_digest
from verifier.domains.common import Unavailable


def _module():
    return importlib.import_module("verifier.domains.contracts.object_grounding")


def _objects(iso: bytes):
    make = NamespaceObject.create
    return [make("data", "DATA", {}), make("verifier", "VERIFIER", {}),
            make("room", "OBJECT", {}), make("env", "ENV", {}),
            make("sim", "SIM", {"isolation_evidence_digest": "sha256:" + hashlib.sha256(iso).hexdigest()},
                {"data": ["data"], "verifier": ["verifier"], "objects": ["room"], "env": ["env"]})]


class HostileText(str):
    def __eq__(self, other):
        raise AssertionError("hostile equality was invoked")

    def __ne__(self, other):
        raise AssertionError("hostile inequality was invoked")


class HostileEncoding(str):
    def encode(self, *args, **kwargs):
        raise AssertionError("hostile reference encoder was invoked")


@pytest.mark.parametrize("field", ["schema_version", "semantic_version", "coordinate"])
def test_request_scalar_subclass_rejected_before_comparison(field):
    module = _module()
    request = {"schema_version": module.REQUEST_VERSION, "semantic_version": module.SEMANTIC_VERSION,
        "coordinate": module.COORDINATE, "proposition_digest": module.PROPOSITION_DIGEST,
        "subject_id": "sim", "object_digest": "sha256:" + "0" * 64,
        "collection_digest": "sha256:" + "0" * 64,
        "isolation_evidence_digest": "sha256:" + "0" * 64,
        "policy_digest": "sha256:" + "0" * 64,
        "limits": module.DEFAULT_LIMITS}
    request[field] = HostileText(request[field])
    with pytest.raises(module.CurrentObjectGroundingError):
        module._request(request)


@pytest.mark.parametrize("field", ["schema_version", "mechanism_id"])
def test_policy_scalar_subclass_rejected_before_comparison(field):
    module = _module()
    policy = {"schema_version": module.POLICY_VERSION, "mechanism_id": module.MECHANISM_ID,
        "mechanism_digest": module.mechanism_digest(), "trust_roots": ["external-selector"],
        "max_certificate_bytes": 100000}
    policy[field] = HostileText(policy[field])
    with pytest.raises(module.CurrentObjectGroundingError):
        module._policy(policy)


def test_escaped_reference_bytes_charged_before_collection_serialization(monkeypatch):
    module = _module()
    iso = canonical_bytes({"sim_id": "sim"})
    objects = _objects(iso)
    escaped = '"' * 100
    objects[2] = NamespaceObject.create(escaped, "OBJECT", {})
    objects[-1] = NamespaceObject.create("sim", "SIM", objects[-1].payload,
        {"data": ["data"], "verifier": ["verifier"], "objects": [escaped], "env": ["env"]})
    refs = [item.object_id for item in objects]
    refs += [part for item in objects for role, targets in item.operands for part in (role, *targets)]
    raw = sum(len(part.encode("utf-8")) for part in refs)
    canonical = sum(len(canonical_bytes(part)) for part in refs)
    assert raw < canonical
    limits = dict(module.DEFAULT_LIMITS, max_reference_bytes=(raw + canonical) // 2)
    original = module.canonical_bytes

    def trap(value):
        if type(value) is dict and value.get("schema_version") == module.COLLECTION_VERSION:
            raise AssertionError("whole collection serialized before reference budget")
        return original(value)

    monkeypatch.setattr(module, "canonical_bytes", trap)
    with pytest.raises(Unavailable, match="reference bound"):
        module._capture_objects(objects, limits)


def test_captured_collection_is_snapshot_after_canonical_callback(monkeypatch):
    module = _module()
    iso = canonical_bytes({"sim_id": "sim"})
    objects = _objects(iso)
    original_digest = composition_digest(objects)
    original = module.canonical_bytes

    def mutate(value):
        if type(value) is dict and value.get("schema_version") == module.COLLECTION_VERSION:
            object.__setattr__(objects[-1], "payload_bytes", canonical_bytes({"tampered": True}))
        return original(value)

    monkeypatch.setattr(module, "canonical_bytes", mutate)
    captured, encoded = module._capture_objects(objects, module.DEFAULT_LIMITS)
    assert composition_digest(captured) == original_digest
    assert canonical_bytes({"schema_version": module.COLLECTION_VERSION,
        "objects": [item.to_dict() for item in sorted(captured, key=lambda item: item.object_id)]}) == encoded


def test_reference_subclass_rejected_before_encoding_callback():
    module = _module()
    item = NamespaceObject(HostileEncoding("room"), ObjectKind.OBJECT, b"{}")
    with pytest.raises(module.CurrentObjectGroundingError, match="immutable built-ins"):
        module._capture_objects([item], module.DEFAULT_LIMITS)


def test_operation_budget_exhausts_before_whole_collection_serialization(monkeypatch):
    module = _module()
    objects = _objects(canonical_bytes({"sim_id": "sim"}))
    original = module.canonical_bytes

    def trap(value):
        if type(value) is dict and value.get("schema_version") == module.COLLECTION_VERSION:
            raise AssertionError("whole collection serialized before operation budget")
        return original(value)

    monkeypatch.setattr(module, "canonical_bytes", trap)
    with pytest.raises(Unavailable, match="operation bound"):
        module._capture_objects(objects, dict(module.DEFAULT_LIMITS, max_composition_operations=5))


def test_plain_collection_wire_bytes_stay_unchanged():
    module = _module()
    objects = _objects(canonical_bytes({"sim_id": "sim"}))
    _, encoded = module._capture_objects(objects, module.DEFAULT_LIMITS)
    # Frozen digest from the signed pre-repair wire fixture.
    assert hashlib.sha256(encoded).hexdigest() == "dd5c9f329cc8a460662c691e26728280da0b4b1b7cc7a76d8c77c44c0c5cd65d"
