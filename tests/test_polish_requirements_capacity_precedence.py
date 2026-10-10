"""Adversarial capacity precedence after external inventory selection.

Secure Hash Algorithm 256-bit (SHA-256); JavaScript Object Notation (JSON).
Counts are dimensionless; byte limits count encoded input. This file uses the
adjacent independently prepared admission fixture and never fabricates authority.
"""
from __future__ import annotations

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.runtime import polish, polish_requirements as gate
from test_polish_requirements_admission_order import assess, digest, selection


def forbid(*args, **kwargs):
    raise AssertionError("unadmitted namespace construction or native replay")


@pytest.mark.parametrize("resource", ["request_bytes", "bundle_bytes", "objects", "requirements", "objectives"])
def test_independent_inventory_pin_mismatch_precedes_selected_capacity(resource, monkeypatch):
    bundle, request, inventory = selection()
    request["limits"][resource] = 1
    selected_bytes = canonical_bytes(inventory)
    external_pin = digest(selected_bytes)
    inventory["requirements"][0]["rationale_digest"] = "sha256:" + "0" * 64
    changed = canonical_bytes(inventory)
    assert digest(changed) != external_pin
    monkeypatch.setattr(NamespaceObject, "create", classmethod(forbid))
    monkeypatch.setattr(polish, "assess_polish", forbid)
    report = gate.assess_polish_inventory(canonical_bytes(bundle), request_bytes=canonical_bytes(request),
        inventory_bytes=changed, expected_inventory_digest=external_pin, contract_version="2")
    assert report["status"] == report["declared_coverage"] == "FAIL"
    assert report["reason"] == "EXTERNAL_INVENTORY_DIGEST_DIFFERS"
    assert "native_assessment" not in report


def test_admitted_inventory_comparison_still_precedes_native_replay(monkeypatch):
    bundle, request, inventory = selection()
    request["requirements"].pop()
    monkeypatch.setattr(polish, "assess_polish", forbid)
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "FAIL"
    assert report["reason"] == "REQUEST_TIER_SET_DIFFERS"
    assert "native_assessment" not in report


@pytest.mark.parametrize("source", ["inventory", "request"])
def test_capacity_accounts_for_both_selected_objective_lists(source, monkeypatch):
    bundle, request, inventory = selection()
    request["limits"]["objectives"] = 1
    # The larger list is already outside admitted capacity. Its contents must
    # remain uninterpreted until capacity is available, whichever side carries it.
    chosen = inventory if source == "inventory" else request
    chosen["requirements"][0]["objectives"] = [{}, {}]
    monkeypatch.setattr(NamespaceObject, "create", classmethod(forbid))
    monkeypatch.setattr(polish, "assess_polish", forbid)
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "UNKNOWN"
    assert report["reason"] == "RESOURCE_LIMIT_EXCEEDED"
    assert report["exhausted_resource"] == "objectives"
    assert report["resource_stage"] == "REQUIREMENTS_PREFLIGHT"
    assert "native_assessment" not in report


def test_tiny_selected_bundle_limit_precedes_bundle_hash_parse_and_object_work(monkeypatch):
    # Native v2 currently hashes its bundle before byte admission. This is a
    # stronger wrapper admission requirement, not a claim about existing native
    # hash order. All traced functions call their actual implementation.
    bundle, request, inventory = selection()
    request["limits"]["bundle_bytes"] = 1
    raw_bundle = canonical_bytes(bundle)
    raw_request = canonical_bytes(request)
    raw_inventory = canonical_bytes(inventory)
    inventory_pin = digest(raw_inventory)
    observed = []
    actual_digest, actual_load, actual_create = polish._digest, polish._load, NamespaceObject.create

    def traced_digest(raw):
        if raw is raw_bundle:
            observed.append("bundle_hash")
        return actual_digest(raw)

    def traced_load(raw, bound):
        if raw is raw_bundle:
            observed.append("bundle_parse")
        return actual_load(raw, bound)

    def traced_create(cls, *args, **kwargs):
        observed.append("namespace_construction")
        return actual_create(*args, **kwargs)

    monkeypatch.setattr(polish, "_digest", traced_digest)
    monkeypatch.setattr(polish, "_load", traced_load)
    monkeypatch.setattr(NamespaceObject, "create", classmethod(traced_create))
    report = gate.assess_polish_inventory(raw_bundle, request_bytes=raw_request,
        inventory_bytes=raw_inventory, expected_inventory_digest=inventory_pin, contract_version="2")
    assert report["status"] == report["declared_coverage"] == "UNKNOWN"
    assert report.get("exhausted_resource", report.get("native_assessment", {}).get("exhausted_resource")) == "bundle_bytes"
    assert observed == [], "over-capacity bundle was hashed, parsed or reconstructed"
    assert "native_assessment" not in report
