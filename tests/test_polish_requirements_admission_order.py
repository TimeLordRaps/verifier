"""Independent admission-order and strict-selection regressions.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); command-line interface (CLI); Unicode Transformation Format,
8-bit (UTF-8). OBJECT denotes a generic namespace object. Counts are dimensionless
and sizes count encoded bytes. The native checker remains real in every test.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import object_facets
from verifier.runtime import polish, polish_requirements as gate
from verifier.runtime.polish_capacity import CEILINGS
from verifier.runtime.public_cli import main


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def selection(*, count: int = 3, identifier_width: int = 8):
    objects = [NamespaceObject.create(("item-" + str(index)).ljust(identifier_width, "x"),
        "OBJECT", {"witness": "never-copy-this-private-witness"}) for index in range(count)]
    bundle = {"schema_version": "verifier-polish-bundle-2",
        "objects": [item.to_dict() for item in objects], "certificates": {}, "evidence_payloads": {}}
    request = {"schema_version": "verifier-polish-request-2", "root_id": objects[0].object_id,
        "collection_digest": composition_digest(objects), "bundle_digest": digest(canonical_bytes(bundle)),
        "limits": dict(CEILINGS), "requirements": [
            {"object_id": item.object_id, "tier": tier, "applicability": "REQUIRED",
             "rationale": "Selected finite scope", "objectives": []}
            for item in objects for tier in range(1, 10)]}
    inventory = {"schema_version": gate.INVENTORY_VERSION,
        "semantic_version": object_facets.SEMANTIC_VERSION, "catalog_digest": gate.requirements_catalog_digest(),
        "root_id": request["root_id"], "collection_digest": request["collection_digest"],
        "subjects": [{"object_id": item.object_id, "object_kind": item.kind.value,
            "object_digest": item.digest} for item in objects],
        "requirements": [{"object_id": row["object_id"], "tier": row["tier"],
            "applicability": row["applicability"], "rationale_digest": digest(canonical_bytes(row["rationale"])),
            "objectives": []} for row in request["requirements"]]}
    return bundle, request, inventory


def assess(bundle, request, inventory):
    raw = canonical_bytes(inventory)
    return gate.assess_polish_inventory(canonical_bytes(bundle), request_bytes=canonical_bytes(request),
        inventory_bytes=raw, expected_inventory_digest=digest(raw), contract_version="2")


@pytest.mark.parametrize("resource", ["bundle_bytes", "request_bytes", "objects"])
def test_wrapper_preserves_native_early_capacity_admission_before_namespace_reconstruction(resource, monkeypatch):
    bundle, request, inventory = selection()
    request["limits"][resource] = 1
    observed = []
    actual_create = NamespaceObject.create

    def traced_create(cls, *args, **kwargs):
        observed.append(args[0])
        return actual_create(*args, **kwargs)

    monkeypatch.setattr(NamespaceObject, "create", classmethod(traced_create))
    native = polish.assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(request), contract_version="2")
    assert native["status"] == "UNKNOWN"
    assert native["reason"] == "RESOURCE_LIMIT_EXCEEDED"
    assert native["exhausted_resource"] == resource
    assert observed == [], "native admission itself reconstructed the disallowed workload"

    wrapped = assess(bundle, request, inventory)
    assert wrapped["status"] == "UNKNOWN"
    assert wrapped["declared_coverage"] == "UNKNOWN"
    # This assertion is the intended unchanged-source counterexample: currently
    # _preflight reconstructs every subject before delegating selected admission.
    assert observed == [], "wrapper reconstructed namespace subjects before the selected native limit"
    assert wrapped["polished"] is False


def test_an_exhausted_byte_budget_does_not_become_a_semantic_refutation_from_unadmitted_payload():
    bundle, request, inventory = selection(count=1)
    request["limits"]["bundle_bytes"] = 1
    bundle["objects"][0]["payload"] = []
    request["bundle_digest"] = digest(canonical_bytes(bundle))
    native = polish.assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(request), contract_version="2")
    assert native["status"] == "UNKNOWN"
    assert native["exhausted_resource"] == "bundle_bytes"
    wrapped = assess(bundle, request, inventory)
    assert wrapped["status"] == "UNKNOWN"
    assert wrapped["declared_coverage"] == "UNKNOWN"


@pytest.mark.parametrize("resource", ["requirements", "objectives"])
def test_selected_list_capacity_precedes_namespace_construction(resource, monkeypatch):
    bundle, request, inventory = selection()
    request["limits"][resource] = 1
    if resource == "objectives":
        # These two entries exceed the selected cardinality. Their contents are
        # intentionally unadmitted, so no semantic parsing or replay may be needed.
        request["requirements"][0]["objectives"] = [{}, {}]
        inventory["requirements"][0]["objectives"] = [{}, {}]
    observed = []
    actual_create = NamespaceObject.create

    def traced_create(cls, *args, **kwargs):
        observed.append(args[0])
        return actual_create(*args, **kwargs)

    monkeypatch.setattr(NamespaceObject, "create", classmethod(traced_create))
    wrapped = assess(bundle, request, inventory)
    assert wrapped["status"] == wrapped["declared_coverage"] == "UNKNOWN"
    assert wrapped["reason"] == "RESOURCE_LIMIT_EXCEEDED"
    assert wrapped["exhausted_resource"] == resource
    assert wrapped["resource_stage"] == "REQUIREMENTS_PREFLIGHT"
    assert "native_assessment" not in wrapped
    assert observed == []


@pytest.mark.parametrize("tier", [True, 1.0])
def test_equal_valued_noninteger_tiers_do_not_pass_plain_type_admission(tier):
    bundle, request, inventory = selection(count=1)
    request["requirements"][0]["tier"] = tier
    inventory["requirements"][0]["tier"] = tier
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "FAIL"
    assert report["reason"] == "REQUIREMENT_SUBJECT_OR_TIER_DIFFERS"
    assert "never-copy-this-private-witness" not in json.dumps(report)


def test_canonical_numeric_request_binding_distinguishes_python_equal_values():
    bundle, request, inventory = selection(count=1)
    item = NamespaceObject.create(**{"object_id": bundle["objects"][0]["object_id"],
        "kind": "OBJECT", "payload": bundle["objects"][0]["payload"]})
    policy = object_facets.object_facets_policy(trust_roots=("externally-selected",))
    intent = object_facets.object_facets_request(item, policy=policy)
    certificate = object_facets.build_object_facets_certificate(intent, canonical_bytes(item.to_dict()), policy=policy)
    reference = digest(certificate)
    bundle["certificates"] = {reference: {"encoding": "utf8", "text": certificate.decode("utf-8")}}
    request["bundle_digest"] = digest(canonical_bytes(bundle))
    request["requirements"][0]["objectives"] = [{"semantic_version": object_facets.SEMANTIC_VERSION,
        "coordinate": "OBJECT-1.1", "request": intent, "policy": policy, "certificate_digest": reference}]
    inventory["requirements"][0]["objectives"] = [{"coordinate": "OBJECT-1.1",
        **gate.registered_objective_binding(object_facets.SEMANTIC_VERSION, "OBJECT-1.1", "OBJECT"),
        "request_digest": digest(canonical_bytes(intent)), "policy_digest": digest(canonical_bytes(policy)),
        "certificate_digest": reference}]
    selected = deepcopy(intent)
    limit = next(key for key, value in intent["limits"].items() if type(value) is int)
    intent["limits"][limit] = float(intent["limits"][limit])
    assert selected == intent  # Python equality is not the canonical-value oracle.
    assert canonical_bytes(selected) != canonical_bytes(intent)
    report = assess(bundle, request, inventory)
    assert report["status"] == report["declared_coverage"] == "FAIL"
    assert report["reason"] == "OBJECTIVE_EVIDENCE_SELECTION_DIFFERS"


def test_missing_cli_input_keeps_inventory_authentication_boundary(tmp_path, capsys):
    absent = str(tmp_path / "unavailable.json")
    code = main(["polish", "coverage", absent, "--request", absent, "--requirements", absent,
        "--requirements-digest", "sha256:" + "0" * 64, "--json"])
    assert code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "verifier-polish-requirements-assessment-1"
    assert report["status"] == report["declared_coverage"] == "UNKNOWN"
    assert report["polished"] is False
    assert report["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert report["inventory_authentication"] == "NOT_ESTABLISHED"


def test_documented_wrapper_output_reservation_is_distinct_from_native_budget():
    # Characterization, NOT a passing total-output-bound conformance assertion.
    # The current packaged spec explicitly excludes wrapper metadata from the
    # native output reservation. This exposes the practical magnitude of that
    # documented limitation for a caller, pending a separate wrapper budget.
    bundle, request, inventory = selection(count=50, identifier_width=240)
    request["limits"]["output_bytes"] = 8192
    report = assess(bundle, request, inventory)
    assert len(canonical_bytes(report["native_assessment"])) <= 8192
    assert len(canonical_bytes(report)) > 8192
    assert len(report["open_required_slots"]) == 450
    assert report["status"] == report["declared_coverage"] == "UNKNOWN"
    assert "never-copy-this-private-witness" not in json.dumps(report)
