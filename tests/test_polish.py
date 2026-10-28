"""Verifier Standard (VSTD) polishing must not manufacture certificate closure.

JavaScript Object Notation (JSON); command-line interface (CLI).
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectCoordinate, composition_digest
from verifier.domains.contracts import object_facets
from verifier.domains.contracts.current_object_routes import current_object_route_catalog
from verifier.runtime.public_cli import main


def fixture():
    item = NamespaceObject.create("root", "OBJECT", {"private_value": "do-not-echo"})
    policy = object_facets.object_facets_policy(trust_roots=("consumer-selected",))
    intent = object_facets.object_facets_request(item, policy=policy)
    cert = object_facets.build_object_facets_certificate(
        intent, canonical_bytes(item.to_dict()), policy=policy)
    digest = "sha256:" + hashlib.sha256(cert).hexdigest()
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": [item.to_dict()],
              "certificates": {digest: cert.decode("utf-8")}}
    request = {"schema_version": "verifier-polish-request-1", "root_id": "root",
               "collection_digest": composition_digest([item]),
               "bundle_digest": "sha256:" + hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
               "requirements": [{"object_id": "root", "tier": n,
                  "applicability": "REQUIRED", "rationale": "Declared artifact scope",
                  "objectives": []} for n in range(1, 10)]}
    request["requirements"][0]["objectives"] = [{
        "semantic_version": object_facets.SEMANTIC_VERSION, "coordinate": "OBJECT-1.1",
        "request": intent, "policy": policy, "certificate_digest": digest}]
    return bundle, request


def assess(bundle, request):
    from verifier.runtime.polish import assess_polish
    return assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(request))


def rebind(bundle, request):
    request["bundle_digest"] = "sha256:" + hashlib.sha256(canonical_bytes(bundle)).hexdigest()


def test_native_pass_is_preserved_without_whole_object_promotion():
    bundle, request = fixture()
    report = assess(bundle, request)
    assert report["composition_status"] == "PASS"
    assert report["tier_inventory_status"] == "PASS"
    assert report["objectives"][0]["status"] == "PASS"
    assert report["status"] == "UNKNOWN"
    assert report["polished"] is False
    assert report["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert "do-not-echo" not in json.dumps(report)


def test_private_native_replay_does_not_establish_public_checkability():
    bundle, request = fixture()
    objective = assess(bundle, request)["objectives"][0]
    assert objective["status"] == "PASS"
    assert objective["public_checkability"] == "NOT_ESTABLISHED"
    assert objective["replay_observation"] == "RETAINED_CERTIFICATE_REPLAYED_LOCALLY"


@pytest.mark.parametrize("tier", range(1, 10))
def test_omitted_applicability_row_is_an_explicit_gap(tier):
    bundle, request = fixture()
    request["requirements"] = [r for r in request["requirements"] if r["tier"] != tier]
    report = assess(bundle, request)
    assert report["tier_inventory_status"] == "UNKNOWN"
    assert {"object_id": "root", "tier": tier} in report["missing_tiers"]
    assert report["polished"] is False


def test_not_applicable_assertions_do_not_discharge_obligations():
    bundle, request = fixture()
    row = request["requirements"][-1]
    row["applicability"] = "NOT_APPLICABLE"
    row["rationale"] = "Trust the author"
    report = assess(bundle, request)
    assert report["applicability_status"] == "UNKNOWN"
    assert report["status"] == "UNKNOWN"
    assert report["polished"] is False


def test_unregistered_security_objective_remains_unknown():
    bundle, request = fixture()
    objective = deepcopy(request["requirements"][0]["objectives"][0])
    unsupported = "OBJECT-9.999999999"
    assert str(ObjectCoordinate.parse(unsupported)) == unsupported
    assert unsupported not in {row["objective"] for row in current_object_route_catalog()}
    objective["coordinate"] = unsupported
    request["requirements"][-1]["objectives"] = [objective]
    report = assess(bundle, request)
    assert report["objectives"][-1]["status"] == "UNKNOWN"
    assert report["objectives"][-1]["reason"] == "UNREGISTERED_OBJECTIVE"
    assert report["status"] == "UNKNOWN"
    assert report["polished"] is False


@pytest.mark.parametrize("field,value", [("object_id", "other"), ("record_digest", "sha256:" + "0" * 64)])
def test_native_pass_for_another_subject_cannot_be_attached(field, value):
    bundle, request = fixture()
    request["requirements"][0]["objectives"][0]["request"][field] = value
    report = assess(bundle, request)
    assert report["status"] == "FAIL"
    assert report["polished"] is False


def test_certificate_tamper_with_rebound_bundle_is_rejected():
    bundle, request = fixture()
    key = next(iter(bundle["certificates"]))
    bundle["certificates"][key] += " "
    rebind(bundle, request)
    assert assess(bundle, request)["status"] == "FAIL"


def test_changed_bundle_fails_external_binding():
    bundle, request = fixture()
    bundle["objects"][0]["payload"]["private_value"] = "substituted"
    assert assess(bundle, request)["status"] == "FAIL"


def test_missing_certificate_is_unknown_not_pass():
    bundle, request = fixture()
    bundle["certificates"] = {}
    rebind(bundle, request)
    report = assess(bundle, request)
    assert report["objectives"][0]["status"] == "UNKNOWN"
    assert report["objectives"][0]["reason"] == "PUBLIC_REPLAY_EVIDENCE_MISSING"


@pytest.mark.parametrize("mutation", ["duplicate-row", "boolean-tier", "extra-status", "empty-collection", "wrong-kind", "wrong-root"])
def test_invalid_inventory_cannot_be_polished(mutation):
    bundle, request = fixture()
    if mutation == "duplicate-row":
        request["requirements"].append(deepcopy(request["requirements"][0]))
    elif mutation == "boolean-tier":
        request["requirements"][0]["tier"] = True
    elif mutation == "extra-status":
        bundle["polished"] = True
    elif mutation == "empty-collection":
        bundle["objects"] = []
    elif mutation == "wrong-kind":
        bundle["objects"][0]["kind"] = "GOVERNANCE"
    else:
        request["root_id"] = "absent"
    rebind(bundle, request)
    assert assess(bundle, request)["status"] == "FAIL"


def test_declared_relation_with_missing_target_is_refuted():
    bundle, request = fixture()
    bundle["objects"][0]["operands"] = {"dependency": ["absent"]}
    rebind(bundle, request)
    assert assess(bundle, request)["status"] == "FAIL"


def test_cli_unknown_keeps_files_unchanged(tmp_path, capsys):
    bundle, request = fixture()
    b, r = tmp_path / "bundle.json", tmp_path / "request.json"
    b.write_bytes(canonical_bytes(bundle))
    r.write_bytes(canonical_bytes(request))
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert main(["polish", "assess", str(b), "--request", str(r), "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_duplicate_json_is_rejected():
    from verifier.runtime.polish import assess_polish
    bundle, request = fixture()
    assert assess_polish(b'{"objects":[],"objects":[]}',
        request_bytes=canonical_bytes(request))["status"] == "FAIL"


def test_assessment_can_be_replayed_without_trusting_its_carried_status():
    from verifier.runtime.polish import recheck_polish
    bundle, request = fixture()
    encoded = canonical_bytes(assess(bundle, request))
    result = recheck_polish(encoded, bundle_bytes=canonical_bytes(bundle),
                            request_bytes=canonical_bytes(request))
    assert result["replay_status"] == "REPRODUCED"
    assert result["status"] == "UNKNOWN"
    assert result["polished"] is False


@pytest.mark.parametrize("field,value", [("polished", True), ("status", "PASS"),
                                        ("mechanism_digest", "sha256:" + "0" * 64)])
def test_rehashed_assessment_forgery_is_rejected(field, value):
    from verifier.runtime.polish import recheck_polish
    bundle, request = fixture()
    report = assess(bundle, request)
    report[field] = value
    report.pop("assessment_digest")
    report["assessment_digest"] = "sha256:" + hashlib.sha256(canonical_bytes(report)).hexdigest()
    result = recheck_polish(canonical_bytes(report), bundle_bytes=canonical_bytes(bundle),
                            request_bytes=canonical_bytes(request))
    assert result["status"] == "FAIL"
    assert result["replay_status"] == "REJECTED"


def test_replay_is_bound_to_the_exact_external_request():
    from verifier.runtime.polish import recheck_polish
    bundle, request = fixture()
    encoded = canonical_bytes(assess(bundle, request))
    request["requirements"][0]["rationale"] = "Different external scope"
    assert recheck_polish(encoded, bundle_bytes=canonical_bytes(bundle),
                         request_bytes=canonical_bytes(request))["status"] == "FAIL"


@pytest.mark.parametrize("bound", ["MAX_BUNDLE_BYTES", "MAX_REQUEST_BYTES", "MAX_OBJECTIVES"])
def test_checker_bounds_refuse_before_native_execution(monkeypatch, bound):
    from verifier.runtime import polish
    bundle, request = fixture()
    monkeypatch.setattr(polish, bound, 0)
    def forbidden(*args, **kwargs):
        raise AssertionError("native replay must not execute after exhausted input bounds")
    monkeypatch.setattr(polish, "replay_current_object_certificate", forbidden)
    assert assess(bundle, request)["status"] == "FAIL"


def test_registered_security_objective_without_matching_subject_binding_fails():
    bundle, request = fixture()
    objective = deepcopy(request["requirements"][0]["objectives"][0])
    assert "OBJECT-9.1" in {row["objective"] for row in current_object_route_catalog()}
    objective["coordinate"] = "OBJECT-9.1"
    request["requirements"][-1]["objectives"] = [objective]
    report = assess(bundle, request)
    assert report["objectives"][-1]["status"] == "FAIL"
    assert report["objectives"][-1]["reason"] == "SUBJECT_BINDING_DIFFERS"
