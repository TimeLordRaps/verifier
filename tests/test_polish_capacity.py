"""Versioned Verifier Standard (VSTD) assessment capacity and byte sharing.

JavaScript Object Notation (JSON); command-line interface (CLI).
Counts are dimensionless; encoded and replay workloads are measured in bytes.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import composition_digest
from verifier.runtime import polish
from verifier.runtime.public_cli import main
from test_current_typed_facets import collection
from test_polish import fixture


LIMITS = {
    "bundle_bytes": 64 * 1024 * 1024, "request_bytes": 8 * 1024 * 1024,
    "objects": 4096, "requirements": 36864, "objectives": 8192,
    "certificates": 8192, "evidence_bytes": 64 * 1024 * 1024,
    "certificate_bytes": 64 * 1024 * 1024, "replay_bytes": 256 * 1024 * 1024,
    "composition_operations": 1000000, "composition_payload_bytes": 64 * 1024 * 1024,
    "composition_reference_bytes": 16 * 1024 * 1024, "output_bytes": 32 * 1024 * 1024,
}


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def version2(bundle, request, *, shared=True):
    bundle, request = deepcopy((bundle, request))
    bundle["schema_version"] = "verifier-polish-bundle-2"
    payloads = {}
    for key, text in list(bundle["certificates"].items()):
        certificate = json.loads(text)
        if shared and "evidence_payloads" in certificate and canonical_bytes(certificate) == text.encode():
            evidence = certificate.pop("evidence_payloads")
            for name, encoded in evidence.items():
                assert name == digest(base64.b64decode(encoded, validate=True))
                assert name not in payloads or payloads[name] == encoded
                payloads[name] = encoded
            bundle["certificates"][key] = {
                "encoding": "shared-canonical-json", "envelope": certificate,
                "evidence_refs": sorted(evidence),
            }
        elif shared and type(certificate.get("evidence")) is str and canonical_bytes(certificate) == text.encode():
            raw = certificate.pop("evidence").encode()
            ref = digest(raw)
            payloads[ref] = base64.b64encode(raw).decode()
            bundle["certificates"][key] = {
                "encoding": "shared-text-json", "envelope": certificate, "evidence_ref": ref}
        else:
            bundle["certificates"][key] = {"encoding": "utf8", "text": text}
    bundle["evidence_payloads"] = payloads
    request.update(schema_version="verifier-polish-request-2", limits=dict(LIMITS))
    request["bundle_digest"] = digest(canonical_bytes(bundle))
    return bundle, request


def assess(bundle, request):
    return polish.assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(request),
                                contract_version="2")


def native_workload(kind_count=11):
    # Imported here, not at module level: the module that holds the helper is skipped as a whole where the signing backend is absent,
    # and that must skip only the tests that sign, not the rest of this module.
    from test_current_consent_checks import inputs
    objects = collection()
    selected = {obj.object_id: [] for obj in objects}
    certificates = {}
    for item in sorted(objects, key=lambda obj: obj.object_id)[:kind_count]:
        module, retained, policy, evidence = inputs(item.kind.value, 5, holders=1)
        for stage in range(1, 7):
            selected_evidence = json.loads(evidence)
            if stage != 5:
                for holder in selected_evidence["holders"].values():
                    holder["receipt"] = None
            encoded_evidence = canonical_bytes(selected_evidence)
            request = module.consent_checks_request(object_kind=item.kind.value, stage=stage,
                subject_id=item.object_id, object_digest=item.digest,
                collection_digest=retained["collection_digest"], evidence_ref=digest(encoded_evidence),
                action=retained["action"], evaluation_time=retained["evaluation_time"],
                computational_verdict=retained["computational_verdict"],
                historical_receipts=retained["historical_receipts"] if stage == 5 else {}, policy=policy)
            encoded = module.build_consent_checks_certificate(request, encoded_evidence, policy=policy)
            assert module.recheck_consent_checks_certificate(
                encoded, expected_request=request, policy=policy)["status"] == "PASS"
            key = digest(encoded)
            certificates[key] = encoded.decode()
            selected[item.object_id].append(dict(
                semantic_version=request["semantic_version"], coordinate=request["coordinate"],
                request=request, policy=policy, certificate_digest=key))
    bundle = dict(schema_version="verifier-polish-bundle-1",
                  objects=[obj.to_dict() for obj in objects], certificates=certificates)
    request = dict(schema_version="verifier-polish-request-1", root_id=objects[0].object_id,
        collection_digest=composition_digest(objects), bundle_digest=digest(canonical_bytes(bundle)),
        requirements=[dict(object_id=obj.object_id, tier=tier, applicability="REQUIRED",
            rationale="Selected finite native workload; exhaustive numbered closure remains open.",
            objectives=selected[obj.object_id] if tier == 7 else [])
            for obj in objects for tier in range(1, 10)])
    return bundle, request


@pytest.fixture(scope="module")
def workload():
    return native_workload()


def test_all_twenty_six_kinds_replay_all_six_selected_consent_stages():
    bundle, request = version2(*native_workload(26))
    report = assess(bundle, request)
    assert len(report["objectives"]) == 156
    assert all(row["status"] == "PASS" for row in report["objectives"])
    assert report["status"] == "UNKNOWN" and not report["polished"]


@pytest.mark.parametrize("shared", [False, True])
def test_sixty_six_real_objectives_replay_without_promoting_partial_coverage(workload, shared):
    bundle, request = version2(*workload, shared=shared)
    report = assess(bundle, request)
    assert report["schema_version"] == "verifier-polish-assessment-2"
    assert len(report["objectives"]) == 66
    assert all(row["status"] == "PASS" for row in report["objectives"])
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    assert report["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert report["request_digest"] == digest(canonical_bytes(request))
    assert report["bundle_digest"] == digest(canonical_bytes(bundle))
    assert report["resource_usage"]["replay_bytes"] == sum(
        len(text.encode()) for text in workload[0]["certificates"].values())


def test_shared_payloads_reconstruct_original_bytes_and_reduce_retained_size(workload):
    bundle, request = version2(*workload)
    raw_bundle, _ = version2(*workload, shared=False)
    packed_size, raw_size = len(canonical_bytes(bundle)), len(canonical_bytes(raw_bundle))
    assert packed_size < raw_size
    for key, packed in bundle["certificates"].items():
        assert packed["encoding"] == "shared-text-json"
        rebuilt = canonical_bytes({**packed["envelope"], "evidence": base64.b64decode(
            bundle["evidence_payloads"][packed["evidence_ref"]], validate=True).decode()})
        assert rebuilt == workload[0]["certificates"][key].encode()
        assert digest(rebuilt) == key
    report = assess(bundle, request)
    assert report["resource_usage"]["certificate_bytes"] == sum(
        len(text.encode()) for text in workload[0]["certificates"].values())


def forbid_replay(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("native replay executed before resource or shape preflight completed")
    monkeypatch.setattr(polish, "replay_current_object_certificate", forbidden)


@pytest.mark.parametrize("field", list(LIMITS))
def test_selected_small_limits_stop_before_native_replay(workload, monkeypatch, field):
    bundle, request = version2(*workload)
    request["limits"][field] = 4096 if field == "output_bytes" else 1
    forbid_replay(monkeypatch)
    result = assess(bundle, request)
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "RESOURCE_LIMIT_EXCEEDED"
    assert result["exhausted_resource"] == field
    assert result["polished"] is False
    assert "objectives" not in result


@pytest.mark.parametrize("field,value", [("objects", True), ("objectives", 8193),
                                        ("replay_bytes", 0), ("output_bytes", 4095)])
def test_invalid_resource_contract_is_refuted_before_native_replay(monkeypatch, field, value):
    bundle, request = version2(*fixture())
    request["limits"][field] = value
    forbid_replay(monkeypatch)
    assert assess(bundle, request)["status"] == "FAIL"


@pytest.mark.parametrize("mutation", ["payload", "missing", "unused", "duplicate-ref",
    "certificate-digest", "envelope", "nested-payload", "unknown-encoding", "mixed-version"])
def test_packed_substitution_is_refuted_before_any_native_replay(monkeypatch, mutation):
    bundle, request = version2(*fixture())
    key = next(iter(bundle["certificates"]))
    packed = bundle["certificates"][key]
    ref = packed["evidence_refs"][0]
    if mutation == "payload":
        bundle["evidence_payloads"][ref] = base64.b64encode(b"substituted").decode()
    elif mutation == "missing":
        del bundle["evidence_payloads"][ref]
    elif mutation == "unused":
        bundle["evidence_payloads"][digest(b"unused")] = base64.b64encode(b"unused").decode()
    elif mutation == "duplicate-ref":
        packed["evidence_refs"].append(ref)
    elif mutation == "certificate-digest":
        bundle["certificates"][digest(b"different")] = bundle["certificates"].pop(key)
    elif mutation == "envelope":
        packed["envelope"]["extra"] = True
    elif mutation == "nested-payload":
        packed["envelope"]["evidence_payloads"] = {}
    elif mutation == "unknown-encoding":
        packed["encoding"] = "implicit"
    else:
        bundle["schema_version"] = "verifier-polish-bundle-1"
    request["bundle_digest"] = digest(canonical_bytes(bundle))
    forbid_replay(monkeypatch)
    result = assess(bundle, request)
    assert result["status"] == "FAIL" and result["reason"] == "INVALID_OR_SUBSTITUTED_INPUT"


def test_explicit_version_selection_preserves_version_one(workload):
    bundle, request = workload
    old = polish.assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(request))
    assert old["schema_version"] == "verifier-polish-assessment-1"
    assert old["status"] == "FAIL"
    new_bundle, new_request = version2(bundle, request)
    assert polish.assess_polish(canonical_bytes(new_bundle),
        request_bytes=canonical_bytes(new_request))["status"] == "FAIL"
    assert assess(bundle, request)["status"] == "FAIL"


def test_version2_replay_rejects_forgery_and_changed_limits():
    bundle, request = version2(*fixture())
    report = assess(bundle, request)
    def replay(value, selected):
        return polish.recheck_polish(canonical_bytes(value), bundle_bytes=canonical_bytes(bundle),
            request_bytes=canonical_bytes(selected), contract_version="2")
    result = replay(report, request)
    assert result["schema_version"] == "verifier-polish-replay-2"
    assert result["replay_status"] == "REPRODUCED" and result["status"] == "UNKNOWN"
    changed = deepcopy(request)
    changed["limits"]["objects"] -= 1
    assert replay(report, changed)["replay_status"] == "REJECTED"
    report["status"] = "PASS"
    report.pop("assessment_digest")
    report["assessment_digest"] = digest(canonical_bytes(report))
    assert replay(report, request)["replay_status"] == "REJECTED"


def test_cli_selects_both_versions_without_writing_inputs(tmp_path, capsys):
    bundle, request = version2(*fixture())
    b, r, a = (tmp_path / name for name in ("bundle.json", "request.json", "assessment.json"))
    b.write_bytes(canonical_bytes(bundle)); r.write_bytes(canonical_bytes(request))
    before = (b.read_bytes(), r.read_bytes())
    assert main(["polish", "assess", str(b), "--request", str(r), "--contract-version", "2", "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "verifier-polish-assessment-2"
    a.write_bytes(canonical_bytes(report))
    assert main(["polish", "check", str(a), "--bundle", str(b), "--request", str(r),
                 "--contract-version", "2", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["replay_status"] == "REPRODUCED"
    assert (b.read_bytes(), r.read_bytes()) == before


@pytest.mark.parametrize("field", ["bundle_bytes", "objects", "requirements", "objectives",
    "certificates", "evidence_bytes", "certificate_bytes", "replay_bytes",
    "composition_payload_bytes", "composition_reference_bytes", "output_bytes"])
def test_exact_workload_bound_passes_and_one_less_stops_before_replay(workload, monkeypatch, field):
    bundle, request = version2(*workload)
    full = assess(bundle, request)
    exact = full["resource_usage"][field]
    request["limits"][field] = exact
    result = assess(bundle, request)
    assert len(result["objectives"]) == 66 and all(row["status"] == "PASS" for row in result["objectives"])
    request["limits"][field] = exact - 1
    forbid_replay(monkeypatch)
    result = assess(bundle, request)
    assert result["reason"] == "RESOURCE_LIMIT_EXCEEDED" and result["exhausted_resource"] == field


def test_request_byte_limit_accounts_for_its_own_encoded_selection(monkeypatch):
    bundle, request = version2(*fixture())
    for _ in range(5):
        request["limits"]["request_bytes"] = len(canonical_bytes(request))
    assert request["limits"]["request_bytes"] == len(canonical_bytes(request))
    assert assess(bundle, request)["objectives"][0]["status"] == "PASS"
    request["limits"]["request_bytes"] -= 1
    forbid_replay(monkeypatch)
    assert assess(bundle, request)["exhausted_resource"] == "request_bytes"


def test_repeated_selected_certificate_still_consumes_replay_capacity(monkeypatch):
    bundle, request = version2(*fixture())
    first = request["requirements"][0]["objectives"][0]
    duplicate = deepcopy(first)
    duplicate["coordinate"] = "OBJECT-1.2"
    request["requirements"][0]["objectives"].append(duplicate)
    single = len(next(iter(fixture()[0]["certificates"].values())).encode())
    request["limits"]["replay_bytes"] = single
    forbid_replay(monkeypatch)
    assert assess(bundle, request)["exhausted_resource"] == "replay_bytes"


@pytest.mark.parametrize("field", ["object_id", "record_digest", "policy"])
def test_subject_or_policy_substitution_cannot_promote_reconstructed_certificate(field):
    bundle, request = version2(*fixture())
    selected = request["requirements"][0]["objectives"][0]
    if field == "policy":
        selected["policy"]["trust_roots"] = ["substituted"]
    else:
        selected["request"][field] = "other" if field == "object_id" else digest(b"other")
    assert assess(bundle, request)["status"] == "FAIL"


def test_missing_certificate_and_unregistered_objective_remain_unknown():
    bundle, request = version2(*fixture())
    bundle["certificates"] = {}; bundle["evidence_payloads"] = {}
    request["bundle_digest"] = digest(canonical_bytes(bundle))
    result = assess(bundle, request)
    assert result["objectives"][0]["reason"] == "PUBLIC_REPLAY_EVIDENCE_MISSING"
    request["requirements"][0]["objectives"][0]["coordinate"] = "OBJECT-1.99"
    result = assess(bundle, request)
    assert result["objectives"][0]["reason"] == "UNREGISTERED_OBJECTIVE"
    assert result["status"] == "UNKNOWN" and not result["polished"]


def test_shared_text_replacement_refuses_even_after_transport_rebinding(workload):
    bundle, request = version2(*workload)
    old = next(iter(bundle["evidence_payloads"]))
    replacement = b"{}"
    new = digest(replacement)
    del bundle["evidence_payloads"][old]
    bundle["evidence_payloads"][new] = base64.b64encode(replacement).decode()
    replacements = {}
    for key, packed in list(bundle["certificates"].items()):
        if packed["evidence_ref"] != old:
            continue
        packed["evidence_ref"] = new
        rebuilt = canonical_bytes({**packed["envelope"], "evidence": replacement.decode()})
        replacements[key] = digest(rebuilt)
        bundle["certificates"][replacements[key]] = bundle["certificates"].pop(key)
    for row in request["requirements"]:
        for selected in row["objectives"]:
            selected["certificate_digest"] = replacements.get(selected["certificate_digest"], selected["certificate_digest"])
    request["bundle_digest"] = digest(canonical_bytes(bundle))
    result = assess(bundle, request)
    assert result["status"] == "FAIL" and not result["polished"]


def test_output_reservation_covers_maximum_escaped_selection_text():
    bundle, request = version2(*fixture())
    request["requirements"][0]["objectives"][0]["semantic_version"] = "\x01" * 256
    result = assess(bundle, request)
    assert result["objectives"][0]["reason"] == "UNREGISTERED_OBJECTIVE"
    assert len(canonical_bytes(result)) <= result["resource_usage"]["output_bytes"]


def test_capacity_helper_substitution_invalidates_aggregate_mechanism(monkeypatch):
    from verifier.runtime import polish_capacity
    before = polish.mechanism_digest()
    target = Path(polish_capacity.__file__)
    original = Path.read_bytes
    def changed(path):
        raw = original(path)
        return raw + b"\n# different capacity implementation\n" if path == target else raw
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("relative", [
    "domains/contracts/sim_perspective.py",
    "standard/CURRENT_SIM_PERSPECTIVE.md",
    "domains/contracts/sim_external_law.py",
    "standard/CURRENT_SIM_EXTERNAL_LAW.md",
    "domains/contracts/space_closure.py",
    "standard/CURRENT_SPACE_CLOSURE.md",
])
def test_current_route_substitution_invalidates_aggregate_mechanism(monkeypatch, relative):
    before = polish.mechanism_digest()
    target = (Path(polish.__file__).resolve().parents[1] / relative).resolve()
    original = Path.read_bytes

    def changed(path):
        raw = original(path)
        return raw + b"\n# selected mechanism substitution\n" if path.resolve() == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before
