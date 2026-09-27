"""Terminology: command-line interface (CLI); Verifier Standard (VSTD).

JavaScript Object Notation (JSON); grounded decision certificate (GDC).
"""
from __future__ import annotations

import copy
from dataclasses import replace
import json

import pytest

from verifier.core.certificate import (
    CertificateHeader, ClaimBinding, ClaimCoordinate, ClauseGrounding, CostTier,
    DecisionBlock, DecisionCertificate, EncodingRule, GroundedFact, Grounding,
    ResourceBounds, VariableGrounding, Verdict, canonical_bytes, canonical_digest,
)
from verifier.core.certification_mechanisms import NativeCertificationMechanism
from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, VerificationSession
from verifier.core.grounded_certification import (
    CertificationError, CertificationPolicy, CertificationRequest, MechanismAdmission,
    assess_grounded_certification, build_grounded_certificate, evidence_root,
    recheck_grounded_certificate,
)
from verifier.core.kernel import reference_descriptor
from verifier.core.profile_obligations import BY_ID
from verifier.runtime.public_cli import main


def native_request(obligation, evidence, *, coordinate=None, claim="A bounded claim."):
    mechanism = NativeCertificationMechanism()
    store = EvidenceStore()
    ref = store.add(canonical_bytes(evidence))
    policy = CertificationPolicy({obligation: MechanismAdmission(
        mechanism.mechanism_id, mechanism.mechanism_digest, ("local:native-checker",))})
    binding = ClaimBinding(claim, coordinate or ClaimCoordinate("subject:example", "bounded"),
        policy.digest(), evidence_root([ref]), reference_descriptor(), ResourceBounds(10000, 10000, 1000000))
    proposition = BoundProposition("claim:example", BY_ID[obligation].predicate, True,
        mechanism.mechanism_id, mechanism.mechanism_digest, (ref,), ("local:native-checker",),
        EvidenceBounds(1, 1000000), {"claim_binding_digest": binding.digest(),
        "claim_binding": canonical_bytes(binding.to_dict()).decode()})
    request = CertificationRequest("claim:example", binding, BY_ID[obligation].profile, {obligation: proposition})
    session = VerificationSession(store)
    session.register(mechanism)
    return request, policy, session


def claim_request():
    record = {"claim_id": "claim:example", "subject": "subject:example",
        "statement": "A bounded claim.", "predicate": "bounded", "scope": "one local record",
        "limitations": ["Record binding does not establish the statement."],
        "falsification_condition": "The record differs from the committed coordinate."}
    return native_request("1.1", record, coordinate=ClaimCoordinate("subject:example", "bounded",
        {"scope": record["scope"], "claim_record_digest": canonical_digest(record)}))


def test_native_claim_binding_earns_only_its_specific_obligation():
    request, policy, session = claim_request()
    cert = build_grounded_certificate(request, policy=policy, session=session)
    assert cert["result"]["obligations"]["1.1"]["outcome"] == "PASS"
    assert cert["result"]["status"] == "UNKNOWN"
    assert cert["result"]["certified_profile_depth"] == 0
    assert recheck_grounded_certificate(cert, policy=policy,
        mechanisms=[NativeCertificationMechanism()], expected_request_digest=canonical_digest(request.to_dict())) == cert["result"]


def decision_evidence():
    binding = ClaimBinding("The committed formula has a checked model.",
        ClaimCoordinate("subject:example", "formula-has-model"), "a"*64, "b"*64,
        reference_descriptor(), ResourceBounds(10000, 10000, 1000000))
    grounding = Grounding((VariableGrounding(1, GroundedFact("subject:example", "atom", "TRUE")),),
        (ClauseGrounding(0, "ATOM", {"atom": 1}, {"atom": "subject:example"}),),
        (EncodingRule("ATOM", ("atom",), ((1, "atom"),)),))
    cert = DecisionCertificate(CertificateHeader(Verdict.PASS, CostTier.UP, 1, 1, 1, 0,
        binding.digest()), ((1,),), grounding, DecisionBlock(model={1: True}))
    return {"binding": binding.to_dict(), "certificate": cert.to_dict()}, binding


@pytest.mark.parametrize("obligation", ["4.1", "4.3", "4.5"])
@pytest.mark.parametrize("tamper", [False, True])
def test_native_decision_checker_replays_proof_not_status(obligation, tamper):
    evidence, binding = decision_evidence()
    if tamper:
        evidence["certificate"]["decision"]["model"]["1"] = False
    request, policy, session = native_request(obligation, evidence,
        coordinate=ClaimCoordinate("subject:example", "decision-check", {"decision_binding_digest": binding.digest()}))
    result = assess_grounded_certification(request, policy=policy, session=session)
    assert result["obligations"][obligation]["outcome"] == ("FAIL" if tamper else "PASS")
    assert result["certified_profile_depth"] == 0


def test_native_decision_refuses_missing_resource_ceiling():
    evidence, binding = decision_evidence()
    binding = replace(binding, bounds=ResourceBounds(10000, 10000, 0))
    evidence["binding"] = binding.to_dict()
    evidence["certificate"]["header"]["binding"] = binding.digest()
    request, policy, session = native_request("4.5", evidence,
        coordinate=ClaimCoordinate("subject:example", "decision-check", {"decision_binding_digest": binding.digest()}))
    result = assess_grounded_certification(request, policy=policy, session=session)
    assert result["obligations"]["4.5"]["outcome"] == "UNKNOWN"


@pytest.mark.parametrize("obligation", ["2.1", "2.2"])
@pytest.mark.parametrize("tamper", [False, True])
def test_native_geometry_checker_validates_bound_references(obligation, tamper):
    from verifier.core.geometry import (
        Subject, Facet, Locus, LocusKind, Grain, Stratum, Coordinate,
        VerificationSurface, VerificationGeometry,
    )
    geometry = VerificationGeometry("geometry:example", "subject:example",
        [Subject("subject:example", "Example", "1")],
        [Locus("locus:example", "subject:example", "Example", LocusKind.PROCESS,
               Grain.SUBJECT, Stratum.EXECUTION, "example")],
        [Facet("facet:example", "Example", "one facet")],
        [Coordinate("coordinate:example", "locus:example", "facet:example")],
        VerificationSurface("surface:example", "subject:example", ("coordinate:example",),
                            scope_statement="one coordinate"))
    payload = geometry.to_dict()
    if tamper:
        payload["coordinates"][0]["locus_id"] = "missing:locus"
    request, policy, session = native_request(obligation, payload,
        coordinate=ClaimCoordinate("subject:example", "geometry-check", {"geometry_digest": geometry.canonical_digest()}))
    result = assess_grounded_certification(request, policy=policy, session=session)
    assert result["obligations"][obligation]["outcome"] == ("FAIL" if tamper else "PASS")


def test_cli_catalog_and_unknown_certificate_round_trip(tmp_path, capsys):
    assert main(["certification", "catalog", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["obligations"]) == 47
    request, policy, session = claim_request()
    req = tmp_path / "request.json"
    pol = tmp_path / "policy.json"
    ev = tmp_path / "evidence.json"
    cert = tmp_path / "certificate.json"
    req.write_bytes(canonical_bytes(request.to_dict()))
    pol.write_bytes(canonical_bytes(policy.to_dict()))
    refs = tuple(r for p in request.obligations.values() for r in p.evidence_refs)
    ev.write_bytes(canonical_bytes(session.evidence.export_base64(refs)))
    args = ["certification", "assess", str(req), "--policy", str(pol), "--evidence", str(ev),
            "--output", str(cert), "--json"]
    assert main(args) == 2
    assert json.loads(capsys.readouterr().out)["result"]["obligations"]["1.1"]["outcome"] == "PASS"
    assert main(["certification", "check", str(cert), "--request", str(req), "--policy", str(pol), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "UNKNOWN"
    original = cert.read_bytes()
    assert main(args) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "REJECTED"
    assert cert.read_bytes() == original


def test_cli_rejects_duplicate_keys_and_embedded_plugin_instructions(tmp_path, capsys):
    req = tmp_path / "request.json"
    pol = tmp_path / "policy.json"
    pol.write_text('{"schema_version":"x","schema_version":"y"}')
    assert main(["certification", "assess", str(req), "--policy", str(pol),
                 "--evidence", "unused", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "REJECTED"
    _, policy, _ = claim_request()
    payload = policy.to_dict()
    payload["plugin"] = "arbitrary:import"
    with pytest.raises(CertificationError):
        CertificationPolicy.from_dict(payload)
