"""Composed object/context closure rejects independently passing substitutions.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). The positive fixture is a finite synthetic control,
not evidence of actual revision history, authority, or whole-object conformance.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import application_requirements as application
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import receipt_chain
from verifier.domains.contracts import selected_native_contexts as contexts
from verifier.domains.contracts import subject_security as security
from verifier.domains.contracts import typed_facets
from verifier.runtime import object_context_closure as closure


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def security_selection(subject: NamespaceObject, context_digest: str
        ) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    chain_policy = receipt_chain.receipt_chain_policy(trust_roots=["external-chain-anchor"])
    policy = security.subject_security_policy(object_kind=subject.kind.value,
        chain_policy=chain_policy, trust_roots=["external-context-selection"])
    message = security.subject_security_message(object_kind=subject.kind.value,
        subject_id=subject.object_id, object_digest=subject.digest,
        receipt_object_id="selected-receipt", domain="synthetic-control",
        genesis_digest="sha256:" + "a" * 64, first_sequence=0, sequence=0,
        context_digest=context_digest, policy=policy)
    raw_message = encoded(message)
    tip = digest(encoded({"schema_version": "verifier-receipt-chain-link-1",
        "domain": "synthetic-control", "sequence": 0,
        "previous": "sha256:" + "a" * 64, "receipt_digest": digest(raw_message)}))
    receipt = {"object_id": "selected-receipt", "kind": "RECEIPT",
        "payload": {"chain_domain": "synthetic-control",
            "chain_genesis_digest": "sha256:" + "a" * 64,
            "chain_first_sequence": 0, "chain_tip_digest": tip},
        "operands": {"subject": [subject.object_id], "hardware": ["retained-device"]}}
    chain_evidence = encoded({"schema_version": "verifier-receipt-chain-evidence-1",
        "domain": "synthetic-control", "receipt_object": receipt,
        "entries": [{"sequence": 0,
            "receipt_base64": base64.b64encode(raw_message).decode("ascii")}]})
    chain_request = receipt_chain.receipt_chain_request(
        receipt_object_id="selected-receipt", receipt_object_digest=digest(encoded(receipt)),
        domain="synthetic-control", genesis_digest="sha256:" + "a" * 64,
        first_sequence=0, tip_digest=tip, evidence_ref=digest(chain_evidence),
        policy=chain_policy)
    chain_certificate = receipt_chain.build_receipt_chain_certificate(
        chain_request, chain_evidence, policy=chain_policy)
    evidence = encoded({"schema_version": "verifier-current-subject-security-evidence-1",
        "subject": subject.to_dict(), "chain_certificate": chain_certificate.decode("utf-8")})
    request = security.subject_security_request(object_kind=subject.kind.value,
        subject_id=subject.object_id, object_digest=subject.digest,
        context_digest=context_digest, chain_request=chain_request,
        chain_certificate_digest=digest(chain_certificate), chain_sequence=0,
        evidence_ref=digest(evidence), policy=policy)
    certificate = security.build_subject_security_certificate(request, evidence, policy=policy)
    assert security.recheck_subject_security_certificate(certificate,
        expected_request=request, policy=policy)["status"] == "PASS"
    return certificate, request, policy


def selected_fixture() -> dict[str, Any]:
    subject = NamespaceObject.create("selected-human", "HUMAN",
        {"declared": "bounded synthetic control"})
    evidence = canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION,
        "objects": [subject.to_dict()]})
    native_policy = typed_facets.typed_facets_policy(
        trust_roots=["external-native-selection"])
    native_request = typed_facets.typed_facets_request(object_kind="HUMAN",
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]), evidence_ref=digest(evidence),
        policy=native_policy)
    native_certificate = typed_facets.build_typed_facets_certificate(
        native_request, evidence, policy=native_policy)
    registration = typed_facets.registration("HUMAN")
    profile = {"schema_version": dag.PROFILE, "profile_id": "selected-human-profile",
        "profile_version": "1", "object_kind": "HUMAN", "obligations": [{
            "claim_id": "declared-facets", "semantic_version": typed_facets.SEMANTIC_VERSION,
            "objective": typed_facets.coordinate("HUMAN"),
            "proposition_digest": typed_facets.FacetDescriptor("HUMAN").PROPOSITION_DIGEST,
            "scope": registration["scope"], "assumptions": [], "dependencies": []}]}
    profile_digest = digest(canonical_bytes(profile))
    node = {"node_id": "declared-facets", "object_id": subject.object_id,
        "claim_id": "declared-facets", "certificate_path": "certificates/facets.json",
        "certificate_digest": digest(native_certificate), "request": native_request,
        "checker_policy": native_policy, "contract_version": "1",
        "artifact_bindings": [{"path": "retained/source.bin",
            "digest": digest(b"retained source bytes")}],
        "facet_bindings": {"payload_digest": digest(subject.payload_bytes),
            "operands_digest": digest(canonical_bytes(subject.to_dict()["operands"]))}}
    bundle = {"schema_version": dag.BUNDLE, "profiles": [profile],
        "objects": [subject.to_dict()], "nodes": [node], "edges": []}
    files = {"certificates/facets.json": native_certificate,
        "retained/source.bin": b"retained source bytes"}
    dependency_policy = {"schema_version": dag.POLICY,
        "approved_profiles": [profile_digest], "required_objects": [{
            "object_id": subject.object_id, "object_kind": "HUMAN",
            "record_digest": subject.digest, "profile_digest": profile_digest}],
        "required_roots": [node["node_id"]], "nodes": deepcopy(bundle["nodes"]),
        "artifact_files_digest": dag.artifact_files_digest(files)}
    compiler_body = {"schema_version": application.SCHEMA, "status": "UNKNOWN",
        "replayable": False, "mechanism_digest": None, "closure_status": "UNKNOWN",
        "claim_boundary": "bounded synthetic compiler-manifest bytes only"}
    compiler_manifest_digest = digest(canonical_bytes(compiler_body))
    compiler_manifest = canonical_bytes({**compiler_body,
        "manifest_digest": compiler_manifest_digest})
    context_policy = {"schema_version": contexts.POLICY,
        "mechanism_digest": contexts.mechanism_digest(),
        "compiler_manifest_digest": compiler_manifest_digest, "contexts": [{
            "node_id": node["node_id"], "adapter_id": "typed-collection/1",
            "subject_id": subject.object_id, "object_kind": "HUMAN",
            "object_digest": subject.digest, "member_ids": [subject.object_id],
            "collection_digest": composition_digest([subject])}]}
    context_assessment = contexts.assess_selected_native_contexts(canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency_policy),
        expected_context_policy_bytes=canonical_bytes(context_policy), artifact_files=files)
    assert context_assessment["status"] == "PASS"
    context_assessment_bytes = canonical_bytes(context_assessment)
    context_assessment_digest = context_assessment["assessment_digest"]
    security_certificate, security_request, security_policy = security_selection(
        subject, context_assessment_digest)
    ancestry = canonical_bytes({"schema_version": closure.ANCESTRY_EVIDENCE_SCHEMA,
        "subject_id": subject.object_id, "object_digest": subject.digest,
        "evidence_kind": "DECLARED_REVISION_OR_ANCESTRY_EVIDENCE",
        "admission": "EXTERNALLY_ADMITTED",
        "actual_revision_history": "NOT_ESTABLISHED"})
    denominator = canonical_bytes({"schema_version": closure.APPLICABILITY_SCHEMA,
        "subject_id": subject.object_id, "object_digest": subject.digest,
        "context_assessment_digest": context_assessment_digest,
        "node_ids": [node["node_id"]], "admission": "EXTERNALLY_ADMITTED",
        "complete_application_applicability": "NOT_ESTABLISHED"})
    return {"bundle_bytes": canonical_bytes(bundle),
        "expected_dependency_policy_bytes": canonical_bytes(dependency_policy),
        "expected_context_policy_bytes": canonical_bytes(context_policy),
        "selected_context_assessment_bytes": context_assessment_bytes,
        "expected_selected_context_assessment_digest": context_assessment_digest,
        "compiler_manifest_bytes": compiler_manifest,
        "expected_compiler_manifest_digest": compiler_manifest_digest,
        "subject_security_certificate_bytes": security_certificate,
        "expected_subject_security_request": security_request,
        "subject_security_policy": security_policy,
        "ancestry_evidence_bytes": ancestry,
        "expected_ancestry_evidence_digest": digest(ancestry),
        "applicability_denominator_bytes": denominator,
        "expected_applicability_denominator_digest": digest(denominator),
        "artifact_files": files}


def assess(args: dict[str, Any]) -> dict[str, Any]:
    return closure.assess_object_context_closure(**args)


def refresh_context(args: dict[str, Any]) -> None:
    report = contexts.assess_selected_native_contexts(args["bundle_bytes"],
        expected_dependency_policy_bytes=args["expected_dependency_policy_bytes"],
        expected_context_policy_bytes=args["expected_context_policy_bytes"],
        artifact_files=args["artifact_files"])
    assert report["status"] == "PASS"
    args["selected_context_assessment_bytes"] = canonical_bytes(report)
    context_digest = report["assessment_digest"]
    args["expected_selected_context_assessment_digest"] = context_digest
    bundle = json.loads(args["bundle_bytes"])
    subject = NamespaceObject.create(**bundle["objects"][0])
    certificate, request, policy = security_selection(subject, context_digest)
    args.update(subject_security_certificate_bytes=certificate,
        expected_subject_security_request=request, subject_security_policy=policy)
    denominator = canonical_bytes({"schema_version": closure.APPLICABILITY_SCHEMA,
        "subject_id": subject.object_id, "object_digest": subject.digest,
        "context_assessment_digest": context_digest,
        "node_ids": sorted(node["node_id"] for node in bundle["nodes"]),
        "admission": "EXTERNALLY_ADMITTED",
        "complete_application_applicability": "NOT_ESTABLISHED"})
    args["applicability_denominator_bytes"] = denominator
    args["expected_applicability_denominator_digest"] = digest(denominator)


def test_bounded_positive_synthetic_control_passes_only_composed_closure() -> None:
    result = assess(selected_fixture())
    assert result["status"] == "PASS"
    assert set(result["components"]) == {"compiler_manifest", "selected_context",
        "native_certificates", "subject_security", "ancestry_evidence",
        "applicability_denominator"}
    assert all(row["status"] == "PASS" for row in result["components"].values())
    for field in ("authority", "permissions", "release", "whole_object_acceptance",
                  "whole_security_conformance", "actual_revision_history",
                  "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"


def test_all_ones_compiler_pin_cannot_reuse_narrow_context_pass() -> None:
    args = selected_fixture()
    policy = json.loads(args["expected_context_policy_bytes"])
    policy["compiler_manifest_digest"] = "sha256:" + "1" * 64
    args["expected_context_policy_bytes"] = canonical_bytes(policy)
    args["expected_compiler_manifest_digest"] = "sha256:" + "1" * 64
    refresh_context(args)
    assert json.loads(args["selected_context_assessment_bytes"])["status"] == "PASS"
    result = assess(args)
    assert result["status"] == "FAIL"
    assert result["components"]["compiler_manifest"]["status"] == "FAIL"


def test_missing_path_and_zero_certificate_digest_cannot_reuse_context_pass() -> None:
    args = selected_fixture()
    bundle = json.loads(args["bundle_bytes"])
    dependency = json.loads(args["expected_dependency_policy_bytes"])
    bundle["nodes"][0]["certificate_path"] = "certificates/missing.json"
    bundle["nodes"][0]["certificate_digest"] = "sha256:" + "0" * 64
    dependency["nodes"] = deepcopy(bundle["nodes"])
    files = {key: value for key, value in args["artifact_files"].items()
             if key != "certificates/facets.json"}
    dependency["artifact_files_digest"] = dag.artifact_files_digest(files)
    args.update(bundle_bytes=canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency), artifact_files=files)
    refresh_context(args)
    assert json.loads(args["selected_context_assessment_bytes"])["status"] == "PASS"
    result = assess(args)
    assert result["status"] == "UNKNOWN"
    assert result["components"]["native_certificates"]["status"] == "UNKNOWN"


def test_all_ones_zero_digest_and_missing_path_combination_cannot_pass() -> None:
    args = selected_fixture()
    bundle = json.loads(args["bundle_bytes"])
    dependency = json.loads(args["expected_dependency_policy_bytes"])
    policy = json.loads(args["expected_context_policy_bytes"])
    bundle["nodes"][0]["certificate_path"] = "certificates/missing.json"
    bundle["nodes"][0]["certificate_digest"] = "sha256:" + "0" * 64
    dependency["nodes"] = deepcopy(bundle["nodes"])
    files = {key: value for key, value in args["artifact_files"].items()
             if key != "certificates/facets.json"}
    dependency["artifact_files_digest"] = dag.artifact_files_digest(files)
    policy["compiler_manifest_digest"] = "sha256:" + "1" * 64
    args.update(bundle_bytes=canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency),
        expected_context_policy_bytes=canonical_bytes(policy), artifact_files=files,
        expected_compiler_manifest_digest="sha256:" + "1" * 64)
    refresh_context(args)
    result = assess(args)
    assert result["status"] == "FAIL"
    assert result["components"]["compiler_manifest"]["status"] == "FAIL"
    assert result["components"]["native_certificates"]["status"] == "UNKNOWN"


def test_present_wrong_certificate_digest_is_fail_not_unknown() -> None:
    args = selected_fixture()
    bundle = json.loads(args["bundle_bytes"])
    dependency = json.loads(args["expected_dependency_policy_bytes"])
    bundle["nodes"][0]["certificate_digest"] = "sha256:" + "0" * 64
    dependency["nodes"] = deepcopy(bundle["nodes"])
    args.update(bundle_bytes=canonical_bytes(bundle),
        expected_dependency_policy_bytes=canonical_bytes(dependency))
    refresh_context(args)
    result = assess(args)
    assert result["status"] == "FAIL"
    assert result["components"]["native_certificates"]["status"] == "FAIL"


def test_arbitrary_security_context_pass_is_refuted_by_composed_equality() -> None:
    args = selected_fixture()
    subject = NamespaceObject.create("selected-human", "HUMAN",
        {"declared": "bounded synthetic control"})
    certificate, request, policy = security_selection(subject, "sha256:" + "b" * 64)
    assert security.recheck_subject_security_certificate(certificate,
        expected_request=request, policy=policy)["status"] == "PASS"
    args.update(subject_security_certificate_bytes=certificate,
        expected_subject_security_request=request, subject_security_policy=policy)
    result = assess(args)
    assert result["status"] == "FAIL"
    assert result["components"]["subject_security"]["status"] == "FAIL"


def test_missing_independent_inputs_preserve_unknown() -> None:
    for missing in (("compiler_manifest_bytes", "expected_compiler_manifest_digest"),
                    ("ancestry_evidence_bytes", "expected_ancestry_evidence_digest"),
                    ("applicability_denominator_bytes",
                     "expected_applicability_denominator_digest")):
        args = selected_fixture()
        for field in missing:
            args[field] = None
        result = assess(args)
        assert result["status"] == "UNKNOWN"
        assert "FAIL" not in {row["status"] for row in result["components"].values()}
