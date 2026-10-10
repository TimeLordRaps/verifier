"""Public typed-subject security integration under exact external selection.

Verifier Standard (VSTD); command-line interface (CLI); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Counts are
dimensionless. The independent retained-entry specimen is reused from the
native adversarial tests, without calling a producer message helper.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import subject_security as security
from verifier.domains.inventory import MECHANIZED_12_POINT_BINDINGS, slot_inventory
from verifier.runtime import polish
from verifier.runtime.public_cli import main
from test_current_subject_security import KINDS, digest, encoded, fixture, replay


def public_replay(certificate: bytes, request: dict[str, Any], policy: dict[str, Any],
        *, represented_kind: str | None = None) -> dict[str, Any]:
    return routes.replay_current_object_certificate(certificate,
        semantic_version=request["semantic_version"], objective=request["coordinate"],
        represented_kind=represented_kind or request["object_kind"],
        expected_request=request, policy=policy)


@pytest.mark.parametrize("kind", KINDS)
def test_every_public_kind_replays_exact_native_subject_binding(kind: str) -> None:
    request, policy, evidence, _ = fixture(kind)
    certificate, native = replay(request, policy, evidence)
    report = public_replay(certificate, request, policy)
    assert report["schema_version"] == "verifier-current-object-route-replay-1"
    assert report["selection"] == {"semantic_version": security.SEMANTIC_VERSION,
        "objective": security.coordinate(kind), "represented_kind": kind}
    assert report["replay_status"] == "REPRODUCED"
    assert report["computational_status"] == "PASS" and report["native_result"] == native
    assert report["certificate_sha256"] == digest(certificate)
    assert report["request_sha256"] == digest(encoded(request))
    assert report["policy_sha256"] == digest(encoded(policy))
    assert "typed-subject" in report["claim_boundary"]
    assert "no issuer authenticity" in report["claim_boundary"]


@pytest.mark.parametrize("kind", KINDS)
def test_wrong_public_represented_kind_cannot_transplant_selected_certificate(kind: str) -> None:
    request, policy, evidence, _ = fixture(kind)
    certificate, _ = replay(request, policy, evidence)
    foreign_kind = "ENV" if kind != "ENV" else "MODEL"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        public_replay(certificate, request, policy, represented_kind=foreign_kind)


@pytest.mark.parametrize("field,value", [
    ("object_kind", "ENV"), ("object_kind", None),
    ("coordinate", "MODEL-9.2"), ("semantic_version", "legacy"),
    ("status", "REJECTED"), ("status", True),
    ("object_profile_conformance", "PASS"),
])
def test_public_route_rejects_inconsistent_native_result(field: str, value: Any,
        monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, _ = fixture("MODEL")
    certificate, native = replay(request, policy, evidence)
    key = (security.SEMANTIC_VERSION, security.coordinate("MODEL"))
    selected_route = routes.select_current_object_route(semantic_version=key[0],
        objective=key[1], represented_kind="MODEL")
    def inconsistent(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {**native, field: value}
    monkeypatch.setitem(routes._ROUTES, key, replace(selected_route, replay=inconsistent))
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        public_replay(certificate, request, policy)


@pytest.mark.parametrize("kind", KINDS)
def test_catalog_and_numbered_inventory_bind_exact_kind_and_proposition(kind: str) -> None:
    coordinate = security.coordinate(kind)
    selected = [row for row in routes.current_object_route_catalog()
                if row["objective"] == coordinate and row["semantic_version"] == security.SEMANTIC_VERSION]
    assert len(selected) == 1
    assert selected[0]["represented_kind_rule"] == kind
    assert selected[0]["certificate_schema_version"] == security.CERTIFICATE_VERSION
    assert selected[0]["scope"] == security.SCOPE
    assert selected[0]["proposition_digest"] == security.SubjectSecurityDescriptor(kind).PROPOSITION_DIGEST
    assert selected[0]["object_profile_conformance"] == "NOT_ESTABLISHED"
    binding = MECHANIZED_12_POINT_BINDINGS[coordinate]
    assert binding["exact_claim"] == security.registration(kind)["proposition"]
    assert binding["artifact_coordinate"] == coordinate
    assert binding["checking_mechanism"] == "verifier.domains.contracts.subject_security.recheck_subject_security_certificate"
    assert binding["resulting_evidence"] == security.CERTIFICATE_VERSION
    assert binding["admitted_verdicts"] == ["PASS", "FAIL", "UNKNOWN"]
    slot = next(row for row in slot_inventory() if row["object_kind"] == kind and row["tier"] == 9)
    assert slot["mechanized"] is True
    assert slot["coordinate"] == ("RECEIPT-9.1" if kind == "RECEIPT" else coordinate)
    assert {objective["coordinate"] for objective in slot["registered_objectives"]} >= {coordinate}
    assert slot["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert slot["coordinate_role"] == "PRIMARY_REGISTERED_OBJECTIVE"


def test_receipt_chain_and_issuer_signature_registration_are_preserved() -> None:
    catalog = {row["objective"]: row for row in routes.current_object_route_catalog()}
    assert catalog["RECEIPT-9.1"]["certificate_schema_version"] == "verifier-current-receipt-chain-certificate-1"
    assert catalog["RECEIPT-9.2"]["certificate_schema_version"] == "verifier-current-receipt-authenticity-certificate-1"
    assert catalog["RECEIPT-9.3"]["certificate_schema_version"] == security.CERTIFICATE_VERSION
    assert len({catalog[address]["proposition_digest"] for address in ("RECEIPT-9.1", "RECEIPT-9.2", "RECEIPT-9.3")}) == 3


@pytest.mark.parametrize("changes,status", [({}, "PASS"),
    ({"chain_subjects": ["foreign-subject"]}, "FAIL"),
    ({"include_chain": False}, "UNKNOWN"), ({"child_status": "UNKNOWN"}, "UNKNOWN"),
    ({"child_status": "FAIL"}, "FAIL")])
def test_public_route_preserves_native_pass_fail_and_unknown(changes: dict[str, Any], status: str) -> None:
    request, policy, evidence, _ = fixture(**changes)
    certificate, native = replay(request, policy, evidence)
    report = public_replay(certificate, request, policy)
    assert report["computational_status"] == native["status"] == status
    assert report["replay_status"] == "REPRODUCED"
    assert report["native_result"]["issuer_authenticity"] == "NOT_ESTABLISHED"
    assert report["native_result"]["context_consumption"] == "NOT_ESTABLISHED"


def assessment_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    request, policy, evidence, _ = fixture("OBJECT")
    certificate, _ = replay(request, policy, evidence)
    item = NamespaceObject.create(**json.loads(evidence)["subject"])
    ref = digest(certificate)
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": [item.to_dict()],
              "certificates": {ref: certificate.decode("utf-8")}}
    assessment = {"schema_version": "verifier-polish-request-1", "root_id": item.object_id,
        "collection_digest": composition_digest([item]), "bundle_digest": digest(encoded(bundle)),
        "requirements": [{"object_id": item.object_id, "tier": tier, "applicability": "REQUIRED",
            "rationale": "Externally selected finite association", "objectives": []} for tier in range(1, 10)]}
    assessment["requirements"][8]["objectives"] = [{"semantic_version": security.SEMANTIC_VERSION,
        "coordinate": security.coordinate("OBJECT"), "request": request, "policy": policy,
        "certificate_digest": ref}]
    return bundle, assessment


@pytest.mark.parametrize("version", ["1", "2"])
def test_polish_replays_exact_native_subject_pass_without_aggregate_promotion(version: str) -> None:
    bundle, assessment = assessment_pair()
    if version == "2":
        from test_polish_capacity import version2
        bundle, assessment = version2(bundle, assessment)
    report = polish.assess_polish(encoded(bundle), request_bytes=encoded(assessment), contract_version=version)
    assert report["composition_status"] == "PASS"
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["reason"] == "NATIVE_REPLAY"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    assert report["objective_inventory_closure"] == "NOT_ESTABLISHED"
    bundle["objects"][0]["payload"]["declared"] = "transplanted after selection"
    assessment["bundle_digest"] = digest(encoded(bundle))
    assessment["collection_digest"] = composition_digest([NamespaceObject.create(**record) for record in bundle["objects"]])
    changed = polish.assess_polish(encoded(bundle), request_bytes=encoded(assessment), contract_version=version)
    assert changed["objectives"][0]["status"] == "FAIL"
    assert changed["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"
    assert changed["status"] == "FAIL" and changed["polished"] is False


@pytest.mark.parametrize("relative", ["domains/contracts/subject_security.py", "standard/CURRENT_SUBJECT_SECURITY.md"])
def test_polish_fingerprint_includes_exact_subject_security_bytes(relative: str, monkeypatch: pytest.MonkeyPatch) -> None:
    target = Path(polish.__file__).parents[1] / relative
    original = Path.read_bytes
    before = polish.mechanism_digest()
    def changed(path: Path) -> bytes:
        raw = original(path)
        return raw + b"\nchanged subject-security dependency\n" if path == target else raw
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("kind", KINDS)
def test_declared_requirement_helper_selects_exact_kind_mechanism_digest(kind: str) -> None:
    from verifier.runtime import polish_requirements
    request, policy, _, _ = fixture(kind)
    binding = polish_requirements.registered_objective_binding(
        security.SEMANTIC_VERSION, security.coordinate(kind), kind)
    assert binding == {"mechanism_id": security.MECHANISM_ID,
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": request["proposition_digest"]}
    assert binding["mechanism_digest"] == security.mechanism_digest(kind)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        polish_requirements.registered_objective_binding(security.SEMANTIC_VERSION,
            security.coordinate(kind), "ENV" if kind != "ENV" else "MODEL")


@pytest.mark.parametrize("changes,status,exit_code", [({}, "PASS", 0),
    ({"chain_subjects": ["foreign-subject"]}, "FAIL", 1),
    ({"include_chain": False}, "UNKNOWN", 2)])
def test_public_cli_replays_read_only_with_exact_exit_status(changes: dict[str, Any],
        status: str, exit_code: int, tmp_path: Path, capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence, _ = fixture(**changes)
    certificate, _ = replay(request, policy, evidence)
    certificate_path = tmp_path / "certificate.json"
    request_path = tmp_path / "request.json"
    policy_path = tmp_path / "policy.json"
    certificate_path.write_bytes(certificate)
    request_path.write_bytes(encoded(request))
    policy_path.write_bytes(encoded(policy))
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    def no_write(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("read-only current-object CLI attempted an artifact write")
    monkeypatch.setattr(Path, "write_bytes", no_write)
    monkeypatch.setattr(Path, "write_text", no_write)
    result = main(["current-object", "check", str(certificate_path),
        "--semantic-version", security.SEMANTIC_VERSION, "--objective", request["coordinate"],
        "--represented-kind", request["object_kind"], "--request", str(request_path),
        "--policy", str(policy_path), "--json"])
    assert result == exit_code
    report = json.loads(capsys.readouterr().out)
    assert report["computational_status"] == status and report["replay_status"] == "REPRODUCED"
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize("version", ["1", "2"])
def test_registered_security_assessment_refutes_only_subject_id_substitution(version: str) -> None:
    bundle, assessment = assessment_pair()
    if version == "2":
        from test_polish_capacity import version2
        bundle, assessment = version2(bundle, assessment)
    before = polish.assess_polish(encoded(bundle), request_bytes=encoded(assessment), contract_version=version)
    assert before["objectives"][0]["status"] == "PASS"
    assert before["objectives"][0]["reason"] == "NATIVE_REPLAY"
    assert before["status"] == "UNKNOWN" and before["polished"] is False
    assert before["objective_inventory_closure"] == "NOT_ESTABLISHED"
    # Retain the exact selected subject, bundle, certificate and policy; change
    # only the independently supplied native request's subject identity.
    assessment["requirements"][8]["objectives"][0]["request"]["subject_id"] = "foreign-subject"
    after = polish.assess_polish(encoded(bundle), request_bytes=encoded(assessment), contract_version=version)
    assert after["objectives"][0]["status"] == "FAIL"
    assert after["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"
    assert after["status"] == "FAIL" and after["polished"] is False
