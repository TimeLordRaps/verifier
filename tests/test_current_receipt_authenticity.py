"""Selected issuer-key authentication must preserve the exact receipt boundary.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Ed25519 is the Edwards-curve digital signature
algorithm with a 255-bit field. Times count integer Unix seconds. All signing
keys are ephemeral test values generated in memory, never retained as artifacts.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

import pytest

pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: issuer-key authentication verifies Ed25519 signatures and needs the seal extra (cryptography); the platform-python-contracts workflow job installs it")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import receipt_authenticity as auth, receipt_chain
from test_current_receipt_chain import _evidence, _selection


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def selected(*, child_status: str = "PASS", include_chain: bool = True,
        include_attestation: bool = True, wrong_signer: bool = False,
        payload_changes: dict[str, Any] | None = None,
        issued_at: int = 100, expires_at: int = 200, evaluation_time: int = 100,
        signature_byte: int | None = None, max_evidence_bytes: int = 4 * 1024 * 1024,
        composable: bool = False
        ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    chain_policy = receipt_chain.receipt_chain_policy(trust_roots=["selected-chain-anchor"])
    data, tip = _evidence((b"first", b"second"))
    if child_status == "FAIL":
        data, _ = _evidence((b"first", b"substituted"), object_tip=tip)
    if composable:
        value = json.loads(data)
        value["receipt_object"]["operands"] = {"subject": ["subject"], "hardware": ["hardware"]}
        data = canonical_bytes(value)
    chain_request = _selection(data, tip, policy=chain_policy)
    if composable:
        from verifier.core.namespace import NamespaceObject
        chain_request["receipt_object_digest"] = NamespaceObject.create(**json.loads(data)["receipt_object"]).digest
    child = receipt_chain.build_receipt_chain_certificate(chain_request,
        None if child_status == "UNKNOWN" else data, policy=chain_policy)
    policy = auth.receipt_authenticity_policy(issuer_key_id="selected-issuer-key",
        issuer_public_key=public, chain_policy=chain_policy,
        trust_roots=["externally-admitted-key"], max_validity_seconds=100)
    request = auth.receipt_authenticity_request(chain_request=chain_request,
        chain_certificate_digest=digest(child), challenge="12" * 32,
        evaluation_time=evaluation_time, evidence_ref="sha256:" + "0" * 64,
        policy=policy, max_evidence_bytes=max_evidence_bytes)
    payload = auth.receipt_authenticity_payload(request, policy=policy,
        issued_at=issued_at, expires_at=expires_at)
    payload.update(payload_changes or {})
    signer = Ed25519PrivateKey.generate() if wrong_signer else key
    signature = signer.sign(auth.receipt_authenticity_signing_bytes(payload))
    if signature_byte is not None:
        changed = bytearray(signature); changed[signature_byte] ^= 1 << (signature_byte % 8)
        signature = bytes(changed)
    evidence = canonical_bytes({"schema_version": auth.EVIDENCE_VERSION,
        "chain_certificate": child.decode() if include_chain else None,
        "attestation": {"schema_version": auth.ATTESTATION_VERSION,
            "key_id": policy["issuer_key_id"], "payload": payload,
            "signature": signature.hex()} if include_attestation else None})
    request["evidence_ref"] = digest(evidence)
    return request, policy, evidence


def replay(request: dict[str, Any], policy: dict[str, Any], evidence: bytes | None) -> tuple[bytes, dict[str, Any]]:
    certificate = auth.build_receipt_authenticity_certificate(request, evidence, policy=policy)
    return certificate, auth.recheck_receipt_authenticity_certificate(
        certificate, expected_request=request, policy=policy)


def public_replay(certificate: bytes, request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    from verifier.domains.contracts.current_object_routes import replay_current_object_certificate
    return replay_current_object_certificate(certificate, semantic_version=auth.SEMANTIC_VERSION,
        objective=auth.COORDINATE, represented_kind="RECEIPT", expected_request=request, policy=policy)


@pytest.mark.parametrize("kwargs,status", [({}, "PASS"), ({"wrong_signer": True}, "FAIL"),
    ({"include_chain": False}, "UNKNOWN"), ({"child_status": "UNKNOWN"}, "UNKNOWN")])
def test_integration_public_route_preserves_native_result(kwargs: dict[str, Any], status: str) -> None:
    request, policy, evidence = selected(**kwargs); certificate, native = replay(request, policy, evidence)
    result = public_replay(certificate, request, policy)
    assert result["schema_version"] == "verifier-current-object-route-replay-2"
    assert result["replay_status"] == "REPRODUCED"
    assert result["computational_status"] == status and result["native_result"] == native
    assert "selected issuer key" in result["claim_boundary"]


def test_integration_public_route_preserves_unavailable_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selected(); certificate, _ = replay(request, policy, evidence)
    unavailable_backend(monkeypatch)
    result = public_replay(certificate, request, policy)
    assert result["computational_status"] == "UNKNOWN" and result["replay_status"] == "UNAVAILABLE"
    assert result["native_result"]["real_world_issuer_identity"] == "NOT_ESTABLISHED"


def test_integration_inventory_preserves_distinct_receipt_security_obligations() -> None:
    from verifier.domains.inventory import MECHANIZED_12_POINT_BINDINGS, slot_inventory
    from verifier.domains.contracts.current_object_routes import current_object_route_catalog
    route_rows = current_object_route_catalog()
    routes = {row["objective"]: row for row in route_rows}
    assert len(routes) == len(route_rows)
    expected_receipt_schemas = {
        "RECEIPT-9.1": "verifier-current-receipt-chain-certificate-1",
        "RECEIPT-9.2": "verifier-current-receipt-authenticity-certificate-1",
        "RECEIPT-9.3": "verifier-current-subject-security-certificate-1",
    }
    assert set(expected_receipt_schemas) <= routes.keys()
    assert {coordinate: routes[coordinate]["certificate_schema_version"]
            for coordinate in expected_receipt_schemas} == expected_receipt_schemas
    from verifier.domains.contracts import receipt_chain, subject_security
    assert routes["RECEIPT-9.1"]["certificate_schema_version"] == receipt_chain.CERTIFICATE_VERSION
    assert routes["RECEIPT-9.2"]["certificate_schema_version"] == auth.CERTIFICATE_VERSION
    assert routes["RECEIPT-9.3"]["certificate_schema_version"] == subject_security.CERTIFICATE_VERSION
    assert len({routes[coordinate]["proposition_digest"] for coordinate in expected_receipt_schemas}) == len(expected_receipt_schemas)
    receipt_slot = next(row for row in slot_inventory() if row["object_kind"] == "RECEIPT" and row["tier"] == 9)
    assert receipt_slot["coordinate"] == "RECEIPT-9.1"
    assert {row["coordinate"] for row in receipt_slot["registered_objectives"]} == {"RECEIPT-9.1", "RECEIPT-9.2", "RECEIPT-9.3"}
    assert MECHANIZED_12_POINT_BINDINGS[auth.COORDINATE]["exact_claim"] == auth.registration()["proposition"]
    inventory_rows = slot_inventory()
    registered = [entry for row in inventory_rows for entry in row["registered_objectives"]]
    registered_keys = [(entry["semantic_version"], entry["coordinate"]) for entry in registered]
    assert len(registered_keys) == len(route_rows)
    assert len(registered_keys) == 408
    assert len(set(registered_keys)) == len(registered_keys)
    assert set(registered_keys) == {(row["semantic_version"], row["objective"]) for row in route_rows}
    assert all(row["objective_inventory_closure"] == "NOT_ESTABLISHED" for row in slot_inventory())


def assessment_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    import base64
    from verifier.core.namespace import NamespaceObject, composition_digest
    request, policy, evidence = selected(composable=True); certificate, _ = replay(request, policy, evidence)
    child = json.loads(json.loads(evidence)["chain_certificate"])
    child_data = json.loads(base64.b64decode(next(iter(child["evidence_payloads"].values()))))
    item = NamespaceObject.create(**child_data["receipt_object"])
    objects = [item, NamespaceObject.create("subject", "OBJECT", {}), NamespaceObject.create("hardware", "HARDWARE", {})]
    ref = digest(certificate)
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": [obj.to_dict() for obj in objects],
        "certificates": {ref: certificate.decode()}}
    assessment = {"schema_version": "verifier-polish-request-1", "root_id": item.object_id,
        "collection_digest": composition_digest(objects), "bundle_digest": digest(canonical_bytes(bundle)),
        "requirements": [{"object_id": obj.object_id, "tier": n, "applicability": "REQUIRED",
            "rationale": "Selected receipt authentication", "objectives": []} for obj in objects for n in range(1, 10)]}
    assessment["requirements"][8]["objectives"] = [{"semantic_version": auth.SEMANTIC_VERSION,
        "coordinate": auth.COORDINATE, "request": request, "policy": policy, "certificate_digest": ref}]
    return bundle, assessment


@pytest.mark.parametrize("version", [1, 2])
def test_integration_polish_binds_receipt_subject_without_promotion(version: int) -> None:
    from verifier.core.namespace import NamespaceObject, composition_digest
    from verifier.runtime.polish import assess_polish
    from test_polish_capacity import version2
    bundle, request = assessment_pair()
    if version == 2:
        bundle, request = version2(bundle, request)
    result = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(request), contract_version=str(version))
    assert result["objectives"][0]["status"] == "PASS" and result["composition_status"] == "PASS"
    assert result["status"] == "UNKNOWN" and result["polished"] is False
    bundle["objects"][0]["payload"]["chain_domain"] = "substituted-domain"
    request["bundle_digest"] = digest(canonical_bytes(bundle))
    request["collection_digest"] = composition_digest([NamespaceObject.create(**obj) for obj in bundle["objects"]])
    changed = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(request), contract_version=str(version))
    assert changed["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"
    assert changed["status"] == "FAIL" and changed["polished"] is False


def test_integration_canonical_receipt_signature_evidence_cannot_be_redacted() -> None:
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    certificate = json.loads(replay(*selected())[0])
    surface = DisclosureSurface("RECEIPT", tuple(key for key in certificate if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(certificate, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/receipt_authenticity.py", "standard/CURRENT_RECEIPT_AUTHENTICITY.md"])
def test_integration_polish_fingerprint_binds_authenticity(relative: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.runtime import polish
    original = Path.read_bytes; target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged dependency bytes\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


def test_exact_selected_signature_requires_replayed_chain_and_preserves_authority_limits() -> None:
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert certificate == auth.build_receipt_authenticity_certificate(request, evidence, policy=policy)
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["receipt_chain_status"] == "PASS"
    for name in ("real_world_issuer_identity", "governance_authority", "trusted_time",
                 "live_revocation", "challenge_consumption", "security_tier_conformance",
                 "public_disclosure_authority", "object_profile_conformance"):
        assert result[name] == "NOT_ESTABLISHED"
    payload = json.loads(evidence)["attestation"]["payload"]
    expected = b"verifier-current-receipt-issuer-attestation-1\x00" + canonical_bytes(payload)
    assert auth.receipt_authenticity_signing_bytes(payload) == expected


@pytest.mark.parametrize("position", [0, 1, 7, 15, 31, 32, 47, 63])
def test_single_bit_signature_changes_cannot_be_repaired_by_outer_hashes(position: int) -> None:
    assert replay(*selected(signature_byte=position))[1]["status"] == "FAIL"


def test_signature_from_other_key_is_not_the_selected_issuer() -> None:
    assert replay(*selected(wrong_signer=True))[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [
    ("schema_version", "other-message"), ("semantic_version", "legacy"),
    ("coordinate", "RECEIPT-9.1"), ("proposition_digest", "sha256:" + "1" * 64),
    ("issuer_key_id", "other-key"), ("receipt_object_id", "other-receipt"),
    ("receipt_object_digest", "sha256:" + "2" * 64),
    ("chain_certificate_digest", "sha256:" + "3" * 64),
    ("chain_request_digest", "sha256:" + "4" * 64),
    ("policy_digest", "sha256:" + "5" * 64), ("challenge", "34" * 32),
    ("evaluation_time", 101),
])
def test_valid_signature_for_different_intent_is_refuted(field: str, value: object) -> None:
    assert replay(*selected(payload_changes={field: value}))[1]["status"] == "FAIL"


@pytest.mark.parametrize("now,status", [(99, "FAIL"), (100, "PASS"), (199, "PASS"), (200, "FAIL")])
def test_selected_interval_has_inclusive_start_and_exclusive_expiry(now: int, status: str) -> None:
    assert replay(*selected(evaluation_time=now))[1]["status"] == status


@pytest.mark.parametrize("start,end", [(100, 100), (200, 100), (99, 200)])
def test_empty_reversed_and_policy_exceeding_intervals_fail(start: int, end: int) -> None:
    assert replay(*selected(issued_at=start, expires_at=end))[1]["status"] == "FAIL"


@pytest.mark.parametrize("kwargs,status", [
    ({"child_status": "FAIL"}, "FAIL"), ({"child_status": "UNKNOWN"}, "UNKNOWN"),
    ({"include_chain": False}, "UNKNOWN"), ({"include_attestation": False}, "UNKNOWN"),
    ({"max_evidence_bytes": 1}, "UNKNOWN"),
    ({"include_chain": False, "wrong_signer": True}, "FAIL"),
])
def test_signature_never_repairs_unavailable_or_refuted_prerequisite(kwargs: dict[str, Any], status: str) -> None:
    assert replay(*selected(**kwargs))[1]["status"] == status


def test_missing_outer_evidence_is_unknown() -> None:
    request, policy, _ = selected()
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("evaluation_time", True), ("challenge", "00"), ("receipt_object_digest", "sha256:" + "f" * 64)])
def test_malformed_or_cross_subject_external_selection_refuses(field: str, value: object) -> None:
    request, policy, evidence = selected(); request[field] = value
    with pytest.raises(auth.ReceiptAuthenticityError):
        replay(request, policy, evidence)


@pytest.mark.parametrize("field", ["schema_version", "semantic_version", "coordinate"])
def test_foreign_selection_values_are_rejected_before_equality_callbacks(field: str) -> None:
    class Foreign:
        def __eq__(self, other: object) -> bool:
            raise RuntimeError("foreign equality callback executed")
        def __ne__(self, other: object) -> bool:
            raise RuntimeError("foreign inequality callback executed")
    request, policy, evidence = selected(); request[field] = Foreign()
    with pytest.raises(auth.ReceiptAuthenticityError):
        auth.build_receipt_authenticity_certificate(request, evidence, policy=policy)


def unavailable_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)


def test_missing_backend_does_not_reproduce_carried_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selected(); certificate, _ = replay(request, policy, evidence)
    unavailable_backend(monkeypatch)
    result = auth.recheck_receipt_authenticity_certificate(certificate, expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN" and result["replay_status"] == "UNAVAILABLE"
    missing, result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN" and "replay_status" not in result
    assert missing != certificate


def test_unavailable_backend_cannot_hide_forged_positive_observations(monkeypatch: pytest.MonkeyPatch) -> None:
    request, policy, evidence = selected(); certificate, _ = replay(request, policy, evidence)
    forged = json.loads(certificate); forged["result"]["evaluation"]["observations"]["receipt_chain_status"] = "UNKNOWN"
    forged["digest"] = digest(canonical_bytes({k: v for k, v in forged.items() if k != "digest"}))
    unavailable_backend(monkeypatch)
    with pytest.raises(auth.ReceiptAuthenticityError, match="observation"):
        auth.recheck_receipt_authenticity_certificate(canonical_bytes(forged), expected_request=request, policy=policy)


@pytest.mark.parametrize("field", ["governance_authority", "real_world_issuer_identity", "security_tier_conformance"])
def test_rehashed_authority_promotion_refuses(field: str) -> None:
    request, policy, evidence = selected(); certificate, _ = replay(request, policy, evidence)
    value = json.loads(certificate); value["result"][field] = "ESTABLISHED"
    value["digest"] = digest(canonical_bytes({k: v for k, v in value.items() if k != "digest"}))
    with pytest.raises(auth.ReceiptAuthenticityError):
        auth.recheck_receipt_authenticity_certificate(canonical_bytes(value), expected_request=request, policy=policy)


@pytest.mark.parametrize("name", ["domains/contracts/receipt_chain.py", "core/signature_keys.py", "standard/CURRENT_RECEIPT_AUTHENTICITY.md"])
def test_transitive_chain_and_key_admission_source_are_bound(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    request, policy, evidence = selected(); certificate, _ = replay(request, policy, evidence)
    target = Path(auth.__file__).parents[2] / name
    original = Path.read_bytes
    def changed(path: Path) -> bytes:
        value = original(path)
        return value + b"\n# changed trusted source\n" if path == target else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(auth.ReceiptAuthenticityError):
        auth.recheck_receipt_authenticity_certificate(certificate, expected_request=request, policy=policy)
