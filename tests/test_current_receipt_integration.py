"""Current receipt security integration and independent boundary checks.

Verifier Standard (VSTD); JavaScript Object Notation (JSON).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import receipt_chain
from verifier.domains.contracts.current_object_routes import current_object_route_catalog


def test_receipt_security_is_registered_alongside_checker_dynamics() -> None:
    routes = {row["objective"] for row in current_object_route_catalog()}
    assert {"RECEIPT-9.1", "VERIFIER-2.1"} <= routes


def specimen() -> tuple[Any, dict, dict, bytes, NamespaceObject]:
    contract = receipt_chain
    import base64
    import hashlib
    genesis = "sha256:" + "0" * 64
    domain, first, raw = "independent-test-domain", 3, b"retained receipt bytes"
    tip = digest({"schema_version": contract.LINK_VERSION, "domain": domain, "sequence": first,
                  "previous": genesis, "receipt_digest": "sha256:" + hashlib.sha256(raw).hexdigest()})
    item = NamespaceObject.create("receipt:chain", "RECEIPT", {"chain_domain": domain,
        "chain_genesis_digest": genesis, "chain_first_sequence": first, "chain_tip_digest": tip},
        {"subject": ["subject"], "hardware": ["hardware"]})
    suite = {"schema_version": contract.EVIDENCE_VERSION, "domain": domain,
             "receipt_object": item.to_dict(), "entries": [{"sequence": first,
             "receipt_base64": base64.b64encode(raw).decode("ascii")}]}
    policy = contract.receipt_chain_policy(trust_roots=["independently-retained-tip"])
    request = contract.receipt_chain_request(domain=domain, genesis_digest=genesis, first_sequence=first,
        tip_digest=tip, evidence_ref=digest(suite), receipt_object_id=item.object_id,
        receipt_object_digest=item.digest, policy=policy)
    return contract, request, policy, canonical_bytes(suite), item


def test_receipt_polish_replays_exact_record_without_profile_promotion() -> None:
    from verifier.runtime.polish import assess_polish
    import hashlib
    contract, request, policy, evidence, item = specimen()
    certificate = contract.build_receipt_chain_certificate(request, evidence, policy=policy)
    ref = "sha256:" + hashlib.sha256(certificate).hexdigest()
    objects = [item, NamespaceObject.create("subject", "OBJECT", {}), NamespaceObject.create("hardware", "HARDWARE", {})]
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": [obj.to_dict() for obj in objects],
              "certificates": {ref: certificate.decode("utf-8")}}
    assessment = {"schema_version": "verifier-polish-request-1", "root_id": item.object_id,
        "collection_digest": composition_digest(objects), "bundle_digest": digest(bundle),
        "requirements": [{"object_id": obj.object_id, "tier": n, "applicability": "REQUIRED",
                          "rationale": "Bounded receipt assessment", "objectives": []} for obj in objects for n in range(1, 10)]}
    assessment["requirements"][8]["objectives"] = [{"semantic_version": contract.SEMANTIC_VERSION,
        "coordinate": contract.COORDINATE, "request": request, "policy": policy, "certificate_digest": ref}]
    result = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(assessment))
    assert result["objectives"][0]["status"] == "PASS"
    assert result["composition_status"] == "PASS"
    assert result["status"] == "UNKNOWN" and result["polished"] is False
    bundle["objects"][0]["payload"]["chain_domain"] = "different-domain"
    assessment["bundle_digest"] = digest(bundle)
    assessment["collection_digest"] = composition_digest([NamespaceObject.create(**obj) for obj in bundle["objects"]])
    result = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(assessment))
    assert result["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"
    assert result["status"] == "FAIL"


def test_receipt_canonical_evidence_cannot_be_redacted() -> None:
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence, _ = specimen()
    certificate = json.loads(contract.build_receipt_chain_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("RECEIPT", tuple(key for key in certificate if key != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local-evaluation"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(certificate, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/receipt_chain.py", "standard/CURRENT_RECEIPT_CHAIN.md"])
def test_receipt_dependencies_change_polish_fingerprint(relative: str, monkeypatch: Any) -> None:
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1]/relative
    before = polish.mechanism_digest()
    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged dependency bytes\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("operands", [None, [], False, ""])
def test_wire_record_cannot_normalize_invalid_operands_to_selected_empty_map(operands: Any) -> None:
    contract, request, policy, evidence, item = specimen()
    suite = json.loads(evidence)
    # Select a valid empty-operand record for this standalone security objective.
    # It does not establish composition, but malformed wire values cannot become it.
    selected = NamespaceObject.create(item.object_id, "RECEIPT", item.payload)
    suite["receipt_object"] = selected.to_dict()
    request["receipt_object_digest"] = selected.digest
    request["evidence_ref"] = digest(suite)
    valid = contract.build_receipt_chain_certificate(request, canonical_bytes(suite), policy=policy)
    assert contract.recheck_receipt_chain_certificate(valid, expected_request=request, policy=policy)["status"] == "PASS"
    suite["receipt_object"]["operands"] = operands
    request["evidence_ref"] = digest(suite)
    invalid = contract.build_receipt_chain_certificate(request, canonical_bytes(suite), policy=policy)
    assert contract.recheck_receipt_chain_certificate(invalid, expected_request=request, policy=policy)["status"] == "FAIL"


def test_hostile_request_key_refuses_before_comparison() -> None:
    contract, request, policy, evidence, _ = specimen()
    class Key(str):
        __hash__ = str.__hash__
        def __eq__(self, other: Any) -> bool:
            raise AssertionError("caller key comparison executed")
    version = request.pop("schema_version")
    request[Key("schema_version")] = version
    with pytest.raises(contract.ReceiptChainError):
        contract.build_receipt_chain_certificate(request, evidence, policy=policy)
