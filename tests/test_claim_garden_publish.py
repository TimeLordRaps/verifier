"""Terminology: application programming interface (API);
Boolean satisfiability problem (SAT); command-line interface (CLI);
conjunctive normal form (CNF); grounded decision certificate (GDC);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
unsatisfiable (UNSAT); Verifier Standard (VSTD).

Fail-closed preflight and transmission tests for Claim Garden publication.
"""

from __future__ import annotations

import hashlib
import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest

from verifier.core.receipt import canonical_json_dumps
from verifier.interoperability.claim_garden import (
    ClaimGardenClientError,
    TransportRequest,
    TransportResponse,
    publish_claim,
)
from verifier.runtime.public_cli import main

PUBLISHER = "publisher:sha256:" + "a" * 64


@pytest.fixture
def credential(tmp_path: Path) -> Path:
    path = tmp_path / "publisher.credential"
    path.write_text("T" * 48, encoding="ascii")
    return path


def stored_response(claim: dict[str, Any], receipt: dict[str, Any], duplicate: bool = False) -> dict[str, Any]:
    retained = copy.deepcopy(receipt)
    retained["receipt_id"] = "retained-server-receipt"
    retained["claim_digest"] = "sha256:" + receipt["claim_digest"].removeprefix("sha256:")
    return {
        "schema_version": "CLAIM-GARDEN-STORED-1.0", "status": "STORED",
        "state": "PENDING_REVIEW", "publication_gate": "HUMAN_REVIEW_REQUIRED",
        "claim_id": claim["claim_id"], "claim_digest": retained["claim_digest"],
        "receipt_id": retained["receipt_id"], "receipt": retained,
        "retrieval_path": f"/v1/claims/records/{retained['claim_digest']}?publisher_id={quote(PUBLISHER, safe='')}",
        "deduplicated": duplicate,
    }


def _canonical_digest(data: Any) -> str:
    return hashlib.sha256(canonical_json_dumps(data).encode("utf-8")).hexdigest()


def _valid_claim_packet() -> tuple[dict[str, Any], dict[str, Any]]:
    claim = {
        "category": "SAT_UNSAT",
        "claim_id": "SAT-GDC-REFUTATION-TEST",
        "evidence_payload": {
            "data": {
                "clauses": [[1, 2], [-1], [-2]],
                "num_vars": 2,
            },
            "format": "DIMACS_CNF",
        },
        "proposition": {
            "statement": "UNSAT refutation verified via propositional unit propagation kernel",
            "target_artifact": {
                "name": "formula.cnf",
                "sha256": "39c442988b425a1e4cc7c6bb41d4fb35046dea61a5be3cdf39a582b054eae341",
            },
        },
        "template_version": "1.0.0",
        "verification_mechanism": {
            "expected_verdict": "VERIFIED",
            "target_layer": "VSTD-4",
            "verifier_id": "vstd-kernel-gdc-4.7",
        },
    }
    claim_digest = _canonical_digest(claim)
    receipt = {
        "checked_at": "2026-09-18T14:00:00.000Z",
        "claim_digest": claim_digest,
        "claim_id": "SAT-GDC-REFUTATION-TEST",
        "execution_metrics": {
            "duration_ms": 1.25,
            "memory_bytes_estimate": 4096,
            "statements_checked": 3,
        },
        "notary_binding": {
            "notary_key_id": "sha256:d8b9072a3a9562dc25e580760bab154190ce0aa2f1d598c545be3833d6d81bb7",
            "notary_publisher_id": "publisher:claim-garden-alpha-authority",
            "signature": "sig_valid_ed25519_test_mock_signature_data",
        },
        "receipt_id": "VFY-GDC-TEST-0001",
        "reproduction_manifest": {
            "canonical_inputs": {
                "claim": claim_digest,
            },
            "command": "vstd verify receipt.json",
        },
        "schema_version": "VSTD-3",
        "verdict": "VERIFIED",
        "verifier_coordinate": {
            "engine": "vstd-gdc-checker",
            "verifier_id": "vstd-kernel-gdc-4.7",
            "version": "2.0.0",
        },
        "vstd_layer_achieved": "VSTD-4",
    }
    return claim, receipt


def test_publish_claim_success_with_packet_dict(tmp_path: Path, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    requests: list[TransportRequest] = []

    def transport(request: TransportRequest) -> TransportResponse:
        requests.append(request)
        body = stored_response(claim, receipt)
        return TransportResponse(201, {"Content-Type": "application/json"}, canonical_json_dumps(body).encode("utf-8"))

    result = publish_claim(
        receipt=receipt,
        claim=claim,
        endpoint="https://hub.invalid",
        publisher_id=PUBLISHER,
        credential_file=credential,
        transport=transport,
    )

    assert result["result"] == "SUBMITTED"
    assert result["status"] == "STORED"
    assert result["claim_id"] == claim["claim_id"]
    assert result["receipt_id"] == "retained-server-receipt"
    assert result["publication_gate"] == "HUMAN_REVIEW_REQUIRED"
    assert result["transport_performed"] is True
    assert result["publication"] == "NOT_ESTABLISHED"

    assert len(requests) == 1
    assert requests[0].url == "https://hub.invalid/v1/claims/publish"
    assert requests[0].method == "POST"
    sent = json.loads(requests[0].body)
    assert sent["claim"] == claim
    assert sent["receipt"] == receipt


def test_publish_claim_with_credential_file(tmp_path: Path) -> None:
    claim, receipt = _valid_claim_packet()
    credential = tmp_path / "publisher.cred"
    token = "T" * 48
    credential.write_text(token, encoding="ascii")
    requests: list[TransportRequest] = []

    def transport(request: TransportRequest) -> TransportResponse:
        requests.append(request)
        body = stored_response(claim, receipt)
        return TransportResponse(201, {"Content-Type": "application/json"}, canonical_json_dumps(body).encode("utf-8"))

    result = publish_claim(
        receipt=receipt,
        claim=claim,
        endpoint="https://hub.invalid",
        publisher_id=PUBLISHER,
        credential_file=credential,
        transport=transport,
    )
    assert result["status"] == "STORED"
    assert len(requests) == 1
    assert requests[0].headers.get("Authorization") == f"Bearer {token}"


def test_publish_claim_refuses_unverified_verdict() -> None:
    claim, receipt = _valid_claim_packet()
    receipt["verdict"] = "FALSIFIED"

    calls = 0

    def transport(_: TransportRequest) -> TransportResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("network must not be contacted on unverified claim")

    with pytest.raises(ClaimGardenClientError, match="cannot publish unverified claim; verdict is 'FALSIFIED'"):
        publish_claim(
            receipt=receipt,
            claim=claim,
            endpoint="https://hub.invalid",
            transport=transport,
        )
    assert calls == 0


def test_publish_claim_refuses_unknown_verdict() -> None:
    claim, receipt = _valid_claim_packet()
    receipt["verdict"] = "UNKNOWN"

    calls = 0

    def transport(_: TransportRequest) -> TransportResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("network must not be contacted on unverified claim")

    with pytest.raises(ClaimGardenClientError, match="cannot publish unverified claim; verdict is 'UNKNOWN'"):
        publish_claim(
            receipt=receipt,
            claim=claim,
            endpoint="https://hub.invalid",
            transport=transport,
        )
    assert calls == 0


def test_publish_claim_refuses_tampered_claim_digest() -> None:
    claim, receipt = _valid_claim_packet()
    receipt["claim_digest"] = "0" * 64

    calls = 0

    def transport(_: TransportRequest) -> TransportResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("network must not be contacted on tampered claim digest")

    with pytest.raises(ClaimGardenClientError, match="claim digest mismatch"):
        publish_claim(
            receipt=receipt,
            claim=claim,
            endpoint="https://hub.invalid",
            transport=transport,
        )
    assert calls == 0


def test_publish_claim_refuses_zero_statements_checked() -> None:
    claim, receipt = _valid_claim_packet()
    receipt["execution_metrics"]["statements_checked"] = 0

    calls = 0

    def transport(_: TransportRequest) -> TransportResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("network must not be contacted on zero statements checked")

    with pytest.raises(ClaimGardenClientError, match="statement count must be greater than 0"):
        publish_claim(
            receipt=receipt,
            claim=claim,
            endpoint="https://hub.invalid",
            transport=transport,
        )
    assert calls == 0


def test_publish_claim_refuses_missing_notary_binding_signature() -> None:
    claim, receipt = _valid_claim_packet()
    receipt["notary_binding"]["signature"] = ""

    calls = 0

    def transport(_: TransportRequest) -> TransportResponse:
        nonlocal calls
        calls += 1
        raise AssertionError("network must not be contacted on unsigned notary binding")

    with pytest.raises(ClaimGardenClientError, match="unsigned receipt missing notary binding"):
        publish_claim(
            receipt=receipt,
            claim=claim,
            endpoint="https://hub.invalid",
            transport=transport,
        )
    assert calls == 0


def test_publish_claim_from_packet_file(tmp_path: Path, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps({"claim": claim, "receipt": receipt}), encoding="utf-8")

    requests: list[TransportRequest] = []

    def transport(request: TransportRequest) -> TransportResponse:
        requests.append(request)
        body = stored_response(claim, receipt)
        return TransportResponse(201, {"Content-Type": "application/json"}, canonical_json_dumps(body).encode("utf-8"))

    result = publish_claim(
        receipt=packet_path,
        endpoint="https://hub.invalid",
        publisher_id=PUBLISHER,
        credential_file=credential,
        transport=transport,
    )
    assert result["status"] == "STORED"
    assert len(requests) == 1


def test_publish_claim_from_directory(tmp_path: Path, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    (bundle_dir / "claim.json").write_text(json.dumps(claim), encoding="utf-8")
    (bundle_dir / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")

    requests: list[TransportRequest] = []

    def transport(request: TransportRequest) -> TransportResponse:
        requests.append(request)
        body = stored_response(claim, receipt)
        return TransportResponse(201, {"Content-Type": "application/json"}, canonical_json_dumps(body).encode("utf-8"))

    result = publish_claim(
        receipt=bundle_dir,
        endpoint="https://hub.invalid",
        publisher_id=PUBLISHER,
        credential_file=credential,
        transport=transport,
    )
    assert result["status"] == "STORED"
    assert len(requests) == 1


def test_publish_cli_integration_success(tmp_path: Path, credential: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    claim, receipt = _valid_claim_packet()
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps({"claim": claim, "receipt": receipt}), encoding="utf-8")

    def fake_publish_claim(*args: Any, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["publisher_id"] == PUBLISHER
        assert kwargs["credential_file"] == str(credential)
        return {
            "result": "SUBMITTED",
            "status": "STORED",
            "claim_id": claim["claim_id"],
            "receipt_id": receipt["receipt_id"],
            "claim_digest": receipt["claim_digest"],
            "state": "PENDING_REVIEW",
            "publication_gate": "HUMAN_REVIEW_REQUIRED",
            "publication": "NOT_ESTABLISHED",
        }

    import verifier.interoperability.claim_garden as claim_garden_mod
    monkeypatch.setattr(claim_garden_mod, "publish_claim", fake_publish_claim)

    exit_code = main(["publish", str(packet_path), "--publisher-id", PUBLISHER, "--credential-file", str(credential), "--endpoint", "https://hub.invalid", "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["status"] == "STORED"
    assert data["publication_gate"] == "HUMAN_REVIEW_REQUIRED"


def test_publish_cli_integration_failure(tmp_path: Path, credential: Path, capsys: pytest.CaptureFixture[str]) -> None:
    claim, receipt = _valid_claim_packet()
    receipt["verdict"] = "FALSIFIED"
    packet_path = tmp_path / "falsified.json"
    packet_path.write_text(json.dumps({"claim": claim, "receipt": receipt}), encoding="utf-8")

    exit_code = main(["publish", str(packet_path), "--publisher-id", PUBLISHER, "--credential-file", str(credential), "--endpoint", "https://hub.invalid", "--json"])
    assert exit_code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["result"] == "REJECTED"
    assert "cannot publish unverified claim" in data["error"]
