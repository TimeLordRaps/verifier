"""Verifier Standard (VSTD) authenticated claim-storage transport contract tests.

Hypertext Transfer Protocol (HTTP); JavaScript Object Notation (JSON).
Injected transport establishes client behavior, not a deployed server observation.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from test_claim_garden_publish import PUBLISHER, _valid_claim_packet, stored_response
from verifier.interoperability.claim_garden import ClaimGardenClientError, TransportResponse, publish_claim

@pytest.fixture
def credential(tmp_path: Path) -> Path:
    path = tmp_path / "publisher.credential"
    path.write_text("T" * 48, encoding="ascii")
    return path


@pytest.mark.parametrize("publisher", [None, "", "publisher:someone", "publisher:sha256:" + "A" * 64])
def test_missing_or_malformed_publisher_never_transmits(publisher: str | None, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    def forbidden(_: Any) -> Any:
        pytest.fail("invalid publisher must not reach transport")
    with pytest.raises(ClaimGardenClientError, match="publisher"):
        publish_claim(receipt, claim=claim, publisher_id=publisher, credential_file=credential, transport=forbidden)


def test_missing_credential_never_transmits() -> None:
    claim, receipt = _valid_claim_packet()
    def forbidden(_: Any) -> Any:
        pytest.fail("missing credential must not reach transport")
    with pytest.raises(ClaimGardenClientError, match="credential"):
        publish_claim(receipt, claim=claim, publisher_id=PUBLISHER, transport=forbidden)


def test_repeated_submission_accepts_new_and_deduplicated_storage(credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    requests = []
    def transport(request: Any) -> TransportResponse:
        requests.append(request)
        duplicate = len(requests) > 1
        return TransportResponse(200 if duplicate else 201, {"Content-Type": "application/json"},
                                 json.dumps(stored_response(claim, receipt, duplicate)).encode())
    for duplicate in (False, True):
        result = publish_claim(receipt, claim=claim, publisher_id=PUBLISHER,
                               credential_file=credential, transport=transport)
        assert result["deduplicated"] is duplicate
        assert result["receipt_id"] != receipt["receipt_id"]
        assert result["state"] == "PENDING_REVIEW"
        assert result["publication_gate"] == "HUMAN_REVIEW_REQUIRED"
        assert result["publication"] == "NOT_ESTABLISHED"
    assert requests[0].body == requests[1].body
    assert json.loads(requests[0].body)["publisher_id"] == PUBLISHER
    assert requests[0].headers["Authorization"] == "Bearer " + "T" * 48


@pytest.mark.parametrize("field,value", [
    ("schema_version", "UNKNOWN"), ("status", "ADMITTED"), ("state", "APPROVED"),
    ("publication_gate", "CLI_VERIFIED_TAMPER_LOCKED"), ("claim_id", "other-claim"),
    ("claim_digest", "sha256:" + "0" * 64), ("receipt_id", "wrong-receipt"),
    ("receipt", {}), ("retrieval_path", "https://other.invalid/"), ("deduplicated", 0),
])
def test_malformed_or_misbound_response_is_rejected(field: str, value: Any, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    response = stored_response(claim, receipt)
    response[field] = value
    with pytest.raises(ClaimGardenClientError):
        publish_claim(receipt, claim=claim, publisher_id=PUBLISHER, credential_file=credential,
                      transport=lambda _: TransportResponse(201, {"Content-Type": "application/json"},
                                                            json.dumps(response).encode()))


@pytest.mark.parametrize("missing", list(stored_response(*_valid_claim_packet())))
def test_every_storage_response_field_is_required(missing: str, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    response = stored_response(claim, receipt)
    del response[missing]
    with pytest.raises(ClaimGardenClientError):
        publish_claim(receipt, claim=claim, publisher_id=PUBLISHER, credential_file=credential,
                      transport=lambda _: TransportResponse(201, {"Content-Type": "application/json"},
                                                            json.dumps(response).encode()))


@pytest.mark.parametrize("status,duplicate", [(200, False), (201, True), (202, False)])
def test_status_and_deduplication_must_agree(status: int, duplicate: bool, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    response = stored_response(claim, receipt, duplicate)
    with pytest.raises(ClaimGardenClientError):
        publish_claim(receipt, claim=claim, publisher_id=PUBLISHER, credential_file=credential,
                      transport=lambda _: TransportResponse(status, {"Content-Type": "application/json"},
                                                            json.dumps(response).encode()))


@pytest.mark.parametrize("bad_token", ["", "short", "x" * 513, "x" * 48 + "\nAuthorization: attacker"])
def test_malformed_credentials_never_transmit(bad_token: str, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    credential.write_text(bad_token, encoding="ascii")
    calls = []
    with pytest.raises(ClaimGardenClientError, match="credential"):
        publish_claim(receipt, claim=claim, publisher_id=PUBLISHER, credential_file=credential,
                      transport=lambda request: calls.append(request))
    assert calls == []


@pytest.mark.parametrize("mutation", ["claim_id", "claim_digest", "verdict", "count"])
def test_retained_receipt_must_bind_claim_and_positive_execution(mutation: str, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    response = stored_response(claim, receipt)
    if mutation == "count":
        response["receipt"]["execution_metrics"]["statements_checked"] = True
    else:
        response["receipt"][mutation] = "wrong"
    with pytest.raises(ClaimGardenClientError):
        publish_claim(receipt, claim=claim, publisher_id=PUBLISHER, credential_file=credential,
                      transport=lambda _: TransportResponse(201, {"Content-Type": "application/json"},
                                                            json.dumps(response).encode()))


@pytest.mark.parametrize("mutation", ["missing-digest", "boolean-count", "missing-count"])
def test_preflight_never_infers_digest_or_execution_from_claim_text(mutation: str, credential: Path) -> None:
    claim, receipt = _valid_claim_packet()
    if mutation == "missing-digest":
        del receipt["claim_digest"]
    elif mutation == "boolean-count":
        receipt["execution_metrics"]["statements_checked"] = True
    else:
        del receipt["execution_metrics"]
    calls = []
    with pytest.raises(ClaimGardenClientError):
        publish_claim(receipt, claim=claim, publisher_id=PUBLISHER, credential_file=credential,
                      transport=lambda request: calls.append(request))
    assert calls == []
