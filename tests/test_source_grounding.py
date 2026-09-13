"""Adversarial experimental Verifier Standard (VSTD) source-grounding tests.

JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
records establish only the bounded propositions replayed here.  A serialized
identifier (ID) names a mechanism or proposition.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import json

import pytest

from verifier.interoperability import source_grounding as grounding


VOCABULARY = "sha256:" + "a" * 64
PRODUCER = "test:source-grounding-producer@0.1"


def _declaration(
    source: bytes,
    *,
    expected: object = "ready",
    mechanism_id: str = grounding.MECHANISM_ID,
    frame_id: str = "CANONICAL-JSON-OBJECT-0.1",
    certificate_override: bytes | None = None,
) -> tuple[bytes, bytes, dict[str, bytes]]:
    source_digest = grounding.digest_bytes(source)
    base = {
        "assumptions": ["source bytes use the declared vocabulary"],
        "certificate": {
            "certificate_kind": "DERIVATION",
            "digest": "sha256:" + "0" * 64,
            "size_bytes": 0,
        },
        "declarer_coordinate": "test:source-grounding-declarer@0.1",
        "ground_proposition": {
            "expected": expected,
            "path": ["claim", "state"],
            "predicate": "JSON_POINTER_EQUALS",
            "proposition_id": "claim-state-is-ready",
        },
        "interpretation": {
            "checker_coordinate": grounding.current_checker_coordinate().to_dict(),
            "mechanism_id": mechanism_id,
            "mechanism_profile_digest": grounding.source_grounding_mechanism_profile_digest(),
            "profile_id": grounding.INTERPRETATION_PROFILE,
        },
        "schema_version": grounding.DECLARATION_SCHEMA,
        "semantic_frame": {
            "facets": ["claim", "metadata"],
            "frame_id": frame_id,
            "proposition_language": "CANONICAL_JSON_OBJECT",
            "vocabulary_digest": VOCABULARY,
        },
        "source": {"digest": source_digest, "size_bytes": len(source)},
    }
    provisional = grounding.decode_source_grounding_declaration(grounding.canonical_bytes(base))
    certificate = certificate_override or grounding.expected_source_grounding_certificate(
        provisional, source, PRODUCER
    )
    base["certificate"] = {
        "certificate_kind": "DERIVATION",
        "digest": grounding.digest_bytes(certificate),
        "size_bytes": len(certificate),
    }
    declaration = grounding.canonical_bytes(base)
    return declaration, certificate, {
        source_digest: source,
        grounding.digest_bytes(certificate): certificate,
    }


@pytest.fixture
def source() -> bytes:
    return grounding.canonical_bytes({
        "claim": {"state": "ready"},
        "metadata": {"specimen": "non-critical"},
    })


def test_exact_source_and_replayed_certificate_establish_bounded_grounding(source: bytes) -> None:
    declaration, _certificate, evidence = _declaration(source)

    receipt = grounding.qualify_source_grounding(declaration, evidence)

    assert receipt.result is grounding.GroundingResult.ESTABLISHED
    assert dict(receipt.checks) == {
        "certificate_binding": "BOUND",
        "certificate_recheck": "REPRODUCED",
        "frame_compatibility": "COMPATIBLE",
        "mechanism_support": "SUPPORTED",
        "proposition_evaluation": "ESTABLISHED",
        "source_binding": "BOUND",
    }
    assert "PRODUCER_INDEPENDENCE_NOT_ESTABLISHED" in receipt.residual_obligations
    receipt_bytes = grounding.build_source_grounding_receipt(declaration, evidence)
    assert grounding.decode_source_grounding_receipt(receipt_bytes) == receipt


def test_false_ground_proposition_is_refuted_only_after_exact_replay(source: bytes) -> None:
    declaration, _certificate, evidence = _declaration(source, expected="not-ready")

    receipt = grounding.qualify_source_grounding(declaration, evidence)

    assert receipt.result is grounding.GroundingResult.REFUTED
    assert dict(receipt.checks)["proposition_evaluation"] == "REFUTED"
    assert dict(receipt.checks)["certificate_recheck"] == "REPRODUCED"


def test_json_boolean_does_not_equal_integer_one() -> None:
    source = grounding.canonical_bytes({"claim": {"state": True}, "metadata": {}})
    declaration, _certificate, evidence = _declaration(source, expected=1)

    receipt = grounding.qualify_source_grounding(declaration, evidence)

    assert receipt.result is grounding.GroundingResult.REFUTED


def test_false_refutation_status_is_invalid_not_accepted(source: bytes) -> None:
    declaration, certificate, _evidence = _declaration(source)
    forged = json.loads(certificate)
    forged["result"] = "REFUTED"
    forged_bytes = grounding.canonical_bytes(forged)
    declaration_record = json.loads(declaration)
    declaration_record["certificate"]["digest"] = grounding.digest_bytes(forged_bytes)
    declaration_record["certificate"]["size_bytes"] = len(forged_bytes)
    rebound = grounding.canonical_bytes(declaration_record)
    evidence = {
        grounding.digest_bytes(source): source,
        grounding.digest_bytes(forged_bytes): forged_bytes,
    }

    receipt = grounding.qualify_source_grounding(rebound, evidence)

    assert receipt.result is grounding.GroundingResult.INVALID
    assert "CERTIFICATE_RECHECK_INVALID" in receipt.reason_codes


@pytest.mark.parametrize("which", ["source", "certificate"])
def test_evidence_substitution_is_invalid(source: bytes, which: str) -> None:
    declaration, certificate, evidence = _declaration(source)
    declaration_record = json.loads(declaration)
    digest = (
        declaration_record["source"]["digest"]
        if which == "source"
        else declaration_record["certificate"]["digest"]
    )
    evidence[digest] = (source if which == "source" else certificate) + b" "

    receipt = grounding.qualify_source_grounding(declaration, evidence)

    assert receipt.result is grounding.GroundingResult.INVALID
    assert f"{which.upper()}_INVALID" in receipt.reason_codes


def test_missing_certificate_and_unsupported_mechanism_remain_unknown(source: bytes) -> None:
    declaration, _certificate, evidence = _declaration(source, mechanism_id="unregistered")
    evidence.pop(json.loads(declaration)["certificate"]["digest"])

    receipt = grounding.qualify_source_grounding(declaration, evidence)

    assert receipt.result is grounding.GroundingResult.UNKNOWN
    assert set(receipt.reason_codes) == {
        "CERTIFICATE_UNKNOWN",
        "MECHANISM_OR_PROFILE_UNSUPPORTED",
    }


def test_declaration_only_certificate_origin_cannot_establish(source: bytes) -> None:
    declaration, certificate, _evidence = _declaration(source)
    claimed = json.loads(certificate)
    claimed["evidence_origin"] = "DECLARATION_ONLY"
    claimed_bytes = grounding.canonical_bytes(claimed)
    record = json.loads(declaration)
    record["certificate"]["digest"] = grounding.digest_bytes(claimed_bytes)
    record["certificate"]["size_bytes"] = len(claimed_bytes)
    rebound = grounding.canonical_bytes(record)

    receipt = grounding.qualify_source_grounding(
        rebound,
        {grounding.digest_bytes(source): source, grounding.digest_bytes(claimed_bytes): claimed_bytes},
    )

    assert receipt.result is grounding.GroundingResult.INVALID
    assert dict(receipt.checks)["certificate_recheck"] == "INVALID"


def test_aliased_source_and_certificate_are_circular_and_invalid(source: bytes) -> None:
    declaration, _certificate, evidence = _declaration(source)
    record = json.loads(declaration)
    record["certificate"] = {
        "certificate_kind": "DERIVATION",
        "digest": record["source"]["digest"],
        "size_bytes": record["source"]["size_bytes"],
    }
    aliased = grounding.canonical_bytes(record)

    receipt = grounding.qualify_source_grounding(aliased, evidence)

    assert receipt.result is grounding.GroundingResult.INVALID
    assert "CIRCULAR_EVIDENCE_BINDING" in receipt.reason_codes


@pytest.mark.parametrize("mutation", ["unknown-field", "unsorted", "noncanonical", "oversized"])
def test_declaration_rejects_unknown_fields_bounds_and_noncanonical_order(
    source: bytes, mutation: str
) -> None:
    declaration, _certificate, _evidence = _declaration(source)
    record = json.loads(declaration)
    if mutation == "unknown-field":
        record["claimed_established"] = True
        payload = grounding.canonical_bytes(record)
    elif mutation == "unsorted":
        record["semantic_frame"]["facets"] = ["metadata", "claim"]
        payload = grounding.canonical_bytes(record)
    elif mutation == "noncanonical":
        payload = json.dumps(record, indent=2, sort_keys=True).encode("utf-8")
    else:
        payload = b"{" + b" " * grounding.MAX_RECORD_BYTES + b"}"

    with pytest.raises(grounding.SourceGroundingError):
        grounding.decode_source_grounding_declaration(payload)


def test_declaration_records_are_frozen(source: bytes) -> None:
    declaration, _certificate, _evidence = _declaration(source)
    decoded = grounding.decode_source_grounding_declaration(declaration)

    with pytest.raises(FrozenInstanceError):
        decoded.declarer_coordinate = "changed"  # type: ignore[misc]


def test_receipt_recheck_rejects_changed_current_evidence(source: bytes) -> None:
    declaration, _certificate, evidence = _declaration(source)
    receipt = grounding.build_source_grounding_receipt(declaration, evidence)
    evidence.pop(json.loads(declaration)["certificate"]["digest"])

    with pytest.raises(
        grounding.SourceGroundingError,
        match="SOURCE_GROUNDING_RECEIPT_NOT_REPRODUCED",
    ):
        grounding.recheck_source_grounding_receipt(declaration, receipt, evidence)
