"""Cross-runtime proposition-transfer specimens and installed resource boundaries.

Verifier Standard (VSTD); JavaScript Object Notation (JSON).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.build_proposition_transfer_fixture import (
    ROOT, TARGET, assessment_summary, build_fixture, render_fixture,
)
from scripts.release_artifacts import PACKAGED_SCHEMA_NAMES
from verifier.interoperability.network import canonical_bytes, digest_bytes
from verifier.interoperability.proposition_transfer import (
    assess_transfer, decode_transfer, decode_transfer_receipt,
    recheck_transfer_receipt, rule_profile_bytes,
)

SCHEMA_NAME = "vstd-proposition-transfer-0.1.schema.json"


def test_shared_fixture_has_hand_specified_semantic_oracles_and_is_fresh() -> None:
    assert TARGET.read_bytes() == render_fixture()
    fixture = build_fixture()
    assert len(fixture["cases"]) == 18
    assert fixture["rule_profile_digest"] == digest_bytes(rule_profile_bytes())
    assert fixture["rule_profile_canonical_json"].encode("utf-8") == rule_profile_bytes()
    for case in fixture["cases"]:
        declaration = case["declaration_canonical_json"].encode("utf-8")
        receipt = case["receipt_canonical_json"].encode("utf-8")
        evidence = {
            item["digest"]: base64.urlsafe_b64decode(item["bytes_base64url"] + "=" * (-len(item["bytes_base64url"]) % 4))
            for item in case["objects"]
        }
        assert digest_bytes(declaration) == case["declaration_digest"], case["case_id"]
        assert digest_bytes(receipt) == case["receipt_digest"], case["case_id"]
        for digest, payload in evidence.items():
            assert digest_bytes(payload) == digest, case["case_id"]
        result = recheck_transfer_receipt(declaration, receipt, evidence)
        assert result == assess_transfer(declaration, evidence), case["case_id"]
        assert assessment_summary(result) == case["expected"], case["case_id"]


def test_new_wire_schema_copies_and_release_inventory_cover_every_fixture_record() -> None:
    source = ROOT / "standard/schemas" / SCHEMA_NAME
    installed = ROOT / "src/verifier/schemas" / SCHEMA_NAME
    assert source.read_bytes() == installed.read_bytes()
    assert SCHEMA_NAME in PACKAGED_SCHEMA_NAMES
    schema = json.loads(source.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(json.loads(rule_profile_bytes()))
    fixture = json.loads(TARGET.read_text(encoding="utf-8"))
    for case in fixture["cases"]:
        declaration = decode_transfer(case["declaration_canonical_json"].encode("utf-8"))
        receipt = decode_transfer_receipt(case["receipt_canonical_json"].encode("utf-8"))
        validator.validate(declaration)
        validator.validate(receipt)
        validator.validate(receipt["assessment"])
        assert canonical_bytes(declaration).decode("utf-8") == case["declaration_canonical_json"]


def test_rule_document_is_installed_without_strengthening_authority_or_graph_claims() -> None:
    source = ROOT / "standard/PROPOSITION_TRANSFER.md"
    installed = ROOT / "src/verifier/specifications/PROPOSITION_TRANSFER.md"
    assert source.read_bytes() == installed.read_bytes()
    text = source.read_text(encoding="utf-8")
    assert "authority_admissibility" in text
    assert "always NOT_ESTABLISHED" in text
    assert "existing generic DEPENDS_ON edges remain unsupported" in text
    assert "not the full" in text
