"""Terminology: Concise Binary Object Representation (CBOR);
CBOR Object Signing and Encryption (COSE); Supply Chain Integrity, Transparency, and Trust (SCITT);
Verifier Standard (VSTD).

Optional real-COSE integration test for the self-contained example."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource


pytest.importorskip("scitt_cose")
pytest.importorskip("cryptography")

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO = REPO_ROOT / "examples" / "scitt_interop" / "demo.py"


def _load_demo():
    spec = importlib.util.spec_from_file_location("vstd_scitt_demo", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_real_signed_statement_receipt_and_independent_consumption(tmp_path):
    result = _load_demo().produce(tmp_path)
    assert result["vstd_kernel"]["outcome"] == "ACCEPTED"
    assert result["vstd_kernel"]["verdict"] == "PASS"
    assert result["scitt_observation"]["signed_statement_verified"] is True
    assert result["scitt_observation"]["receipt_verified"] is True
    assert result["composition"]["status"] == "PASS"
    assert result["vstd_observation"]["conformance_status"] == "NOT_ESTABLISHED"
    assert result["composition"]["vstd_conformance_status"] == "NOT_ESTABLISHED"
    assert result["composition"]["status_scope"] == (
        "NATIVE_VSTD_RESULT_AND_SCITT_REGISTRATION"
    )
    assert "conformance NOT_ESTABLISHED" in result["composition"]["reason"]

    schema_dir = REPO_ROOT / "receipts" / "schema"
    receipt_schema = json.loads((schema_dir / "vstd4_receipt.json").read_text())
    certificate_schema = json.loads(
        (schema_dir / "vstd4_certificate.json").read_text()
    )
    registry = Registry().with_resource(
        certificate_schema["$id"], Resource.from_contents(certificate_schema)
    )
    receipt = json.loads((tmp_path / "vstd_receipt.json").read_text())
    Draft202012Validator(receipt_schema, registry=registry).validate(receipt)
    assert receipt["conformance_status"] == "NOT_ESTABLISHED"


def test_application_payload_is_deterministic_but_ephemeral_cose_keys_are_not(
    tmp_path,
):
    demo = _load_demo()
    first = tmp_path / "first"
    second = tmp_path / "second"
    demo.produce(first)
    demo.produce(second)

    assert (first / "vstd_scitt_payload.json").read_bytes() == (
        second / "vstd_scitt_payload.json"
    ).read_bytes()
    assert (first / "signed_statement.cose").read_bytes() != (
        second / "signed_statement.cose"
    ).read_bytes()


def test_real_statement_and_receipt_tampering_are_rejected(tmp_path):
    demo = _load_demo()
    demo.produce(tmp_path)

    statement = tmp_path / "signed_statement.cose"
    statement_bytes = statement.read_bytes()
    statement.write_bytes(statement_bytes[:-1] + bytes([statement_bytes[-1] ^ 1]))
    with pytest.raises(RuntimeError, match="signature did not verify"):
        demo.verify(tmp_path)

    demo.produce(tmp_path)
    receipt = tmp_path / "receipt.cose"
    receipt_bytes = receipt.read_bytes()
    receipt.write_bytes(receipt_bytes[:-1] + bytes([receipt_bytes[-1] ^ 1]))
    with pytest.raises(RuntimeError, match="COSE Receipt failed"):
        demo.verify(tmp_path)


def test_real_malformed_scitt_statement_is_rejected_before_composition(tmp_path):
    demo = _load_demo()
    demo.produce(tmp_path)
    (tmp_path / "signed_statement.cose").write_bytes(b"\x80")

    with pytest.raises(RuntimeError, match="malformed SCITT Signed Statement"):
        demo.verify(tmp_path)


def test_real_scitt_registration_does_not_upgrade_vstd_budget_exhaustion(tmp_path):
    demo = _load_demo()
    demo.produce(tmp_path)
    result = demo.verify(tmp_path, vstd_budget=0)
    assert result["scitt_observation"]["signed_statement_verified"] is True
    assert result["scitt_observation"]["receipt_verified"] is True
    assert result["vstd_kernel"]["outcome"] == "REFUSED"
    assert result["vstd_kernel"]["verdict"] == "UNKNOWN"
    assert result["composition"]["status"] == "UNKNOWN"


def test_real_valid_scitt_registration_does_not_repair_rejected_vstd_claim(tmp_path):
    result = _load_demo().produce(tmp_path, vstd_binding_tamper=True)
    assert result["scitt_observation"]["signed_statement_verified"] is True
    assert result["scitt_observation"]["receipt_verified"] is True
    assert result["vstd_kernel"]["outcome"] == "REJECTED"
    assert result["vstd_observation"]["state"] == "REJECTED"
    assert result["composition"]["status"] == "FAIL"
