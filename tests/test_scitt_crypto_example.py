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


cbor2 = pytest.importorskip("cbor2")
scitt_cose = pytest.importorskip("scitt_cose")
pytest.importorskip("cryptography")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

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
    assert result["scitt_verifier_runtime"] == {
        "coordinate_status": "MATCHED",
        "distribution_name": "scitt-cose",
        "distribution_version": "0.2.2",
        "import_package": "scitt_cose",
        "module_version": "0.2.2",
        "verification_entrypoints": [
            "scitt_cose.statement:parse_signed_statement",
            "scitt_cose.receipt:verify_receipt",
            "scitt_cose.statement:extract_receipts",
        ],
        "claim_boundary": (
            "This result records that the current Python process imported the "
            "scitt_cose package from the installed scitt-cose==0.2.2 distribution "
            "and executed the named verification entrypoints. It does not "
            "authenticate that distribution, establish producer provenance, attest "
            "the runtime environment, prove independent reproduction or distinct "
            "actors, cover the complete transitive cryptographic implementation, or "
            "promote the VSTD SCITT adapters to native catalog components."
        ),
    }
    assert result["direct_runtime_dependencies"] == [
        {
            "distribution_name": "cbor2",
            "distribution_version": "6.1.4",
            "role": "Concise Binary Object Representation codec",
        },
        {
            "distribution_name": "cryptography",
            "distribution_version": "50.0.0",
            "role": "Edwards-curve Digital Signature Algorithm primitives",
        },
    ]
    written_result = json.loads((tmp_path / "verification_result.json").read_text())
    assert written_result["scitt_verifier_runtime"] == result["scitt_verifier_runtime"]
    payload_text = (tmp_path / "vstd_scitt_payload.json").read_text()
    assert "scitt_verifier_runtime" not in payload_text
    assert "scitt-cose" not in payload_text

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


def test_scitt_runtime_rejects_distribution_version_drift(monkeypatch):
    demo = _load_demo()
    monkeypatch.setitem(
        demo.EXPECTED_NATIVE_DISTRIBUTIONS, "scitt-cose", "0.2.3"
    )

    with pytest.raises(RuntimeError, match="native distribution version mismatch"):
        demo._crypto()


def test_scitt_runtime_rejects_module_version_disagreement(monkeypatch):
    demo = _load_demo()
    monkeypatch.setattr(scitt_cose, "__version__", "0.2.1")

    with pytest.raises(RuntimeError, match="module version does not match"):
        demo._crypto()


def test_scitt_runtime_rejects_distribution_metadata_name_disagreement(monkeypatch):
    demo = _load_demo()
    real_distribution = demo.importlib_metadata.distribution

    class DistributionProxy:
        def __init__(self, wrapped):
            self._wrapped = wrapped
            self.metadata = {"Name": "not-scitt-cose"}

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

    def mismatched_distribution(name):
        distribution = real_distribution(name)
        if name == "scitt-cose":
            return DistributionProxy(distribution)
        return distribution

    monkeypatch.setattr(
        demo.importlib_metadata, "distribution", mismatched_distribution
    )
    with pytest.raises(RuntimeError, match="metadata name mismatch"):
        demo._crypto()


def test_scitt_runtime_rejects_shadowed_entrypoint(monkeypatch):
    demo = _load_demo()
    monkeypatch.setattr(scitt_cose, "parse_signed_statement", lambda *_: None)

    with pytest.raises(RuntimeError, match="not supplied by the installed"):
        demo._crypto()


def test_scitt_runtime_rejects_shadowed_root_module(monkeypatch, tmp_path):
    demo = _load_demo()
    monkeypatch.setattr(scitt_cose, "__file__", str(tmp_path / "scitt_cose.py"))

    with pytest.raises(RuntimeError, match="imported scitt_cose module is not supplied"):
        demo._crypto()


@pytest.mark.parametrize(
    ("module", "label"),
    (
        (cbor2, "cbor2"),
        (serialization, "cryptography serialization"),
    ),
)
def test_scitt_runtime_rejects_shadowed_dependency_module(
    monkeypatch, tmp_path, module, label
):
    demo = _load_demo()
    monkeypatch.setattr(module, "__file__", str(tmp_path / "shadowed.py"))

    with pytest.raises(RuntimeError, match=f"imported {label} module is not supplied"):
        demo._crypto()


def test_scitt_runtime_rejects_direct_dependency_version_drift(monkeypatch):
    demo = _load_demo()
    monkeypatch.setitem(demo.EXPECTED_NATIVE_DISTRIBUTIONS, "cbor2", "6.1.5")

    with pytest.raises(RuntimeError, match="native distribution version mismatch"):
        demo._crypto()


def test_checked_in_scitt_result_records_bounded_verifier_runtime() -> None:
    result = json.loads(
        (REPO_ROOT / "examples" / "scitt_interop" / "generated" / "verification_result.json")
        .read_text(encoding="utf-8")
    )

    assert result["scitt_verifier_runtime"]["coordinate_status"] == "MATCHED"
    assert result["scitt_verifier_runtime"]["distribution_name"] == "scitt-cose"
    assert result["scitt_verifier_runtime"]["distribution_version"] == "0.2.2"
    assert result["scitt_verifier_runtime"]["verification_entrypoints"] == [
        "scitt_cose.statement:parse_signed_statement",
        "scitt_cose.receipt:verify_receipt",
        "scitt_cose.statement:extract_receipts",
    ]
    assert [
        (item["distribution_name"], item["distribution_version"])
        for item in result["direct_runtime_dependencies"]
    ] == [("cbor2", "6.1.4"), ("cryptography", "50.0.0")]
    payload_text = (
        REPO_ROOT / "examples" / "scitt_interop" / "generated" / "vstd_scitt_payload.json"
    ).read_text(encoding="utf-8")
    assert "scitt_verifier_runtime" not in payload_text
    assert "scitt-cose" not in payload_text


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
