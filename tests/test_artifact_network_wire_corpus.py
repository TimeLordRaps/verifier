"""Reject the shared Verifier Standard (VSTD) negative wire corpus."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable

import pytest

from scripts.build_artifact_network_negative_corpus import (
    CASE_FIELDS,
    MAX_CASES,
    MAX_CORPUS_BYTES,
    SCHEMA,
    TARGETS,
    build_negative_corpus,
)
from scripts.build_artifact_network_fixture import TARGET as POSITIVE_FIXTURE, build_fixture
from verifier.interoperability import network
from verifier.interoperability.network import (
    AuthorityModel,
    ContentAddressedStore,
    NetworkError,
    ObjectRecord,
    PublisherRecord,
    SignedHead,
    SiloCommit,
    build_silo_assessment_receipt,
    canonical_bytes,
    digest_bytes,
    materialize_silo_transfer,
    verify_head,
)


CORPUS = Path("examples/artifact-network/canonical-wire-negative-corpus.json")
CRYPTOGRAPHIC_CASES = {
    "signed-head-signature-substitution",
    "silo-transfer-signature-substitution",
    # The public materializer verifies the signed head before recomputing receipts.
    "silo-transfer-receipt-substitution",
}


def _load_retained(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_CORPUS_BYTES + 1)
    assert len(raw) <= MAX_CORPUS_BYTES
    value = json.loads(raw)
    assert isinstance(value, dict)
    assert raw == (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    return value


def _load_corpus() -> dict[str, Any]:
    return _load_retained(CORPUS)


def test_fixture_builders_import_without_optional_site_packages() -> None:
    root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ, PYTHONPATH=str(root / "src"))
    subprocess.run(
        [sys.executable, "-u", "-S", "-c",
         "import scripts.build_artifact_network_fixture; "
         "import scripts.build_artifact_network_negative_corpus; "
         "import scripts.build_silo_composition_fixture; import sys; "
         "assert not any(name == 'cryptography' or name.startswith('cryptography.') "
         "for name in sys.modules); print('Fixture imports require no optional site packages')"],
        cwd=root, env=environment, check=True, timeout=30,
    )


def test_retained_wire_fixtures_match_cryptographic_regeneration() -> None:
    pytest.importorskip("cryptography", reason="fixture freshness regenerates Ed25519 keys and signatures")
    assert _load_retained(POSITIVE_FIXTURE) == build_fixture()
    assert _load_corpus() == build_negative_corpus()


def test_negative_wire_corpus_is_bounded_exact_and_canonical() -> None:
    corpus = _load_corpus()
    assert set(corpus) == {"schema_version", "cases", "claim_boundary"}
    assert corpus["schema_version"] == SCHEMA
    assert 0 < len(corpus["cases"]) <= MAX_CASES
    case_ids = [case["case_id"] for case in corpus["cases"]]
    assert case_ids == sorted(set(case_ids))
    assert {case["target"] for case in corpus["cases"]} == TARGETS
    assert CRYPTOGRAPHIC_CASES <= set(case_ids)
    for case in corpus["cases"]:
        assert set(case) == CASE_FIELDS
        assert case["target"] in TARGETS
        assert case["expected_result"] == "REJECT"
        assert 0 < len(case["claim_boundary"].encode("utf-8")) <= 512


@pytest.mark.parametrize("case", _load_corpus()["cases"], ids=lambda case: case["case_id"])
def test_public_decoders_and_materializer_reject_every_negative_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: dict[str, Any],
) -> None:
    if case["case_id"] in CRYPTOGRAPHIC_CASES:
        pytest.importorskip("cryptography", reason="this public rejection path must verify an Ed25519 signature")
    else:
        def unexpected_crypto() -> None:
            pytest.fail("structural rejection must precede optional cryptographic operations")
        monkeypatch.setattr(network, "_crypto", unexpected_crypto)
    positive = _load_retained(POSITIVE_FIXTURE)["records"]
    publisher = PublisherRecord.from_dict(positive["publisher"])

    def signed_head(record: dict[str, Any], _destination: Path) -> None:
        verify_head(SignedHead.from_dict(record), publisher)

    def transfer(record: dict[str, Any], destination: Path) -> None:
        materialize_silo_transfer(record, destination)

    dispatch: dict[str, Callable[[dict[str, Any], Path], object]] = {
        "AUTHORITY_MODEL": lambda record, _destination: AuthorityModel.from_dict(record),
        "COMMIT": lambda record, _destination: SiloCommit.from_dict(record),
        "OBJECT": lambda record, _destination: ObjectRecord.from_dict(record),
        "PUBLISHER": lambda record, _destination: PublisherRecord.from_dict(record),
        "SIGNED_HEAD": signed_head,
        "SILO_TRANSFER": transfer,
    }
    destination = tmp_path / case["case_id"]
    with pytest.raises(NetworkError) as rejection:
        dispatch[case["target"]](case["record"], destination)
    assert str(rejection.value), case["case_id"]
    assert "require verifier-standard[seal]" not in str(rejection.value)
    if case["case_id"] in CRYPTOGRAPHIC_CASES:
        expected = (
            "transferred assessment receipt does not match local recomputation"
            if case["case_id"] == "silo-transfer-receipt-substitution"
            else "signed head signature did not verify"
        )
        assert str(rejection.value) == expected
    assert not destination.exists(), case["case_id"]


def test_retained_receipt_recomputation_detects_substitution_without_signatures(tmp_path: Path) -> None:
    positive = _load_retained(POSITIVE_FIXTURE)
    records = positive["records"]
    commit = SiloCommit.from_dict(records["commit"])
    supplied_objects = {
        item["digest"]: base64.urlsafe_b64decode(item["bytes_base64url"] + "=" * (-len(item["bytes_base64url"]) % 4))
        for item in records["silo_transfer"]["objects"]
    }
    assert set(supplied_objects) == {entry.object_record.object_digest for entry in commit.census}
    store = ContentAddressedStore(tmp_path / "retained")
    for entry in commit.census:
        expected = entry.object_record
        assert store.add_object(
            supplied_objects[expected.object_digest], expected.media_type,
            expected.artifact_kind, expected.declared_schema_id,
        ) == expected
    computed = build_silo_assessment_receipt(commit, store).to_dict()
    assert computed == records["assessment_receipt"]
    assert canonical_bytes(computed).decode("utf-8") == positive["expected"]["assessment_receipt_canonical_json"]
    assert digest_bytes(canonical_bytes(computed)) == positive["expected"]["assessment_receipt_digest"]
    case = next(item for item in _load_corpus()["cases"] if item["case_id"] == "silo-transfer-receipt-substitution")
    substituted = case["record"]["assessment_receipt"]
    assert case["record"]["portable_manifest"]["assessment_receipt_digest"] == digest_bytes(canonical_bytes(substituted))
    assert canonical_bytes(computed) != canonical_bytes(substituted)
