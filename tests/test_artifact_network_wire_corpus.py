"""Reject the shared Verifier Standard (VSTD) negative wire corpus."""

from __future__ import annotations

import json
from pathlib import Path
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
from scripts.build_artifact_network_fixture import build_fixture
from verifier.interoperability.network import (
    AuthorityModel,
    NetworkError,
    ObjectRecord,
    PublisherRecord,
    SignedHead,
    SiloCommit,
    materialize_silo_transfer,
    verify_head,
)


CORPUS = Path("examples/artifact-network/canonical-wire-negative-corpus.json")


def _load_corpus() -> dict[str, Any]:
    with CORPUS.open("rb") as stream:
        raw = stream.read(MAX_CORPUS_BYTES + 1)
    assert len(raw) <= MAX_CORPUS_BYTES
    value = json.loads(raw)
    assert value == build_negative_corpus()
    return value


def test_negative_wire_corpus_is_bounded_exact_and_canonical() -> None:
    corpus = _load_corpus()
    assert set(corpus) == {"schema_version", "cases", "claim_boundary"}
    assert corpus["schema_version"] == SCHEMA
    assert 0 < len(corpus["cases"]) <= MAX_CASES
    case_ids = [case["case_id"] for case in corpus["cases"]]
    assert case_ids == sorted(set(case_ids))
    assert {case["target"] for case in corpus["cases"]} == TARGETS
    for case in corpus["cases"]:
        assert set(case) == CASE_FIELDS
        assert case["target"] in TARGETS
        assert case["expected_result"] == "REJECT"
        assert 0 < len(case["claim_boundary"].encode("utf-8")) <= 512


def test_public_decoders_and_materializer_reject_every_negative_case(tmp_path: Path) -> None:
    corpus = _load_corpus()
    positive = build_fixture()["records"]
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
    for case in corpus["cases"]:
        destination = tmp_path / case["case_id"]
        with pytest.raises(NetworkError) as rejection:
            dispatch[case["target"]](case["record"], destination)
        assert str(rejection.value), case["case_id"]
        assert not destination.exists(), case["case_id"]
