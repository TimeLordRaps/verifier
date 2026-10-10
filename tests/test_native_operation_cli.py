"""command-line interface (CLI) controls for exact native operation metadata.

JavaScript Object Notation (JSON). Metadata success supplies no native replay,
mandatory census, complete application conformance or release acceptance.
"""
from __future__ import annotations

import json

import pytest

from verifier.runtime.native_operation_contracts import DESCRIPTOR, LOOKUP, HISTORICAL, TEN_TIER
from verifier.runtime.public_cli import main


@pytest.mark.parametrize("family,count", [(HISTORICAL, 408), (TEN_TIER, 2)])
def test_separate_operation_catalogs(family: str, count: int, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["operations", "catalog", "--semantic-version", family]) == 0
    result = json.loads(capsys.readouterr().out)
    assert len(result["routes"]) == count
    assert result["semantic_version"] == family
    assert result["native_replay"] == "NOT_RUN"
    assert result["mandatory_obligation_census"] == "UNKNOWN"


@pytest.mark.parametrize("version", [DESCRIPTOR, LOOKUP])
def test_schema_export_closed_wire(version: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["operations", "schema", version]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == version


def test_lookup_pins_and_wrong_pin_refutation(capsys: pytest.CaptureFixture[str]) -> None:
    command = ["operations", "lookup", "--semantic-version", HISTORICAL,
               "--objective", "HARNESS-1.6", "--represented-kind", "HARNESS"]
    assert main(command) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["metadata_status"] == "AVAILABLE"
    assert result["native_replay"] == "NOT_RUN"
    assert result["full_execution_qualification"] == "UNKNOWN"
    assert main(command + ["--expected-descriptor-digest", result["descriptor_digest"]]) == 0
    assert json.loads(capsys.readouterr().out)["pin_comparison"] == "MATCH"
    assert main(command + ["--expected-descriptor-digest", "sha256:" + "0" * 64]) == 1
    assert json.loads(capsys.readouterr().out)["pin_comparison"] == "DIFFERS"


def test_wrong_selector_refused_before_support_reads(monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    from verifier.runtime import native_operation_contracts as operations

    def forbid(*args: object, **kwargs: object) -> bytes:
        pytest.fail("wrong selector opened support files")

    monkeypatch.setattr(operations, "_read_package", forbid)
    assert main(["operations", "lookup", "--semantic-version", TEN_TIER,
                 "--objective", "VERIFIER-10.2", "--represented-kind", "VERIFIER"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "[REJECTED]" in captured.err


def test_missing_schema_reports_unknown(monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    from verifier.runtime import native_operation_contracts as operations

    def absent(*args: object, **kwargs: object) -> bytes:
        raise OSError("support unavailable")

    monkeypatch.setattr(operations, "_read_package", absent)
    assert main(["operations", "schema", DESCRIPTOR]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "[UNKNOWN]" in captured.err
