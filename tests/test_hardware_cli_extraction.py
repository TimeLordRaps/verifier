"""Terminology: command-line interface (CLI); JavaScript Object Notation (JSON);
Verifier Standard (VSTD).

Characterization tests for the compatibility boundaries of the VSTD 3 CLI facade.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifier.runtime import hardware_cli
from verifier.runtime.hardware_cli_support import status_exit
from verifier.runtime.public_cli import main


KEY_ID = "hardware-extraction-test"
KEY_HEX = "23" * 32


def _empty_generic_fixture(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "VSTD3-GENERIC-FIXTURE-1.0",
                "profile_id": "generic.ai-asic",
                "observed_at": "2026-10-13T12:00:00Z",
                "boundary_id": "empty-fixture",
                "devices": [],
            }
        ),
        encoding="utf-8",
    )


def test_facade_declares_only_the_three_supported_exports() -> None:
    assert hardware_cli.__all__ == (
        "add_vstd3_parsers",
        "parse_verification_keys",
        "handle_vstd3_command",
    )


def test_verification_keys_preserve_identical_duplicates_and_reject_conflicts() -> None:
    key_arg = f"{KEY_ID}={KEY_HEX}"
    resolver, keys = hardware_cli.parse_verification_keys([key_arg, key_arg])

    assert keys == {KEY_ID: bytes.fromhex(KEY_HEX)}
    assert resolver(KEY_ID) == bytes.fromhex(KEY_HEX)
    assert resolver("missing") is None

    with pytest.raises(ValueError, match=f"conflicting verification keys for {KEY_ID}"):
        hardware_cli.parse_verification_keys([key_arg, f"{KEY_ID}={'24' * 32}"])


@pytest.mark.parametrize(
    ("status", "expected"),
    (("PASS", 0), ("FAIL", 1), ("UNKNOWN", 2), ("UNSUPPORTED", 2)),
)
def test_claim_status_exit_mapping_is_stable(status: str, expected: int) -> None:
    assert status_exit(status) == expected


def test_attest_remains_the_virtual_emulation_path(tmp_path: Path, capsys) -> None:
    receipt = tmp_path / "attestation.json"

    assert (
        main(
            [
                "hardware",
                "attest",
                "--virtual",
                "--output",
                str(receipt),
                "--created-at",
                "2026-10-13T12:00:00Z",
                "--key-id",
                KEY_ID,
                "--key-hex",
                KEY_HEX,
                "--json",
            ]
        )
        == 0
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["operation"] == "hardware.emulate"
    assert "not physical-hardware attestation" in payload["summary"]
    assert receipt.exists()


def test_empty_generic_discovery_is_unsupported_and_overwrites_output(
    tmp_path: Path, capsys
) -> None:
    fixture = tmp_path / "empty.json"
    output = tmp_path / "adapter-result.json"
    _empty_generic_fixture(fixture)
    output.write_text("stale content that must be replaced", encoding="utf-8")

    assert (
        main(
            [
                "hardware",
                "discover",
                "--adapter",
                "generic",
                "--fixture",
                str(fixture),
                "--output",
                str(output),
                "--json",
            ]
        )
        == 2
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "UNSUPPORTED"
    assert payload["adapter_result"]["descriptors"] == []
    assert json.loads(output.read_text(encoding="utf-8")) == payload["adapter_result"]
    assert output.read_bytes().endswith(b"\n")
    assert b"stale content" not in output.read_bytes()


def test_hardware_registry_failure_still_precedes_virtual_probe(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "must-not-exist.json"

    def fail_registry_load():
        raise ValueError("characterized registry failure")

    monkeypatch.setattr(hardware_cli, "load_builtin_registry", fail_registry_load)

    assert (
        main(
            [
                "hardware",
                "emulate",
                "--output",
                str(output),
                "--created-at",
                "2026-10-13T12:00:00Z",
                "--key-id",
                KEY_ID,
                "--key-hex",
                KEY_HEX,
                "--json",
            ]
        )
        == 1
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "characterized registry failure" in captured.err
    assert not output.exists()


def test_json_output_remains_sorted_indented_and_newline_terminated(capsys) -> None:
    assert main(["claims", "explain", "FIRMWARE_INTEGRITY", "--json"]) == 0

    output = capsys.readouterr().out
    assert output.startswith('{\n  "claim": {')
    assert output.endswith("\n")
    assert json.dumps(json.loads(output), indent=2, sort_keys=True) + "\n" == output
