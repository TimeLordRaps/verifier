from __future__ import annotations

import json
from pathlib import Path

from verifiable.runtime.public_cli import build_parser, main


KEY_ID = "cli-test-key"
KEY_HEX = "11" * 32


def _json_output(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def test_vstd3_parser_exposes_required_command_families() -> None:
    parser = build_parser()
    assert parser.parse_args(["hardware", "list"]).command == "hardware"
    assert parser.parse_args(["hardware", "verify", "receipt.json"]).hardware_command == "verify"
    assert parser.parse_args(["continuity", "verify", "receipt.json"]).command == "continuity"
    assert parser.parse_args(["fleet", "verify", "receipt.json"]).command == "fleet"
    assert parser.parse_args(["evidence", "inspect", "receipt.json"]).command == "evidence"
    assert parser.parse_args(["claims", "explain", "DEVICE_IDENTITY"]).command == "claims"


def test_hardware_registry_cli_is_machine_readable(capsys) -> None:
    assert main(["hardware", "list", "--vendor", "NVIDIA", "--json"]) == 0
    payload = _json_output(capsys)
    assert payload["status"] == "PASS"
    assert payload["profiles"]
    assert {item["vendor"] for item in payload["profiles"]} == {"NVIDIA"}

    assert main(["hardware", "inspect", "nvidia.hopper", "--json"]) == 0
    payload = _json_output(capsys)
    assert payload["profile"]["profile_id"] == "nvidia.hopper"


def test_virtual_probe_cli_and_verification_statuses(tmp_path: Path, capsys) -> None:
    receipt_path = tmp_path / "receipt.json"
    assert (
        main(
            [
                "hardware",
                "emulate",
                "--output",
                str(receipt_path),
                "--created-at",
                "2026-08-21T20:00:00Z",
                "--device-id",
                "cli-device",
                "--key-id",
                KEY_ID,
                "--key-hex",
                KEY_HEX,
                "--json",
            ]
        )
        == 0
    )
    generated = _json_output(capsys)
    assert generated["status"] == "PASS"
    assert "not physical-hardware attestation" in generated["summary"]
    assert receipt_path.exists()

    assert main(["continuity", "verify", str(receipt_path), "--json"]) == 2
    assert _json_output(capsys)["status"] == "UNKNOWN"
    key_arg = f"{KEY_ID}={KEY_HEX}"
    assert main(["hardware", "verify", str(receipt_path), "--json"]) == 2
    assert _json_output(capsys)["status"] == "UNKNOWN"
    assert main(["continuity", "verify", str(receipt_path), "--key", key_arg, "--json"]) == 0
    assert _json_output(capsys)["status"] == "PASS"

    assert main(["evidence", "inspect", str(receipt_path), "--key", key_arg, "--json"]) == 0
    assert _json_output(capsys)["status"] == "PASS"

    assert main(["hardware", "verify", str(receipt_path), "--key", key_arg, "--json"]) == 0
    assert _json_output(capsys)["status"] == "PASS"

    assert main(["hardware", "capabilities", str(receipt_path), "--key", key_arg, "--json"]) == 2
    capabilities = _json_output(capsys)
    by_profile = {item["profile"]: item["status"] for item in capabilities["profiles"]}
    assert by_profile["VSTD3-COMPLETE-MEDIATION"] == "PASS"
    assert by_profile["VSTD3-FLEET"] in {"UNKNOWN", "UNSUPPORTED"}

    assert main(["claims", "evaluate", str(receipt_path), "--key", key_arg, "--json"]) == 2
    claims = _json_output(capsys)
    assert claims["status"] == "UNKNOWN"
    assert claims["validation_errors"] == []
    by_kind = {item["claim_kind"]: item["status"] for item in claims["claims"]}
    assert by_kind["COMPLETE_MEDIATION"] == "PASS"
    assert by_kind["PHYSICAL_WORLD_COMPLETENESS"] == "UNSUPPORTED"

    assert main(["fleet", "verify", str(receipt_path), "--json"]) == 2
    assert _json_output(capsys)["status"] == "UNSUPPORTED"


def test_claim_explanation_translates_prohibited_inference(capsys) -> None:
    assert main(["claims", "explain", "FIRMWARE_INTEGRITY", "--json"]) == 0
    payload = _json_output(capsys)
    assert payload["status"] == "PASS"
    assert "does not prove" in payload["claim"]["prohibited_inference"]


def test_generic_discovery_requires_fixture_and_preserves_host_only_status(
    tmp_path: Path, capsys
) -> None:
    assert main(["hardware", "discover", "--adapter", "generic", "--json"]) == 1
    assert "requires --fixture" in capsys.readouterr().err

    fixture = tmp_path / "generic.json"
    fixture.write_text(
        json.dumps(
            {
                "schema_version": "VSTD3-GENERIC-FIXTURE-1.0",
                "profile_id": "generic.ai-asic",
                "observed_at": "2026-08-21T20:00:00Z",
                "boundary_id": "fixture",
                "devices": [
                    {
                        "device_id": "unknown-0",
                        "model": "Unknown X",
                        "architecture": "unknown",
                        "serial": "unknown-serial",
                        "deployment_class": "datacenter",
                        "partitions": [],
                        "attributes": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "hardware",
                "discover",
                "--adapter",
                "generic",
                "--fixture",
                str(fixture),
                "--json",
            ]
        )
        == 0
    )
    payload = _json_output(capsys)
    source = payload["adapter_result"]["evidence_sources"][0]
    assert source["capabilities"] == ["HOST_OBSERVED"]
    assert source["verification_state"] == "NOT_VERIFIED"
