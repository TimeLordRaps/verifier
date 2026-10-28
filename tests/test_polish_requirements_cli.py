"""Gates in the command-line interface (CLI) for independently pinned requirements."""
from __future__ import annotations

import json

import pytest

from verifier.runtime.public_cli import build_parser, main


def test_coverage_accepts_explicit_requirements_and_digest() -> None:
    args = build_parser().parse_args([
        "polish", "coverage", "bundle.json", "--request", "request.json",
        "--requirements", "requirements.json", "--requirements-digest", "sha256:" + "0" * 64,
        "--contract-version", "2", "--json"])
    assert args.polish_command == "coverage"
    assert args.requirements == "requirements.json"
    assert args.requirements_digest == "sha256:" + "0" * 64
    assert args.contract_version == "2"


def test_coverage_refuses_omitting_the_independent_inventory_pin(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as rejected:
        build_parser().parse_args([
            "polish", "coverage", "bundle.json", "--request", "request.json",
            "--requirements", "requirements.json"])
    assert rejected.value.code == 2
    assert "--requirements-digest" in capsys.readouterr().err


def test_missing_inputs_remain_unknown_instead_of_manufacturing_coverage(tmp_path, capsys) -> None:
    missing = str(tmp_path / "absent.json")
    code = main(["polish", "coverage", missing, "--request", missing,
                 "--requirements", missing, "--requirements-digest", "sha256:" + "0" * 64,
                 "--json"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["status"] == "UNKNOWN"
    assert result["declared_coverage"] == "UNKNOWN"
    assert result["polished"] is False
    assert result["objective_inventory_closure"] == "NOT_ESTABLISHED"
