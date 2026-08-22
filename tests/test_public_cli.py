"""Tests for the target-neutral public CLI surface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from verifiable.runtime.public_cli import build_parser, main


def _manifest(project: Path) -> Path:
    (project / "input.txt").write_text("21", encoding="utf-8")
    (project / "double.py").write_text(
        "import json, sys\n"
        "value = int(open(sys.argv[1], encoding='utf-8').read())\n"
        "json.dump({'doubled': value * 2}, open(sys.argv[2], 'w', encoding='utf-8'))\n",
        encoding="utf-8",
    )
    manifest = {
        "claim": {
            "id": "RUN-PUBLIC-TEST",
            "title": "Public CLI test",
            "statement": "The declared command doubles the input integer.",
            "scope": "test fixture",
            "limitations": ["single integer"],
            "falsification_condition": "the declared output is absent or changes on rerun",
        },
        "command": [sys.executable, "double.py", "input.txt", "output.json"],
        "cwd": ".",
        "inputs": [
            {"path": "double.py", "role": "entrypoint_source"},
            {"path": "input.txt", "role": "primary_input"},
        ],
        "outputs": [{"path": "output.json", "role": "primary_output"}],
        "determinism_declared": "DETERMINISTIC",
    }
    path = project / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_public_parser_has_no_target_specific_generation_commands() -> None:
    parser = build_parser()
    assert parser.parse_args(["validate", "receipt.json"]).command == "validate"
    assert parser.parse_args(["data", "export", "receipt.json"]).data_command == "export"
    assert parser.parse_args(["plan", "manifest.json"]).command == "plan"


def test_public_cli_plan_is_side_effect_free_and_reports_scope(
    tmp_path: Path, capsys
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manifest = _manifest(project)
    assert main(["plan", str(manifest), "--json"]) == 0

    plan = json.loads(capsys.readouterr().out)
    assert plan["executes_without_sandbox"] is True
    assert plan["cwd"]["outside_manifest_directory"] is False
    assert plan["inputs"][0]["present_before_execution"] is True
    assert not (project / "output.json").exists()


def test_public_cli_plan_discloses_external_paths(tmp_path: Path, capsys) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manifest_path = _manifest(project)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["repo_dir"] = ".."
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert main(["plan", str(manifest_path), "--json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["repo_dir"]["outside_manifest_directory"] is True


def test_public_cli_generic_run_lifecycle(tmp_path: Path, capsys) -> None:
    manifest = _manifest(tmp_path)
    receipt_dir = tmp_path / "receipt"
    assert main(["run", str(manifest), "--output", str(receipt_dir)]) == 0
    assert main(["validate", str(receipt_dir)]) == 0
    assert main(["inspect", str(receipt_dir)]) == 0
    assert main(["reproduce", str(receipt_dir), "--rerun"]) == 0
    assert "[UNSANDBOXED EXECUTION]" in capsys.readouterr().err


def test_public_cli_rejects_unknown_receipt(tmp_path: Path) -> None:
    path = tmp_path / "receipt.json"
    path.write_text('{"schema_version": "UNKNOWN"}', encoding="utf-8")
    assert main(["validate", str(path)]) == 1
