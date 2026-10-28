"""Terminology: command-line interface (CLI); JavaScript Object Notation (JSON).

The wiring of `vstd publish --clearance` and of the `vstd polish PATH` shortcut. The clearance flow itself is
tested in test_cli_clearance_workflow.py; this file holds what that file does not reach: the two usage guards of
`publish`, the options that need `--clearance`, and the shortcut's boundaries. The shortcut must not take a
real `polish` subcommand for a path, must select the gates preparation report that the clearance flow consumes,
and must leave an explicit `--report-format` after the path in force."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from verifier.runtime import public_cli
from verifier.runtime.public_cli import build_parser, main

GATES_REPORT = "verifier-polish-preparation-1"
WORKFLOW_REPORT = "verifier-polish-workflow-report-1"


def subparsers_of(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    raise AssertionError("the parser has no subcommands")


def polish_subcommands() -> set[str]:
    return set(subparsers_of(subparsers_of(build_parser())["polish"]))


def source(tmp_path: Path) -> Path:
    target = tmp_path / "program.py"
    target.write_bytes(b"result = 2 + 3\n")
    return target


def test_the_shortcut_exclusion_set_is_exactly_the_polish_subcommands() -> None:
    assert public_cli.POLISH_SUBCOMMANDS == polish_subcommands()


@pytest.mark.parametrize("name", sorted(polish_subcommands()))
def test_a_polish_subcommand_is_not_taken_for_a_path(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["polish", name, "--help"])
    assert stop.value.code == 0
    usage = " ".join(capsys.readouterr().out.split("\n\n", 1)[0].split())
    assert usage.startswith("usage: vstd polish " + name + " ")


def test_an_option_after_polish_is_not_taken_for_a_path(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["polish", "--help"])
    assert stop.value.code == 0
    usage = " ".join(capsys.readouterr().out.split("\n\n", 1)[0].split())
    assert usage.startswith("usage: vstd polish [-h] {")


def test_polish_without_a_word_after_it_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["polish"])
    assert stop.value.code == 2
    assert "the following arguments are required: polish_command" in capsys.readouterr().err


def test_the_polish_path_shortcut_selects_the_gates_preparation_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "preparation.json"
    assert main(["polish", str(source(tmp_path)), "--dry-run", "--output", str(output), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == GATES_REPORT and report["mode"] == "DRY_RUN" and report["polished"] is False


def test_an_explicit_report_format_after_the_path_overrides_the_shortcut(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["polish", str(source(tmp_path)), "--report-format", WORKFLOW_REPORT, "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == WORKFLOW_REPORT and report["status"] == "FAIL"


def test_publish_without_a_receipt_or_clearance_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["publish"])
    assert stop.value.code == 2
    assert "publish requires a receipt or the --clearance preparation mode" in capsys.readouterr().err


@pytest.mark.parametrize("option", ["--dependency-policy", "--facet-inventory", "--facet-specification", "--facet-policy"])
def test_a_dependency_or_facet_requirement_needs_clearance(option: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["publish", "receipt.json", option, "selected.json"])
    assert stop.value.code == 2
    assert "dependency and facet requirements require --clearance" in capsys.readouterr().err


def test_clearance_alone_reaches_the_clearance_handler_not_the_receipt_modes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["publish", "--clearance", str(tmp_path / "clearance.json"), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["result"] == "REJECTED" and report["transport_performed"] is False and report["publication"] == "NOT_ESTABLISHED"
