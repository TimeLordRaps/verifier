"""Boundaries for the Verifier Standard (VSTD) polish command-line interface (CLI)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from verifier.runtime import polish, polish_cli, polish_workflow_cli


def test_bounded_assessment_exports_retain_their_source_module() -> None:
    assert polish.assess_polish.__module__ == "verifier.runtime.polish"
    assert polish.recheck_polish.__module__ == "verifier.runtime.polish"
    assert polish.polish_catalog.__module__ == "verifier.runtime.polish"
    assert polish.mechanism_digest.__module__ == "verifier.runtime.polish"


def test_legacy_entry_points_lazily_forward_to_the_cli_module(monkeypatch) -> None:
    parser_token = object()
    captured: list[object] = []
    monkeypatch.setattr(
        polish_cli,
        "add_polish_parsers",
        lambda subparsers: captured.append(subparsers),
    )
    monkeypatch.setattr(polish_cli, "handle_polish_command", lambda args: 17)

    polish.add_polish_parsers(parser_token)
    assert captured == [parser_token]
    assert polish.handle_polish_command(object()) == 17


def test_catalog_routing_calls_the_engine_export_and_never_promotes(
    monkeypatch, capsys
) -> None:
    observed: list[bool] = []

    def catalog(*, include_inventory: bool = False) -> dict[str, object]:
        observed.append(include_inventory)
        return {
            "schema_version": "verifier-polish-catalog-1",
            "polished": False,
            "claim_boundary": "bounded test catalog",
        }

    monkeypatch.setattr(polish, "polish_catalog", catalog)
    args = argparse.Namespace(polish_command="catalog", inventory=True, json=True)
    assert polish_cli.handle_polish_command(args) == 0
    assert observed == [True]
    assert json.loads(capsys.readouterr().out)["polished"] is False


def test_workflow_cli_preserves_fail_closed_non_promoting_boundary(tmp_path) -> None:
    args = argparse.Namespace(
        artifact=str(tmp_path),
        normalize_text=False,
        dry_run=False,
        recover=None,
        associate=None,
        policy=None,
        policy_digest=None,
        definition=None,
        quality_profile=None,
        quality_profile_digest=None,
        requirements=None,
        requirements_digest=None,
        git_root=None,
        base=None,
        commit=None,
        output=None,
        resume=None,
        apply=False,
        rollback=False,
    )
    result = polish_workflow_cli._handle_preparation(args)
    assert result["status"] == "FAIL"
    assert result["polished"] is result["promotable"] is False


def test_command_modules_do_not_expand_the_assessment_mechanism_digest(
    monkeypatch,
) -> None:
    targets = {Path(polish_cli.__file__), Path(polish_workflow_cli.__file__)}
    original = Path.read_bytes
    before = polish.mechanism_digest()

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged command routing\n" if path in targets else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() == before
