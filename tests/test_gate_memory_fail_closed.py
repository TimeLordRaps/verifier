"""Gate command-line interface (CLI) memory-failure boundary tests."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from verifier.runtime import gate, gate_pipeline, public_cli


UNKNOWN_RECEIPT = {
    "schema_version": "verifier-public-cli-unknown-1",
    "status": "UNKNOWN",
    "reason": "LOCAL_MEMORY_UNAVAILABLE",
    "command": "gate",
    "claim_boundary": (
        "The selected public CLI command did not complete; no command outcome, "
        "claim truth, or release clearance is established."
    ),
}


def _raise_memory_error(*_args: object, **_kwargs: object) -> None:
    raise MemoryError("injected private allocation detail")


def _assert_json_unknown(
    exit_code: int,
    capsys: pytest.CaptureFixture[str],
    *,
    command: str = "gate",
) -> None:
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err == ""
    assert json.loads(captured.out) == {**UNKNOWN_RECEIPT, "command": command}
    assert "PASS" not in captured.out
    assert "FAIL" not in captured.out
    assert "Traceback" not in captured.out
    assert "injected private allocation detail" not in captured.out


def test_gate_path_read_memory_error_is_structured_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "selected.txt"
    target.write_text("bounded selected text\n", encoding="utf-8")
    monkeypatch.setattr(gate, "_read_scan_text", _raise_memory_error)

    exit_code = public_cli.main(["gate", "paths", str(target), "--json"])

    _assert_json_unknown(exit_code, capsys)


def test_gate_pipeline_manifest_memory_error_is_structured_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = tmp_path / "gate-pipeline.json"
    manifest.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(gate_pipeline, "_read", _raise_memory_error)

    exit_code = public_cli.main(["gate", "plan", str(manifest), "--json"])

    _assert_json_unknown(exit_code, capsys)


def test_gate_handler_dispatch_memory_error_is_structured_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "selected.txt"
    target.write_text("bounded selected text\n", encoding="utf-8")
    monkeypatch.setattr(gate, "handle_gate_command", _raise_memory_error)

    exit_code = public_cli.main(["gate", "paths", str(target), "--json"])

    _assert_json_unknown(exit_code, capsys)


def test_gate_memory_error_is_concise_unknown_on_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "selected.txt"
    target.write_text("bounded selected text\n", encoding="utf-8")
    monkeypatch.setattr(gate, "_read_scan_text", _raise_memory_error)

    exit_code = public_cli.main(["gate", "paths", str(target)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == (
        "[UNKNOWN] selected command did not complete because local memory was "
        "unavailable\n"
    )
    assert "Traceback" not in captured.err
    assert "injected private allocation detail" not in captured.err


def test_numeric_self_polish_memory_error_is_structured_unknown(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from verifier.runtime import self_polish_tiers

    monkeypatch.setattr(
        self_polish_tiers, "handle_self_polish_tier_argv", _raise_memory_error
    )

    exit_code = public_cli.main(["polish", "1", "--json"])

    _assert_json_unknown(exit_code, capsys, command="polish")


def test_numeric_self_polish_import_outage_is_structured_unknown(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setitem(sys.modules, "verifier.runtime.self_polish_tiers", None)

    exit_code = public_cli.main(["polish", "2", "--json"])

    _assert_json_unknown(exit_code, capsys, command="polish")


def test_malformed_gate_pipeline_input_remains_fail(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = tmp_path / "malformed.json"
    manifest.write_text("{\n", encoding="utf-8")

    exit_code = public_cli.main(["gate", "plan", str(manifest), "--json"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["status"] == "FAIL"
    assert payload["claim_boundary"] == gate_pipeline.BOUNDARY
