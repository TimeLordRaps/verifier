"""Falsifier tests for the selected secret gate: content and length bindings, size limits, path rules and the scanner command line.

tests/test_secret_gate.py is carried unchanged. A mutation check of that file left one decision of
src/verifier/runtime/secret_gate.py unrefuted where it matters most (the content digest is masked by the length check, because
every changed-content test also changes the length), and nothing tested the size limits the standard states, the path rules or the
scanner command line. Each test here fails when the decision it names is removed from the gate.
Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
from types import SimpleNamespace
import uuid

import pytest

from verifier.runtime import secret_gate as gate


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def bind(request: dict) -> None:
    scope = {key: request[key] for key in ("mode", "selection", "coverage_requirements", "scanner_policy")}
    scope["artifacts"] = [
        {key: item for key, item in artifact.items() if key != "content_path"}
        for artifact in request["artifacts"]
    ]
    request["scope_manifest_sha256"] = digest(gate._canonical(scope))


@pytest.fixture
def selected(tmp_path, monkeypatch):
    """One exactly selected artifact and a scanner that is a stub: the gate's own decisions are what these tests exercise."""
    binary = tmp_path / "scanner.exe"
    binary.write_bytes(b"nonexecuted fixture scanner")
    config = tmp_path / "scanner.toml"
    config.write_bytes(gate.CONFIGURATION)
    text = tmp_path / "selected.txt"
    text.write_bytes(b"ordinary retained source text")
    request = {
        "schema": gate.REQUEST,
        "request_id": str(uuid.uuid4()),
        "mode": "staged-index",
        "selection": {"index_paths": ["selected.txt"]},
        "coverage_requirements": list(gate.COVERAGE),
        "scanner_policy": {
            "name": "gitleaks",
            "version": gate.VERSION,
            "configuration_sha256": digest(config.read_bytes()),
            "binary_sha256": digest(binary.read_bytes()),
        },
        "artifacts": [{
            "id": "selected:1",
            "kind": "git-blob",
            "content_path": str(text),
            "bytes": len(text.read_bytes()),
            "content_sha256": digest(text.read_bytes()),
            "selected_path": "selected.txt",
        }],
    }
    path = tmp_path / "request.json"
    monkeypatch.setattr(gate, "_process", lambda *args: (0, gate.VERSION.encode()))
    monkeypatch.setattr(gate, "_scan", lambda *args: 0)

    def run():
        bind(request)
        path.write_bytes(gate._canonical(request))
        return gate.assess_secret_request(path, scanner_binary=binary, scanner_configuration=config)

    return request, text, run


def test_control_the_untouched_selection_passes(selected):
    _, _, run = selected
    receipt = run()
    assert receipt["outcome"] == "PASS" and receipt["coverage_complete"] is True


def test_changed_bytes_of_the_same_length_fail_on_the_content_digest(selected):
    _, text, run = selected
    original = text.read_bytes()
    text.write_bytes(bytes(reversed(original)))
    assert len(text.read_bytes()) == len(original) and text.read_bytes() != original
    receipt = run()
    assert receipt["outcome"] == "FAIL" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["ARTIFACT_CONTENT_BINDING_MISMATCH"]


def test_a_declared_length_that_differs_from_the_bytes_fails_although_the_digest_matches(selected):
    request, _, run = selected
    request["artifacts"][0]["bytes"] += 1
    receipt = run()
    assert receipt["outcome"] == "FAIL" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["ARTIFACT_CONTENT_BINDING_MISMATCH"]


def test_more_artifacts_than_the_count_limit_are_unknown(selected):
    request, _, run = selected
    request["artifacts"] = [
        dict(request["artifacts"][0], id=f"selected:{index}") for index in range(gate.LIMIT_ARTIFACTS + 1)
    ]
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["ARTIFACT_COUNT_LIMIT"]


def test_one_artifact_over_the_byte_limit_is_unknown(selected):
    request, _, run = selected
    request["artifacts"][0]["bytes"] = gate.LIMIT_FILE + 1
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["SELECTED_BYTE_LIMIT"]


def test_artifacts_that_each_fit_but_exceed_the_total_limit_are_unknown(selected):
    request, _, run = selected
    count = gate.LIMIT_TOTAL // gate.LIMIT_FILE + 1
    request["artifacts"] = [
        dict(request["artifacts"][0], id=f"selected:{index}", bytes=gate.LIMIT_FILE) for index in range(count)
    ]
    assert len(request["artifacts"]) * gate.LIMIT_FILE > gate.LIMIT_TOTAL
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["SELECTED_TOTAL_BYTE_LIMIT"]


def test_a_relative_content_path_is_unknown(selected):
    request, _, run = selected
    request["artifacts"][0]["content_path"] = "selected.txt"
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["ABSOLUTE_REGULAR_PATH_REQUIRED"]


def test_a_directory_as_content_path_is_unknown(selected, tmp_path):
    request, _, run = selected
    request["artifacts"][0]["content_path"] = str(tmp_path)
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["REGULAR_FILE_REQUIRED"]


@pytest.mark.parametrize("info", [
    SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_file_attributes=0),
    SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_file_attributes=0x400),
], ids=["symbolic-link-mode", "reparse-point-attribute"])
def test_a_linked_content_path_is_unknown(selected, monkeypatch, info):
    _, text, run = selected
    real_lstat = Path.lstat

    def linked(self):
        return info if self == text else real_lstat(self)

    monkeypatch.setattr(Path, "lstat", linked)
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["LINKED_PATH_UNSUPPORTED"]


def test_a_scanner_that_reports_another_version_is_unknown(selected, monkeypatch):
    _, _, run = selected
    monkeypatch.setattr(gate, "_process", lambda *args: (0, b"8.30.0"))
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["SCANNER_VERSION_UNAVAILABLE_OR_MISMATCH"]


def test_a_scanner_that_fails_its_version_command_is_unknown(selected, monkeypatch):
    _, _, run = selected
    monkeypatch.setattr(gate, "_process", lambda *args: (1, gate.VERSION.encode()))
    receipt = run()
    assert receipt["outcome"] == "UNKNOWN" and receipt["coverage_complete"] is False
    assert receipt["reason_codes"] == ["SCANNER_VERSION_UNAVAILABLE_OR_MISMATCH"]


def test_the_scanner_command_line_disables_baselines_allow_comments_and_decoding(tmp_path, monkeypatch):
    seen = {}

    def fake(argv, content, temporary, timeout):
        seen["argv"] = list(argv)
        (temporary / "findings.json").write_bytes(gate._canonical([]))
        return 0, b""

    monkeypatch.setattr(gate, "_process", fake)
    assert gate._scan(tmp_path / "scanner", tmp_path / "config", b"", tmp_path, 1) == 0
    argv = seen["argv"]

    def value_after(flag):
        return argv[argv.index(flag) + 1]

    assert argv[0] == str(tmp_path / "scanner") and argv[1] == "stdin"
    assert value_after("--config") == str(tmp_path / "config")
    assert value_after("--max-decode-depth") == "0" and value_after("--max-archive-depth") == "0"
    assert "--ignore-gitleaks-allow" in argv
    ignore_file = Path(value_after("--gitleaks-ignore-path"))
    assert ignore_file.parent == tmp_path and not ignore_file.exists()
    assert value_after("--exit-code") == "10"
    assert "--redact=100" in argv
