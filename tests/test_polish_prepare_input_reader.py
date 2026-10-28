"""Terminology: command-line interface (CLI); JavaScript Object Notation (JSON); Unicode Transformation Format, 8-bit (UTF-8).

`vstd polish prepare` reads every selected input through the one bounded reader of verifier.runtime.gate.
A selected input that is missing, is not a regular file, is linked, is over the byte bound or is not strict
UTF-8 text is a refusal with a JSON report, never a crash and never an accepted input."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from verifier.runtime import gate
from verifier.runtime.public_cli import main

REFUSAL = "INVALID_OR_UNAVAILABLE_SELECTED_PREPARATION_INPUT"
DIGEST = "sha256:" + "0" * 64


def artifact(tmp_path: Path) -> Path:
    target = tmp_path / "program.py"
    target.write_bytes(b"result = 2 + 3\n")
    return target


def refusal(capsys: pytest.CaptureFixture[str]) -> tuple[str, bool, str]:
    report = json.loads(capsys.readouterr().out)
    return report["status"], report["polished"], report["reason"]


def test_prepare_without_a_pinned_policy_is_a_refusal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["polish", "prepare", str(artifact(tmp_path)), "--json"]) == 1
    assert refusal(capsys) == ("FAIL", False, REFUSAL)


def test_prepare_with_a_policy_path_that_does_not_exist_is_a_refusal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["polish", "prepare", str(artifact(tmp_path)), "--policy", str(tmp_path / "missing.json"),
            "--policy-digest", DIGEST, "--json"]
    assert main(argv) == 1
    assert refusal(capsys) == ("FAIL", False, REFUSAL)


def test_prepare_with_a_directory_as_the_policy_is_a_refusal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["polish", "prepare", str(artifact(tmp_path)), "--policy", str(tmp_path),
            "--policy-digest", DIGEST, "--json"]
    assert main(argv) == 1
    assert refusal(capsys) == ("FAIL", False, REFUSAL)


def test_prepare_with_a_policy_that_is_not_strict_utf8_is_a_refusal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy = tmp_path / "policy.json"
    policy.write_bytes(b"\xff\xfe\x00")
    argv = ["polish", "prepare", str(artifact(tmp_path)), "--policy", str(policy),
            "--policy-digest", DIGEST, "--json"]
    assert main(argv) == 1
    assert refusal(capsys) == ("FAIL", False, REFUSAL)


def test_the_reader_returns_the_exact_bytes_of_a_regular_file(tmp_path: Path) -> None:
    data = "café\n".encode("utf-8")
    path = tmp_path / "input.txt"
    path.write_bytes(data)
    assert gate._prdel_file(str(path)) == data


def test_the_reader_refuses_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular file"):
        gate._prdel_file(str(tmp_path))


def test_the_reader_accepts_exactly_the_bound_and_refuses_one_byte_more(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "MAX_PRDEL_INPUT_BYTES", 8)
    at_bound, over_bound = tmp_path / "at.txt", tmp_path / "over.txt"
    at_bound.write_bytes(b"12345678")
    over_bound.write_bytes(b"123456789")
    assert gate._prdel_file(str(at_bound)) == b"12345678"
    with pytest.raises(ValueError, match="byte bound"):
        gate._prdel_file(str(over_bound))


def test_the_reader_does_not_open_a_file_that_is_already_over_the_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "MAX_PRDEL_INPUT_BYTES", 8)
    path = tmp_path / "over.txt"
    path.write_bytes(b"123456789")

    def forbidden(self: Path, *args: object, **kwargs: object) -> None:
        raise AssertionError("an over-bound file must be refused before it is opened")

    monkeypatch.setattr(Path, "open", forbidden)
    with pytest.raises(ValueError, match="byte bound"):
        gate._prdel_file(str(path))


def test_the_reader_refuses_a_file_that_grew_after_it_was_inspected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "MAX_PRDEL_INPUT_BYTES", 8)
    path = tmp_path / "grown.txt"
    path.write_bytes(b"123456789")
    real_lstat = Path.lstat

    def inspected_small(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        value = real_lstat(self, *args, **kwargs)
        return os.stat_result((value.st_mode, value.st_ino, value.st_dev, value.st_nlink, value.st_uid,
                               value.st_gid, 4, int(value.st_atime), int(value.st_mtime), int(value.st_mtime)))

    monkeypatch.setattr(Path, "lstat", inspected_small)
    with pytest.raises(ValueError, match="byte bound"):
        gate._prdel_file(str(path))


def test_the_reader_refuses_text_that_is_not_strict_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad.txt"
    path.write_bytes(b"ok\xff\n")
    with pytest.raises(UnicodeDecodeError):
        gate._prdel_file(str(path))


def test_the_reader_refuses_a_linked_file(tmp_path: Path) -> None:
    real, link = tmp_path / "real.txt", tmp_path / "link.txt"
    real.write_bytes(b"ok\n")
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("OS_CAPABILITY_GUARD: file symlink creation is unavailable")
    with pytest.raises(ValueError, match="regular file"):
        gate._prdel_file(str(link))


@pytest.mark.parametrize("byte_limit", [0, -1, False, True, 64 * 1024 * 1024 + 1])
def test_the_reader_refuses_invalid_explicit_limits_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, byte_limit: int | bool,
) -> None:
    path = tmp_path / "tiny.txt"
    path.write_bytes(b"x")

    def forbidden(self: Path, *args: object, **kwargs: object) -> None:
        raise AssertionError("an invalid explicit limit must be refused before opening input")

    monkeypatch.setattr(Path, "open", forbidden)
    with pytest.raises(ValueError, match="positive bounded input allocation required"):
        gate._prdel_file(str(path), byte_limit=byte_limit)


def test_the_reader_accepts_the_maximum_explicit_limit_with_a_tiny_file(tmp_path: Path) -> None:
    path = tmp_path / "tiny.txt"
    path.write_bytes(b"x")
    assert gate.MAX_PRDEL_INPUT_BYTES == 64 * 1024 * 1024
    assert gate._prdel_file(str(path), byte_limit=64 * 1024 * 1024) == b"x"
