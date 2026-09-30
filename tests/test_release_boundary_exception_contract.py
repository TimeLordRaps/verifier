"""Release diagnostics must contain encrypted ZIP archive format (ZIP) failures.

Diagnostics must not echo payloads. The archive's general-purpose encryption
flag is set in both real headers; no exception is monkeypatched.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def release(monkeypatch: pytest.MonkeyPatch):
    root = ROOT
    def load(name: str, filename: str):
        path = root / "scripts" / filename
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert Path(module.__file__).resolve() == path
        return module
    monkeypatch.setitem(sys.modules, "check_presentation", load("exception_presentation", "check_presentation.py"))
    return load("exception_release", "check_release_boundary.py")


def _zip(path: Path, member: str, *, encrypted_flag: bool) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr(member, b'{"portable":"docs/guide.md"}')
    if encrypted_flag:
        raw = bytearray(path.read_bytes())
        local = raw.index(b"PK\x03\x04")
        central = raw.index(b"PK\x01\x02")
        for offset in (local + 6, central + 8):
            struct.pack_into("<H", raw, offset, struct.unpack_from("<H", raw, offset)[0] | 1)
        path.write_bytes(raw)
    with zipfile.ZipFile(path) as archive:
        assert len(archive.infolist()) == 1
        assert bool(archive.infolist()[0].flag_bits & 1) is encrypted_flag


def test_ordinary_archive_positive_control(release, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "ordinary.zip"
    _zip(path, "package/guide.json", encrypted_flag=False)
    errors: list[str] = []
    assert release.check_artifact(path, errors) == 1
    assert errors == []
    assert release.main([str(path)]) == 0
    output = capsys.readouterr()
    assert "[BOUNDARY OK]" in output.out
    assert output.err == ""


def test_encrypted_member_returns_redacted_failure(release, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "encrypted.zip"
    marker = "C:" + "/" + "Users" + "/synthetic-person/" + "sk-" + "a" * 40 + ".json"
    _zip(path, marker, encrypted_flag=True)
    assert release.main([str(path)]) == 1
    output = capsys.readouterr()
    assert marker not in output.out + output.err
    assert "sk-" + "a" * 40 not in output.out + output.err
    assert str(tmp_path) not in output.out + output.err
    assert "[BOUNDARY FAIL]" in output.err
    assert "encrypted.zip" in output.err
