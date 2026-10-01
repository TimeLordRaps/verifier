"""Release boundary checks for decoded JavaScript Object Notation (JSON).

All negative coordinates are synthetic, assembled only inside these tests.
Base, unit, archive integration, and preventative resource checks remain distinct.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
from types import ModuleType
import tarfile
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def checker(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    def load(name: str, filename: str) -> ModuleType:
        spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    presentation = load("release_boundary_presentation_fixture", "check_presentation.py")
    monkeypatch.setitem(sys.modules, "check_presentation", presentation)
    return load("release_boundary_path_fixture", "check_release_boundary.py")


def _forms() -> dict[str, str]:
    slash = chr(92)
    return {
        "windows": "E:" + slash + "private-workspace" + slash + "plan.md",
        "unix-home": "/" + "home" + "/synthetic-user/private/plan.md",
        "mac-home": "/" + "Users" + "/synthetic-user/private/plan.md",
        "unc": slash * 2 + "synthetic-host" + slash + "private" + slash + "plan.md",
    }


def _escaped(value: str) -> str:
    return '"' + "".join(chr(92) + "u" + format(ord(c), "04x") for c in value) + '"'


def _check(checker: ModuleType, data: bytes, member: str = "example/config.json") -> list[str]:
    errors: list[str] = []
    checker._scan_text(Path("synthetic.whl"), member, data, errors)
    return errors


# Base: unchanged independent counterexamples and controls.
def test_positive_plain_windows_path_rejected(checker: ModuleType) -> None:
    assert _check(checker, json.dumps({"path": _forms()["windows"]}).encode())


def test_positive_repository_relative_path_accepted(checker: ModuleType) -> None:
    assert not _check(checker, b'{"path":"docs/guide.md"}')


def test_json_unicode_escape_cannot_hide_an_absolute_workspace_path(checker: ModuleType) -> None:
    path = _forms()["windows"]
    data = ('{"path":' + _escaped(path) + '}').encode()
    assert json.loads(data)["path"] == path
    assert _check(checker, data), "Decoded JSON string values must be inspected"


@pytest.mark.parametrize("kind", ["unix-home", "mac-home", "unc"])
def test_other_workstation_absolute_forms_are_rejected(checker: ModuleType, kind: str) -> None:
    assert _check(checker, json.dumps({"path": _forms()[kind]}).encode())


# Unit: decoded keys, nested values, duplicate keys, and portable controls.
@pytest.mark.parametrize("kind", ["windows", "unix-home", "mac-home", "unc"])
@pytest.mark.parametrize("placement", ["key", "value", "duplicate-first"])
def test_decoded_nested_strings_cannot_disappear(
    checker: ModuleType, kind: str, placement: str,
) -> None:
    encoded = _escaped(_forms()[kind])
    if placement == "key":
        data = '{"outer":[{"nested":{' + encoded + ':true}}]}'
    elif placement == "value":
        data = '{"outer":[{"nested":[null,42,' + encoded + ']}]}'
    else:
        data = '{"outer":{"same":' + encoded + ',"same":"docs/guide.md"}}'
    errors = _check(checker, data.encode())
    assert errors
    assert not any("malformed" in error for error in errors), "Valid syntax must reach semantic scanning"
    assert all(_forms()[kind] not in error for error in errors)


@pytest.mark.parametrize("value", [
    "docs/guide.md", "src/package/core.py", "../shared/data.json",
    "https://example.invalid/docs/guide", "urn:example:record:1",
    "λ and ordinary Unicode", "home/synthetic-user/file", "Users/example/file",
    "prefix" + "/home" + "/example", "https://example.invalid" + "/Users" + "/example",
    chr(92) * 2 + "alpha " + chr(92) + "beta", chr(92) * 2 + "d+",
])
def test_portable_values_are_not_workstation_coordinates(checker: ModuleType, value: str) -> None:
    assert _check(checker, json.dumps({"ordinary": [value, {value: None}, 2, True]}).encode()) == []


@pytest.mark.parametrize("payload", [
    b'{"key":', b'{"key":"bad\\uZZZZ"}', b'{} trailing', b'{"key":NaN}',
    b'{"key":Infinity}', b'{"key":-Infinity}', b'\xff',
])
def test_malformed_json_or_encoding_fails_closed(checker: ModuleType, payload: bytes) -> None:
    assert _check(checker, payload)


@pytest.mark.parametrize("payload", [b'[]', b'{}', b'null', b'42', b'"ordinary"'])
def test_valid_json_root_types_are_accepted(checker: ModuleType, payload: bytes) -> None:
    assert _check(checker, payload) == []


def test_decoded_controls_and_escaped_slashes_are_handled(checker: ModuleType) -> None:
    home = _forms()["unix-home"]
    payload = json.dumps({"nested": ["first\n" + home + "\tlast"]}).replace("/", chr(92) + "/")
    assert _check(checker, payload.encode())


# Integration: invoke actual archive reading and command-line entrypoint.
@pytest.mark.parametrize("suffix", [".whl", ".zip", ".tar.gz", ".json"])
@pytest.mark.parametrize("prohibited", [False, True])
def test_actual_artifact_route_inspects_decoded_payloads(
    checker: ModuleType, tmp_path: Path, suffix: str, prohibited: bool,
) -> None:
    path = tmp_path / ("synthetic" + suffix)
    payload = ('{"nested":[{' + _escaped(_forms()["unc"] if prohibited else "portable") + ':true}]}').encode()
    if suffix in {".whl", ".zip"}:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("package/data.json", payload)
    elif suffix == ".tar.gz":
        with tarfile.open(path, "w:gz") as bundle:
            member = tarfile.TarInfo("package/data.json")
            member.size = len(payload)
            bundle.addfile(member, io.BytesIO(payload))
    else:
        path.write_bytes(payload)
    errors: list[str] = []
    assert checker.check_artifact(path, errors) == 1
    assert bool(errors) is prohibited
    assert checker.main([str(path)]) == int(prohibited)


def test_diagnostics_redact_prohibited_archive_member(checker: ModuleType) -> None:
    member = _forms()["unix-home"] + ".json"
    errors = _check(checker, b'{"ordinary":true}', member)
    assert errors and all(member not in error for error in errors)
    assert all("redacted" in error for error in errors)


@pytest.mark.parametrize("kind", ["windows", "unix-home", "mac-home", "unc"])
def test_malformed_diagnostics_do_not_echo_payload(checker: ModuleType, kind: str) -> None:
    value = _forms()[kind]
    errors = _check(checker, ('{"value":' + _escaped(value)).encode())
    assert errors and all(value not in error for error in errors)


def test_updated_source_and_tests_do_not_contain_literal_coordinates(checker: ModuleType) -> None:
    presentation = sys.modules["check_presentation"]
    for path in (ROOT / "scripts/check_release_boundary.py", Path(__file__)):
        assert presentation.public_boundary_violations(path.read_text(encoding="utf-8")) == []


def test_split_drive_fixture_is_not_a_network_share(checker: ModuleType) -> None:
    # A source-level escaped suffix after a colon is part of the drive fixture,
    # not a host and share. Complete drive paths still have their own detector.
    source = '"C" + ":' + chr(92) * 2 + 'private' + chr(92) * 2 + 'result.json"'
    presentation = sys.modules["check_presentation"]
    assert presentation.public_boundary_violations(source) == []


def test_parser_limits_run_before_json_allocation(checker: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checker, "MAX_JSON_DEPTH", 8, raising=False)
    def unexpected_parse(*args: object, **kwargs: object) -> None:
        pytest.fail("excessive JSON nesting reached the allocator")
    monkeypatch.setattr(json, "loads", unexpected_parse)
    assert _check(checker, b"[" * 9 + b"0" + b"]" * 9)


def test_string_delimiters_do_not_consume_structure_budget(checker: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checker, "MAX_JSON_DEPTH", 2, raising=False)
    monkeypatch.setattr(checker, "MAX_JSON_STRUCTURE_TOKENS", 4, raising=False)
    value = 'quoted " with escapes ' + chr(92) * 4 + " {[,:]}" * 10
    assert _check(checker, json.dumps([value]).encode()) == []


# Preventative: a small configured bound exercises denial without large allocation.
def test_text_size_limit_is_enforced_before_decoding(checker: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checker, "MAX_TEXT_BYTES", 32, raising=False)
    errors = _check(checker, b'"' + b"a" * 32 + b'"')
    assert errors and any("size limit" in error for error in errors)


def test_json_nesting_is_bounded(checker: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checker, "MAX_JSON_DEPTH", 8, raising=False)
    assert _check(checker, b"[" * 9 + b"0" + b"]" * 9)
    assert _check(checker, b"[" * 8 + b"0" + b"]" * 8) == []
    assert _check(checker, json.dumps("[" * 30).encode()) == []


def test_json_structure_budget_is_bounded(checker: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checker, "MAX_JSON_STRUCTURE_TOKENS", 12, raising=False)
    assert _check(checker, ("[" + ",".join(["null"] * 20) + "]").encode())
    assert _check(checker, b"[null,null]") == []


@pytest.mark.parametrize("suffix", [".whl", ".zip", ".tar.gz", ".json"])
def test_artifact_member_read_is_bounded(
    checker: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str,
) -> None:
    monkeypatch.setattr(checker, "MAX_TEXT_BYTES", 32, raising=False)
    path = tmp_path / ("bounded" + suffix)
    payload = b'"' + b"a" * 64 + b'"'
    if suffix in {".whl", ".zip"}:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("package/data.json", payload)
        def unexpected_open(*args: object, **kwargs: object) -> None:
            pytest.fail("oversized member was opened before its metadata was rejected")
        monkeypatch.setattr(zipfile.ZipFile, "open", unexpected_open)
    elif suffix == ".tar.gz":
        with tarfile.open(path, "w:gz") as bundle:
            member = tarfile.TarInfo("package/data.json")
            member.size = len(payload)
            bundle.addfile(member, io.BytesIO(payload))
        def unexpected_extract(*args: object, **kwargs: object) -> None:
            pytest.fail("oversized member was extracted before its metadata was rejected")
        monkeypatch.setattr(tarfile.TarFile, "extractfile", unexpected_extract)
    else:
        path.write_bytes(payload)
    errors: list[str] = []
    assert checker.check_artifact(path, errors) == 1
    assert any("size limit" in error for error in errors)


def test_xml_entity_decoding_remains_checked(checker: ModuleType) -> None:
    value = _forms()["windows"]
    encoded = "".join("&#" + str(ord(c)) + ";" for c in value)
    assert _check(checker, ("<root>" + encoded + "</root>").encode(), "package/data.xml")
    assert _check(checker, b'<root path="docs/guide.md"/>', "package/data.xml") == []


@pytest.mark.parametrize("suffix", [".whl", ".zip"])
@pytest.mark.parametrize("fault", ["encoded-key", "malformed", "valid"])
def test_json_lines_archive_sibling(
    checker: ModuleType, tmp_path: Path, suffix: str, fault: str,
) -> None:
    first = '{"portable":"docs/guide.md"}\n'
    second = {
        "encoded-key": '{"nested":{' + _escaped(_forms()["unc"]) + ':true}}\n',
        "malformed": '{"incomplete":\n',
        "valid": '{"ordinary":[null,2,true]}\n',
    }[fault]
    artifact = tmp_path / ("records" + suffix)
    with zipfile.ZipFile(artifact, "w") as bundle:
        bundle.writestr("package/records.jsonl", (first + second).encode())
    errors: list[str] = []
    assert checker.check_artifact(artifact, errors) == 1
    assert bool(errors) is (fault != "valid")


def test_cli_does_not_echo_source_exception_text(
    checker: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    artifact = tmp_path / "sample.zip"
    artifact.write_bytes(b"placeholder")
    marker = _forms()["windows"]
    def unreadable(path: Path, errors: list[str]) -> int:
        raise OSError(marker)
    monkeypatch.setattr(checker, "check_artifact", unreadable)
    assert checker.main([str(artifact)]) == 1
    stderr = capsys.readouterr().err
    assert marker not in stderr
    assert "sample.zip" in stderr


def test_missing_artifact_diagnostic_does_not_echo_parent_directories(
    checker: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "synthetic-sensitive-parent"
    artifact = tmp_path / marker / "missing.zip"
    assert checker.main([str(artifact)]) == 1
    stderr = capsys.readouterr().err
    assert marker not in stderr
    assert "missing.zip" in stderr
