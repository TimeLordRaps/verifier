"""Refutable contract for a selected-source reader with no discovery authority.

The production reader is intentionally absent in the pre-edit candidate.  The
first independent run must therefore be RED before any implementation is added.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import ModuleType
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
READER = ROOT / "scripts" / "exact_source_scope.py"
SCHEMA = "verifier-selected-source-scope-1"
SOURCE_COORDINATE = "ab" * 32


def _canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _member(path: str, payload: bytes, *, role: str = "SOURCE") -> dict[str, Any]:
    return {
        "path": path,
        "role": role,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


def _manifest(*members: dict[str, Any], **overrides: Any) -> bytes:
    document: dict[str, Any] = {
        "schema_version": SCHEMA,
        "candidate_status": "CANDIDATE",
        "completeness": "UNKNOWN",
        "release_admissible": False,
        "source_coordinate": SOURCE_COORDINATE,
        "members": list(members),
    }
    document.update(overrides)
    return _canonical(document)


@pytest.fixture(scope="module")
def reader() -> ModuleType:
    assert READER.is_file(), (
        "EXACT_SCOPE_READER_MISSING: preserve this pre-edit RED before adding "
        "scripts/exact_source_scope.py"
    )
    spec = importlib.util.spec_from_file_location("exact_source_scope_candidate", READER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load(
    module: ModuleType,
    raw: bytes,
    observations: dict[str, Any],
    *,
    expected_manifest_sha256: str | None = None,
    expected_source_coordinate: str = SOURCE_COORDINATE,
    max_member_bytes: int = 64,
    max_total_bytes: int = 256,
) -> tuple[Any, list[str]]:
    calls: list[str] = []

    def read_member(path: str) -> Any:
        calls.append(path)
        observed = observations[path]
        if isinstance(observed, BaseException):
            raise observed
        if isinstance(observed, tuple):
            kind, content = observed
            return module.MemberObservation(kind=kind, content=content)
        return module.MemberObservation(kind="REGULAR", content=observed)

    scope = module.load_selected_source_scope(
        manifest_bytes=raw,
        expected_manifest_sha256=(
            expected_manifest_sha256 or hashlib.sha256(raw).hexdigest()
        ),
        expected_source_coordinate=expected_source_coordinate,
        read_member=read_member,
        max_member_bytes=max_member_bytes,
        max_total_bytes=max_total_bytes,
    )
    return scope, calls


def _rejected(
    module: ModuleType,
    raw: bytes,
    observations: dict[str, Any],
    code: str,
    **kwargs: Any,
) -> list[str]:
    calls: list[str] = []

    def read_member(path: str) -> Any:
        calls.append(path)
        observed = observations[path]
        if isinstance(observed, BaseException):
            raise observed
        if isinstance(observed, tuple):
            kind, content = observed
            return module.MemberObservation(kind=kind, content=content)
        return module.MemberObservation(kind="REGULAR", content=observed)

    with pytest.raises(module.ScopeInputError) as captured:
        module.load_selected_source_scope(
            manifest_bytes=raw,
            expected_manifest_sha256=kwargs.pop(
                "expected_manifest_sha256", hashlib.sha256(raw).hexdigest()
            ),
            expected_source_coordinate=kwargs.pop(
                "expected_source_coordinate", SOURCE_COORDINATE
            ),
            read_member=read_member,
            max_member_bytes=kwargs.pop("max_member_bytes", 64),
            max_total_bytes=kwargs.pop("max_total_bytes", 256),
            **kwargs,
        )
    assert captured.value.code == code
    return calls


def test_valid_scope_reads_only_declared_members(
    reader: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = b"alpha\n"
    second = b"value = 2\n"
    raw = _manifest(
        _member("docs/a.txt", first, role="DOCUMENT"),
        _member("src/verifier/a.py", second),
    )
    observations = {
        "docs/a.txt": first,
        "src/verifier/a.py": second,
        "unlisted/secret.txt": b"must never be requested",
    }

    def forbidden_discovery(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("reader attempted path discovery")

    with monkeypatch.context() as isolated:
        isolated.setattr(os, "walk", forbidden_discovery)
        isolated.setattr(os, "scandir", forbidden_discovery)
        isolated.setattr(subprocess, "run", forbidden_discovery)
        isolated.setattr(subprocess, "check_output", forbidden_discovery)
        isolated.setattr(Path, "glob", forbidden_discovery)
        isolated.setattr(Path, "rglob", forbidden_discovery)
        isolated.setattr(Path, "iterdir", forbidden_discovery)
        scope, calls = _load(reader, raw, observations)

    assert calls == ["docs/a.txt", "src/verifier/a.py"]
    assert "unlisted/secret.txt" not in calls
    assert scope.member_paths == ("docs/a.txt", "src/verifier/a.py")
    assert scope.source_coordinate == SOURCE_COORDINATE
    assert scope.completeness == "UNKNOWN"
    assert scope.release_admissible is False


@pytest.mark.parametrize(
    "path",
    (
        "../escape.txt",
        "/absolute.txt",
        "C:" + "/drive.txt",
        "a\\b.txt",
        "a/../b.txt",
        "./relative.txt",
        "a//b.txt",
    ),
    ids=(
        "parent-segment",
        "absolute",
        "drive-qualified",
        "backslash",
        "embedded-parent-segment",
        "dot-segment",
        "empty-segment",
    ),
)
def test_noncanonical_or_traversing_paths_fail_before_member_io(
    reader: ModuleType, path: str
) -> None:
    payload = b"x"
    raw = _manifest(_member(path, payload))
    assert _rejected(reader, raw, {path: payload}, "MEMBER_PATH_INVALID") == []


def test_case_colliding_paths_fail_before_member_io(reader: ModuleType) -> None:
    payload = b"x"
    raw = _manifest(
        _member("Docs/A.txt", payload, role="DOCUMENT"),
        _member("docs/a.txt", payload, role="DOCUMENT"),
    )
    observations = {"Docs/A.txt": payload, "docs/a.txt": payload}
    assert _rejected(reader, raw, observations, "MEMBER_PATH_COLLISION") == []


@pytest.mark.parametrize(
    "path",
    ("bad-\ud800.txt", "docs/cafe\u0301.txt"),
    ids=("unpaired-surrogate", "non-nfc"),
)
def test_nonportable_unicode_paths_fail_before_member_io(
    reader: ModuleType, path: str
) -> None:
    payload = b"x"
    raw = _manifest(_member(path, payload))
    assert _rejected(reader, raw, {path: payload}, "MEMBER_PATH_INVALID") == []


def test_normalization_aliases_fail_before_member_io(reader: ModuleType) -> None:
    payload = b"x"
    composed = "docs/caf\u00e9.txt"
    decomposed = "docs/cafe\u0301.txt"
    raw = _manifest(
        _member(composed, payload, role="DOCUMENT"),
        _member(decomposed, payload, role="DOCUMENT"),
    )
    observations = {composed: payload, decomposed: payload}
    assert _rejected(reader, raw, observations, "MEMBER_PATH_INVALID") == []


def test_duplicate_json_keys_are_rejected_before_member_io(reader: ModuleType) -> None:
    payload = b"x"
    raw = _manifest(_member("src/verifier/a.py", payload))
    raw = raw.replace(
        b'"candidate_status":"CANDIDATE"',
        b'"candidate_status":"REJECTED","candidate_status":"CANDIDATE"',
        1,
    )
    assert _rejected(
        reader,
        raw,
        {"src/verifier/a.py": payload},
        "MANIFEST_JSON_INVALID",
    ) == []


@pytest.mark.parametrize("kind", ("LINK", "REPARSE", "DIRECTORY"))
def test_nonregular_member_kinds_are_rejected(reader: ModuleType, kind: str) -> None:
    payload = b"x"
    raw = _manifest(_member("src/verifier/a.py", payload))
    calls = _rejected(
        reader,
        raw,
        {"src/verifier/a.py": (kind, payload)},
        "MEMBER_NOT_REGULAR",
    )
    assert calls == ["src/verifier/a.py"]


def test_missing_member_is_rejected(reader: ModuleType) -> None:
    payload = b"x"
    raw = _manifest(_member("src/verifier/missing.py", payload))
    calls = _rejected(
        reader,
        raw,
        {"src/verifier/missing.py": FileNotFoundError("synthetic missing member")},
        "MEMBER_MISSING",
    )
    assert calls == ["src/verifier/missing.py"]


def test_member_digest_mismatch_is_rejected(reader: ModuleType) -> None:
    raw = _manifest(_member("src/verifier/a.py", b"expected"))
    calls = _rejected(
        reader,
        raw,
        {"src/verifier/a.py": b"substituted"},
        "MEMBER_DIGEST_MISMATCH",
    )
    assert calls == ["src/verifier/a.py"]


def test_declared_member_size_limit_fails_before_member_io(reader: ModuleType) -> None:
    payload = b"12345"
    raw = _manifest(_member("src/verifier/a.py", payload))
    assert _rejected(
        reader,
        raw,
        {"src/verifier/a.py": payload},
        "MEMBER_SIZE_LIMIT",
        max_member_bytes=4,
    ) == []


def test_observed_member_size_mismatch_is_rejected(reader: ModuleType) -> None:
    raw = _manifest(_member("src/verifier/a.py", b"1234"))
    calls = _rejected(
        reader,
        raw,
        {"src/verifier/a.py": b"12345"},
        "MEMBER_SIZE_MISMATCH",
    )
    assert calls == ["src/verifier/a.py"]


def test_manifest_digest_must_match_external_selection(reader: ModuleType) -> None:
    payload = b"x"
    raw = _manifest(_member("src/verifier/a.py", payload))
    assert _rejected(
        reader,
        raw,
        {"src/verifier/a.py": payload},
        "MANIFEST_DIGEST_MISMATCH",
        expected_manifest_sha256="00" * 32,
    ) == []


def test_source_coordinate_must_match_external_selection(reader: ModuleType) -> None:
    payload = b"x"
    raw = _manifest(_member("src/verifier/a.py", payload))
    assert _rejected(
        reader,
        raw,
        {"src/verifier/a.py": payload},
        "SOURCE_COORDINATE_MISMATCH",
        expected_source_coordinate="cd" * 32,
    ) == []


@pytest.mark.parametrize(
    ("overrides", "code"),
    (
        ({"completeness": "COMPLETE"}, "UNSUPPORTED_COMPLETENESS_CLAIM"),
        ({"release_admissible": True}, "RELEASE_CLAIM_FORBIDDEN"),
        ({"candidate_status": "RELEASED"}, "CANDIDATE_STATUS_INVALID"),
    ),
)
def test_manifest_cannot_self_promote(
    reader: ModuleType, overrides: dict[str, Any], code: str
) -> None:
    payload = b"x"
    raw = _manifest(_member("src/verifier/a.py", payload), **overrides)
    assert _rejected(reader, raw, {"src/verifier/a.py": payload}, code) == []


def test_all_local_passes_still_produce_global_unknown(reader: ModuleType) -> None:
    result = reader.summarize_candidate_scope(
        {
            "byte_integrity": "PASS",
            "namespace": "PASS",
            "presentation": "PASS",
        }
    )
    assert result["bounded_status"] == "PASS"
    assert result["status"] == "UNKNOWN"
    assert result["repository_completeness"] == "UNKNOWN"
    assert result["semantic_completeness"] == "UNKNOWN"
    assert result["release_admissible"] is False
    assert "REPOSITORY_COMPLETENESS_NOT_ESTABLISHED" in result["findings"]


def test_any_local_failure_remains_failure(reader: ModuleType) -> None:
    result = reader.summarize_candidate_scope(
        {"byte_integrity": "PASS", "namespace": "FAIL"}
    )
    assert result["bounded_status"] == "FAIL"
    assert result["status"] == "FAIL"
    assert result["release_admissible"] is False

