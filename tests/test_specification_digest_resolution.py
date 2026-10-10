"""Terminology: Verifier Standard (VSTD).

A reported specification digest names the normative bytes the package carries. An
outside party compares it with the bytes they downloaded, so it must not change with
the directory a process was launched from.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from verifier.core.checker import UNAVAILABLE_PREFIX, IndependentAuditor, _source_digest
from verifier.core.kernel import reference_descriptor

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGED = REPO_ROOT / "src" / "verifier" / "standard"
DECOY = b"decoy bytes that are not the packaged specification\n"


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _decoy_standard(root: Path, *names: str) -> None:
    (root / "standard").mkdir()
    for name in names:
        (root / "standard" / name).write_bytes(DECOY)


def test_checker_specification_digest_ignores_a_decoy_in_the_working_directory(
    tmp_path: Path, monkeypatch
) -> None:
    _decoy_standard(tmp_path, "VSTD-1.md")
    monkeypatch.chdir(tmp_path)
    assert (Path.cwd() / "standard" / "VSTD-1.md").read_bytes() == DECOY

    reported = IndependentAuditor.verifier_descriptor().specification_hash

    assert reported == _digest((PACKAGED / "VSTD-1.md").read_bytes())
    assert reported != _digest(DECOY)


def test_kernel_specification_digest_ignores_a_decoy_in_the_working_directory(
    tmp_path: Path, monkeypatch
) -> None:
    _decoy_standard(tmp_path, "VSTD-4.md", "LADDER.md")
    monkeypatch.chdir(tmp_path)

    reported = reference_descriptor().specification_hash

    assert reported == _digest((PACKAGED / "VSTD-4.md").read_bytes())
    assert reported != _digest(DECOY)


def test_standard_coordinate_resolves_only_to_the_packaged_copy(
    tmp_path: Path, monkeypatch
) -> None:
    name = "standard/NOT-A-PACKAGED-DOCUMENT.md"
    _decoy_standard(tmp_path, "NOT-A-PACKAGED-DOCUMENT.md")
    monkeypatch.chdir(tmp_path)

    assert _source_digest(name) == f"{UNAVAILABLE_PREFIX}{name}"


def test_specification_digests_are_the_same_from_any_launch_directory(
    tmp_path: Path, monkeypatch
) -> None:
    def reported() -> tuple[str, str]:
        return (
            IndependentAuditor.verifier_descriptor().specification_hash,
            reference_descriptor().specification_hash,
        )

    here = reported()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert reported() == here
    assert not any(value.startswith(UNAVAILABLE_PREFIX) for value in here)


def test_other_relative_coordinates_still_resolve_against_the_working_directory(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "local-source.txt").write_bytes(b"local bytes\n")
    monkeypatch.chdir(tmp_path)

    assert _source_digest("local-source.txt") == _digest(b"local bytes\n")
