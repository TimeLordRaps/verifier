"""Supply Chain Integrity, Transparency, and Trust (SCITT) staging tests.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256). Synthetic comparison fixtures are not native evidence.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

import pytest

from test_scitt_catalog_entry import entry, files
from test_scitt_package_comparison import comparison, specimen
from test_scitt_native_runner import runner
from verifier.interoperability.storage import StoredComponentPackage


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def staging(entry: ModuleType) -> ModuleType:
    sys.modules["catalog_entry"] = entry
    spec = importlib.util.spec_from_file_location("scitt_distribution_test", ROOT / "examples/scitt_native_interop/stage_distribution.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def retained(entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path) -> tuple[Path, str, Path]:
    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    output.mkdir()
    package, sidecar, _ = files(source, specimen)
    path = source / "entry.json"
    made = entry.create_entry(path, package, sidecar)
    return path, made["entry_digest"], output


def test_stage_exact_three_files_and_reinspect_without_native_calls(
    staging: ModuleType, entry: ModuleType, retained: tuple[Path, str, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, output = retained
    monkeypatch.setattr(runner, "_run_process", lambda *a, **k: pytest.fail("staging must not execute native code"))
    result = staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    destination = output / digest
    assert result["entry_digest"] == digest
    assert Path(result["destination"]) == destination
    assert set(result["filenames"]) == {"entry.json", "package.json", "sidecar.json"}
    assert {item.name for item in destination.iterdir()} == set(result["filenames"])
    assert all((destination / name).read_bytes() == (path.parent / name).read_bytes() for name in result["filenames"])
    assert entry.inspect_entry(destination / path.name, expected_entry_digest=digest) == entry.inspect_entry(path, expected_entry_digest=digest)
    assert result["native_execution_performed"] is False
    assert result["network_operations_performed"] is False
    assert set(result) == {"entry_digest", "destination", "filenames", "native_execution_performed", "network_operations_performed", "claim_boundary"}


@pytest.mark.parametrize("kind", ["directory", "partial", "file", "case_alias"])
def test_existing_digest_destination_is_never_overwritten(
    staging: ModuleType, retained: tuple[Path, str, Path], kind: str,
) -> None:
    path, digest, output = retained
    existing = output / (digest.upper() if kind == "case_alias" else digest)
    if kind == "file": existing.write_bytes(b"preserve")
    else:
        existing.mkdir()
        if kind == "partial": (existing / "package.json").write_bytes(b"partial preserve")
    with pytest.raises(FileExistsError):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    assert existing.exists()
    if kind == "file": assert existing.read_bytes() == b"preserve"
    if kind == "partial": assert (existing / "package.json").read_bytes() == b"partial preserve"


@pytest.mark.parametrize("overlap", ["same", "ancestor", "descendant"])
def test_nested_source_and_destination_roots_refused(
    staging: ModuleType, retained: tuple[Path, str, Path], overlap: str,
) -> None:
    path, digest, _ = retained
    output = {"same": path.parent, "ancestor": path.parent.parent, "descendant": path.parent / "nested"}[overlap]
    output.mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="non-nested"):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    assert not (output / digest).exists()


@pytest.mark.parametrize("target", ["entry", "package", "sidecar"])
def test_postinspection_substitution_is_not_copied_or_used_for_paths(
    staging: ModuleType, entry: ModuleType, retained: tuple[Path, str, Path], monkeypatch: pytest.MonkeyPatch, target: str,
) -> None:
    path, digest, output = retained
    private = path.parent / "unadmitted-neighbor.json"
    private.write_bytes(b"unadmitted neighbor bytes")
    original = entry.inspect_entry
    def inspect_then_change(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = original(*args, **kwargs)
        if target == "entry":
            value = json.loads(path.read_bytes())
            value["package"]["filename"] = private.name
            value["package"]["sha256"] = comparison.sha(private.read_bytes())
            path.write_bytes(comparison.canonical(value))
        else:
            (path.parent / (target + ".json")).write_bytes(b"unadmitted substituted bytes")
        return result
    monkeypatch.setattr(entry, "inspect_entry", inspect_then_change)
    reader = staging.read_regular
    reads = []
    def recording_read(source: Path, limit: int) -> bytes:
        reads.append(source)
        return reader(source, limit)
    monkeypatch.setattr(staging, "read_regular", recording_read)
    with pytest.raises(ValueError, match="changed before snapshot"):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    assert private not in reads
    assert not (output / digest).exists()


@pytest.mark.parametrize("mutation", ["source_package", "staged_package", "extra_file", "extra_directory", "write_error"])
def test_write_time_mutation_or_failure_retains_rejected_directory(
    staging: ModuleType, retained: tuple[Path, str, Path], monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    path, digest, output = retained
    writer = staging._write_new
    calls = 0
    def changing_write(destination: Path, raw: bytes) -> None:
        nonlocal calls
        calls += 1
        if mutation == "write_error" and calls == 2:
            raise OSError("synthetic exclusive write failure")
        writer(destination, raw)
        if calls == 1:
            if mutation == "source_package": (path.parent / "package.json").write_bytes(b"changed source")
            elif mutation == "staged_package": destination.write_bytes(b"changed staged")
            elif mutation == "extra_file": (destination.parent / "unadmitted.txt").write_bytes(b"extra")
            elif mutation == "extra_directory": (destination.parent / "extra").mkdir()
    monkeypatch.setattr(staging, "_write_new", changing_write)
    with pytest.raises(staging.DistributionStageError, match="retained and may be partial"):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    destination = output / digest
    assert destination.is_dir() and any(destination.iterdir())
    with pytest.raises(FileExistsError):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)


def test_source_inventory_drift_after_admission_stops_before_creation(
    staging: ModuleType, entry: ModuleType, retained: tuple[Path, str, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, output = retained
    original = entry.inspect_entry
    def inspect_then_drift(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = original(*args, **kwargs)
        monkeypatch.setattr(entry, "source_inventory", lambda: {"changed": "0" * 64})
        return result
    monkeypatch.setattr(entry, "inspect_entry", inspect_then_drift)
    with pytest.raises(ValueError, match="source inventory changed"):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    assert not (output / digest).exists()


def test_extra_added_during_final_inspection_is_not_success(
    staging: ModuleType, entry: ModuleType, retained: tuple[Path, str, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, output = retained
    original = entry.inspect_entry
    def inspect_then_add(selected: Path, **kwargs: Any) -> dict[str, Any]:
        result = original(selected, **kwargs)
        if selected.parent == output / digest:
            (selected.parent / "extra.txt").write_bytes(b"not admitted")
        return result
    monkeypatch.setattr(entry, "inspect_entry", inspect_then_add)
    with pytest.raises(staging.DistributionStageError):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    assert (output / digest / "extra.txt").exists()


@pytest.mark.parametrize("surface", ["source", "output"])
def test_reparse_parent_refused_without_link_creation_privilege(
    staging: ModuleType, retained: tuple[Path, str, Path], monkeypatch: pytest.MonkeyPatch, surface: str,
) -> None:
    from types import SimpleNamespace
    path, digest, output = retained
    selected = path.parent if surface == "source" else output
    original = Path.lstat
    def marked(target: Path, *args: Any, **kwargs: Any) -> Any:
        info = original(target, *args, **kwargs)
        return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400) if target == selected else info
    monkeypatch.setattr(Path, "lstat", marked)
    with pytest.raises(ValueError, match="reparse"):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    assert not (output / digest).exists()


def test_existing_dangling_alias_refused_when_supported(staging: ModuleType, retained: tuple[Path, str, Path]) -> None:
    path, digest, output = retained
    destination = output / digest
    try:
        destination.symlink_to(output / "missing", target_is_directory=True)
    except OSError:
        pytest.skip("local symlink creation privilege unavailable")
    with pytest.raises(FileExistsError):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    assert destination.is_symlink()


def test_root_scan_and_digest_input_are_bounded(
    staging: ModuleType, retained: tuple[Path, str, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, output = retained
    for invalid in (None, True, "../escape", "A" * 64):
        with pytest.raises(ValueError, match="digest"):
            staging.stage_distribution(path, expected_entry_digest=invalid, output_root=output)
    (output / "one").write_bytes(b"one")
    (output / "two").write_bytes(b"two")
    monkeypatch.setattr(staging, "MAX_ROOT_ENTRIES", 1)
    with pytest.raises(ValueError, match="entry bound"):
        staging.stage_distribution(path, expected_entry_digest=digest, output_root=output)
    assert not (output / digest).exists()


def test_staging_command_requires_explicit_paths_and_digest(staging: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    def selected(path: Path, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs))
        return {"entry_digest": "a" * 64}
    monkeypatch.setattr(staging, "stage_distribution", selected)
    assert staging.main(["entry.json", "--expected-entry-sha256", "a" * 64, "--output-root", "output"]) == 0
    assert calls == [(Path("entry.json"), {"expected_entry_digest": "a" * 64, "output_root": Path("output")})]
