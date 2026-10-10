"""Supply Chain Integrity, Transparency, and Trust (SCITT) source-freeze tests.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256). Synthetic packages exercise retention, not native execution.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import ModuleType
from typing import Any

import pytest

from test_scitt_catalog_entry import entry, files
from test_scitt_distribution import staging
from test_scitt_package_comparison import comparison, specimen
from test_scitt_native_runner import runner
from verifier.interoperability.storage import StoredComponentPackage


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def reconstruction(entry: ModuleType, staging: ModuleType) -> ModuleType:
    sys.modules["catalog_entry"] = entry
    sys.modules["stage_distribution"] = staging
    spec = importlib.util.spec_from_file_location("scitt_reconstruction_test", ROOT / "examples/scitt_native_interop/freeze_reconstruction.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def retained(entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path) -> tuple[Path, str, Path, Path]:
    source = tmp_path / "entry-source"
    source.mkdir()
    package, sidecar, _ = files(source, specimen)
    path = source / "entry.json"
    result = entry.create_entry(path, package, sidecar)
    return path, result["entry_digest"], tmp_path / "source-stage", tmp_path / "bundle"


def test_freeze_retains_exact_reconstruction_allowlist_without_execution(
    reconstruction: ModuleType, retained: tuple[Path, str, Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, stage, bundle = retained
    monkeypatch.setattr(runner, "_run_process", lambda *a, **k: pytest.fail("freezing invoked native execution"))
    result = reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    assert result["entry_digest"] == digest
    assert result["state"] == "FROZEN_UNSEALED"
    assert result["native_execution_performed"] is False
    assert (bundle / "freeze.json").is_file()
    assert (bundle / "payload/entry/entry.json").read_bytes() == path.read_bytes()
    manifest = json.loads(path.read_bytes())
    expected = {name: (ROOT / name).read_bytes() for name in manifest["reconstruction_sources"]}
    expected.update({name: (ROOT / name).read_bytes() for name in ("LICENSE", "NOTICE")})
    expected.update({"entry/" + name: (path.parent / name).read_bytes() for name in (path.name, manifest["package"]["filename"], manifest["sidecar"]["filename"])})
    for tree in (stage, bundle / "payload"):
        observed = {item.relative_to(tree).as_posix(): item.read_bytes() for item in tree.rglob("*") if item.is_file()}
        assert observed == expected
        assert {item.relative_to(tree).as_posix() for item in tree.rglob("*") if item.is_dir()} == reconstruction._directories(expected)
    assert result["retained_file_count"] == len(expected) == len(manifest["reconstruction_sources"]) + 5
    frozen = json.loads((bundle / "freeze.json").read_bytes())
    assert frozen["lineage"] == frozen["bound_contexts"] == []
    verified = reconstruction.verify_frozen_artifact(bundle, require_seal=False, expected_artifact_id=result["artifact_id"])
    assert verified.freeze_valid and verified.guard_valid and verified.errors == ()
    assert not verified.sealed and verified.valid_seal_ids == ()
    assert reconstruction.verify_frozen_artifact(bundle, require_seal=True).state == "NOT_ESTABLISHED"


@pytest.mark.parametrize("target", ["entry", "package", "sidecar"])
def test_changed_transport_after_inspection_cannot_choose_or_copy_private_neighbor(
    reconstruction: ModuleType, entry: ModuleType, retained: tuple[Path, str, Path, Path], monkeypatch: pytest.MonkeyPatch, target: str,
) -> None:
    path, digest, stage, bundle = retained
    neighbor = path.parent / "unadmitted.json"
    neighbor.write_bytes(b"unadmitted neighboring bytes")
    original = entry.inspect_entry
    def changed(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = original(*args, **kwargs)
        if target == "entry":
            manifest = json.loads(path.read_bytes())
            manifest["package"]["filename"] = neighbor.name
            manifest["package"]["sha256"] = comparison.sha(neighbor.read_bytes())
            path.write_bytes(comparison.canonical(manifest))
        else:
            (path.parent / (target + ".json")).write_bytes(b"substitution")
        return result
    monkeypatch.setattr(entry, "inspect_entry", changed)
    original_read = reconstruction.read_regular
    observed = []
    def tracking_read(selected: Path, limit: int) -> bytes:
        observed.append(selected)
        return original_read(selected, limit)
    monkeypatch.setattr(reconstruction, "read_regular", tracking_read)
    with pytest.raises(ValueError, match="before snapshot"):
        reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    assert neighbor not in observed
    assert not stage.exists() and not bundle.exists()


@pytest.mark.parametrize("source", ["library", "license", "notice"])
def test_changed_source_snapshot_refused_before_output_creation(
    reconstruction: ModuleType, retained: tuple[Path, str, Path, Path], monkeypatch: pytest.MonkeyPatch, source: str,
) -> None:
    path, digest, stage, bundle = retained
    selected = ROOT / {"library": "src/verifier/__init__.py", "license": "LICENSE", "notice": "NOTICE"}[source]
    original = reconstruction.read_regular
    def changed(selected_path: Path, limit: int) -> bytes:
        raw = original(selected_path, limit)
        return raw + b"changed" if selected_path == selected else raw
    monkeypatch.setattr(reconstruction, "read_regular", changed)
    with pytest.raises(ValueError):
        reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    assert not stage.exists() and not bundle.exists()


def test_added_library_source_inventory_refused_before_writes(
    reconstruction: ModuleType, entry: ModuleType, retained: tuple[Path, str, Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, stage, bundle = retained
    original = entry.inspect_entry
    inventory = entry.source_inventory
    def changed(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = original(*args, **kwargs)
        monkeypatch.setattr(entry, "source_inventory", lambda: {**inventory(), "src/verifier/added.py": "a" * 64})
        return result
    monkeypatch.setattr(entry, "inspect_entry", changed)
    with pytest.raises(ValueError, match="source inventory changed"):
        reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    assert not stage.exists() and not bundle.exists()


@pytest.mark.parametrize("when", ["before_freeze", "inside_freeze"])
@pytest.mark.parametrize("extra", ["file", "empty_directory"])
def test_exact_allowlist_rejects_extras_even_in_generic_valid_freeze(
    reconstruction: ModuleType, retained: tuple[Path, str, Path, Path], monkeypatch: pytest.MonkeyPatch, when: str, extra: str,
) -> None:
    path, digest, stage, bundle = retained
    def add_extra() -> None:
        if extra == "file": (stage / "unadmitted-notes.txt").write_bytes(b"not in entry contract")
        else: (stage / "unadmitted-empty").mkdir()
    if when == "before_freeze":
        original_write = reconstruction._write_new
        injected = False
        def changed_write(destination: Path, raw: bytes) -> None:
            nonlocal injected
            original_write(destination, raw)
            if not injected:
                add_extra()
                injected = True
        monkeypatch.setattr(reconstruction, "_write_new", changed_write)
    else:
        original_freeze = reconstruction.freeze_artifact
        def changed_freeze(source: Path, destination: Path) -> dict[str, Any]:
            add_extra()
            return original_freeze(source, destination)
        monkeypatch.setattr(reconstruction, "freeze_artifact", changed_freeze)
    with pytest.raises(reconstruction.ReconstructionFreezeError, match="retained"):
        reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    assert stage.is_dir()
    if when == "inside_freeze":
        assert reconstruction.verify_frozen_artifact(bundle, require_seal=False).state == "FROZEN_UNSEALED"
    else:
        assert not bundle.exists()


@pytest.mark.parametrize("destination", ["stage", "bundle"])
@pytest.mark.parametrize("kind", ["file", "directory"])
def test_preexisting_outputs_refused_and_preserved(
    reconstruction: ModuleType, retained: tuple[Path, str, Path, Path], destination: str, kind: str,
) -> None:
    path, digest, stage, bundle = retained
    selected = stage if destination == "stage" else bundle
    if kind == "directory": selected.mkdir()
    else: selected.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    assert selected.exists()
    if kind == "file": assert selected.read_bytes() == b"preserve"


@pytest.mark.parametrize("overlap", ["checkout", "entry_parent", "each_other"])
def test_source_stage_and_bundle_overlap_refused(
    reconstruction: ModuleType, retained: tuple[Path, str, Path, Path], overlap: str,
) -> None:
    path, digest, stage, bundle = retained
    if overlap == "checkout": stage = ROOT / "forbidden-stage"
    elif overlap == "entry_parent": stage = path.parent / "forbidden-stage"
    else: bundle = stage
    with pytest.raises(ValueError, match="disjoint"):
        reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    assert not stage.exists() and not bundle.exists()


def test_freeze_failure_retains_staged_source_without_cleanup(
    reconstruction: ModuleType, retained: tuple[Path, str, Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest, stage, bundle = retained
    def refused(source: Path, destination: Path) -> dict[str, Any]:
        raise ValueError("synthetic generic freeze refusal")
    monkeypatch.setattr(reconstruction, "freeze_artifact", refused)
    with pytest.raises(reconstruction.ReconstructionFreezeError, match="no publication"):
        reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    assert stage.is_dir() and (stage / "entry/entry.json").is_file()
    assert not bundle.exists()


def test_explicit_host_command_does_not_supply_replay_authority(reconstruction: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    def selected(path: Path, **kwargs: Any) -> dict[str, Any]:
        calls.append((path, kwargs))
        return {"native_execution_performed": False}
    monkeypatch.setattr(reconstruction, "freeze_reconstruction", selected)
    assert reconstruction.main(["entry.json", "--expected-entry-sha256", "a" * 64, "--source-stage", "stage", "--bundle", "bundle"]) == 0
    assert calls == [(Path("entry.json"), {"expected_entry_digest": "a" * 64, "source_stage": Path("stage"), "bundle_path": Path("bundle")})]


def test_guard_preserving_relocation_allows_separately_selected_source_import(
    reconstruction: ModuleType, retained: tuple[Path, str, Path, Path], tmp_path: Path,
) -> None:
    path, digest, stage, bundle = retained
    result = reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    # Trust the current checkout's checker before importing any payload source.
    original = reconstruction.verify_frozen_artifact(bundle, require_seal=False, expected_artifact_id=result["artifact_id"])
    assert original.state == "FROZEN_UNSEALED" and original.freeze_valid and original.guard_valid
    relocated = tmp_path / "relocated"
    assert not relocated.exists()
    shutil.copytree(bundle, relocated)
    admitted = reconstruction.verify_frozen_artifact(relocated, require_seal=False, expected_artifact_id=result["artifact_id"])
    assert admitted.state == "FROZEN_UNSEALED" and admitted.freeze_valid and admitted.guard_valid
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    payload = relocated / "payload"
    environment = {key: os.environ[key] for key in ("SystemRoot", "TEMP", "TMP") if key in os.environ}
    environment["PYTHONPATH"] = str(payload / "src")
    expected_source_count = len(json.loads(path.read_bytes())["reconstruction_sources"])
    program = """import sys
from pathlib import Path
print('START host-selected relocated source import', flush=True)
tools = Path(sys.argv[1])
payload = tools.parents[1]
sys.path.insert(0, str(tools))
import catalog_entry
import verifier
assert Path(verifier.__file__).absolute() == payload / 'src/verifier/__init__.py'
assert catalog_entry.ROOT == payload
catalog_entry._check_import_locations()
entry = catalog_entry.strict_json_loads((payload / 'entry' / sys.argv[2]).read_bytes())
inventory = catalog_entry.source_inventory()
assert inventory == entry['reconstruction_sources']
assert len(inventory) == int(sys.argv[3])
print(f'END relocated source import: {len(inventory)} exact sources; synthetic native outputs not reconstructed', flush=True)
"""
    # Host-selected code checks import resolution only. The synthetic package's
    # patched native-source pins are not used as evidence in this child process.
    subprocess.run([sys.executable, "-u", "-B", "-S", "-c", program,
                    str(payload / "examples/scitt_native_interop"), path.name, str(expected_source_count)],
                   cwd=neutral, env=environment, check=True, timeout=30)
    after = reconstruction.verify_frozen_artifact(relocated, require_seal=False, expected_artifact_id=result["artifact_id"])
    assert after.state == "FROZEN_UNSEALED" and after.freeze_valid and after.guard_valid


def test_lost_directory_guard_fails_before_payload_import_despite_exact_bytes(
    reconstruction: ModuleType, retained: tuple[Path, str, Path, Path], tmp_path: Path,
) -> None:
    path, digest, stage, bundle = retained
    result = reconstruction.freeze_reconstruction(path, expected_entry_digest=digest, source_stage=stage, bundle_path=bundle)
    assert reconstruction.verify_frozen_artifact(bundle, require_seal=False, expected_artifact_id=result["artifact_id"]).state == "FROZEN_UNSEALED"
    relocated = tmp_path / "guard-lost"
    shutil.copytree(bundle, relocated)
    directory = relocated / "payload/src/verifier"
    directory.chmod(directory.stat().st_mode | stat.S_IWUSR)
    checked = reconstruction.verify_frozen_artifact(relocated, require_seal=False, expected_artifact_id=result["artifact_id"])
    assert checked.freeze_valid is True
    assert checked.guard_valid is False and checked.state == "FAIL"
    assert checked.artifact_id == result["artifact_id"]
    assert any("write guard is not active" in error for error in checked.errors)
    # The guard gate fails: no payload import or child process follows it.
