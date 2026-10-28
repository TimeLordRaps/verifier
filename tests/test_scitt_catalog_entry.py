"""Supply Chain Integrity, Transparency, and Trust (SCITT) local entry tests.

JavaScript Object Notation (JSON).
All process outputs and upstream source fixtures are synthetic, not native evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import verifier as verifier_module
from examples.scitt_native_interop import catalog_entry

from test_scitt_package_comparison import change_json, comparison, specimen
from verifier.interoperability.storage import StoredComponentPackage


ROOT = Path(__file__).resolve().parents[1]
Retained = tuple[Path, Path, Path, dict[str, Any]]


@pytest.fixture
def entry() -> ModuleType:
    return catalog_entry


def files(tmp_path: Path, package: StoredComponentPackage) -> tuple[Path, Path, dict[str, Any]]:
    package_path, sidecar_path = tmp_path / "package.json", tmp_path / "sidecar.json"
    package_path.write_bytes(package.canonical_json_bytes())
    report = comparison.compare_package(package, expected_digest=package.canonical_digest())
    sidecar_path.write_bytes(comparison.canonical(report))
    return package_path, sidecar_path, report


def test_entry_binds_complete_package_and_reconstructs_without_native_execution(entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from test_scitt_native_runner import runner
    monkeypatch.setattr(runner, "capture_comparison", lambda *a, **k: pytest.fail("native execution forbidden"))
    package_path, sidecar_path, report = files(tmp_path, specimen)
    path = tmp_path / "entry.json"
    made = entry.create_entry(path, package_path, sidecar_path)
    inspected = entry.inspect_entry(path, expected_entry_digest=made["entry_digest"])
    assert inspected == made
    assert inspected["comparison"] == report
    assert inspected["comparison"]["native_execution_performed"] is False
    assert inspected["comparison"]["native_qualification"] == "NOT_ESTABLISHED"


@pytest.fixture
def retained(entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path) -> Retained:
    package_path, sidecar_path, report = files(tmp_path, specimen)
    path = tmp_path / "entry.json"
    made = entry.create_entry(path, package_path, sidecar_path)
    return path, package_path, sidecar_path, made


@pytest.mark.parametrize("target", ["package", "sidecar", "entry"])
def test_same_named_substitution_does_not_reuse_entry_coordinate(entry: ModuleType, retained: Retained, target: str) -> None:
    path, package_path, sidecar_path, made = retained
    {"package": package_path, "sidecar": sidecar_path, "entry": path}[target].write_bytes(b"{}")
    with pytest.raises(ValueError, match="differ"):
        entry.inspect_entry(path, expected_entry_digest=made["entry_digest"])


def test_raw_package_formatting_is_bound_separately(entry: ModuleType, retained: Retained) -> None:
    path, package_path, _, made = retained
    raw = package_path.read_bytes()
    package_path.write_bytes(raw + b"\n")
    with pytest.raises(ValueError, match="artifact bytes"):
        entry.inspect_entry(path, expected_entry_digest=made["entry_digest"])


@pytest.mark.parametrize("mutation", ["extra", "missing", "version_bool", "package_null", "digest_bool", "uppercase_digest", "sources_list", "source_digest_bool", "source_escape", "filename_int", "parent", "absolute", "drive", "reserved", "trailing_dot", "case_collision", "self_reference"])
def test_malformed_manifest_is_refused_even_with_new_external_digest(entry: ModuleType, retained: Retained, mutation: str, monkeypatch: pytest.MonkeyPatch) -> None:
    path, _, _, _ = retained
    value = json.loads(path.read_bytes())
    if mutation == "extra": value["extra"] = 1
    elif mutation == "missing": del value["sidecar"]
    elif mutation == "version_bool": value["schema_version"] = True
    elif mutation == "package_null": value["package"] = None
    elif mutation == "digest_bool": value["package"]["sha256"] = True
    elif mutation == "uppercase_digest": value["package"]["sha256"] = "A" * 64
    elif mutation == "sources_list": value["reconstruction_sources"] = []
    elif mutation == "source_digest_bool": value["reconstruction_sources"][next(iter(value["reconstruction_sources"]))] = True
    elif mutation == "source_escape": value["reconstruction_sources"]["../escape.py"] = "a" * 64
    elif mutation == "filename_int": value["package"]["filename"] = 1
    elif mutation == "parent": value["package"]["filename"] = "../package.json"
    elif mutation == "absolute": value["package"]["filename"] = "/package.json"
    elif mutation == "drive": value["package"]["filename"] = "Z:package.json"
    elif mutation == "reserved": value["package"]["filename"] = "NUL.json"
    elif mutation == "trailing_dot": value["package"]["filename"] = "package."
    elif mutation == "case_collision": value["sidecar"]["filename"] = "PACKAGE.JSON"
    else: value["package"]["filename"] = path.name
    raw = comparison.canonical(value)
    path.write_bytes(raw)
    monkeypatch.setattr(comparison, "reconstruct_sidecar", lambda *a, **k: pytest.fail("malformed entry reached reconstruction"))
    with pytest.raises(ValueError):
        entry.inspect_entry(path, expected_entry_digest=comparison.sha(raw))


@pytest.mark.parametrize("transport", ["newline", "duplicate"])
def test_noncanonical_or_duplicate_entry_transport_refused(entry: ModuleType, retained: Retained, transport: str) -> None:
    path, _, _, _ = retained
    raw = path.read_bytes()
    raw = raw + b"\n" if transport == "newline" else b'{"schema_version":"duplicate",' + raw[1:]
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        entry.inspect_entry(path, expected_entry_digest=comparison.sha(raw))


def test_forged_sidecar_summary_refused_with_fresh_raw_and_entry_digests(entry: ModuleType, retained: Retained) -> None:
    path, _, sidecar, _ = retained
    value = json.loads(path.read_bytes())
    report = json.loads(sidecar.read_bytes())
    report["native_qualification"] = "QUALIFIED"
    sidecar.write_bytes(comparison.canonical(report))
    value["sidecar"]["sha256"] = comparison.sha(sidecar.read_bytes())
    raw = comparison.canonical(value)
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="sidecar does not reconstruct"):
        entry.inspect_entry(path, expected_entry_digest=comparison.sha(raw))


def fake_checkout(entry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "checkout"
    paths = ("src/verifier/__init__.py", "src/verifier/nested/module.py", *entry.TOOLS)
    for name in paths:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"# Synthetic selected source, never loaded.\n")
    monkeypatch.setattr(entry, "ROOT", root)
    monkeypatch.setattr(entry, "_check_import_locations", lambda: None)
    return root


@pytest.mark.parametrize("mutation", ["library_changed", "library_missing", "library_added", "decoder_changed", "entry_changed", "runner_changed"])
def test_complete_source_inventory_rejects_changes(entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    root = fake_checkout(entry, tmp_path, monkeypatch)
    package_path, sidecar_path, _ = files(tmp_path, specimen)
    path = tmp_path / "entry.json"
    made = entry.create_entry(path, package_path, sidecar_path)
    library = root / "src/verifier/nested/module.py"
    if mutation == "library_missing": library.unlink()
    elif mutation == "library_added": (library.parent / "extra.py").write_bytes(b"# added")
    elif mutation == "library_changed": library.write_bytes(b"# changed")
    else:
        index = {"decoder_changed": 1, "entry_changed": 2, "runner_changed": 0}[mutation]
        (root / entry.TOOLS[index]).write_bytes(b"# changed")
    monkeypatch.setattr(comparison, "reconstruct_sidecar", lambda *a, **k: pytest.fail("source drift reached reconstruction"))
    with pytest.raises(ValueError, match="source inventory differs"):
        entry.inspect_entry(path, expected_entry_digest=made["entry_digest"])


@pytest.mark.parametrize("changed", ["source", "package", "sidecar"])
def test_dependency_change_during_reconstruction_leaves_no_entry(entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str) -> None:
    root = fake_checkout(entry, tmp_path, monkeypatch)
    package, sidecar, _ = files(tmp_path, specimen)
    original = comparison.reconstruct_sidecar
    def changing(*args: Any, **kwargs: Any) -> dict[str, Any]:
        report = original(*args, **kwargs)
        target = {"source": root / "src/verifier/__init__.py", "package": package, "sidecar": sidecar}[changed]
        target.write_bytes(b"changed during reconstruction")
        return report
    monkeypatch.setattr(comparison, "reconstruct_sidecar", changing)
    path = tmp_path / "entry.json"
    with pytest.raises(ValueError, match="changed"):
        entry.create_entry(path, package, sidecar)
    assert not path.exists()


def test_creation_never_overwrites_or_accepts_nonsiblings(entry: ModuleType, retained: Retained, tmp_path: Path) -> None:
    path, package, sidecar, made = retained
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        entry.create_entry(path, package, sidecar)
    assert path.read_bytes() == original
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    with pytest.raises(ValueError, match="siblings"):
        entry.create_entry(elsewhere / "entry.json", package, sidecar)
    assert not (elsewhere / "entry.json").exists()


@pytest.mark.parametrize("status", ["unknown", "conflicted"])
def test_entry_preserves_uncertainty_and_disagreement(entry: ModuleType, specimen: StoredComponentPackage, tmp_path: Path, status: str) -> None:
    from test_scitt_package_comparison import change_artifact, native_output
    if status == "unknown":
        specimen = change_json(specimen, "observations.json", lambda value: value["observations"][0].update(stop_reason="TIMEOUT"))
    else:
        raw = comparison.canonical(native_output("python", "statement", False, "0" * 64))
        specimen = change_artifact(specimen, "outputs/positive-statement-python.stdout", raw)
        specimen = change_json(specimen, "observations.json", lambda value: value["observations"][0].update(exit_code=1, stdout_sha256=comparison.sha(raw)))
    package, sidecar, report = files(tmp_path, specimen)
    path = tmp_path / "entry.json"
    made = entry.create_entry(path, package, sidecar)
    result = entry.inspect_entry(path, expected_entry_digest=made["entry_digest"])["comparison"]
    assert result == report
    assert result["agreement"] == ("NOT_ESTABLISHED" if status == "unknown" else "CONFLICTED")


@pytest.mark.parametrize("bound", ["MAX_SOURCE_FILES", "MAX_SOURCE_BYTES", "MAX_TOTAL_SOURCE_BYTES", "MAX_WALK_ENTRIES"])
def test_source_discovery_is_bounded(entry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bound: str) -> None:
    fake_checkout(entry, tmp_path, monkeypatch)
    monkeypatch.setattr(entry, bound, 1)
    with pytest.raises(ValueError, match="bound"):
        entry.source_inventory()


def test_alias_source_directory_rejected_without_following(entry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace
    root = fake_checkout(entry, tmp_path, monkeypatch)
    target = root / "src/verifier/nested"
    original = Path.lstat
    def marked(path: Path, *args: Any, **kwargs: Any) -> Any:
        result = original(path, *args, **kwargs)
        return SimpleNamespace(st_mode=result.st_mode, st_file_attributes=0x400) if path == target else result
    monkeypatch.setattr(Path, "lstat", marked)
    with pytest.raises(ValueError, match="reparse"):
        entry.source_inventory()


def test_explicit_external_digest_required_before_reconstruction(entry: ModuleType, retained: Retained, monkeypatch: pytest.MonkeyPatch) -> None:
    path, _, _, _ = retained
    monkeypatch.setattr(entry, "source_inventory", lambda: pytest.fail("invalid authority reached inventory"))
    for expected in (None, True, 1, "", "A" * 64, "0" * 64):
        with pytest.raises(ValueError):
            entry.inspect_entry(path, expected_entry_digest=expected)


@pytest.mark.parametrize("module_name", ["comparison", "native_runner", "verifier"])
def test_obviously_shadowed_import_refused(entry: ModuleType, retained: Retained, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module_name: str) -> None:
    path, _, _, made = retained
    modules = {
        "comparison": entry.comparison,
        "native_runner": entry.native_runner,
        "verifier": verifier_module,
    }
    module = modules[module_name]
    monkeypatch.setattr(module, "__file__", str(tmp_path / "shadowed.py"))
    with pytest.raises(ValueError, match="import is outside"):
        entry.inspect_entry(path, expected_entry_digest=made["entry_digest"])


def test_canonical_package_identity_is_checked_beside_raw_digest(entry: ModuleType, retained: Retained) -> None:
    path, _, _, _ = retained
    value = json.loads(path.read_bytes())
    value["package"]["canonical_digest"] = "0" * 64
    raw = comparison.canonical(value)
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="complete package coordinate"):
        entry.inspect_entry(path, expected_entry_digest=comparison.sha(raw))


@pytest.mark.parametrize("bound", ["MAX_ENTRY_BYTES", "MAX_PACKAGE_BYTES", "MAX_SIDECAR_BYTES"])
def test_retained_transport_reads_are_bounded(entry: ModuleType, retained: Retained, monkeypatch: pytest.MonkeyPatch, bound: str) -> None:
    path, _, _, made = retained
    monkeypatch.setattr(entry, bound, 1)
    with pytest.raises(ValueError, match="read bound"):
        entry.inspect_entry(path, expected_entry_digest=made["entry_digest"])


def test_public_commands_require_separate_consumer_digest(entry: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    def create(*args: Any) -> dict[str, str]:
        calls.append(("create", args))
        return {"entry_digest": "a" * 64}
    def inspect(*args: Any, **kwargs: Any) -> dict[str, str]:
        calls.append(("inspect", args, kwargs))
        return {"entry_digest": "a" * 64}
    monkeypatch.setattr(entry, "create_entry", create)
    monkeypatch.setattr(entry, "inspect_entry", inspect)
    assert entry.main(["create", "entry.json", "package.json", "sidecar.json"]) == 0
    assert entry.main(["inspect", "entry.json", "--expected-entry-sha256", "a" * 64]) == 0
    assert calls == [("create", (Path("entry.json"), Path("package.json"), Path("sidecar.json"))),
                     ("inspect", (Path("entry.json"),), {"expected_entry_digest": "a" * 64})]
    with pytest.raises(SystemExit) as stopped:
        entry.main(["inspect", "entry.json"])
    assert stopped.value.code == 2
    assert len(calls) == 2


@pytest.mark.parametrize("suffix", [".PY", ".Py"])
def test_noncanonical_python_source_suffix_is_refused(entry: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str) -> None:
    root = fake_checkout(entry, tmp_path, monkeypatch)
    (root / "src/verifier" / ("additional" + suffix)).write_bytes(b"# Case-sensitive discovery must not omit this.")
    with pytest.raises(ValueError, match="case"):
        entry.source_inventory()


def test_casefolded_source_inventory_collision_is_refused(entry: ModuleType, retained: Retained) -> None:
    path, _, _, _ = retained
    manifest = json.loads(path.read_bytes())
    sources = manifest["reconstruction_sources"]
    sources["src/verifier/__INIT__.py"] = sources["src/verifier/__init__.py"]
    raw = comparison.canonical(manifest)
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="case-folded"):
        entry.inspect_entry(path, expected_entry_digest=comparison.sha(raw))
