"""Supply Chain Integrity, Transparency, and Trust (SCITT) requirement tests.

Only synthetic distribution metadata is retained in these tests.
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
"""

from __future__ import annotations

import importlib
import base64
import copy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def test_requirements_module_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "examples/scitt_native_interop"))
    assert callable(importlib.import_module("python_requirements").capture_requirements)


@pytest.fixture
def checker(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    parser = pytest.importorskip("packaging", reason="optional selected requirement parser unavailable")
    if parser.__version__ != "26.3": pytest.skip("requires exact optional packaging 26.3 parser")
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "examples/scitt_native_interop"))
    return importlib.import_module("python_requirements")


@pytest.fixture
def environment() -> dict[str, str]:
    return {"implementation_name": "cpython", "implementation_version": "3.12.8", "os_name": "nt",
            "platform_machine": "AMD64", "platform_release": "synthetic", "platform_system": "Windows",
            "platform_version": "synthetic", "python_full_version": "3.12.8",
            "platform_python_implementation": "CPython", "python_version": "3.12", "sys_platform": "win32", "extra": ""}


def metadata(name: str, version: str = "1", requirements: tuple[str, ...] = (), python: str | None = ">=3.9") -> bytes:
    lines = ["Metadata-Version: 2.4", "Name: " + name, "Version: " + version]
    if python is not None: lines.append("Requires-Python: " + python)
    lines.extend("Requires-Dist: " + requirement for requirement in requirements)
    return ("\n".join(lines) + "\n\nSynthetic description.\n").encode("utf-8")


def install(root: Path, raw: bytes, location: str) -> Path:
    directory = root / (location + ".dist-info")
    directory.mkdir(parents=True)
    path = directory / "METADATA"
    path.write_bytes(raw)
    return path


def capture(checker: ModuleType, root: Path, environment: dict[str, str], roots: dict[str, str] | None = None) -> dict[str, Any]:
    return checker.capture_requirements({"root": "1"} if roots is None else roots, environment=environment, search_paths=(root,))


def recheck(checker: ModuleType, snapshot: dict[str, Any]) -> dict[str, Any]:
    return checker.recheck_requirements(snapshot, expected_snapshot_digest=checker.snapshot_digest(snapshot))


def test_reachable_only_transitive_capture_and_offline_recheck(checker: ModuleType, environment: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    retained = [metadata("root", requirements=("middle>=2", "absent; extra == 'test'")), metadata("middle", "2", ("leaf==3",)), metadata("leaf", "3")]
    for index, raw in enumerate(retained): install(tmp_path, raw, str(index))
    install(tmp_path, metadata("unrelated"), "unrelated")
    snapshot = capture(checker, tmp_path, environment)
    assert {base64.b64decode(item["metadata_b64"]) for item in snapshot["documents"]} == set(retained)
    expected = checker.snapshot_digest(snapshot)
    report = recheck(checker, snapshot)
    assert report["status"] == "CONSISTENT"
    assert [edge["status"] for edge in report["edges"]] == ["MATCHED", "INACTIVE", "MATCHED"]
    assert report["native_execution_performed"] is False and report["installed_inventory_rechecked"] is False
    for path in tmp_path.glob("*/METADATA"): path.write_bytes(b"changed after capture")
    monkeypatch.setattr(checker, "capture_requirements", lambda *args, **kwargs: pytest.fail("offline recheck must not discover providers"))
    assert checker.recheck_requirements(snapshot, expected_snapshot_digest=expected) == report


def test_all_incoming_edges_checked_after_cycle_dedup(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    for name, requirements in (("root", ("a", "b")), ("a", ("c>=2",)), ("b", ("c<2",)), ("c", ("root==1",))):
        install(tmp_path, metadata(name, "2" if name == "c" else "1", requirements), name)
    report = recheck(checker, capture(checker, tmp_path, environment))
    assert report["status"] == "INCONSISTENT"
    assert len(report["providers"]) == 4 and len(report["edges"]) == 5
    assert [edge["status"] for edge in report["edges"] if edge["target"] == "c"] == ["MATCHED", "MISMATCH"]


@pytest.mark.parametrize("requirement,provider,status", [("dep>=1", "1.5a1", "CONSISTENT"), ("dep>=2", "2.0a1", "INCONSISTENT"), ("dep<2", "2.0a1", "INCONSISTENT")])
def test_installed_prereleases_preserve_ordered_specifier_semantics(checker: ModuleType, environment: dict[str, str], tmp_path: Path, requirement: str, provider: str, status: str) -> None:
    install(tmp_path, metadata("root", requirements=(requirement,)), "root")
    install(tmp_path, metadata("dep", provider), "dep")
    assert recheck(checker, capture(checker, tmp_path, environment))["status"] == status


@pytest.mark.parametrize("requirements,status", [(("missing",), "UNKNOWN"), (("dep[extra]",), "UNKNOWN"), (("dep @ https://example.invalid/archive.whl",), "UNKNOWN"), (("dep; 'test' in extras",), "UNKNOWN"), (("dep; 'test' in dependency_groups",), "UNKNOWN"), (("dep; extra == 'test'",), "CONSISTENT"), (("dep; python_version == '0'",), "CONSISTENT"), (("dep>=2", "missing"), "INCONSISTENT"), (("dep>=2", "elsewhere[extra]"), "INCONSISTENT")])
def test_unresolved_and_inactive_edges_never_become_matches(checker: ModuleType, environment: dict[str, str], tmp_path: Path, requirements: tuple[str, ...], status: str) -> None:
    install(tmp_path, metadata("root", requirements=requirements), "root")
    install(tmp_path, metadata("dep"), "dep")
    report = recheck(checker, capture(checker, tmp_path, environment))
    assert report["status"] == status
    if status == "INCONSISTENT":
        assert any(edge["status"] == "MISMATCH" for edge in report["edges"])
        assert any(edge["status"] in ("UNKNOWN", "MISSING_PROVIDER") for edge in report["edges"])


def test_requires_python_uses_full_version_for_every_provider(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    install(tmp_path, metadata("root", requirements=("dep",), python=">=3.12.1"), "root")
    install(tmp_path, metadata("dep", python="!=3.12.8"), "dep")
    report = recheck(checker, capture(checker, tmp_path, environment))
    assert report["status"] == "INCONSISTENT"
    assert {node["name"]: node["python_status"] for node in report["providers"]} == {"root": "MATCHED", "dep": "MISMATCH"}


def test_normalized_duplicate_providers_remain_ambiguous(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    install(tmp_path, metadata("root", requirements=("Foo.Bar",)), "root")
    install(tmp_path, metadata("Foo.Bar"), "first")
    install(tmp_path, metadata("Foo__Bar"), "second")
    snapshot = capture(checker, tmp_path, environment)
    assert len(snapshot["documents"]) == 3
    report = recheck(checker, snapshot)
    assert report["status"] == "UNKNOWN" and report["edges"][0]["status"] == "AMBIGUOUS_PROVIDER"


@pytest.mark.parametrize("raw", [b"Name: root\nVersion: 1\n", b"Metadata-Version: 9.0\nName: root\nVersion: 1\n", metadata("root").replace(b"Name: root", b"Name: root\nName: other"), metadata("root").replace(b"Version: 1\n", b"Version: 1\nVersion: 2\n"), metadata("root").replace(b"Requires-Python: >=3.9", b"Requires-Python: >=3.9\nRequires-Python: >=3.10"), b"not metadata\n", b"\xff"])
def test_malformed_or_unsupported_provider_is_not_ignored(checker: ModuleType, environment: dict[str, str], tmp_path: Path, raw: bytes) -> None:
    install(tmp_path, metadata("root"), "root")
    install(tmp_path, raw, "unrelated")
    with pytest.raises(ValueError): capture(checker, tmp_path, environment)


@pytest.mark.parametrize("mutation", ["missing_key", "extra_key", "bool", "extras", "inconsistent_version"])
def test_environment_complete_exact_and_no_fallback(checker: ModuleType, environment: dict[str, str], tmp_path: Path, mutation: str) -> None:
    install(tmp_path, metadata("root"), "root")
    if mutation == "missing_key": environment.pop("os_name")
    elif mutation == "extra_key": environment["extras"] = "test"
    elif mutation == "bool": environment["os_name"] = True
    elif mutation == "extras": environment["extra"] = "test"
    else: environment["python_version"] = "3.10"
    with pytest.raises(ValueError): capture(checker, tmp_path, environment)


@pytest.mark.parametrize("mutation", ["roots", "environment", "metadata", "discovery", "helper", "parser"])
def test_semantic_substitutions_cannot_reuse_old_digest(checker: ModuleType, environment: dict[str, str], tmp_path: Path, mutation: str) -> None:
    install(tmp_path, metadata("root"), "root")
    snapshot = capture(checker, tmp_path, environment)
    digest = checker.snapshot_digest(snapshot)
    if mutation == "roots": snapshot["roots"]["root"] = "2"
    elif mutation == "environment": snapshot["environment"]["platform_release"] = "changed"
    elif mutation == "metadata": snapshot["documents"][0]["metadata_b64"] = base64.b64encode(metadata("root", "2")).decode()
    elif mutation == "discovery": snapshot["discovery"]["provider_count"] += 1
    elif mutation == "helper": snapshot["parser"]["checker_sha256"] = "a" * 64
    else: snapshot["parser"]["source_sha256"]["__init__.py"] = "a" * 64
    with pytest.raises(ValueError, match="separately supplied"):
        checker.recheck_requirements(snapshot, expected_snapshot_digest=digest)


def test_fresh_digest_does_not_authorize_other_parser_sources(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    install(tmp_path, metadata("root"), "root")
    snapshot = capture(checker, tmp_path, environment)
    snapshot["parser"]["checker_sha256"] = "a" * 64
    with pytest.raises(ValueError, match="source coordinate"):
        recheck(checker, snapshot)


def test_malformed_snapshot_types_and_extra_fields_refused(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    install(tmp_path, metadata("root"), "root")
    snapshot = capture(checker, tmp_path, environment)
    changes = [("documents", ()), ("schema_version", True), ("extra", 1)]
    for key, value in changes:
        changed = {**snapshot, key: value}
        with pytest.raises(ValueError): checker.snapshot_digest(changed)
    changed = copy.deepcopy(snapshot)
    changed["discovery"]["provider_count"] = True
    with pytest.raises(ValueError): checker.snapshot_digest(changed)


def test_missing_metadata_unsupported_layout_and_read_caps(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    path = tmp_path / "root.dist-info"
    path.mkdir()
    with pytest.raises((ValueError, OSError)): capture(checker, tmp_path, environment)
    (path / "METADATA").write_bytes(b"x" * (checker.MAX_DOCUMENT_BYTES + 1))
    with pytest.raises(ValueError): capture(checker, tmp_path, environment)


def test_unsupported_legacy_layout_refused(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    (tmp_path / "legacy.egg").mkdir()
    with pytest.raises(ValueError, match="unsupported provider layout"): capture(checker, tmp_path, environment)


def test_bounded_requirement_nesting_before_recursive_parser(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    install(tmp_path, metadata("root", requirements=("dep; " + "(" * 17 + "os_name == 'nt'" + ")" * 17,)), "root")
    with pytest.raises(ValueError, match="nesting bound"): capture(checker, tmp_path, environment)


def test_capture_defensively_snapshots_environment_and_roots(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    install(tmp_path, metadata("root"), "root")
    roots = {"root": "1"}
    snapshot = capture(checker, tmp_path, environment, roots)
    digest = checker.snapshot_digest(snapshot)
    roots["root"] = "2"
    environment["python_full_version"] = "0"
    assert checker.snapshot_digest(snapshot) == digest


@pytest.mark.parametrize("specifier,status", [("", "MATCHED"), ("not-a-specifier", "UNKNOWN")])
def test_explicit_unconstrained_and_malformed_python_specifiers(checker: ModuleType, environment: dict[str, str], tmp_path: Path, specifier: str, status: str) -> None:
    install(tmp_path, metadata("root", python=specifier), "root")
    report = recheck(checker, capture(checker, tmp_path, environment))
    assert report["providers"][0]["python_status"] == status
    # The pinned parser treats an explicitly empty specifier as no restriction.
    assert report["status"] == ("CONSISTENT" if status == "MATCHED" else "UNKNOWN")


def test_parser_import_locations_cannot_mix_installations(checker: ModuleType, environment: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import packaging.requirements
    install(tmp_path, metadata("root"), "root")
    monkeypatch.setattr(packaging.requirements, "__file__", str(tmp_path / "shadowed.py"))
    with pytest.raises(ValueError, match="mixed parser"):
        capture(checker, tmp_path, environment)


def test_missing_root_retained_as_unknown(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    snapshot = capture(checker, tmp_path, environment)
    assert snapshot["documents"] == []
    report = recheck(checker, snapshot)
    assert report["status"] == "UNKNOWN" and report["roots"][0]["status"] == "MISSING_PROVIDER"


def test_no_inspected_distribution_import_or_installer_call(checker: ModuleType, environment: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins
    original = builtins.__import__

    def guarded(name: str, *args: Any, **kwargs: Any) -> Any:
        if name in {"root", "dep"}: pytest.fail("inspected distribution code imported")
        return original(name, *args, **kwargs)

    install(tmp_path, metadata("root", requirements=("dep",)), "root")
    install(tmp_path, metadata("dep"), "dep")
    monkeypatch.setattr(builtins, "__import__", guarded)
    assert recheck(checker, capture(checker, tmp_path, environment))["status"] == "CONSISTENT"


@pytest.mark.parametrize("scenario,status", [("unrelated", "CONSISTENT"), ("duplicate", "UNKNOWN"), ("dependency", "UNKNOWN"), ("root", "UNKNOWN"), ("mismatch", "INCONSISTENT")])
def test_legacy_index_never_supplies_dependency_completeness(checker: ModuleType, environment: dict[str, str], tmp_path: Path, scenario: str, status: str) -> None:
    legacy = tmp_path / "legacy.egg-info"
    legacy.mkdir()
    name = "root" if scenario in ("duplicate", "root") else "dep"
    (legacy / "PKG-INFO").write_bytes(metadata(name))
    (legacy / "requires.txt").write_bytes(b"missing-not-interpreted")
    if scenario != "root":
        install(tmp_path, metadata("root", requirements=("dep>=2",) if scenario == "mismatch" else ("dep",) if scenario == "dependency" else ()), "root")
    snapshot = capture(checker, tmp_path, environment)
    report = recheck(checker, snapshot)
    assert report["status"] == status
    if scenario == "unrelated": assert len(snapshot["documents"]) == 1
    else: assert any(item["layout"] == "egg-info" for item in snapshot["documents"])
    assert all(edge["target"] != "missing-not-interpreted" for edge in report["edges"])
    if scenario in ("dependency", "root", "mismatch"):
        assert any(item["python_status"] == "UNSUPPORTED_LAYOUT" for item in report["providers"])


def test_legacy_missing_metadata_cannot_be_ignored(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    (tmp_path / "unrelated.egg-info").mkdir()
    install(tmp_path, metadata("root"), "root")
    with pytest.raises((OSError, ValueError)): capture(checker, tmp_path, environment)


def test_changed_layout_cannot_reuse_snapshot_digest(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    install(tmp_path, metadata("root"), "root")
    snapshot = capture(checker, tmp_path, environment)
    expected = checker.snapshot_digest(snapshot)
    snapshot["documents"][0]["layout"] = "egg-info"
    with pytest.raises(ValueError, match="separately supplied"):
        checker.recheck_requirements(snapshot, expected_snapshot_digest=expected)


@pytest.mark.parametrize("bound,value", [("MAX_ENTRIES", 1), ("MAX_DISCOVERY_DOCUMENTS", 1), ("MAX_DISCOVERY_BYTES", 1), ("MAX_RETAINED_BYTES", 1)])
def test_admission_and_discovery_bounds_refuse_instead_of_partial_success(checker: ModuleType, environment: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bound: str, value: int) -> None:
    install(tmp_path, metadata("root", requirements=("dep",)), "root")
    install(tmp_path, metadata("dep"), "dep")
    monkeypatch.setattr(checker, bound, value)
    with pytest.raises(ValueError, match="bound"):
        capture(checker, tmp_path, environment)


def test_total_traversal_edge_bound_applies_across_documents(checker: ModuleType, environment: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install(tmp_path, metadata("root", requirements=("dep",)), "root")
    install(tmp_path, metadata("dep", requirements=("root",)), "dep")
    monkeypatch.setattr(checker, "MAX_EDGES", 1)
    with pytest.raises(ValueError, match="traversal edge bound"):
        capture(checker, tmp_path, environment)


def test_legacy_alias_is_not_followed(checker: ModuleType, environment: dict[str, str], tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "PKG-INFO").write_bytes(metadata("root"))
    alias = tmp_path / "root.egg-info"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("OS_CAPABILITY_GUARD: host does not permit creating symbolic links")
    with pytest.raises((ValueError, OSError)):
        capture(checker, tmp_path, environment)


@pytest.mark.parametrize("scenario,status", [("unrelated", "CONSISTENT"), ("duplicate", "UNKNOWN"), ("dependency", "UNKNOWN"), ("mismatch", "INCONSISTENT")])
def test_unsupported_metadata_version_indexes_identity_only(checker: ModuleType, environment: dict[str, str], tmp_path: Path, scenario: str, status: str) -> None:
    unsupported = metadata("root" if scenario == "duplicate" else "dep", requirements=("never-interpreted",)).replace(b"Metadata-Version: 2.4", b"Metadata-Version: 2.0")
    install(tmp_path, unsupported, "unsupported")
    install(tmp_path, metadata("root", requirements=("dep>=2",) if scenario == "mismatch" else ("dep",) if scenario == "dependency" else ()), "root")
    snapshot = capture(checker, tmp_path, environment)
    report = recheck(checker, snapshot)
    assert report["status"] == status
    if scenario == "unrelated": assert len(snapshot["documents"]) == 1
    else: assert unsupported in {base64.b64decode(item["metadata_b64"]) for item in snapshot["documents"]}
    if scenario in ("dependency", "mismatch"):
        assert any(node["python_status"] == "UNSUPPORTED_METADATA_VERSION" for node in report["providers"])
    assert all(edge["target"] != "never-interpreted" for edge in report["edges"])
