"""Terminology: Verifier Standard (VSTD).

Adversarial source-inventory tests for the stored-component example.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from verifier.interoperability.reference_catalog import reference_component_registry
from verifier.interoperability.storage import load_component_package, save_component_package


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "stored_components" / "build_reference_package.py"


def _example():
    spec = importlib.util.spec_from_file_location("vstd_stored_component_example", EXAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _inventory(monkeypatch, tmp_path: Path, *, untracked: tuple[str, ...] = ()):
    example = _example()
    names = sorted(example.FIXED_FILES | {"src/verifier/__init__.py"})
    for name in [*names, *untracked]:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"public specimen\n")

    def git(root: Path, *arguments: str) -> bytes:
        assert root == tmp_path
        if arguments == ("rev-parse", "--show-toplevel"):
            return str(tmp_path).encode()
        if arguments == ("remote", "get-url", "origin"):
            return b"https://github.com/TimeLordRaps/verifier.git"
        if arguments == ("ls-files", "--stage", "-z"):
            return b"".join(f"100644 {'a' * 40} 0\t{name}\0".encode() for name in names)
        if arguments == ("ls-files", "--others", "--exclude-standard", "-z"):
            return b"\0".join(name.encode() for name in untracked)
        if arguments == ("rev-parse", "HEAD"):
            return b"a" * 40
        if arguments == ("status", "--porcelain=v1", "--untracked-files=normal"):
            return b" M src/verifier/__init__.py"
        raise AssertionError(arguments)

    monkeypatch.setattr(example, "_git", git)
    return example


def test_reference_export_requires_explicit_untracked_public_source(monkeypatch, tmp_path: Path) -> None:
    extra = "src/verifier/new_component.py"
    example = _inventory(monkeypatch, tmp_path, untracked=(extra, "private-note.md"))
    with pytest.raises(ValueError, match="untracked public source"):
        example._capture_snapshot(tmp_path)
    captured, head, dirty = example._capture_snapshot(tmp_path, (extra,))
    assert extra in captured
    assert "private-note.md" not in captured
    assert head == "a" * 40
    assert dirty is True
    for bad_paths in (("private-note.md",), (extra, extra), ("src/verifier/../outside.py",)):
        with pytest.raises(ValueError, match="include-untracked"):
            example._capture_snapshot(tmp_path, bad_paths)


def test_reference_export_rejects_parent_reparse_point(monkeypatch, tmp_path: Path) -> None:
    example = _inventory(monkeypatch, tmp_path)
    original = Path.lstat

    def lstat(path: Path):
        if path == tmp_path / "src" / "verifier":
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        return original(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ValueError, match="parent directories"):
        example._capture_snapshot(tmp_path)


def test_reference_export_rejects_other_repository_identity(monkeypatch, tmp_path: Path) -> None:
    example = _inventory(monkeypatch, tmp_path)
    original = example._git

    def git(root: Path, *arguments: str) -> bytes:
        if arguments == ("remote", "get-url", "origin"):
            return b"https://example.invalid/unrelated.git"
        return original(root, *arguments)

    monkeypatch.setattr(example, "_git", git)
    with pytest.raises(ValueError, match="public TimeLordRaps/verifier"):
        example._capture_snapshot(tmp_path)


def test_reference_package_roundtrip_binds_all_roles_without_execution(monkeypatch, tmp_path: Path) -> None:
    example = _example()
    registry = reference_component_registry()
    captured = {name: b"public metadata\n" for name in example.FIXED_FILES}
    for component in registry.components:
        module_name = component.implementation_ref.split(":", 1)[0]
        captured["src/" + module_name.replace(".", "/") + ".py"] = b"raise RuntimeError('must not execute')\n"
    for module in (example.catalog_module, example.reference_module):
        captured["src/" + module.__name__.replace(".", "/") + ".py"] = Path(module.__file__).read_bytes()
    monkeypatch.setattr(example, "_capture_snapshot", lambda *_: (captured, "a" * 40, True))
    package = example.build_package(tmp_path, "1.3.0-test")
    assert len(package.registry.components) == len(package.implementations) == 17
    assert "dirty=true" in package.description
    assert "Dependency closure NOT_ESTABLISHED" in package.description
    assert {binding.component_id for binding in package.implementations} == {
        component.component_id for component in registry.components
    }
    output = tmp_path / "reference-components.json"
    save_component_package(package, output)
    restored = load_component_package(output, expected_digest=package.canonical_digest())
    assert restored.registry.canonical_digest() == registry.canonical_digest()
    assert {artifact.path: artifact.content for artifact in restored.artifacts} == captured


def test_reference_export_rejects_mismatched_catalog_snapshot(monkeypatch, tmp_path: Path) -> None:
    example = _example()
    monkeypatch.setattr(example, "_capture_snapshot", lambda *_: ({}, "a" * 40, False))
    with pytest.raises(ValueError, match="captured catalog source differs"):
        example.build_package(tmp_path, "1.3.0-test")


def test_installed_wheel_gate_exercises_package_bound_planning() -> None:
    import yaml

    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = workflow["jobs"]["installed-wheel-smoke"]
    steps = "\n".join(step.get("run", "") for step in job["steps"])
    assert "examples/stored_components/build_reference_package.py" in steps
    assert "/tmp/vstd-wheel/bin/vstd components inspect" in steps
    assert "--plan --package /tmp/vstd-components.json" in steps
    assert 'plan["binding_scope"] == "STORED_PACKAGE"' in steps
    assert 'plan["package_digest"] == package.canonical_digest()' in steps
