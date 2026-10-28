"""Public export coverage for Verifier Standard (VSTD), without subject execution."""
from __future__ import annotations

import ast
from copy import deepcopy
import json
from pathlib import Path
import subprocess
from typing import Callable
from typing import Any

import pytest

from verifier.runtime.namespace_admission import assess, build_template
from verifier.runtime.namespace_discovery import discover
from verifier.runtime.namespace_exports import has_dynamic_construction
from test_namespace_admission import save


DISPATCH = '''from importlib import import_module
_LAZY_EXPORTS = {"Public": ("sample.subject", "Original")}
__all__ = list(_LAZY_EXPORTS)
def __getattr__(name):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value
'''


def repository(root: Path, initializer: str = DISPATCH) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    package = root / "sample"
    package.mkdir()
    (package / "__init__.py").write_text(initializer, encoding="utf-8")
    (package / "subject.py").write_text('__vstd_kinds__ = ("LEDGER",)\nclass Original: pass\n', encoding="utf-8")
    return root


@pytest.mark.parametrize("source", [
    'from importlib.resources import files\nresource = files("sample").joinpath("data.json")\n',
    'from importlib.resources import files as package_files\nresource = package_files("sample")\n',
    'from importlib.util import find_spec\nspec = find_spec("sample.subject")\n',
    'from importlib.util import find_spec as locate_spec\nspec = locate_spec("sample.subject")\n',
])
def test_importlib_leaf_readers_are_not_misbound_as_module_escapes(source: str) -> None:
    assert not has_dynamic_construction(ast.parse(source), closed_lazy=False)


@pytest.mark.parametrize("source", [
    'from importlib import import_module\nmodule = import_module(selected)\n',
    'from importlib.util import module_from_spec\nmodule = module_from_spec(spec)\n',
    'from importlib.metadata import entry_points\nplugin = entry_points()[0].load()\n',
    'from importlib.abc import Loader\nclass SubjectLoader(Loader):\n    pass\n',
])
def test_importlib_construction_and_loader_capabilities_remain_dynamic(source: str) -> None:
    assert has_dynamic_construction(ast.parse(source), closed_lazy=False)


def test_lazy_alias_is_owned_separately_and_carries_target_role(tmp_path: Path) -> None:
    root = repository(tmp_path)
    observed = discover(root)
    alias = next(row for row in observed["surfaces"] if row["surface_id"] == "python-export:sample/__init__.py:Public")
    assert alias["target_surface_id"] == "python:sample/subject.py:Original"
    assert alias["source_kinds"] == ["LEDGER"]
    assert alias["target_source_digest"] == next(row["sha256"] for row in observed["census"]["files"] if row["path"] == "sample/subject.py")
    assert not observed["gaps"]


def test_omitted_export_is_not_covered_by_its_file_or_target_definition(tmp_path: Path) -> None:
    root = repository(tmp_path)
    document = build_template(root)["manifest"]
    for row in document["objects"]:
        row["surfaces"] = [surface for surface in row["surfaces"] if not surface.startswith("python-export:")]
    save(root, document)
    result = assess(root)
    assert any(row["code"] == "NAMESPACE_SURFACE_UNCOVERED" and row["surface_id"] == "python-export:sample/__init__.py:Public"
               for row in result["findings"])


def test_literal_exports_include_reexports_and_constants_without_importing(tmp_path: Path) -> None:
    root = repository(tmp_path, 'from .subject import Original as Public\nVERSION = 1\n__all__ = ["Public", "VERSION"]\nraise RuntimeError("never import")\n')
    aliases = {row["surface_id"].rsplit(":", 1)[-1]: row for row in discover(root)["surfaces"] if row["form"] == "Export"}
    assert set(aliases) == {"Public", "VERSION"}
    assert aliases["Public"]["target_surface_id"] == "python:sample/subject.py:Original"
    assert aliases["VERSION"]["target_surface_id"] == "python-binding:sample/__init__.py:VERSION"


@pytest.mark.parametrize("change", [
    lambda text: text + '_LAZY_EXPORTS["Hidden"] = ("sample.subject", "Original")\n',
    lambda text: text + 'alias = _LAZY_EXPORTS\n',
    lambda text: text + 'def rewrite():\n    _LAZY_EXPORTS.clear()\n',
    lambda text: text.replace('return value', 'return object()'),
    lambda text: text.replace('def __getattr__(name):', '@decorate\ndef __getattr__(name):'),
    lambda text: text.replace('def __getattr__(name):', 'def __getattr__(name="Public"):'),
    lambda text: text + '__getattr__ = replacement\n',
    lambda text: text + 'globals()["hidden"] = object()\n',
    lambda text: text + 'list = custom\n',
    lambda text: text + '__all__.append("Hidden")\n',
    lambda text: text + 'exposed = __all__\n',
    lambda text: text.replace('__all__ =', 'exposed = __all__ ='),
    lambda text: text.replace('def __getattr__(name):', 'def __getattr__(name: _LAZY_EXPORTS.clear()):'),
    lambda text: text + 'def __dir__(arg=_LAZY_EXPORTS.clear()):\n    return sorted(set(globals()) | set(__all__))\n',
])
def test_dispatch_mutation_cannot_close_dynamic_coverage(tmp_path: Path, change: Callable[[str], str]) -> None:
    root = repository(tmp_path, change(DISPATCH))
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED" and row["path"] == "sample/__init__.py"
               for row in discover(root)["gaps"])


@pytest.mark.parametrize("initializer", [
    '__all__ = ["missing"]\n',
    '__all__ = ["x", "x"]\nx = 1\n',
    '__all__: list[str]\n',
    'if enabled:\n    __all__ = ["x"]\nx = 1\n',
    'x = 1\nif enabled:\n    x = 2\n__all__ = ["x"]\n',
    'from .subject import *\n__all__ = ["Original"]\n',
    DISPATCH.replace('"Original")}', '"Absent")}'),
    DISPATCH.replace('{"Public":', '{"Public": ("sample.subject", "Absent"), "Public":'),
])
def test_unresolved_exports_are_never_an_empty_success(tmp_path: Path, initializer: str) -> None:
    root = repository(tmp_path, initializer)
    assert any(row["code"] == "NAMESPACE_PYTHON_EXPORTS_UNRESOLVED" for row in discover(root)["gaps"])


def test_recursive_reexports_bind_terminal_source_and_detect_cycles(tmp_path: Path) -> None:
    root = repository(tmp_path, 'from .bridge import middle as Public\n__all__ = ["Public"]\n')
    bridge = root / "sample/bridge.py"
    bridge.write_text('from .subject import Original as middle\n', encoding="utf-8")
    observed = discover(root)
    alias = next(row for row in observed["surfaces"] if row["form"] == "Export")
    assert alias["target_surface_id"] == "python:sample/subject.py:Original"
    assert not observed["gaps"]
    bridge.write_text('from . import Public as middle\n', encoding="utf-8")
    assert any(row["code"] == "NAMESPACE_PYTHON_EXPORTS_UNRESOLVED" for row in discover(root)["gaps"])


def test_same_module_name_under_two_roots_is_not_guessed(tmp_path: Path) -> None:
    root = repository(tmp_path)
    duplicate = root / "other/sample"
    duplicate.mkdir(parents=True)
    (duplicate / "__init__.py").write_text("", encoding="utf-8")
    (duplicate / "subject.py").write_text("class Original: pass\n", encoding="utf-8")
    assert any(row["code"] == "NAMESPACE_PYTHON_EXPORTS_UNRESOLVED" for row in discover(root)["gaps"])


def test_namespace_child_beneath_regular_package_retains_qualified_name(tmp_path: Path) -> None:
    root = repository(tmp_path, DISPATCH.replace("sample.subject", "sample.inner.subject"))
    child = root / "sample/inner"
    child.mkdir()
    (child / "subject.py").write_text('class Original: pass\n', encoding="utf-8")
    observed = discover(root)
    alias = next(row for row in observed["surfaces"] if row["form"] == "Export")
    assert alias["target_surface_id"] == "python:sample/inner/subject.py:Original"
    assert not observed["gaps"]


def test_assignment_alias_cannot_erase_class_local_role(tmp_path: Path) -> None:
    root = repository(tmp_path, 'from .subject import Original\nPublic = Original\n__all__ = ["Public"]\n')
    (root / "sample/subject.py").write_text('class Original:\n    __vstd_kinds__ = ("LEDGER",)\n', encoding="utf-8")
    alias = next(row for row in discover(root)["surfaces"] if row["form"] == "Export")
    assert alias["source_kinds"] == ["LEDGER"]
    assert alias["target_surface_id"] == "python:sample/subject.py:Original"


@pytest.mark.parametrize("statement", ["Original = replacement()", "del Original", "class Original: pass", "from other import Original"])
def test_global_rebinding_prevents_unique_export_target(tmp_path: Path, statement: str) -> None:
    root = repository(tmp_path)
    (root / "sample/subject.py").write_text('class Original: pass\ndef replace():\n    global Original\n    ' + statement + '\n', encoding="utf-8")
    assert any(row["code"] == "NAMESPACE_PYTHON_EXPORTS_UNRESOLVED" for row in discover(root)["gaps"])


def test_global_read_and_nested_local_write_do_not_replace_module_binding(tmp_path: Path) -> None:
    root = repository(tmp_path)
    (root / "sample/subject.py").write_text('class Original: pass\ndef inspect():\n    global Original\n    def nested():\n        Original = 1\n    return Original\n', encoding="utf-8")
    observed = discover(root)
    assert not observed["gaps"]
    assert observed["export_bindings"][0]["target_surface_id"] == "python:sample/subject.py:Original"


def test_added_alias_breaks_old_manifest_coverage(tmp_path: Path) -> None:
    root = repository(tmp_path)
    document = build_template(root)["manifest"]
    save(root, deepcopy(document))
    (root / "sample/__init__.py").write_text(DISPATCH.replace('{"Public":', '{"New": ("sample.subject", "Original"), "Public":'), encoding="utf-8")
    report = assess(root)
    assert any(row["code"] == "NAMESPACE_SURFACE_UNCOVERED" and row["surface_id"] == "python-export:sample/__init__.py:New"
               for row in report["findings"])


def test_reconciliation_binds_alias_target_even_when_kinds_are_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from verifier.runtime import namespace_admission as admission
    from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest
    root = repository(tmp_path)
    save(root, build_template(root)["manifest"])
    original = admission._run_bounded_reconciler

    def changed(command: list[str], wire: bytes, **kwargs: Any) -> Any:
        if str(command[-1]).endswith("namespace_reconcile.mjs"):
            payload = json.loads(wire)
            next(row for row in payload["surfaces"] if row["form"] == "Export")["target_surface_id"] = "python:sample/subject.py:Different"
            wire = canonical_bytes(payload)
        return original(command, wire, **kwargs)

    baseline = assess(root)
    assert baseline["independent_reconciliation"]["status"] == "PASS"
    assert baseline["export_binding_digest"] == value_digest(baseline["export_bindings"])
    monkeypatch.setattr(admission, "_run_bounded_reconciler", changed)
    report = assess(root)
    assert report["independent_reconciliation"]["status"] == "FAIL"
