"""Terminology: abstract syntax tree (AST).

Every `from verifier.<module> import <name>` statement in the shipped source must name something that
exists, including the statements inside function bodies that importing the package never executes. A
carried module that imports a helper from a module whose own change was not carried fails only when the
command that reaches that function runs, as an ImportError and not as a refusal. This test reads the
AST of every source file, imports the target module of each such statement and checks each name; the
same function is run on small packages that hold a missing name, a missing module and clean imports, so
a pass is not the absence of a finding by a function that cannot find anything."""

from __future__ import annotations

import ast
import importlib
import importlib.util
from pathlib import Path
import sys
from typing import Iterator

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"


def _is_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _runtime_imports(tree: ast.AST) -> Iterator[ast.ImportFrom]:
    """Yield each from-import that can run, leaving out the ones under `if TYPE_CHECKING:`."""
    skipped = {
        id(child)
        for node in ast.walk(tree)
        if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.dump(node.test)
        for child in ast.walk(node)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and id(node) not in skipped:
            yield node


def unresolved_imports(source: Path, package: str) -> list[str]:
    """Return one line per from-import of `package` in `source/package` that names a missing module or name."""
    problems: list[str] = []
    for path in sorted((source / package).rglob("*.py")):
        relative = path.relative_to(source)
        owner = list(relative.with_suffix("").parts)[:-1]  # the package that contains this file, __init__.py included
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in _runtime_imports(tree):
            if node.level:
                base = owner[: len(owner) - (node.level - 1)]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            if module.split(".")[0] != package:
                continue
            where = relative.as_posix() + ":" + str(node.lineno)
            try:
                imported = importlib.import_module(module)
            except ModuleNotFoundError as error:
                if error.name and error.name.split(".")[0] != package:
                    continue  # a third-party package that this environment does not have installed
                problems.append(where + ": module " + module + " does not exist")
                continue
            except Exception as error:  # a module of the package that fails on import is a finding too
                problems.append(where + ": module " + module + " does not import (" + type(error).__name__ + ")")
                continue
            for alias in node.names:
                if alias.name != "*" and not hasattr(imported, alias.name) and not _is_module(module + "." + alias.name):
                    problems.append(where + ": from " + module + " import " + alias.name)
    return problems


@pytest.fixture
def fixture_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Write a small package under tmp_path, make it importable and forget it afterwards."""
    created: list[str] = []

    def make(name: str, files: dict[str, str]) -> str:
        for relative, text in files.items():
            target = tmp_path / name / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
        monkeypatch.syspath_prepend(str(tmp_path))
        importlib.invalidate_caches()
        created.append(name)
        return name

    yield make
    for name in created:
        for loaded in [key for key in sys.modules if key == name or key.startswith(name + ".")]:
            del sys.modules[loaded]


def test_every_verifier_import_in_the_shipped_source_resolves() -> None:
    assert unresolved_imports(SOURCE, "verifier") == []


def test_a_function_level_import_of_a_missing_name_is_reported(tmp_path: Path, fixture_package) -> None:
    name = fixture_package("srcres_missing_name", {
        "__init__.py": "",
        "b.py": "present = 1\n",
        "a.py": "def reach():\n    from srcres_missing_name.b import absent\n    return absent\n",
    })
    assert unresolved_imports(tmp_path, name) == ["srcres_missing_name/a.py:2: from srcres_missing_name.b import absent"]


def test_an_import_of_a_missing_module_is_reported(tmp_path: Path, fixture_package) -> None:
    name = fixture_package("srcres_missing_module", {
        "__init__.py": "",
        "a.py": "from srcres_missing_module.nowhere import anything\n",
    })
    assert unresolved_imports(tmp_path, name) == ["srcres_missing_module/a.py:1: module srcres_missing_module.nowhere does not exist"]


def test_imports_that_resolve_are_not_reported(tmp_path: Path, fixture_package) -> None:
    name = fixture_package("srcres_clean", {
        "__init__.py": "",
        "b.py": "present = 1\n",
        "sub/__init__.py": "",
        "sub/c.py": "from .. import b\nfrom ..b import present\nfrom . import d\n",
        "sub/d.py": "value = 2\n",
        "a.py": (
            "from typing import TYPE_CHECKING\n"
            "from srcres_clean import b\n"
            "from srcres_clean.b import present\n"
            "from json import dumps\n"
            "if TYPE_CHECKING:\n"
            "    from srcres_clean.b import only_for_type_checkers\n"
            "def reach():\n"
            "    from srcres_clean.sub.d import value\n"
            "    return value\n"
        ),
    })
    assert unresolved_imports(tmp_path, name) == []
