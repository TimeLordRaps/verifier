"""Terminology: abstract syntax tree (AST).

Every `from verifier.<module> import <name>` statement in the shipped source must name something that
exists, including statements inside function bodies. This test resolves modules and their declared
top-level names from abstract syntax trees (ASTs) without importing repository code. The same resolver
is run on small packages with a missing name, a missing module and clean imports, so a pass is not the
absence of a finding by a function that cannot find anything."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"


def _module_file(source: Path, name: str) -> Path | None:
    stem = source.joinpath(*name.split("."))
    candidates = [path for path in (stem.with_suffix(".py"), stem / "__init__.py")
                  if path.is_file()]
    if stem.is_dir() and not (stem / "__init__.py").exists():
        candidates.append(stem)
    return candidates[0] if len(candidates) == 1 else None


def _declared_names(path: Path) -> set[str]:
    if path.is_dir():
        return {child.stem if child.is_file() else child.name for child in path.iterdir()
                if (child.is_file() and child.suffix == ".py") or child.is_dir()}
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    lazy_names: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(statement.name)
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split(".")[0]
                         for alias in statement.names if alias.name != "*")
        elif isinstance(statement, ast.Assign):
            names.update(target.id for target in statement.targets if isinstance(target, ast.Name))
            if (len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name)
                    and statement.targets[0].id == "_LAZY_EXPORTS"
                    and isinstance(statement.value, ast.Dict)):
                lazy_names = {key.value for key in statement.value.keys
                              if isinstance(key, ast.Constant) and type(key.value) is str}
            if (len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name)
                    and statement.targets[0].id == "__all__"
                    and isinstance(statement.value, (ast.List, ast.Tuple))):
                names.update(item.value for item in statement.value.elts
                             if isinstance(item, ast.Constant) and type(item.value) is str)
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None \
                and isinstance(statement.target, ast.Name):
            names.add(statement.target.id)
    names.update(lazy_names)
    return names


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
            target = _module_file(source, module)
            if target is None:
                problems.append(where + ": module " + module + " does not exist")
                continue
            declared = _declared_names(target)
            for alias in node.names:
                if (alias.name != "*" and alias.name not in declared
                        and _module_file(source, module + "." + alias.name) is None):
                    problems.append(where + ": from " + module + " import " + alias.name)
    return problems


@pytest.fixture
def fixture_package(tmp_path: Path):
    """Write a small package under tmp_path for non-executing resolution."""
    def make(name: str, files: dict[str, str]) -> str:
        for relative, text in files.items():
            target = tmp_path / name / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
        return name
    return make


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
