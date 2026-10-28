"""A mandatory test dependency must fail collection when it is absent, never skip.

Terminology: abstract syntax tree (AST); continuous integration (CI); Python Package Index (PyPI) distribution names. The ``test`` extra of
``pyproject.toml`` is installed by every CI job that runs the base test suite, so the distributions it declares are present
wherever those jobs run. ``pytest.importorskip`` of one of them would turn an absent package into a silent skip. Packages that
only an optional extra declares are the business of ``test_optional_dependency_collection.py``. ``referencing`` and
``packaging`` are not named by the ``test`` extra, but ``jsonschema`` and ``pytest`` require them unconditionally, so they are
mandatory as well.
"""

from __future__ import annotations

import ast
import importlib.metadata
from pathlib import Path
import re

from test_optional_dependency_collection import IMPORT_NAME, declared_extras

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
# Mandatory distributions that the ``test`` extra does not name, each with the declared package that requires it.
REQUIRED_BY = {"referencing": "jsonschema", "packaging": "pytest"}


def _normal(distribution: str) -> str:
    return re.sub(r"[-_.]+", "-", distribution).lower()


def mandatory_import_names(text: str) -> frozenset[str]:
    """Import names of the distributions that the ``test`` extra declares, and of those it requires without naming them."""
    named = {IMPORT_NAME.get(item, item.replace("-", "_")) for item in declared_extras(text)["test"]}
    return frozenset(named | set(REQUIRED_BY))


def declared_import_names(text: str) -> frozenset[str]:
    """Import names of every distribution that any optional-dependency group of ``pyproject.toml`` declares, plus the mandatory ones."""
    declared = {IMPORT_NAME.get(item, item.replace("-", "_")) for items in declared_extras(text).values() for item in items}
    return frozenset(declared | mandatory_import_names(text))


def importorskip_calls(tree: ast.AST) -> list[tuple[int, str | None]]:
    """Line and top-level package of each ``importorskip`` call; the package is None when the name is not a string literal."""
    found: list[tuple[int, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        called = function.attr if isinstance(function, ast.Attribute) else function.id if isinstance(function, ast.Name) else None
        if called != "importorskip":
            continue
        named = node.args[0] if node.args else next((item.value for item in node.keywords if item.arg == "modname"), None)
        if isinstance(named, ast.Constant) and isinstance(named.value, str):
            found.append((node.lineno, named.value.split(".")[0]))
        else:
            found.append((node.lineno, None))
    return found


def suppressed_mandatory(tree: ast.AST, mandatory: frozenset[str]) -> list[tuple[int, str]]:
    """Line and package of each ``importorskip`` call that names a mandatory package."""
    return [(line, package) for line, package in importorskip_calls(tree) if package in mandatory]


def undeclared_importorskips(tree: ast.AST, declared: frozenset[str]) -> list[tuple[int, str]]:
    """Line and package of each ``importorskip`` call that names a package no optional-dependency group or mandatory list declares."""
    return [(line, package) for line, package in importorskip_calls(tree) if package is not None and package not in declared]


def unclassifiable_importorskips(tree: ast.AST) -> list[int]:
    """Lines of ``importorskip`` calls whose package name is not a string literal, so no rule can see what they skip."""
    return [line for line, package in importorskip_calls(tree) if package is None]


def test_the_mandatory_names_are_the_test_extra_and_the_packages_it_requires() -> None:
    names = mandatory_import_names(PYPROJECT.read_text(encoding="utf-8"))
    assert {"jsonschema", "yaml", "pytest", "pytest_timeout", "coverage", "build", "referencing", "packaging"} <= names
    assert not names & {"cryptography", "cbor2", "scitt_cose", "llguidance", "torch", "transformers", "twine"}


def test_the_unnamed_mandatory_packages_are_unconditional_requirements_of_the_named_ones() -> None:
    for dependency, parent in REQUIRED_BY.items():
        unconditional = [
            requirement for requirement in importlib.metadata.requires(parent) or [] if "extra ==" not in requirement
        ]
        names = {_normal(re.split(r"[\s;<>=!~\[(]", requirement, maxsplit=1)[0]) for requirement in unconditional}
        assert _normal(dependency) in names, (dependency, parent)


def test_the_rule_recognises_each_spelling_of_importorskip() -> None:
    mandatory = frozenset({"jsonschema", "yaml", "referencing", "packaging"})

    def flagged(source: str) -> list[tuple[int, str]]:
        return suppressed_mandatory(ast.parse(source), mandatory)

    assert flagged("import pytest\npytest.importorskip('jsonschema')\n") == [(2, "jsonschema")]
    assert flagged("from pytest import importorskip\nimportorskip('referencing.jsonschema')\n") == [(2, "referencing")]
    assert flagged("import pytest\n\n\ndef helper():\n    return pytest.importorskip('yaml', reason='r')\n") == [(5, "yaml")]
    assert flagged("import pytest\npytest.importorskip(modname='packaging')\n") == [(2, "packaging")]
    assert flagged("import pytest\npytest.importorskip('cryptography')\n") == []
    assert flagged("import pytest\npytest.importorskip('jsonschemas')\n") == []
    assert unclassifiable_importorskips(ast.parse("import pytest\nname = 'yaml'\npytest.importorskip(name)\n")) == [3]


def test_no_test_module_skips_a_mandatory_package_with_importorskip() -> None:
    mandatory = mandatory_import_names(PYPROJECT.read_text(encoding="utf-8"))
    suppressed = [
        f"{path.relative_to(TESTS)}:{line} ({package})"
        for path in sorted(TESTS.rglob("*.py"))
        for line, package in suppressed_mandatory(ast.parse(path.read_text(encoding="utf-8")), mandatory)
    ]
    assert not suppressed, (
        "these tests skip a mandatory package instead of failing when it is absent; use a normal import: " + ", ".join(suppressed)
    )


def test_the_undeclared_rule_flags_a_package_no_extra_declares() -> None:
    declared = declared_import_names(PYPROJECT.read_text(encoding="utf-8"))
    assert {"transformers", "cryptography", "jsonschema", "packaging"} <= declared
    assert undeclared_importorskips(ast.parse("import pytest\npytest.importorskip('pip._internal.utils.unpacking')\n"), declared) == [(2, "pip")]
    assert undeclared_importorskips(ast.parse("import pytest\npytest.importorskip('transformers')\n"), declared) == []
    assert undeclared_importorskips(ast.parse("import pytest\nname = 'pip'\npytest.importorskip(name)\n"), declared) == []


def test_every_importorskip_names_a_package_that_pyproject_declares() -> None:
    declared = declared_import_names(PYPROJECT.read_text(encoding="utf-8"))
    undeclared = [
        f"{path.relative_to(TESTS)}:{line} ({package})"
        for path in sorted(TESTS.rglob("*.py"))
        for line, package in undeclared_importorskips(ast.parse(path.read_text(encoding="utf-8")), declared)
    ]
    assert not undeclared, (
        "these importorskip calls name a package that no optional-dependency group declares, so the skip has no declared extra: "
        + ", ".join(undeclared)
    )


def test_every_importorskip_names_its_package_as_a_literal() -> None:
    unclassified = [
        f"{path.relative_to(TESTS)}:{line}"
        for path in sorted(TESTS.rglob("*.py"))
        for line in unclassifiable_importorskips(ast.parse(path.read_text(encoding="utf-8")))
    ]
    assert not unclassified, "these importorskip calls name no literal package, so the mandatory rule cannot see them: " + ", ".join(unclassified)
