"""The polish mechanism digest binds every module a registered route can execute and the standard named for it.

Terminology: abstract syntax tree (AST); Secure Hash Algorithm 256-bit (SHA-256).
``verifier.runtime.polish.mechanism_digest`` is documented to bind the installed assessment code, the helpers it executes
and the specification. A module that the digest does not read can change without changing the digest that a polish
assessment records. The executed modules are found from the import statements of ``current_object_routes``, followed
through the ``verifier`` package and including imports inside functions, so a route added later is covered without
editing this file. A standard is the document in ``standard/`` named ``CURRENT_<MODULE>.md`` or ``<MODULE>.md`` for a module.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

from verifier.domains.contracts import current_object_routes
from verifier.runtime import polish

PACKAGE = Path(polish.__file__).parents[1]


def _module_file(name: str) -> Path | None:
    base = PACKAGE.joinpath(*name.split(".")[1:])
    if name != "verifier" and base.with_suffix(".py").is_file():
        return base.with_suffix(".py")
    return base / "__init__.py" if (base / "__init__.py").is_file() else None


def _imports(path: Path, name: str) -> set[str]:
    package = name.split(".") if path.name == "__init__.py" else name.split(".")[:-1]
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                module = ".".join(package[: len(package) - node.level + 1] + ([node.module] if node.module else []))
            found.add(module)
            found.update(f"{module}.{alias.name}" for alias in node.names)
    return {item for item in found if item == "verifier" or item.startswith("verifier.")}


def _executed_modules() -> dict[str, Path]:
    pending, seen = [current_object_routes.__name__], {}
    while pending:
        name = pending.pop()
        path = None if name in seen else _module_file(name)
        if path is not None:
            seen[name] = path
            pending.extend(_imports(path, name))
    return seen


def _standards(modules: dict[str, Path]) -> dict[str, Path]:
    found = {}
    for name in modules:
        leaf = name.rsplit(".", 1)[-1]
        for candidate in (f"CURRENT_{leaf.upper()}.md", f"{leaf.upper()}.md"):
            document = PACKAGE / "standard" / candidate
            if leaf != "__init__" and document.is_file():
                found[f"{name}:{candidate}"] = document
    return found


MODULES = _executed_modules()
STANDARDS = _standards(MODULES)


def _digest_with_changed_bytes(target: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    return polish.mechanism_digest()


def test_the_walk_reaches_the_known_executed_modules_and_every_route_target() -> None:
    for name in ("token_checks", "independence_checks", "certificate_dag", "sim_isolation", "object_grounding"):
        assert f"verifier.domains.contracts.{name}" in MODULES
    assert "verifier.core.checker" in MODULES and "verifier.domains.statics" in MODULES
    assert "verifier.domains.contracts.current_object_routes" in MODULES
    for route in current_object_routes._ROUTES.values():
        assert route.replay.__module__ in MODULES, route.replay.__module__
    assert any(key.endswith(":CURRENT_TOKEN_CHECKS.md") for key in STANDARDS)
    assert any(key.endswith(":SIM_ISOLATION.md") for key in STANDARDS)


def test_imports_inside_functions_and_relative_imports_are_followed(tmp_path: Path) -> None:
    module = tmp_path / "sample.py"
    module.write_text(
        "from . import sibling\n"
        "from .other import value\n"
        "import verifier.core.checker\n"
        "def later():\n"
        "    from verifier.domains import statics\n"
        "    import json\n",
        encoding="utf-8", newline="\n",
    )
    found = _imports(module, "verifier.domains.contracts.sample")
    assert {"verifier.domains.contracts.sibling", "verifier.domains.contracts.other",
            "verifier.core.checker", "verifier.domains.statics"} <= found
    assert "json" not in found
    initializer = tmp_path / "__init__.py"
    initializer.write_text("from . import helper\n", encoding="utf-8", newline="\n")
    assert "verifier.domains.contracts.helper" in _imports(initializer, "verifier.domains.contracts")


def test_a_file_the_routes_never_execute_leaves_the_digest_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    unrelated = PACKAGE / "runtime" / "quality_checks.py"
    assert unrelated.is_file() and "verifier.runtime.quality_checks" not in MODULES
    before = polish.mechanism_digest()
    assert _digest_with_changed_bytes(unrelated, monkeypatch) == before


@pytest.mark.parametrize("name", sorted(MODULES))
def test_the_digest_changes_when_an_executed_module_changes(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    before = polish.mechanism_digest()
    assert _digest_with_changed_bytes(MODULES[name], monkeypatch) != before, name


@pytest.mark.parametrize("key", sorted(STANDARDS))
def test_the_digest_changes_when_a_standard_of_an_executed_module_changes(key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    before = polish.mechanism_digest()
    assert _digest_with_changed_bytes(STANDARDS[key], monkeypatch) != before, key


def test_owner_hardware_eligibility_standard_changes_the_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    target = PACKAGE / "standard" / "CURRENT_OWNER_HARDWARE_ELIGIBILITY.md"
    assert target.is_file()
    before = polish.mechanism_digest()
    assert _digest_with_changed_bytes(target, monkeypatch) != before



@pytest.mark.parametrize("name", ["polish_requirements", "polish_inventory",
                                 "polish_inventory_authority", "polish_public_authority"])
def test_each_wrapper_binds_its_own_source_without_claiming_inner_scope(
    name: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper = importlib.import_module("verifier.runtime." + name)
    target = Path(wrapper.__file__)
    before, inner_before = wrapper.mechanism_digest(), polish.mechanism_digest()
    original = Path.read_bytes

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged wrapper dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert wrapper.mechanism_digest() != before
    assert polish.mechanism_digest() == inner_before
