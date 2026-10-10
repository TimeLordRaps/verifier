"""A test module that needs an optional extra must skip, not break the run, where the extra is absent.

Terminology: abstract syntax tree (AST); continuous integration (CI). The CI jobs named ``base`` and ``coverage`` install
only the ``test`` extra of ``pyproject.toml``, so the packages of every other extra (``cryptography``, ``cbor2``,
``scitt_cose``, ``llguidance``, ``torch`` and ``twine``) and ``transformers`` are absent there, while a developer
environment usually has some of them. A test module that imports one of them while it is being imported, without a guard,
is a collection error there, and one collection error interrupts the whole pytest run before any test starts (exit
status 2). A test that imports one inside a function, without a guard, fails there instead. The first kind is found by
collecting the modules that can import an extra in a child process that refuses those imports, the way those two jobs see
them; this module is collected beside them as a control that needs no extra, because a run in which every selected module
skips itself collects nothing and pytest then exits with status 5, which must not pass for a clean run. The second kind is
found by reading each function that imports an extra for the ``pytest.importorskip`` that must precede the import.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import preflight  # noqa: E402

TESTS = Path(__file__).resolve().parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
# A distribution whose import name differs from its normalised distribution name.
IMPORT_NAME = {"scitt-cose": "scitt_cose", "pyyaml": "yaml"}
# The logits-constraints CI job installs this one outside any extra.
OUTSIDE_EXTRAS = frozenset({"transformers"})
# This module needs no extra: it is collected beside the selected modules as the control that proves collection ran.
CONTROL = Path(__file__).resolve()
COLLECTION_ERROR = re.compile(r"^_+ ERROR collecting (\S+) _+$", re.MULTILINE)
MODULE_REPORT = re.compile(r"^COLLECTED_MODULE (\w+) (\S+)$", re.MULTILINE)
ITEM_REPORT = re.compile(r"^COLLECTED_ITEM (\S+)$", re.MULTILINE)
HANDLED = frozenset({"ImportError", "ModuleNotFoundError", "Exception", "BaseException"})

# Runs in the child process. It refuses the named imports once the session has started (so a plugin that needs one at
# startup is unaffected), purges any copy already loaded, stops the run if a refused name still imports, and reports
# the outcome of every module and the node identifier of every item that collection produced.
CHILD = """
import importlib
import importlib.abc
import sys

import pytest

refused = frozenset(sys.argv[1].split(","))


class Refuse(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in refused:
            raise ModuleNotFoundError("No module named " + repr(name), name=name)
        return None


class Session:
    def pytest_sessionstart(self, session):
        for loaded in [name for name in sys.modules if name.split(".")[0] in refused]:
            del sys.modules[loaded]
        sys.meta_path.insert(0, Refuse())
        for name in sorted(refused):
            try:
                importlib.import_module(name)
            except ModuleNotFoundError:
                continue
            pytest.exit("the child process still imports " + name, returncode=97)

    def pytest_collectreport(self, report):
        if report.nodeid.endswith(".py"):
            print("COLLECTED_MODULE " + report.outcome + " " + report.nodeid, flush=True)

    def pytest_collection_modifyitems(self, session, config, items):
        for item in items:
            print("COLLECTED_ITEM " + item.nodeid, flush=True)


raise SystemExit(pytest.main(sys.argv[2:], plugins=[Session()]))
"""


def _normal(distribution: str) -> str:
    return re.sub(r"[-_.]+", "-", distribution).lower()


def declared_extras(text: str) -> dict[str, list[str]]:
    """Map each optional-dependency group of ``pyproject.toml`` to its distribution names."""
    block = re.search(r"^\[project\.optional-dependencies\]\n(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
    assert block is not None, "pyproject.toml declares no optional dependencies"
    groups = re.findall(r"^([A-Za-z0-9_-]+)\s*=\s*\[(.*?)\]", block.group(1), re.MULTILINE | re.DOTALL)
    return {name: [_normal(item) for item in re.findall(r'"([A-Za-z0-9_.-]+)', body)] for name, body in groups}


def optional_import_names(text: str) -> frozenset[str]:
    """Import names of the optional packages that the ``test`` extra does not install."""
    extras = declared_extras(text)
    installed = set(extras["test"])
    optional = {item for items in extras.values() for item in items} - installed
    return frozenset(IMPORT_NAME.get(item, item.replace("-", "_")) for item in optional) | OUTSIDE_EXTRAS


def import_time_imports(tree: ast.AST) -> set[str]:
    """Top-level names imported by statements that run when the module is imported (not inside a function body)."""
    found: set[str] = set()
    pending = list(ast.iter_child_nodes(tree))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
        pending.extend(ast.iter_child_nodes(node))
    return found


def modules_that_can_import_an_extra(directory: Path, names: frozenset[str]) -> list[Path]:
    """Test modules that import a named package at import time, directly or through a module of the same directory."""
    imports = {path.stem: import_time_imports(ast.parse(path.read_text(encoding="utf-8"))) for path in sorted(directory.glob("*.py"))}
    selected = {stem for stem, found in imports.items() if found & names}
    grown = True
    while grown:
        grown = False
        for stem, found in imports.items():
            if stem not in selected and found & selected:
                selected.add(stem)
                grown = True
    return [directory / f"{stem}.py" for stem in sorted(selected) if stem.startswith("test_")]


def _requested_by_importorskip(call: ast.AST) -> str | None:
    """The top-level package name that a ``pytest.importorskip("<package>...")`` call asks for, if it is one."""
    if not isinstance(call, ast.Call) or not call.args:
        return None
    function = call.func
    called = function.attr if isinstance(function, ast.Attribute) else function.id if isinstance(function, ast.Name) else None
    first = call.args[0]
    if called != "importorskip" or not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return None
    return first.value.split(".")[0]


def _imports_package(node: ast.AST, names: frozenset[str]) -> str | None:
    """The named top-level package that an import statement brings in, if it does."""
    if isinstance(node, ast.Import):
        return next((alias.name.split(".")[0] for alias in node.names if alias.name.split(".")[0] in names), None)
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module and node.module.split(".")[0] in names:
        return node.module.split(".")[0]
    return None


def _handles_import_error(node: ast.Try) -> bool:
    for handler in node.handlers:
        caught = handler.type
        if caught is None:
            return True
        members = caught.elts if isinstance(caught, ast.Tuple) else [caught]
        if any(isinstance(member, ast.Name) and member.id in HANDLED for member in members):
            return True
    return False


def unguarded_function_imports(tree: ast.AST, names: frozenset[str]) -> list[tuple[str, int]]:
    """Function name and line of each function-level import of a named package that nothing guards.

    An import is guarded by a ``pytest.importorskip`` of the same package before it in the same or an enclosing function,
    by one at module level, or by a ``try`` statement that handles ``ImportError``.
    """
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def enclosing(node: ast.AST) -> list[ast.AST]:
        chain, current = [], parents.get(node)
        while current is not None:
            chain.append(current)
            current = parents.get(current)
        return chain

    module_guards = {package for call in ast.walk(tree) if (package := _requested_by_importorskip(call))
                     and not any(isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) for item in enclosing(call))}
    offenders: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        package = _imports_package(node, names)
        if package is None or package in module_guards:
            continue
        chain = enclosing(node)
        functions = [item for item in chain if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if not functions:
            continue
        if any(isinstance(item, ast.Try) and _handles_import_error(item) for item in chain):
            continue
        if any(isinstance(call, ast.Call) and _requested_by_importorskip(call) == package and call.lineno < node.lineno
               for function in functions for call in ast.walk(function)):
            continue
        offenders.append((functions[0].name, node.lineno))
    return sorted(offenders, key=lambda item: item[1])


def collect_without(names: frozenset[str], *paths: Path, cwd: Path) -> tuple[int, str]:
    """Collect the given test modules in a child process that refuses the named imports; return its exit status and output."""
    environment = {key: value for key, value in os.environ.items() if key != "PYTEST_ADDOPTS"}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", CHILD, ",".join(sorted(names)), "--collect-only", "-p", "no:cacheprovider", "-rs",
         *map(str, paths)],
        cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45, env=environment,
    )
    return result.returncode, result.stdout + result.stderr


def collection_problems(status: int, output: str, modules: list[Path], control: Path) -> list[str]:
    """Why a collection run of ``modules`` beside the dependency-free ``control`` module cannot be accepted; empty if it can.

    The run is accepted only if the child exited with status 0, visited every module and found none broken, collected
    exactly the tests that ``control`` defines, and skipped at least one module for an absent extra with a reason that
    docs/TEST_SKIP_RUBRIC.md classifies.
    """
    problems: list[str] = []
    visited = {Path(node).name: outcome for outcome, node in MODULE_REPORT.findall(output)}
    for path in modules + [control]:
        if path.name not in visited:
            problems.append(f"{path.name} was never visited by the child process")
    broken = {Path(item).name for item in COLLECTION_ERROR.findall(output)} | {name for name, outcome in visited.items() if outcome == "failed"}
    if broken:
        problems.append("these modules fail at collection: " + ", ".join(sorted(broken)))
    expected = {node.name for node in ast.parse(control.read_text(encoding="utf-8")).body
                if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")}
    collected = {item.split("::", 1)[1].split("[", 1)[0] for item in ITEM_REPORT.findall(output)
                 if "::" in item and Path(item.split("::", 1)[0]).name == control.name}
    if not expected or collected != expected:
        problems.append(f"the control module {control.name} collected {sorted(collected)} where it defines {sorted(expected)}")
    if status != 0:
        problems.append(f"the child process exited with status {status}, not 0")
    ok, counts, unclassified = preflight.audit_test_skips(output)
    if not ok:
        problems.append(f"{len(unclassified)} skip reason(s) are not classified by docs/TEST_SKIP_RUBRIC.md")
    if not counts["OPTIONAL_DEPENDENCY_ABSENT"]:
        problems.append("no module skipped for an absent extra, so the child process did not refuse the extras")
    return problems


def _write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def test_the_refused_names_are_the_optional_extras_that_the_test_extra_does_not_install() -> None:
    names = optional_import_names(PYPROJECT.read_text(encoding="utf-8"))
    assert {"cryptography", "cbor2", "scitt_cose", "llguidance", "torch", "transformers", "twine"} <= names
    assert "build" not in names
    assert not names & {"yaml", "jsonschema", "pytest", "pytest_timeout", "coverage"}
    assert all(name.isidentifier() for name in names)


def test_a_new_optional_extra_is_refused_without_editing_the_test() -> None:
    text = '[project.optional-dependencies]\ntest = ["pytest>=8.0", "pyyaml>=6.0"]\nyaml = ["pyyaml>=6.0"]\nfast = ["some-fast-lib==1.0"]\n[tool.other]\n'
    assert optional_import_names(text) == frozenset({"some_fast_lib"}) | OUTSIDE_EXTRAS


def test_selection_follows_import_time_imports_and_helper_chains(tmp_path: Path) -> None:
    _write(tmp_path, "test_direct.py", "import cryptography\n")
    _write(tmp_path, "test_in_class.py", "class Holder:\n    import torch\n")
    _write(tmp_path, "test_in_conditional.py", "try:\n    import cbor2\nexcept ImportError:\n    cbor2 = None\n")
    _write(tmp_path, "test_in_function.py", "def helper():\n    import cryptography\n")
    _write(tmp_path, "test_relative_name_only.py", "from . import cryptography_helpers\n")
    _write(tmp_path, "helper_module.py", "from cryptography.hazmat import primitives\n")
    _write(tmp_path, "test_through_helper.py", "from helper_module import primitives\n")
    _write(tmp_path, "test_plain.py", "import json\n")
    selected = {path.name for path in modules_that_can_import_an_extra(tmp_path, frozenset({"cryptography", "torch", "cbor2"}))}
    assert selected == {"test_direct.py", "test_in_class.py", "test_in_conditional.py", "test_through_helper.py"}


def test_the_child_distinguishes_an_unguarded_import_from_a_guarded_one(tmp_path: Path) -> None:
    refused = frozenset({"cryptography"})
    reason = "OPTIONAL_DEPENDENCY_ABSENT: seal extra (cryptography); exercised by the platform-python-contracts workflow job"
    plain = _write(tmp_path, "test_plain.py", "def test_plain():\n    assert True\n")
    unguarded = _write(tmp_path, "test_unguarded.py", "import cryptography\n\n\ndef test_unguarded():\n    assert cryptography\n")
    guarded = _write(
        tmp_path, "test_guarded.py",
        "import pytest\n\npytest.importorskip('cryptography', reason=" + repr(reason) + ")\nimport cryptography\n\n\n"
        "def test_guarded():\n    assert cryptography\n",
    )
    status, output = collect_without(refused, plain, unguarded, cwd=tmp_path)
    assert status == 2
    assert COLLECTION_ERROR.findall(output) == ["test_unguarded.py"]
    assert any("test_unguarded.py" in item for item in collection_problems(status, output, [unguarded], plain))
    status, output = collect_without(refused, plain, guarded, cwd=tmp_path)
    assert status == 0
    assert COLLECTION_ERROR.findall(output) == []
    assert sorted(ITEM_REPORT.findall(output)) == ["test_plain.py::test_plain"]
    ok, counts, unclassified = preflight.audit_test_skips(output)
    assert ok and not unclassified
    assert counts["OPTIONAL_DEPENDENCY_ABSENT"] == 1
    assert collection_problems(status, output, [guarded], plain) == []


def test_a_run_in_which_every_selected_module_skips_is_not_a_clean_run_without_the_control(tmp_path: Path) -> None:
    refused = frozenset({"cryptography"})
    reason = "OPTIONAL_DEPENDENCY_ABSENT: seal extra (cryptography); exercised by the platform-python-contracts workflow job"
    plain = _write(tmp_path, "test_plain.py", "def test_plain():\n    assert True\n")
    guarded = _write(
        tmp_path, "test_guarded.py",
        "import pytest\n\npytest.importorskip('cryptography', reason=" + repr(reason) + ")\nimport cryptography\n\n\n"
        "def test_guarded():\n    assert cryptography\n",
    )
    status, output = collect_without(refused, guarded, cwd=tmp_path)
    assert status == 5, "pytest reports no tests collected when every module skips itself"
    problems = collection_problems(status, output, [guarded], plain)
    assert any("test_plain.py was never visited" in item for item in problems)
    assert any("status 5" in item for item in problems)


def test_the_collection_judgement_refuses_each_way_a_run_can_be_vacuous_or_broken(tmp_path: Path) -> None:
    control = _write(tmp_path, "test_control.py", "def test_first():\n    pass\n\n\ndef test_second():\n    pass\n")
    guarded = tmp_path / "test_guarded.py"
    other = tmp_path / "test_other.py"
    visits = "COLLECTED_MODULE skipped test_guarded.py\nCOLLECTED_MODULE passed test_control.py\n"
    items = "COLLECTED_ITEM test_control.py::test_first\nCOLLECTED_ITEM test_control.py::test_second\n"
    skip = "SKIPPED [1] test_guarded.py:3: OPTIONAL_DEPENDENCY_ABSENT: seal extra (cryptography)\n"
    healthy = visits + items + skip
    assert collection_problems(0, healthy, [guarded], control) == []
    cases = [
        ("status 5", 5, healthy, [guarded]),
        ("status 2", 2, healthy, [guarded]),
        ("test_other.py was never visited", 0, healthy, [guarded, other]),
        ("test_control.py was never visited", 0, healthy.replace("COLLECTED_MODULE passed test_control.py\n", ""), [guarded]),
        ("collected ['test_first']", 0, healthy.replace("COLLECTED_ITEM test_control.py::test_second\n", ""), [guarded]),
        ("collected []", 0, visits + skip, [guarded]),
        ("fail at collection: test_guarded.py", 0, healthy.replace("COLLECTED_MODULE skipped", "COLLECTED_MODULE failed"), [guarded]),
        ("fail at collection: test_guarded.py", 0, healthy + "_______ ERROR collecting test_guarded.py _______\n", [guarded]),
        ("not classified", 0, healthy.replace("OPTIONAL_DEPENDENCY_ABSENT: seal extra (cryptography)", "no reason given"), [guarded]),
        ("did not refuse the extras", 0, healthy.replace(skip, ""), [guarded]),
    ]
    for fragment, status, output, modules in cases:
        problems = collection_problems(status, output, modules, control)
        assert any(fragment in item for item in problems), (fragment, problems)


def test_every_module_that_can_import_an_extra_collects_where_the_extras_are_absent() -> None:
    names = optional_import_names(PYPROJECT.read_text(encoding="utf-8"))
    modules = modules_that_can_import_an_extra(TESTS, names)
    assert modules, "no test module imports an optional extra, so the selection is vacuous"
    assert CONTROL not in modules, "the control module imports an optional extra, so it cannot show that collection ran"
    status, output = collect_without(names, *modules, CONTROL, cwd=REPO_ROOT)
    problems = collection_problems(status, output, modules, CONTROL)
    assert not problems, (
        "collection where the optional extras are absent, as in the base and coverage CI jobs, is not clean: " + "; ".join(problems)
        + ". Guard each module that needs an extra with pytest.importorskip(..., reason='OPTIONAL_DEPENDENCY_ABSENT: ...') "
        "before the import."
    )


def test_the_function_rule_separates_guarded_from_unguarded_imports() -> None:
    names = frozenset({"cryptography", "torch"})

    def flagged(source: str) -> list[tuple[str, int]]:
        return unguarded_function_imports(ast.parse(source), names)

    assert flagged("def helper():\n    import cryptography\n") == [("helper", 2)]
    assert flagged("def helper():\n    from cryptography.hazmat import primitives\n") == [("helper", 2)]
    assert flagged("import pytest\n\n\ndef helper():\n    import cryptography\n    pytest.importorskip('cryptography')\n") == [("helper", 5)]
    assert flagged("import pytest\n\n\ndef helper():\n    pytest.importorskip('cryptography.hazmat.primitives')\n    import cryptography\n") == []
    assert flagged("import pytest\n\n\ndef helper():\n    pytest.importorskip('torch')\n    import cryptography\n") == [("helper", 6)]
    assert flagged("import pytest\n\npytest.importorskip('cryptography')\n\n\ndef helper():\n    import cryptography\n") == []
    assert flagged("def helper():\n    try:\n        import cryptography\n    except ImportError:\n        cryptography = None\n") == []
    assert flagged("def helper():\n    try:\n        import cryptography\n    except ValueError:\n        cryptography = None\n") == [("helper", 3)]
    assert flagged("import pytest\n\n\ndef outer():\n    pytest.importorskip('cryptography')\n\n    def inner():\n        import cryptography\n") == []
    assert flagged("class Holder:\n    def method(self):\n        import torch\n") == [("method", 3)]
    assert flagged("def helper():\n    import json\n    from . import cryptography\n") == []


def test_every_function_level_import_of_an_extra_is_guarded() -> None:
    names = optional_import_names(PYPROJECT.read_text(encoding="utf-8"))
    offenders = [
        f"{path.name}:{line} ({function})"
        for path in sorted(TESTS.glob("*.py"))
        for function, line in unguarded_function_imports(ast.parse(path.read_text(encoding="utf-8")), names)
    ]
    assert not offenders, (
        "these functions import an optional extra without a preceding pytest.importorskip, so they fail instead of skipping "
        "where the extra is absent: " + ", ".join(offenders)
    )
