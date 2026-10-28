"""Source-bound local imports for Verifier Standard (VSTD) discovery.

The adapter reads abstract syntax trees and current Git-census bytes only. It
never imports the subject or treats an arbitrary loader as a local source edge.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from verifier.runtime.namespace_discovery import discover


TARGET = 'def public():\n    return "observed"\n'


def repository(root: Path, source: str, *, track_target: bool = True,
               target_source: str = TARGET) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "loader.py").write_text(source, encoding="utf-8")
    (root / "target.py").write_text(target_source, encoding="utf-8")
    selected = ["loader.py", *(("target.py",) if track_target else ())]
    subprocess.run(["git", "add", "--", *selected], cwd=root, check=True)
    return root


DERIVED = '''from importlib import util
from pathlib import Path
def run():
    target = Path(__file__).resolve().parent / "target.py"
    spec = util.spec_from_file_location("bounded_target", target)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.public()
'''

LITERAL = '''from importlib.util import module_from_spec, spec_from_file_location
def run():
    spec = spec_from_file_location("bounded_target", "target.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("unavailable")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.public()
'''

BOUNDED_REGISTRY = '''import sys
from importlib import util
def run():
    spec = util.spec_from_file_location("bounded_target", "target.py")
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    if "bounded_target" in sys.modules:
        raise RuntimeError("module name already present")
    sys.modules["bounded_target"] = module
    try:
        spec.loader.exec_module(module)
        return module.public()
    finally:
        del sys.modules["bounded_target"]
'''

HELD_CHECKER_WORKER = '''from __future__ import annotations
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

def _safe_checker_path(source_root: Path, relative: Any) -> Path:
    if type(relative) is not str or not relative.startswith("verifier/runtime/"):
        raise ValueError("checker source coordinate invalid")
    candidate = (source_root / Path(*relative.split("/"))).resolve(strict=True)
    if (
        candidate.suffix != ".py"
        or not candidate.is_relative_to(source_root)
        or candidate.parent != source_root / "verifier" / "runtime"
    ):
        raise ValueError("checker source coordinate invalid")
    return candidate

def _load_held_checker(path: Path, raw: bytes) -> ModuleType:
    """Compile the held source bytes without consulting a bytecode cache."""

    name = "verifier.runtime." + path.stem
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = "verifier.runtime"
    sys.modules[name] = module
    code = compile(
        raw,
        str(path),
        "exec",
        dont_inherit=True,
        optimize=sys.flags.optimize,
    )
    exec(code, module.__dict__)
    return module
'''

ISOLATED_TEST_WORKER = '''def _worker(adapter):
    exec(compile(adapter.WORKER, "<vstd-worker>", "exec"), {"__name__": "__main__"})
'''

GENERATED_CHECKER_TEST = '''from __future__ import annotations
import importlib.util
from pathlib import Path
import sys
from types import ModuleType

def _fixture_module(path: Path, source: str) -> ModuleType:
    module = ModuleType("verifier.runtime.fixture_checker_execution")
    module.__file__ = str(path)
    module.__package__ = "verifier.runtime"
    exec(
        compile(
            source,
            str(path),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        ),
        module.__dict__,
    )
    return module

def _normally_imported_fixture_module(path: Path) -> ModuleType:
    """Load source through Python's ordinary source loader, without caller flags."""

    name = "verifier.runtime.fixture_checker_execution"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
'''


def held_checker_repository(root: Path, source: str = HELD_CHECKER_WORKER) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    runtime = root / "src" / "verifier" / "runtime"
    runtime.mkdir(parents=True)
    (runtime / "package_checker_worker.py").write_text(source, encoding="utf-8")
    (runtime / "accepted_checker.py").write_text(
        "ADAPTER = 'accepted-1'\n"
        "CHECKER_CONTRACT = 'observations-only'\n"
        "def check_observations(coordinate, observed): return True\n",
        encoding="utf-8",
    )
    (runtime / "ordinary.py").write_text("def helper(): return 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", "src"], cwd=root, check=True)
    return root


def isolated_test_worker_repository(
    root: Path, source: str = ISOLATED_TEST_WORKER,
) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    tests = root / "tests"
    target = root / "extensions" / "languages" / "src" / "vstd_languages"
    tests.mkdir(parents=True)
    target.mkdir(parents=True)
    (tests / "test_native_language_top24_adapters.py").write_text(
        source, encoding="utf-8",
    )
    (target / "__init__.py").write_text(
        'WORKER = "def bounded(): return True\\n"\n', encoding="utf-8",
    )
    subprocess.run(["git", "add", "--", "tests", "extensions"], cwd=root, check=True)
    return root


def generated_checker_test_repository(
    root: Path, source: str = GENERATED_CHECKER_TEST,
) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    tests = root / "tests"
    tests.mkdir(parents=True)
    (tests / "test_package_checker_source_binding.py").write_text(
        source, encoding="utf-8",
    )
    subprocess.run(["git", "add", "--", "tests"], cwd=root, check=True)
    return root


def test_isolated_test_worker_binds_current_worker_attribute(tmp_path: Path) -> None:
    observed = discover(isolated_test_worker_repository(tmp_path))
    binding = next(
        row for row in observed["surfaces"]
        if row.get("binding_scope")
        == "DECLARED_DIGEST_BOUND_ISOLATED_TEST_WORKER_SOURCE_NOT_RUNTIME_INTERFACE"
    )
    assert binding["target_path"] == (
        "extensions/languages/src/vstd_languages/__init__.py"
    )
    assert binding["target_attribute_names"] == ["WORKER"]
    assert not any(
        row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
        for row in observed["gaps"]
    )


def test_isolated_test_worker_rejects_an_extra_execution_site(tmp_path: Path) -> None:
    observed = discover(
        isolated_test_worker_repository(
            tmp_path, ISOLATED_TEST_WORKER + "\nexec(selected)\n",
        )
    )
    assert not any(
        row.get("binding_scope")
        == "DECLARED_DIGEST_BOUND_ISOLATED_TEST_WORKER_SOURCE_NOT_RUNTIME_INTERFACE"
        for row in observed["surfaces"]
    )
    assert any(
        row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
        for row in observed["gaps"]
    )


def test_generated_checker_test_loader_is_exact_and_digest_bound(
    tmp_path: Path,
) -> None:
    observed = discover(generated_checker_test_repository(tmp_path))
    binding = next(
        row for row in observed["surfaces"]
        if row.get("binding_scope")
        == "DECLARED_DIGEST_BOUND_TEST_LOCAL_CHECKER_SOURCE_NOT_RUNTIME_INTERFACE"
    )
    assert binding["target_attribute_names"] == ["ADAPTER", "check_observations"]
    assert binding["target_source_digest"] == binding["importer_source_digest"]
    assert not any(
        row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
        for row in observed["gaps"]
    )


def test_held_checker_exec_binds_every_current_runtime_source(tmp_path: Path) -> None:
    observed = discover(held_checker_repository(tmp_path))
    bindings = [
        row
        for row in observed["surfaces"]
        if row.get("binding_scope")
        == "DECLARED_FINITE_DIRECTORY_HELD_SOURCE_IMPORT_NOT_RUNTIME_EXECUTION"
    ]
    assert [row["module_name"] for row in bindings] == [
        "verifier.runtime.accepted_checker",
        "verifier.runtime.ordinary",
        "verifier.runtime.package_checker_worker",
    ]
    accepted = bindings[0]
    assert accepted["target_attribute_names"] == [
        "ADAPTER",
        "CHECKER_CONTRACT",
        "check_observations",
    ]
    assert all(row["target_source_digest"].startswith("sha256:") for row in bindings)
    assert not any(
        row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
        and row["path"] == "src/verifier/runtime/package_checker_worker.py"
        for row in observed["gaps"]
    )


@pytest.mark.parametrize(
    "source",
    [
        HELD_CHECKER_WORKER.replace(
            'or candidate.parent != source_root / "verifier" / "runtime"\n', ""
        ),
        HELD_CHECKER_WORKER.replace(
            "exec(code, module.__dict__)", "exec(code, globals())"
        ),
        HELD_CHECKER_WORKER.replace(
            "    return module\n", "    consume(sys.modules)\n    return module\n"
        ),
        HELD_CHECKER_WORKER + "\nexec(selected)\n",
        HELD_CHECKER_WORKER.replace(
            "from types import ModuleType", "from types import ModuleType\nModuleType = replacement"
        ),
    ],
)
def test_held_checker_adapter_rejects_guard_drift_or_capability_escape(
    tmp_path: Path, source: str
) -> None:
    observed = discover(held_checker_repository(tmp_path, source))
    assert not any(
        row.get("binding_scope")
        == "DECLARED_FINITE_DIRECTORY_HELD_SOURCE_IMPORT_NOT_RUNTIME_EXECUTION"
        for row in observed["surfaces"]
    )
    assert any(
        row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
        and row["path"] == "src/verifier/runtime/package_checker_worker.py"
        for row in observed["gaps"]
    )


@pytest.mark.parametrize("source", [DERIVED, LITERAL])
def test_static_default_source_import_emits_digest_bound_site(tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    binding = next(row for row in observed["surfaces"] if row["form"] == "SourceImport")
    target = next(row for row in observed["census"]["files"] if row["path"] == "target.py")
    assert binding == {
        "surface_id": "python-source-import:loader.py:bounded_target@5" if source == DERIVED
                      else "python-source-import:loader.py:bounded_target@3",
        "path": "loader.py",
        "line": 5 if source == DERIVED else 3,
        "form": "SourceImport",
        "source_kinds": [],
        "hints": [],
        "unresolved_marker": False,
        "module_name": "bounded_target",
        "target_path": "target.py",
        "target_surface_id": "python:target.py:<module>",
        "target_attribute_names": ["public"],
        "target_attribute_surface_ids": ["python:target.py:public"],
        "target_source_digest": target["sha256"],
        "importer_source_digest": next(row["sha256"] for row in observed["census"]["files"]
                                           if row["path"] == "loader.py"),
        "binding_scope": "DECLARED_STATIC_LOCAL_SOURCE_IMPORT_NOT_RUNTIME_EXECUTION",
        "binding_reason": (
            "A finite local module name, current target digest, and every post-import "
            "attribute read are statically bound; no subject import was executed."
        ),
    }
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])
    assert any(row["surface_id"] == "python:target.py:public" for row in observed["surfaces"])


def test_source_loader_registry_lifetime_is_exactly_bounded(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, BOUNDED_REGISTRY))
    binding = next(row for row in observed["surfaces"] if row["form"] == "SourceImport")
    assert binding["module_name"] == "bounded_target"
    assert binding["target_attribute_surface_ids"] == ["python:target.py:public"]
    assert binding["binding_scope"] == (
        "DECLARED_STATIC_LOCAL_SOURCE_IMPORT_WITH_BOUNDED_REGISTRY_LIFETIME_"
        "NOT_RUNTIME_EXECUTION"
    )
    assert "unconditional cleanup" in binding["binding_reason"]
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


@pytest.mark.parametrize("source", [
    BOUNDED_REGISTRY.replace(
        '        return module.public()\n',
        '        sys.modules["bounded_target"] = replacement\n'
        '        return module.public()\n',
    ),
    BOUNDED_REGISTRY.replace(
        '        del sys.modules["bounded_target"]\n',
        '        pass\n',
    ),
    BOUNDED_REGISTRY.replace(
        '    if "bounded_target" in sys.modules:\n',
        '    registry = sys.modules\n'
        '    if "bounded_target" in registry:\n',
    ).replace(
        '    sys.modules["bounded_target"] = module\n',
        '    registry["bounded_target"] = module\n',
    ).replace(
        '        del sys.modules["bounded_target"]\n',
        '        del registry["bounded_target"]\n',
    ),
    BOUNDED_REGISTRY.replace(
        'sys.modules["bounded_target"] = module',
        'sys.modules["other_target"] = module',
    ),
    BOUNDED_REGISTRY.replace(
        'sys.modules["bounded_target"] = module',
        'sys.modules["bounded_target"] = replacement',
    ),
])
def test_source_loader_registry_mutation_or_escape_is_not_admitted(
        tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    assert not any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               and row["path"] == "loader.py" for row in observed["gaps"])


def test_extra_registry_use_remains_unknown_even_with_a_bounded_loader(
        tmp_path: Path) -> None:
    source = BOUNDED_REGISTRY + '\ndef snapshot():\n    return sys.modules.copy()\n'
    observed = discover(repository(tmp_path, source))
    assert any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               and row["path"] == "loader.py" for row in observed["gaps"])


def _changed(*, module_name: str = '"bounded_target"', target: str = 'target',
             before_spec: str = "", after_module: str = "",
             result: str = "return module.public()", loader: str = "") -> str:
    return f'''from importlib import util
from pathlib import Path
import os
import sys
def run(selected="target.py", custom=None):
    target = Path(__file__).resolve().parent / "target.py"
    {before_spec}
    spec = util.spec_from_file_location({module_name}, {target}{loader})
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    {after_module}
    spec.loader.exec_module(module)
    {result}
'''


@pytest.mark.parametrize("source", [
    _changed(module_name="selected"),
    _changed(target='Path(os.environ["TARGET"])'),
    _changed(target='"../target.py"'),
    _changed(loader=", loader=custom"),
    _changed(after_module='sys.modules["bounded_target"] = module'),
    _changed(result="return module"),
    _changed(result="return consume(module)"),
    _changed(result="return consume(spec.loader)"),
    _changed(after_module="alias = module"),
    _changed(before_spec='target.write_text("changed", encoding="utf-8")'),
    _changed(before_spec='Path(__file__).write_text("changed", encoding="utf-8")'),
    _changed(after_module="spec = replacement"),
    DERIVED.replace("def run():", "def run(spec=None):"),
    DERIVED.replace("def run():", "def run(module=None):"),
    DERIVED.replace("def run():", "def run(target=None):"),
    DERIVED.replace(
        "    return module.public()",
        "    def escape():\n        return module\n    return module.public()",
    ),
    DERIVED.replace(
        "    target =",
        "    import sys as system\n    target =",
    ).replace(
        "    spec.loader.exec_module(module)",
        '    system.modules["bounded_target"] = module\n    spec.loader.exec_module(module)',
    ),
    '''from importlib import import_module
def run():
    return import_module("target")
''',
])
def test_dynamic_or_escaping_import_capability_remains_unresolved(tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    assert not any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               and row["path"] == "loader.py" for row in observed["gaps"])


def test_untracked_target_cannot_become_a_source_binding(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, DERIVED, track_target=False))
    assert not any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               and row["path"] == "loader.py" for row in observed["gaps"])


def test_same_conventional_names_in_sibling_scope_do_not_hide_closed_site(
        tmp_path: Path) -> None:
    sibling = '''def other():
    spec = object()
    module = object()
    target = object()
    return spec, module, target
'''
    observed = discover(repository(tmp_path, sibling + DERIVED))
    assert any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


def test_literal_local_import_module_binds_the_target_and_selected_attribute(
        tmp_path: Path) -> None:
    source = '''from importlib import import_module
def run():
    return import_module("target").public()
'''
    observed = discover(repository(tmp_path, source))
    binding = next(row for row in observed["surfaces"] if row["form"] == "SourceImport")
    target = next(row for row in observed["census"]["files"] if row["path"] == "target.py")
    assert binding["module_name"] == "target"
    assert binding["target_path"] == "target.py"
    assert binding["target_source_digest"] == target["sha256"]
    assert binding["target_attribute_surface_ids"] == ["python:target.py:public"]
    assert binding["binding_reason"] == (
        "A finite local module name, current target digest, and every post-import "
        "attribute read are statically bound; no subject import was executed."
    )
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


def test_literal_getattr_is_an_exact_post_import_attribute_read(
        tmp_path: Path) -> None:
    source = '''from importlib import import_module
ATTRIBUTE = "public"
def run():
    module = import_module("target")
    return getattr(module, ATTRIBUTE)()
'''
    observed = discover(repository(tmp_path, source))
    binding = next(row for row in observed["surfaces"] if row["form"] == "SourceImport")
    assert binding["target_attribute_surface_ids"] == ["python:target.py:public"]
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


def test_literal_hasattr_is_an_exact_post_import_attribute_read(
        tmp_path: Path) -> None:
    source = '''from importlib import import_module
def run():
    return hasattr(import_module("target"), "public")
'''
    observed = discover(repository(tmp_path, source))
    binding = next(row for row in observed["surfaces"] if row["form"] == "SourceImport")
    assert binding["target_attribute_surface_ids"] == ["python:target.py:public"]
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


def test_unique_top_level_assignment_is_a_digest_bound_target_attribute(
        tmp_path: Path) -> None:
    source = '''from importlib import import_module
def run():
    return import_module("target").PUBLIC_VALUE
'''
    target_source = TARGET + 'PUBLIC_VALUE = "declared"\n'
    observed = discover(repository(tmp_path, source, target_source=target_source))
    binding = next(row for row in observed["surfaces"] if row["form"] == "SourceImport")
    assert binding["target_attribute_names"] == ["PUBLIC_VALUE"]
    assert binding["target_attribute_surface_ids"] == ["python:target.py:<module>"]
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


def test_finite_literal_import_module_table_binds_each_possible_target(
        tmp_path: Path) -> None:
    source = '''from importlib import import_module
MODULES = ("target", "other")
def run():
    return [import_module(name).public() for name in MODULES]
'''
    root = repository(tmp_path, source)
    (root / "other.py").write_text(TARGET, encoding="utf-8")
    subprocess.run(["git", "add", "--", "other.py"], cwd=root, check=True)
    observed = discover(root)
    bindings = [row for row in observed["surfaces"] if row["form"] == "SourceImport"]
    assert [(row["module_name"], row["target_path"]) for row in bindings] == [
        ("other", "other.py"),
        ("target", "target.py"),
    ]
    assert all(row["target_attribute_surface_ids"] == [
        "python:" + row["target_path"] + ":public"
    ] for row in bindings)
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


def test_pytest_literal_parameter_table_binds_transformed_local_modules(
        tmp_path: Path) -> None:
    source = '''import pytest
from importlib import import_module
MODULES = ("TARGET", "OTHER")
@pytest.mark.parametrize("module_name", MODULES)
def test_module(module_name):
    assert import_module(module_name.lower()).public() == "observed"
'''
    root = repository(tmp_path, source)
    (root / "other.py").write_text(TARGET, encoding="utf-8")
    subprocess.run(["git", "add", "--", "other.py"], cwd=root, check=True)
    observed = discover(root)
    bindings = [row for row in observed["surfaces"] if row["form"] == "SourceImport"]
    assert [(row["module_name"], row["target_path"]) for row in bindings] == [
        ("other", "other.py"),
        ("target", "target.py"),
    ]
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


@pytest.mark.parametrize("source", [
    '''import pytest
from importlib import import_module
MODULES = ["TARGET"]
@pytest.mark.parametrize("module_name", MODULES)
def test_module(module_name):
    assert import_module(module_name.lower()).public() == "observed"
''',
    '''import pytest
from importlib import import_module
MODULES = ("TARGET",)
@pytest.mark.parametrize("module_name", MODULES, indirect=True)
def test_module(module_name):
    assert import_module(module_name.lower()).public() == "observed"
''',
], ids=["mutable-named-table", "indirect-parameter"])
def test_pytest_runtime_selected_or_mutable_parameter_table_stays_dynamic(
        tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    assert not any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               and row["path"] == "loader.py" for row in observed["gaps"])


def test_closed_source_loader_may_return_only_to_static_attribute_reads(
        tmp_path: Path) -> None:
    source = '''from importlib import util
def load():
    spec = util.spec_from_file_location("bounded_target", "target.py")
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
def run():
    return load().public()
'''
    observed = discover(repository(tmp_path, source))
    binding = next(row for row in observed["surfaces"] if row["form"] == "SourceImport")
    assert binding["target_attribute_surface_ids"] == ["python:target.py:public"]
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


def test_closed_pytest_fixture_result_binds_only_named_consumer_reads(
        tmp_path: Path) -> None:
    source = '''import pytest
from importlib import util
@pytest.fixture(scope="module")
def target_fixture():
    spec = util.spec_from_file_location("bounded_target", "target.py")
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
def test_consumer(target_fixture):
    assert target_fixture.public() == "observed"
'''
    observed = discover(repository(tmp_path, source))
    binding = next(row for row in observed["surfaces"] if row["form"] == "SourceImport")
    assert binding["target_attribute_names"] == ["public"]
    assert not any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
                   and row["path"] == "loader.py" for row in observed["gaps"])


@pytest.mark.parametrize("source", [
    '''import pytest
from importlib import util
@pytest.fixture
def target_fixture():
    spec = util.spec_from_file_location("bounded_target", "target.py")
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
def test_consumer(target_fixture):
    consume(target_fixture)
''',
    '''import pytest
from importlib import util
@pytest.fixture(params=("runtime-selected",))
def target_fixture():
    spec = util.spec_from_file_location("bounded_target", "target.py")
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
def test_consumer(target_fixture):
    target_fixture.public()
''',
    '''import pytest
from importlib import util
@pytest.fixture
def target_fixture():
    spec = util.spec_from_file_location("bounded_target", "target.py")
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
@pytest.mark.parametrize("target_fixture", (object(),))
def test_consumer(target_fixture):
    target_fixture.public()
''',
    '''import pytest
from importlib import util
@pytest.fixture
def target_fixture():
    spec = util.spec_from_file_location("bounded_target", "target.py")
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
escaped = target_fixture
def test_consumer(target_fixture):
    target_fixture.public()
''',
], ids=["module-escape", "fixture-params", "fixture-name-parametrized",
        "fixture-function-escape"])
def test_pytest_fixture_escape_or_runtime_selection_stays_dynamic(
        tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    assert not any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               and row["path"] == "loader.py" for row in observed["gaps"])


@pytest.mark.parametrize("source", [
    '''from importlib import import_module
def run(name):
    return import_module(name).public()
''',
    '''from importlib import import_module
def run():
    return import_module("json").loads("{}")
''',
    '''from importlib import import_module
def run():
    return import_module("target")
''',
    '''from importlib import import_module
def run():
    return import_module("target").missing()
''',
    '''from importlib import util
def load():
    spec = util.spec_from_file_location("bounded_target", "target.py")
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
def run(consume):
    return consume(load())
''',
    '''from importlib import import_module
def load(flag):
    if flag:
        return import_module("target")
    return object()
def run():
    return load(True).public()
''',
    '''from importlib import import_module
def run(selected):
    for name in ("target",):
        name = selected
        return import_module(name).public()
''',
    '''from importlib import import_module
def run(getattr):
    module = import_module("target")
    return getattr(module, "public")
''',
    '''from importlib import import_module
def run(hasattr):
    return hasattr(import_module("target"), "public")
''',
])
def test_unbounded_module_import_or_attribute_selection_stays_dynamic(
        tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    assert not any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               and row["path"] == "loader.py" for row in observed["gaps"])


@pytest.mark.parametrize("target_source", [
    TARGET + "public = object()\n",
    TARGET + "del public\n",
])
def test_rebound_target_attribute_cannot_name_the_definition_surface(
        tmp_path: Path, target_source: str) -> None:
    source = '''from importlib import import_module
def run():
    return import_module("target").public()
'''
    observed = discover(repository(tmp_path, source, target_source=target_source))
    assert not any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               and row["path"] == "loader.py" for row in observed["gaps"])


@pytest.mark.parametrize("target_source", [
    TARGET + 'if selected:\n    PUBLIC_VALUE = "conditional"\n',
    TARGET + 'PUBLIC_VALUE: str\n',
    TARGET + 'PUBLIC_VALUE, OTHER = ("first", "second")\n',
])
def test_non_direct_target_assignment_does_not_invent_an_attribute_surface(
        tmp_path: Path, target_source: str) -> None:
    source = '''from importlib import import_module
def run():
    return import_module("target").PUBLIC_VALUE
'''
    observed = discover(repository(tmp_path, source, target_source=target_source))
    assert not any(row["form"] == "SourceImport" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               and row["path"] == "loader.py" for row in observed["gaps"])
