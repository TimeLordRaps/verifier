"""Dynamic-source warnings for Verifier Standard (VSTD), without subject execution."""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from verifier.runtime.namespace_admission import assess, assess_gate, build_template, _coverage
from verifier.runtime.namespace_discovery import discover
from test_namespace_admission import save
from test_namespace_exports import DISPATCH, repository as lazy_repository


def repository(root: Path, source: str) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "subject.py").write_text(source, encoding="utf-8")
    return root


@pytest.mark.parametrize("source", [
    'import builtins as runtime\nruntime.exec("def hidden(): pass")\n',
    'from builtins import exec as define\ndefine("def hidden(): pass")\n',
    'define = exec\ndefine("def hidden(): pass")\n',
    'import importlib as loader\nloader.import_module(selected_name)\n',
    'from importlib import import_module as load\nload(selected_name)\n',
    'import builtins as runtime\ngetattr(runtime, "exec")(source)\n',
    'import builtins as runtime\nruntime.__dict__[operation](source)\n',
    'import builtins as runtime\ncopy = runtime\ncopy.exec(source)\n',
    'def install():\n    from builtins import setattr as expose\n    expose(target, name, value)\n',
    'def install():\n    define = exec\n    return define\n',
    'def build(): return type("Generated", (), {})\n',
    'from builtins import type as make\nvalue = make("Generated", (), {})\n',
    'factory = type\nvalue = factory("Generated", (), {})\n',
    'import builtins as runtime\ndef build(args): return runtime.type(*args)\n',
    'from builtins import globals as namespace\nnamespace()[name] = value\n',
    'from builtins import *\n',
    'import importlib.util as loader\nloader.module_from_spec(spec)\n',
    'import importlib\nimportlib.util.spec_from_file_location(name, path)\n',
    'import builtins as runtime\nconsume(runtime)\n',
    'operations = [exec]\noperations[0](source)\n',
    'def remove(): delattr(target, name)\n',
    '__builtins__["exec"](source)\n',
    'from __future__ import annotations\ndef describe(value: register(type)): pass\n',
    'def describe(value, isinstance): return isinstance(value, type)\n',
])
def test_aliases_and_escaped_capabilities_keep_discovery_unresolved(tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED" for row in observed["gaps"])


@pytest.mark.parametrize("source", [
    'def describe(value): return type(value).__name__\n',
    'import builtins as runtime\ndef describe(value): return runtime.type(value).__name__\n',
    'from builtins import type as inspect_type\ndef describe(value): return inspect_type(value).__name__\n',
    'import builtins as runtime\nvalue = runtime.abs(-1)\n',
    'class Worker:\n    def exec(self): pass\nWorker().exec()\n',
    'def add(a, b): return a + b\n',
    'from __future__ import annotations\ndef describe(value: type) -> type:\n    return type(value)\n',
    'from __future__ import annotations\nrecord: tuple[type[object], ...]\n',
    'def describe(value): return isinstance(value, type)\n',
    'def describe(value): return issubclass(value, type)\n',
])
def test_plain_static_operations_do_not_become_dynamic_by_attribute_spelling(tmp_path: Path, source: str) -> None:
    assert not discover(repository(tmp_path, source))["gaps"]


def test_literal_exec_into_closed_namespace_discovers_only_extracted_definition(
        tmp_path: Path) -> None:
    source = (
        "PAYLOAD = 'def hidden():\\n    return 1\\n'\n"
        "NAMESPACE = {}\n"
        "exec(PAYLOAD, NAMESPACE)\n"
        "public = NAMESPACE['hidden']\n"
    )
    observed = discover(repository(tmp_path, source))
    assert not observed["gaps"]
    selected = [
        row
        for row in observed["surfaces"]
        if row["surface_id"].startswith("python-static-exec:")
    ]
    assert [row["surface_id"] for row in selected] == [
        "python-static-exec:subject.py:NAMESPACE.public"
    ]
    assert selected[0]["form"] == "StaticExecFunctionDef"


@pytest.mark.parametrize(
    "source",
    [
        (
            "PAYLOAD = selected\n"
            "NAMESPACE = {}\n"
            "exec(PAYLOAD, NAMESPACE)\n"
            "public = NAMESPACE['hidden']\n"
        ),
        (
            "PAYLOAD = 'def hidden():\\n    return 1\\n'\n"
            "NAMESPACE = {}\n"
            "exec(PAYLOAD, NAMESPACE)\n"
            "public = NAMESPACE['hidden']\n"
            "consume(NAMESPACE)\n"
        ),
        (
            "PAYLOAD = 'exec(selected)\\n'\n"
            "NAMESPACE = {}\n"
            "exec(PAYLOAD, NAMESPACE)\n"
            "public = NAMESPACE['hidden']\n"
        ),
        (
            "PAYLOAD = 'def hidden():\\n    return 1\\ndef unextracted():\\n    return 2\\n'\n"
            "NAMESPACE = {}\n"
            "exec(PAYLOAD, NAMESPACE)\n"
            "public = NAMESPACE['hidden']\n"
        ),
    ],
)
def test_static_exec_adapter_refuses_dynamic_source_escape_or_nested_construction(
        tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    assert any(
        row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
        for row in observed["gaps"]
    )


def test_closed_lazy_export_dispatch_stays_supported(tmp_path: Path) -> None:
    assert not discover(lazy_repository(tmp_path))["gaps"]


def test_closed_dispatch_does_not_exempt_another_loader_reference(tmp_path: Path) -> None:
    root = lazy_repository(tmp_path, DISPATCH + '\nescaped = import_module\n')
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED" for row in discover(root)["gaps"])


def test_dynamic_gap_names_its_owner_and_focused_gate_keeps_it(tmp_path: Path) -> None:
    root = repository(tmp_path, 'exec(source)\n')
    save(root, build_template(root)["manifest"])
    report = assess(root)
    gap = next(row for row in report["findings"] if row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED")
    assert gap["object_id"] == "subject.py"
    assert gap["rerun_argv"] == ["vstd", "gate", "--object", "subject.py", "--obligation", "VSTD-T0.4-namespace-admission"]
    focused = assess_gate("subject.py", "VSTD-T0.4-namespace-admission", root)
    assert focused["status"] == "UNKNOWN"
    assert gap in focused["findings"]
    assert focused["prerequisite_findings"]  # Focusing cannot erase classification prerequisites.


@pytest.mark.parametrize("owner_count", [0, 2])
def test_gap_does_not_invent_an_owner_when_file_ownership_is_ambiguous(owner_count: int) -> None:
    surface = {"surface_id": "file:subject.py"}
    manifest = {"objects": [{"object_id": str(index), "surfaces": [surface["surface_id"]]}
                            for index in range(owner_count)]}
    observed = {"surfaces": [surface], "gaps": [{"code": "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED",
                "path": "subject.py", "reason": "Generated definitions are not known."}]}
    gap = next(row for row in _coverage(manifest, observed) if row["status"] == "UNKNOWN")
    assert gap["object_id"] is None
    assert gap["rerun_argv"] == ["vstd", "polish", "0"]


@pytest.mark.parametrize("source", [
    'def unchanged(value):\n    return vars(value) == {"state": "ready"}\n',
    'def present(value):\n    return "state" in vars(value)\n',
    'def supplied(record):\n    return any(value is None for _, value in vars(record).items())\n',
    'def present():\n    return "value" in locals()\n',
])
def test_declaration_neutral_introspection_reads_are_not_namespace_construction(
        tmp_path: Path, source: str) -> None:
    assert not discover(repository(tmp_path, source))["gaps"]


@pytest.mark.parametrize("source", [
    'def mutate(value):\n    vars(value)[name] = exposed\n',
    'def mutate():\n    locals()[name] = exposed\n',
    'def escape(value):\n    return consume(vars(value))\n',
    'def escape():\n    return globals()\n',
    'def escape(value, sink):\n    return sink == vars(value)\n',
    'def escape():\n    return consume(**locals())\n',
    'def escape(value):\n    return [name for name in vars(value).keys()]\n',
    'def escape(value):\n    return [consume(name) for name in vars(value).keys()]\n',
    'import sys\nsys.modules[name] = module\n',
])
def test_mutating_or_escaping_namespace_views_remains_dynamic(
        tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               for row in observed["gaps"])


def test_exact_module_absence_instrumentation_does_not_construct_an_interface(
        tmp_path: Path) -> None:
    source = (
        "import sys\n"
        "def check(monkeypatch):\n"
        "    monkeypatch.setitem(sys.modules, 'optional.backend', None)\n"
    )
    assert not discover(repository(tmp_path, source))["gaps"]


@pytest.mark.parametrize("source", [
    "import sys\ndef check(monkeypatch, name):\n    monkeypatch.setitem(sys.modules, name, None)\n",
    "import sys\ndef check(monkeypatch, value):\n    monkeypatch.setitem(sys.modules, 'optional.backend', value)\n",
    "import sys\nsys.modules['optional.backend'] = None\n",
])
def test_module_registry_construction_or_computed_selection_stays_dynamic(
        tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, source))
    assert any(row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED"
               for row in observed["gaps"])


def test_compressed_json_result_is_an_inert_data_artifact(tmp_path: Path) -> None:
    root = repository(tmp_path, "value = 1\n")
    (root / "result.json.gz").write_bytes(b"compressed-result-bytes")
    assert not discover(root)["gaps"]


def test_compressed_source_archive_still_requires_a_language_adapter(tmp_path: Path) -> None:
    root = repository(tmp_path, "value = 1\n")
    (root / "subject.py.gz").write_bytes(b"compressed-source-bytes")
    gaps = discover(root)["gaps"]
    assert any(
        row["path"] == "subject.py.gz"
        and row["code"] == "NAMESPACE_LANGUAGE_DISCOVERY_UNSUPPORTED"
        for row in gaps
    )
