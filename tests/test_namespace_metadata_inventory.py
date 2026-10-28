"""Bounded dependency-inventory syntax for Verifier Standard (VSTD).

The abstract syntax tree (AST) checks source shape, not host hooks or successful
imports. Reading dependency data must not exempt plugin loading or lost surfaces.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from test_namespace_dynamic import repository
from test_namespace_admission import save
from verifier.runtime import namespace_exports
from verifier.runtime.namespace_discovery import discover
from verifier.runtime.namespace_admission import assess_gate, build_template


POSITIVE = [
    'from importlib import metadata\ndef inspect(): return metadata.version("package")\n',
    'import importlib.metadata as meta\ndef inspect():\n    dist = meta.distribution("package")\n    return dist.version, dist.files, dist.locate_file("file")\n',
    'import importlib.metadata\ndef inspect(): return importlib.metadata.version("package")\n',
    'from importlib.metadata import distribution\ndef inspect():\n    dist = distribution("package")\n    files = dist.files\n    return dist.locate_file(files[0])\n',
    'from importlib.metadata import distribution\ndef inspect():\n    dist = distribution("package")\n    return dist.metadata.get("Name"), dist.version\n',
    'from importlib import metadata\nVERSIONS = {"first":"1", "second":"2"}\ndef inspect():\n    for name, expected in VERSIONS.items():\n        dist = metadata.distribution(name)\n        print(dist.version, dist.files)\n',
    'from importlib import metadata\nGRAMMARS={"r":("parser", "1")}\ndef inspect(languages):\n    for name, expected in [("runtime", "2"), *(GRAMMARS[language] for language in languages)]:\n        dist = metadata.distribution(name)\n        print(dist.files, dist.version)\n',
    'from importlib import metadata\ndef inspect():\n    for name, expected in (("parser", "1"), ("runtime", "2")):\n        try: metadata.version(name)\n        except metadata.PackageNotFoundError: pass\n',
    'from importlib import metadata\ndef inspect():\n    for name in ("parser", "runtime"):\n        try: metadata.version(name)\n        except metadata.PackageNotFoundError: pass\n',
]


@pytest.mark.parametrize('source', POSITIVE)
def test_closed_dependency_inventory_is_data_reading(source: str) -> None:
    assert not namespace_exports.has_dynamic_construction(ast.parse(source), closed_lazy=False)


@pytest.mark.parametrize('module', ['namespace_systems_worker.py', 'namespace_javascript_worker.py', 'namespace_workflow_worker.py'])
def test_actual_parser_inventory_has_no_unbound_loading(module: str) -> None:
    source = Path(namespace_exports.__file__).with_name(module).read_bytes()
    assert not namespace_exports.has_dynamic_construction(ast.parse(source), closed_lazy=False)


def test_actual_snapshot_finite_version_inventory_is_closed() -> None:
    source = Path(namespace_exports.__file__).with_name('artifact_snapshot.py').read_bytes()
    assert not namespace_exports.has_dynamic_construction(ast.parse(source), closed_lazy=False)


@pytest.mark.parametrize('path', [
    'examples/scitt_interop/demo.py',
    'examples/scitt_native_interop/native_runner.py',
    'examples/scitt_native_interop/package_comparison.py',
])
def test_scitt_distribution_inventory_is_closed_data_reading(path: str) -> None:
    source = Path(path).read_bytes()
    assert not namespace_exports.has_dynamic_construction(
        ast.parse(source), closed_lazy=False
    )
    assert b'packages_distributions(' not in source
    assert b'entry_points(' not in source


def test_quality_tool_inventory_is_direct_bounded_distribution_data() -> None:
    source = Path('src/verifier/runtime/quality_checks.py').read_bytes()
    assert not namespace_exports.has_dynamic_construction(
        ast.parse(source), closed_lazy=False
    )
    assert b'importlib.metadata' not in source
    assert b'entry_points(' not in source


def test_language_runner_uses_only_fixed_optional_package_imports() -> None:
    source = Path('src/verifier/runtime/language_runners.py').read_bytes()
    tree = ast.parse(source)
    assert not namespace_exports.has_dynamic_construction(
        tree, closed_lazy=False
    )
    assert b'entry_points(' not in source
    assert b'vstd_languages' in source and b'vstd_openshell' in source


@pytest.mark.parametrize('source', [
    'from importlib import metadata\ndef f(name): return metadata.version(name)\n',
    'from importlib import metadata\ndef f(): return metadata.distribution("x")\n',
    'from importlib import metadata\ndef f(): return metadata.distribution("x").entry_points[0].load()\n',
    'from importlib import metadata\ndef f():\n    dist=metadata.distribution("x")\n    return dist.entry_points[0].load()\n',
    'from importlib import metadata\ndef f():\n    dist=metadata.distribution("x")\n    alias=dist\n    return alias.files\n',
    'from importlib import metadata\ndef f():\n    dist=metadata.distribution("x")\n    return dist.locate_file\n',
    'from importlib import metadata\ndef f():\n    dist=metadata.distribution("x")\n    return dist.metadata\n',
    'from importlib import metadata\ndef f(key):\n    dist=metadata.distribution("x")\n    return dist.metadata.get(key)\n',
    'from importlib import metadata\ndef f():\n    dist=metadata.distribution("x")\n    dist.files=other\n    return dist.files\n',
    'from importlib import metadata\ndef f(metadata): return metadata.version("x")\n',
    'from importlib import metadata\nreader=metadata.version\nreader("x")\n',
    'from importlib import metadata\ncopy=metadata\ncopy.version("x")\n',
    'from importlib import metadata\nmetadata.version=replacement\nmetadata.version("x")\n',
    'if condition:\n    from importlib import metadata\nmetadata.version("x")\n',
    'from importlib import metadata\nVERSIONS={"first":"1"}\nVERSIONS["second"]="2"\ndef f():\n    for name, expected in VERSIONS.items(): metadata.version(name)\n',
    'from importlib import metadata\nVERSIONS={"first":"1"}\nmodify(VERSIONS)\ndef f():\n    for name, expected in VERSIONS.items(): metadata.version(name)\n',
    'from importlib import metadata\nVERSIONS={"first":"1"}\nVERSIONS.update(other)\ndef f():\n    for name, expected in VERSIONS.items(): metadata.version(name)\n',
    'from importlib import metadata\ndef f():\n    for name, expected in [("x","1")]:\n        name=other\n        metadata.version(name)\n',
    'from importlib import metadata\ndef f():\n    for name, expected in [("x","1")]: pass\n    metadata.version(name)\n',
    'from importlib import metadata\ndef f():\n    for name, expected in supplied: metadata.version(name)\n',
    'from importlib import metadata\ndef f():\n    dist=metadata.distribution("x")\n    def later(): return dist.files\n    return later\n',
    'from importlib import metadata\ndef f():\n    dist=metadata.distribution("x")\n    consume(dist)\n    return dist.files\n',
    'from importlib import metadata\ndef f(): return metadata.version("x")\nexec(code)\n',
])
def test_loading_aliasing_mutation_and_unknown_selection_remain_gaps(source: str) -> None:
    assert namespace_exports.has_dynamic_construction(ast.parse(source), closed_lazy=False)


def test_inventory_read_does_not_execute_subject_or_waive_ownership(tmp_path: Path) -> None:
    root = repository(tmp_path, POSITIVE[1] + 'raise RuntimeError("must not import")\n')
    observed = discover(root)
    assert not observed['gaps']
    document = build_template(root)['manifest']
    omitted = 'python:subject.py:inspect'
    assert any(row['surface_id'] == omitted for row in observed['surfaces'])
    for row in document['objects']:
        row['surfaces'] = [name for name in row['surfaces'] if name != omitted]
    save(root, document)
    report = assess_gate(document['objects'][0]['object_id'], 'VSTD-T0.4-namespace-admission', root)
    assert any(row['code'] == 'NAMESPACE_SURFACE_UNCOVERED' and row['surface_id'] == omitted
               for row in report['prerequisite_findings'])


@pytest.mark.parametrize('mutation', [
    'alias=GRAMMARS["r"]; alias[0]="other"',
    'GRAMMARS["r"][0]="other"',
    'GRAMMARS["r"].append("other")',
])
def test_mutable_nested_selector_is_not_finite_evidence(mutation: str) -> None:
    source = ('from importlib import metadata\nGRAMMARS={"r":["parser", "1"]}\n' + mutation + '\n'
              'def inspect(languages):\n'
              '    for name, expected in [*(GRAMMARS[language] for language in languages)]:\n'
              '        metadata.version(name)\n')
    assert namespace_exports.has_dynamic_construction(ast.parse(source), closed_lazy=False)


@pytest.mark.parametrize('module', ['namespace_systems_worker.py', 'namespace_javascript_worker.py', 'namespace_workflow_worker.py'])
@pytest.mark.parametrize('operation', ['distribution.entry_points[0].load()', 'consume(distribution)', 'alias = distribution'])
def test_actual_inventory_with_loader_or_escape_is_not_closed(module: str, operation: str) -> None:
    source = Path(namespace_exports.__file__).with_name(module).read_text(encoding='utf-8')
    lines = source.splitlines()
    index = next(i for i, line in enumerate(lines) if 'distribution = metadata.distribution(' in line)
    indentation = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
    lines.insert(index + 1, indentation + operation)
    assert namespace_exports.has_dynamic_construction(ast.parse('\n'.join(lines)), closed_lazy=False)


@pytest.mark.parametrize('parameter', ['metadata', '*metadata', '**metadata'])
@pytest.mark.parametrize('reader', ['module', 'direct'])
def test_generic_type_parameters_shadow_reader_bindings(parameter: str, reader: str) -> None:
    prefix = ('from importlib import metadata' if reader == 'module'
              else 'from importlib.metadata import version as metadata')
    call = 'metadata.version("x")' if reader == 'module' else 'metadata("x")'
    source = prefix + '\ndef inspect[' + parameter + ']():\n    return ' + call + '\n'
    if hasattr(ast, 'TypeVar'):
        tree = ast.parse(source)
    else:
        # Older supported interpreters cannot parse this syntax. Exercise the
        # same named-binder node shape without executing or importing a subject.
        class TypeVar(ast.AST):
            _fields = ('name',)
        tree = ast.parse(prefix + '\ndef inspect():\n    return ' + call + '\n')
        function = tree.body[1]
        function._fields = (*function._fields, 'type_params')
        function.type_params = [TypeVar(name='metadata')]
    assert namespace_exports.has_dynamic_construction(tree, closed_lazy=False)
