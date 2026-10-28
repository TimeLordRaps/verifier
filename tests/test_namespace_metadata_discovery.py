"""Metadata inspection is not plugin loading in Verifier Standard (VSTD).

The accepted syntax is checked without importing or executing the subject.
Aliases, escaping distribution objects and entry-point loading remain separate.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from test_namespace_dynamic import repository
from test_namespace_admission import save
from verifier.runtime.namespace_exports import has_dynamic_construction
from verifier.runtime.namespace_discovery import discover
from verifier.runtime.namespace_admission import assess_gate, build_template


@pytest.mark.parametrize("source", [
    'from importlib.metadata import version\ncurrent = version("package")\n',
    'from importlib.metadata import version as release\ndef describe(): return release("package")\n',
    'from importlib.metadata import distribution\ndef locate(name):\n    dist = distribution("package")\n    return dist.locate_file(name)\n',
    'from importlib.metadata import distribution as package\ndef locate(name):\n    selected = package("package")\n    return selected.locate_file(name)\n',
    'from importlib.metadata import distribution\ndef locate(name):\n    return distribution("package").locate_file(name)\n',
    'from importlib.metadata import distribution\ndef locate():\n    dist = distribution("package")\n    files = dist.files\n    return dist.locate_file(files[0])\n',
    'import importlib.metadata as meta\nvalue = meta.version("package")\n',
    'import importlib.metadata\nvalue = importlib.metadata.requires("package")\n',
    'from importlib.metadata import requires\ndef dependencies(): return requires("package")\n',
    'from importlib.metadata import requires\nTABLE = {"dependency": "package"}\ndef dependencies():\n    for dependency, parent in TABLE.items():\n        return [item for item in requires(parent) or []]\n',
])
def test_closed_metadata_reads_do_not_claim_dynamic_definition(source: str) -> None:
    assert not has_dynamic_construction(ast.parse(source), closed_lazy=False)


@pytest.mark.parametrize("source", [
    'from importlib.metadata import entry_points\nplugin = entry_points()[0].load()\n',
    'from importlib.metadata import distribution\nplugin = distribution("package").entry_points[0].load()\n',
    'from importlib.metadata import distribution\ndef load():\n    dist = distribution("package")\n    return dist.entry_points[0].load()\n',
    'from importlib.metadata import distribution\ndef load():\n    dist = distribution("package")\n    alias = dist\n    return alias.locate_file("file")\n',
    'from importlib.metadata import distribution\ndef load():\n    dist = distribution("package")\n    return dist\n',
    'from importlib.metadata import distribution\ndef load():\n    dist = distribution("package")\n    consume(dist)\n    return dist.locate_file("file")\n',
    'from importlib.metadata import distribution\ndef load():\n    dist = distribution("package")\n    return dist.__dict__[operation]\n',
    'from importlib.metadata import distribution\ndef load():\n    dist = distribution("package")\n    return dist.locate_file\n',
    'from importlib.metadata import distribution\ndef load():\n    dist = distribution("package")\n    dist.locate_file = replacement\n    return dist.locate_file("file")\n',
    'from importlib.metadata import version\nreader = version\nvalue = reader("package")\n',
    'from importlib.metadata import version\nvalue = version.__globals__[operation]\n',
    'from importlib.metadata import version\nvalue = version(selected_package)\n',
    'from importlib.metadata import version\nvalue = version(*arguments)\n',
    'from importlib.metadata import version\nversion = replacement\nvalue = version("package")\n',
    'from importlib.metadata import version\ndef run(version): return version("package")\n',
    'from importlib.metadata import requires\nvalue = requires(selected_package)\n',
    'from importlib.metadata import requires\nTABLE = {"dependency": "package"}\nparent = "other"\ndef dependencies():\n    for dependency, parent in TABLE.items():\n        return [item for item in requires(parent) or []]\n',
    'from importlib.metadata import requires\nTABLE = {"dependency": "package"}\nset = consume\nCOPIED = set(TABLE)\ndef dependencies():\n    for dependency, parent in TABLE.items():\n        return [item for item in requires(parent) or []]\n',
    'from importlib.metadata import version\nfrom elsewhere import version\nvalue = version("package")\n',
    'from importlib.metadata import version\ndel version\nvalue = version("package")\n',
    'from importlib.metadata import version\ndef version(name): return replacement(name)\nvalue = version("package")\n',
    'value = version("package")\nfrom importlib.metadata import version\n',
    'if condition:\n    from importlib.metadata import version\nvalue = version("package")\n',
    'import importlib.metadata as metadata\nmetadata.version = replacement\nfrom importlib.metadata import version\nvalue = version("package")\n',
    'from importlib.metadata import version\nfrom importlib import import_module as load\nvalue = version("package")\nload(module_name)\n',
    'from importlib.metadata import distribution\ndist = distribution("package")\npath = dist.locate_file("file")\n',
    'from importlib.metadata import distribution\ndef locate():\n    global dist\n    dist = distribution("package")\n    return dist.locate_file("file")\n',
    'from importlib.metadata import distribution\ndef locate():\n    dist = distribution("package")\n    def later(): return dist.locate_file("file")\n    return later\n',
    'from importlib.metadata import distribution\ndef locate():\n    dist = other = distribution("package")\n    return dist.locate_file("file")\n',
    'from importlib.metadata import distribution\ndef locate():\n    dist = distribution("package")\n    dist = replacement\n    return dist.locate_file("file")\n',
    'from importlib.metadata import version\ntry:\n    work()\nexcept Exception as version:\n    value = version("package")\n',
    'from importlib.metadata import version\nmatch item:\n    case {"reader": version}:\n        value = version("package")\n',
    'from importlib.metadata import distribution\ndef locate():\n    dist = distribution("package")\n    return dist.locate_file(*arguments)\n',
])
def test_loading_escaping_or_rebinding_is_not_metadata_inspection(source: str) -> None:
    assert has_dynamic_construction(ast.parse(source), closed_lazy=False)


@pytest.mark.parametrize("source", [
    'import importlib.metadata as meta\nmeta.entry_points()[0].load()\n',
    'from importlib import metadata\nmetadata.distribution("package").entry_points[0].load()\n',
    'import importlib.metadata\nimportlib.metadata.version.__globals__[operation]\n',
    'import importlib as loader\nloader.metadata.entry_points()[0].load()\n',
    'from importlib import metadata as meta\nreader = meta.version\nreader.__globals__[operation]\n',
    'import importlib.metadata\nconsume(importlib.metadata)\n',
    'import importlib.metadata\ncopy = importlib.metadata\ncopy.entry_points()[0].load()\n',
])
def test_module_style_metadata_capabilities_are_not_silently_closed(source: str) -> None:
    # Individual closed reads are supported; a module alias is never a blanket
    # exemption for plugin loading, reflection or a copied reader.
    assert has_dynamic_construction(ast.parse(source), closed_lazy=False)


@pytest.mark.parametrize("source", [
    'import importlib.metadata as meta\ndef public(): return "unchanged"\n',
    'class Reader:\n    def version(self, name): return name\nReader().version("package")\n',
    'import importlib as loader\nlabel = "metadata"\n',
])
def test_unused_modules_and_unrelated_metadata_spellings_are_not_loading(source: str) -> None:
    assert not has_dynamic_construction(ast.parse(source), closed_lazy=False)


def test_module_style_plugin_loading_stays_visible_in_focused_admission(tmp_path: Path) -> None:
    root = repository(tmp_path, 'import importlib.metadata as meta\n'
        'def load(): return meta.entry_points()[0].load()\n'
        'raise RuntimeError("discovery must not execute this module")\n')
    save(root, build_template(root)["manifest"])
    report = assess_gate("subject.py", "VSTD-T0.4-namespace-admission", root)
    assert report["status"] == "UNKNOWN"
    gap = next(row for row in report["findings"] if row["code"] == "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED")
    assert gap["object_id"] == "subject.py"
    assert gap["rerun_argv"] == ["vstd", "gate", "--object", "subject.py", "--obligation", "VSTD-T0.4-namespace-admission"]


def test_metadata_read_keeps_definitions_and_targeted_coverage_checks(tmp_path: Path) -> None:
    root = repository(tmp_path, 'from importlib.metadata import version\n'
        'def public(): return version("package-that-must-not-be-imported")\n'
        'raise RuntimeError("discovery must not execute this module")\n')
    observed = discover(root)
    assert not observed["gaps"]
    assert any(row["surface_id"] == "python:subject.py:public" for row in observed["surfaces"])
    document = build_template(root)["manifest"]
    for row in document["objects"]:
        row["surfaces"] = [surface for surface in row["surfaces"] if surface != "python:subject.py:public"]
    save(root, document)
    report = assess_gate("subject.py", "VSTD-T0.4-namespace-admission", root)
    assert report["status"] == "FAIL"
    # An unowned definition has no defensible object assignment. It remains a
    # global prerequisite even when this object is the focused selection.
    assert any(row["code"] == "NAMESPACE_SURFACE_UNCOVERED" and row["object_id"] is None
               for row in report["prerequisite_findings"])
