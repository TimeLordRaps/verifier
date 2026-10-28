"""Optional JavaScript source discovery for Verifier Standard (VSTD)."""
from __future__ import annotations

import subprocess
from importlib import metadata
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.runtime.namespace_discovery import discover
from verifier.runtime import namespace_javascript as adapter
from verifier.runtime.namespace_admission import assess, build_template
from test_namespace_admission import save


@pytest.fixture(autouse=True)
def optional_parser() -> None:
    for name, version in (("tree-sitter", "0.25.2"), ("tree-sitter-javascript", "0.25.0")):
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            installed = None
        if installed != version:
            pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: install the pinned discovery-javascript extra for real parser tests")


def repository(root: Path, source: str) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "subject.mjs").write_text(source, encoding="utf-8")
    return root


def test_javascript_definitions_and_export_aliases_are_separate_surfaces(tmp_path: Path) -> None:
    root = repository(tmp_path, 'export class Ledger { post() {} }\nconst f = x => x;\nexport {f as publicCall};\n')
    result = discover(root)
    rows = result["surfaces"]
    assert any(row["form"] == "method_definition" for row in rows)
    assert any(row["form"] == "JavaScriptExport" and row["surface_id"].endswith(":publicCall") for row in rows)
    assert not result["gaps"]


def test_javascript_parse_errors_do_not_become_empty_success(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, "export function broken( {"))
    assert any(row["code"] == "NAMESPACE_JAVASCRIPT_PARSE_UNAVAILABLE" for row in result["gaps"])


def test_javascript_source_marker_survives_generic_labeling(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, 'const __vstd_kinds__ = ["FINBOT"];\nexport function decide() {}\n'))
    assert any("FINBOT" in row["source_kinds"] for row in result["surfaces"])


def test_missing_method_and_export_are_rejected_by_manifest_admission(tmp_path: Path) -> None:
    root = repository(tmp_path, 'export class Ledger { post() {} }\n')
    manifest = build_template(root)["manifest"]
    owner = manifest["objects"][0]
    owner["surfaces"] = [item for item in owner["surfaces"] if not item.endswith(("Ledger.post", ":Ledger"))]
    save(root, manifest)
    report = assess(root)
    failures = [row for row in report["findings"] if row["code"] == "NAMESPACE_SURFACE_UNCOVERED"]
    assert any(row["surface_id"].endswith("Ledger.post") for row in failures)
    assert any(row["surface_id"].startswith("javascript-export:") for row in failures)
    assert report["independent_reconciliation"]["status"] == "PASS"


@pytest.mark.parametrize("source", [
    'const table = {[methodName]: () => 1};',
    'const e = eval; e(source);',
    'const make = Function; make(source);',
    'const p = new Proxy({}, hooks);',
    'Object.defineProperty(target, name, descriptor);',
    'module.exports.hidden = function() {};',
    'exports[name] = callback;',
    'const runtime = import(name);',
    'const module = require(name);',
    'const load = require; load(name);',
    'Reflect[operation](target, name, value);',
])
def test_dynamic_interfaces_remain_explicit_gaps(tmp_path: Path, source: str) -> None:
    result = discover(repository(tmp_path, source))
    assert any(row["code"] == "NAMESPACE_JAVASCRIPT_DYNAMIC_SURFACES_UNRESOLVED" for row in result["gaps"])


@pytest.mark.parametrize("source", [
    "target.visible = true;",
    'target["known"] = value;',
    "table[key] = value;",
    "state.get(id)[domain] = value;",
])
def test_non_global_property_writes_are_exact_owned_surfaces(tmp_path: Path, source: str) -> None:
    result = discover(repository(tmp_path, source))
    writes = [row for row in result["surfaces"] if row["form"] == "JavaScriptPropertyWrite"]
    assert len(writes) == 1
    assert writes[0]["path"] == "subject.mjs"
    assert not result["gaps"]


@pytest.mark.parametrize("source", [
    "globalThis[name] = value;",
    "window.route = handler;",
    "self[route] = handler;",
])
def test_global_property_writes_remain_explicit_gaps(tmp_path: Path, source: str) -> None:
    result = discover(repository(tmp_path, source))
    assert any(row["code"] == "NAMESPACE_JAVASCRIPT_DYNAMIC_SURFACES_UNRESOLVED" for row in result["gaps"])


@pytest.mark.parametrize("source", [
    'export * from "./other.mjs";',
    'export {x as publicX} from "./other.mjs";',
    'export const {x} = value;',
    'export {missing};',
    'import {x} from "./other.mjs"; export {x};',
])
def test_unresolved_export_variants_cannot_hide_behind_file_coverage(tmp_path: Path, source: str) -> None:
    result = discover(repository(tmp_path, source))
    assert any(row["code"] == "NAMESPACE_JAVASCRIPT_EXPORTS_UNRESOLVED" for row in result["gaps"])


@pytest.mark.parametrize("source", [
    'const __vstd_kinds__ = dynamic;',
    'let __vstd_kinds__ = ["BOT"];',
    'const __vstd_kinds__ = ["BOT"]; __vstd_kinds__.push("ROBOT");',
    'function hide() { const __vstd_kinds__ = ["ROBOT"]; }',
    'const __vstd_kinds__ = ["BOT",,];',
])
def test_nonliteral_or_mutated_markers_remain_unresolved(tmp_path: Path, source: str) -> None:
    result = discover(repository(tmp_path, source))
    assert any(row["unresolved_marker"] for row in result["surfaces"])


def test_subject_and_shadow_parser_modules_are_never_executed(tmp_path: Path) -> None:
    root = repository(tmp_path, 'throw new Error("subject must not run"); export const value = 1;')
    marker = root / "executed.txt"
    (root / "tree_sitter.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\nraise RuntimeError()\n", encoding="utf-8")
    report = discover(root)
    assert not marker.exists()
    assert report["javascript_mechanism"] is not None


def test_duplicate_names_and_callbacks_keep_distinct_identities(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, 'const a = () => 1, b = () => 2; function f() {} function f() {}'))
    surfaces = [row for row in result["surfaces"] if row["surface_id"].startswith("javascript:")]
    assert len({row["surface_id"] for row in surfaces}) == len(surfaces)
    assert len([row for row in surfaces if row["form"] == "arrow_function"]) == 2
    assert len([row for row in surfaces if row["form"] == "function_declaration"]) == 2


def test_parser_failure_or_timeout_preserves_unknown(monkeypatch: Any) -> None:
    def timeout(*args: Any, **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired("fixed worker", 45)
    monkeypatch.setattr(adapter.subprocess, "run", timeout)
    result = adapter.discover([("a.mjs", b"export const a=1;")])
    assert result["mechanism"] is None and not result["surfaces"]
    assert result["gaps"][0]["code"] == "NAMESPACE_LANGUAGE_DISCOVERY_UNSUPPORTED"


def test_parser_byte_change_invalidates_recapture(monkeypatch: Any) -> None:
    result = adapter.discover([("a.mjs", b"export const a=1;")])
    assert result["mechanism"]
    monkeypatch.setattr(adapter, "_run", lambda files: {"mechanism": {"changed": True}})
    with pytest.raises(ValueError, match="MECHANISM_CHANGED"):
        adapter.recapture(result["mechanism"])


def test_source_binding_is_verified_before_accepting_worker_rows(monkeypatch: Any) -> None:
    response = {"schema_version": adapter.PROTOCOL, "mechanism": {}, "files": [
        {"path": "wrong.mjs", "source_digest": "sha256:" + "0" * 64, "surfaces": [], "gaps": []}]}
    monkeypatch.setattr(adapter.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, json.dumps(response).encode(), b""))
    assert adapter.discover([("a.mjs", b"")])["gaps"]


def test_zero_javascript_does_not_launch_optional_parser(monkeypatch: Any) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Optional parser launched for no inputs")
    monkeypatch.setattr(adapter.subprocess, "run", forbidden)
    assert adapter.discover([]) == {"surfaces": [], "gaps": [], "mechanism": None}
