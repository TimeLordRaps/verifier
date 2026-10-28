"""Non-executing Rust and Bash discovery for Verifier Standard (VSTD)."""
from __future__ import annotations

from pathlib import Path
import subprocess
from importlib import metadata
from copy import deepcopy
import json
from typing import Any

import pytest

from verifier.runtime.namespace_discovery import discover
from verifier.runtime import namespace_systems as adapter
from verifier.runtime.namespace_admission import build_template, assess
from test_namespace_admission import save


@pytest.fixture
def optional_parser() -> None:
    for name, version in (("tree-sitter", "0.25.2"), ("tree-sitter-rust", "0.24.2"), ("tree-sitter-bash", "0.25.1")):
        try:
            current = metadata.version(name)
        except metadata.PackageNotFoundError:
            current = None
        if current != version:
            pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: install pinned discovery-rust and discovery-shell extras for real parser checks")


def test_rust_methods_and_fields_are_owned_separately(tmp_path: Path, optional_parser: None) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "subject.rs").write_text("pub struct Device { pub reading: u64 }\nimpl Device { pub fn sample(&self) {} }\n", encoding="utf-8")
    report = discover(tmp_path)
    forms = {row["form"] for row in report["surfaces"]}
    assert {"struct_item", "field_declaration", "impl_item", "function_item"} <= forms
    assert not report["gaps"]


def test_shell_commands_and_functions_are_owned_separately(tmp_path: Path, optional_parser: None) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "subject.sh").write_text("#!/usr/bin/env bash\nvalue=one\nf() { printf '%s' x; }\nf\n", encoding="utf-8")
    report = discover(tmp_path)
    forms = {row["form"] for row in report["surfaces"]}
    assert {"function_definition", "variable_assignment", "command"} <= forms
    assert not report["gaps"]


@pytest.mark.parametrize("path,source,forms", [
    ("a.rs", b'pub enum State { On, Off } pub struct Point(pub u32, pub u32);', {"enum_item", "enum_variant", "TupleField"}),
    ("a.rs", b'pub trait T { fn run(&self); } pub const X:u8=1; pub type U=u8;', {"trait_item", "function_signature_item", "const_item", "type_item"}),
    ("a.rs", b'fn f() { fn nested() {} let callback=||1; } fn f() {}', {"function_item", "closure_expression"}),
    ("a.sh", b'f() { f() { :; }; }; x=1; x=2; printf x > out', {"function_definition", "variable_assignment", "file_redirect"}),
])
def test_complete_named_and_anonymous_syntax_identities(path: str, source: bytes, forms: set[str], optional_parser: None) -> None:
    result = adapter.discover([(path, source)])
    assert forms <= {row["form"] for row in result["surfaces"]}
    assert len(result["surfaces"]) == len({row["surface_id"] for row in result["surfaces"]})
    assert not result["gaps"]


@pytest.mark.parametrize("path,source,form", [
    ("a.rs", 'pub struct Device { pub reading: u64 } impl Device { pub fn sample(&self) {} }', "field_declaration"),
    ("a.rs", 'pub struct Device {} impl Device { pub fn sample(&self) {} }', "function_item"),
    ("a.sh", 'f() { printf x; }\nf\n', "function_definition"),
    ("a.sh", 'f() { printf x; }\nf\n', "command"),
])
def test_omitted_interface_fails_actual_admission(tmp_path: Path, path: str, source: str, form: str, optional_parser: None) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / path).write_text(source, encoding="utf-8")
    observed = discover(tmp_path)
    omitted = next(row["surface_id"] for row in observed["surfaces"] if row["form"] == form)
    document = build_template(tmp_path)["manifest"]
    document["objects"][0]["surfaces"].remove(omitted)
    save(tmp_path, document)
    report = assess(tmp_path)
    assert any(row["code"] == "NAMESPACE_SURFACE_UNCOVERED" and row["surface_id"] == omitted for row in report["findings"])
    assert report["independent_reconciliation"]["status"] == "PASS"
    assert "systems_mechanism_digest" in report["independent_reconciliation"]["receipt"]


@pytest.mark.parametrize("source,code", [
    (b'include!(concat!(env!("OUT_DIR"), "/generated.rs"));', "NAMESPACE_RUST_EXPANSION_UNRESOLVED"),
    (b'const ROOT: &str = env!("OUT_DIR");', "NAMESPACE_RUST_EXPANSION_UNRESOLVED"),
    (b'const NAME: &str = concat!("generated", ".rs");', "NAMESPACE_RUST_EXPANSION_UNRESOLVED"),
    (b'#[cfg(feature="robot")] fn f() {}', "NAMESPACE_RUST_EXPANSION_UNRESOLVED"),
    (b'macro_rules! publish { () => { pub fn hidden() {} } } publish!();', "NAMESPACE_RUST_EXPANSION_UNRESOLVED"),
    (b'mod external;', "NAMESPACE_RUST_MODULE_UNRESOLVED"),
    (b'pub use crate::other::{A, B as Alias, *};', "NAMESPACE_RUST_EXPORTS_UNRESOLVED"),
])
def test_unexpanded_rust_interfaces_are_never_complete(source: bytes, code: str, optional_parser: None) -> None:
    result = adapter.discover([("a.rs", source)])
    assert result["surfaces"] and any(row["code"] == code for row in result["gaps"])


def _write_rust_toolchain_and_lock(root: Path, *, serde_checksum: str | None = None) -> None:
    (root / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.97"\ncomponents = ["rust-src"]\nprofile = "minimal"\n',
        encoding="utf-8",
    )
    selected = serde_checksum or "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e"
    (root / "Cargo.lock").write_text(
        'version = 4\n\n'
        '[[package]]\nname = "serde"\nversion = "1.0.228"\n'
        f'checksum = "{selected}"\n\n'
        '[[package]]\nname = "serde_derive"\nversion = "1.0.228"\n'
        'checksum = "d540f220d3187173da220f885ab66608367b6574e925011a9353e4badda91d79"\n\n'
        '[[package]]\nname = "risc0-build"\nversion = "3.0.6"\n'
        'checksum = "bd8216cdd9f573808a94769767480b06ad1e74ae60841c9582fdf51b8e29ba53"\n',
        encoding="utf-8",
    )


def test_exact_pinned_serde_derives_have_source_bound_trait_surfaces(
        tmp_path: Path, optional_parser: None) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "subject"\nversion = "0.1.0"\n\n'
        '[dependencies]\nserde = { version = "=1.0.228", features = ["derive"] }\n',
        encoding="utf-8",
    )
    _write_rust_toolchain_and_lock(tmp_path)
    (tmp_path / "src" / "lib.rs").write_text(
        '#[derive(Clone, Deserialize, Serialize)]\npub struct Device { pub reading: u64 }\n',
        encoding="utf-8",
    )
    report = discover(tmp_path)
    rows = [row for row in report["surfaces"] if row["form"] == "RustExternalDerive"]
    assert len(rows) == 2
    assert {"serde::Deserialize", "serde::Serialize"} == {
        "serde::" + row["surface_id"].split("serde::", 1)[1].split("@", 1)[0] for row in rows}
    assert not any(row["code"] == "NAMESPACE_RUST_EXPANSION_UNRESOLVED" for row in report["gaps"])
    binding = report["systems_mechanism"]["rust_expansion_binding"]
    assert binding["bindings"][0]["kind"] == "SERDE_DERIVE_1_0_228"
    assert "NO_BUILD_SUCCESS" in binding["claim_scope"]


def test_serde_binding_fails_closed_when_lock_checksum_differs(
        tmp_path: Path, optional_parser: None) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "subject"\nversion = "0.1.0"\n\n'
        '[dependencies]\nserde = { version = "=1.0.228", features = ["derive"] }\n',
        encoding="utf-8",
    )
    _write_rust_toolchain_and_lock(tmp_path, serde_checksum="0" * 64)
    (tmp_path / "src" / "lib.rs").write_text(
        '#[derive(Serialize)]\npub struct Device { pub reading: u64 }\n', encoding="utf-8")
    report = discover(tmp_path)
    assert any(row["code"] == "NAMESPACE_RUST_EXPANSION_UNRESOLVED" for row in report["gaps"])
    assert not any(row["form"] == "RustExternalDerive" for row in report["surfaces"])


def test_exact_risc0_embed_methods_has_source_bound_generated_constant_names(
        tmp_path: Path, optional_parser: None) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "guest").mkdir()
    _write_rust_toolchain_and_lock(tmp_path)
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "methods"\nversion = "0.1.0"\n\n'
        '[build-dependencies]\nrisc0-build = { version = "=3.0.6" }\n\n'
        '[package.metadata.risc0]\nmethods = ["guest"]\n', encoding="utf-8")
    (tmp_path / "guest" / "Cargo.toml").write_text(
        '[package]\nname = "vstd-zk-guest"\nversion = "0.1.0"\n', encoding="utf-8")
    (tmp_path / "build.rs").write_text(
        'fn main() {\n    risc0_build::embed_methods();\n}\n', encoding="utf-8")
    (tmp_path / "src" / "lib.rs").write_text(
        'include!(concat!(env!("OUT_DIR"), "/methods.rs"));\n', encoding="utf-8")
    report = discover(tmp_path)
    rows = [row for row in report["surfaces"] if row["form"] == "RustGeneratedConst"]
    assert len(rows) == 2
    assert any("VSTD_ZK_GUEST_ELF" in row["surface_id"] for row in rows)
    assert any("VSTD_ZK_GUEST_ID" in row["surface_id"] for row in rows)
    assert not any(row["code"] == "NAMESPACE_RUST_EXPANSION_UNRESOLVED" for row in report["gaps"])
    assert report["systems_mechanism"]["rust_expansion_binding"]["bindings"][0]["kind"] == (
        "RISC0_EMBED_METHODS_3_0_6")


@pytest.mark.parametrize("macro", ["assert", "debug_assert", "println", "eprintln", "vec"])
def test_declaration_neutral_builtin_macro_is_an_exact_invocation_surface(macro: str, optional_parser: None) -> None:
    result = adapter.discover([("a.rs", f"fn f() {{ {macro}!(true); }}".encode())])
    rows = [row for row in result["surfaces"] if row["form"] == "RustBuiltinMacroInvocation"]
    assert len(rows) == 1 and macro in rows[0]["surface_id"]
    assert not result["gaps"]


@pytest.mark.parametrize("source", [
    b'macro_rules! println { ($value:expr) => {}; } fn f() { println!("x"); }',
    b'use custom::assert; fn f() { assert!(true); }',
    b'use custom::*; fn f() { vec![1]; }',
])
def test_shadowable_builtin_macro_names_do_not_receive_builtin_semantics(source: bytes, optional_parser: None) -> None:
    result = adapter.discover([("a.rs", source)])
    assert not any(row["form"] == "RustBuiltinMacroInvocation" for row in result["surfaces"])
    assert any(row["code"] == "NAMESPACE_RUST_EXPANSION_UNRESOLVED" for row in result["gaps"])


def test_builtin_derives_are_exact_target_bound_surfaces(optional_parser: None) -> None:
    traits = ["Clone", "Copy", "Debug", "Default", "Eq", "Hash", "Ord", "PartialEq", "PartialOrd"]
    source = ("#[derive(" + ", ".join(traits) + ")] pub struct Device {}\n").encode()
    result = adapter.discover([("a.rs", source)])
    rows = [row for row in result["surfaces"] if row["form"] == "RustDerive"]
    assert len(rows) == len(traits)
    assert all("Device.<derive:" in row["surface_id"] for row in rows)
    assert all(any(trait in row["surface_id"] for row in rows) for trait in traits)
    assert not result["gaps"]


@pytest.mark.parametrize("declaration", [
    "pub struct Device {}",
    "pub enum Device { One }",
    "pub union Device { value: u64 }",
])
def test_builtin_derive_binding_names_each_data_item_target(declaration: str, optional_parser: None) -> None:
    result = adapter.discover([("a.rs", ("#[derive(Clone)] " + declaration).encode())])
    rows = [row for row in result["surfaces"] if row["form"] == "RustDerive"]
    assert len(rows) == 1 and "Device.<derive:Clone@" in rows[0]["surface_id"]
    assert not result["gaps"]


@pytest.mark.parametrize("source", [
    b'#[derive(Clone, Serialize)] pub struct Device {}',
    b'use custom::Clone; #[derive(Clone)] pub struct Device {}',
    b'use custom::*; #[derive(Clone)] pub enum Device { One }',
    b'#[derive(Clone)] fn Device() {}',
    b'#[derive(serde::Serialize)] pub union Device { value: u64 }',
])
def test_custom_shadowed_or_unsupported_derives_stay_unresolved(source: bytes, optional_parser: None) -> None:
    result = adapter.discover([("a.rs", source)])
    assert any(row["code"] == "NAMESPACE_RUST_EXPANSION_UNRESOLVED" for row in result["gaps"])


def test_cross_file_macro_definition_prevents_builtin_assumption(optional_parser: None) -> None:
    result = adapter.discover([
        ("lib.rs", b'macro_rules! println { ($value:expr) => {}; }'),
        ("child.rs", b'fn f() { println!("x"); }'),
    ])
    child = [row for row in result["surfaces"] if row["path"] == "child.rs"]
    assert not any(row["form"] == "RustBuiltinMacroInvocation" for row in child)
    assert any(row["path"] == "child.rs" and row["code"] == "NAMESPACE_RUST_EXPANSION_UNRESOLVED"
        for row in result["gaps"])


def test_grouped_reexports_keep_each_name(optional_parser: None) -> None:
    result = adapter.discover([("a.rs", b'pub use crate::other::{A, B as Alias, *};')])
    rows = [row for row in result["surfaces"] if row["form"] == "RustExport"]
    assert len(rows) == 3
    assert any("export:Alias@" in row["surface_id"] for row in rows)


@pytest.mark.parametrize("source", [b'eval "$code"', b'. ./other.sh', b'source ./other.sh', b'$command arg',
    b'"eval" "$code"', b'alias generate=eval', b'builtin eval "$code"', b'bash -c "$code"', b'export "$name=value"'])
def test_dynamic_shell_interfaces_stay_unresolved(source: bytes, optional_parser: None) -> None:
    result = adapter.discover([("a.sh", source)])
    assert any(row["code"] == "NAMESPACE_SHELL_DYNAMIC_SURFACES_UNRESOLVED" for row in result["gaps"])


@pytest.mark.parametrize("source", [b'#!/bin/zsh\necho ok', b'#!/usr/bin/env -S bash -e\necho ok'])
def test_unselected_shell_dialects_are_not_assumed(source: bytes, optional_parser: None) -> None:
    assert any(row["code"] == "NAMESPACE_SHELL_DIALECT_UNRESOLVED" for row in adapter.discover([("a.sh", source)])["gaps"])


@pytest.mark.parametrize("path,source", [("a.rs", b'pub fn broken( {'), ("a.sh", b'if true; then'), ("a.rs", b'\xff'), ("a.sh", b'\xff')])
def test_invalid_source_never_becomes_empty_success(path: str, source: bytes, optional_parser: None) -> None:
    result = adapter.discover([(path, source)])
    assert not result["surfaces"] and result["gaps"]


@pytest.mark.parametrize("name", ["__vstd_kinds__", "r#__vstd_kinds__"])
def test_literal_rust_roles_survive_generic_labeling(name: str, optional_parser: None) -> None:
    result = adapter.discover([("a.rs", ('const ' + name + ': &[&str] = &["ROBOT", "FINBOT"]; fn f() {}').encode())])
    assert all(row["source_kinds"] == ["FINBOT", "ROBOT"] and not row["unresolved_marker"] for row in result["surfaces"])


@pytest.mark.parametrize("path,source", [
    ("a.rs", b'const __vstd_kinds__: &[&str] = make();'),
    ("a.rs", b'static __vstd_kinds__: &[&str] = &["ROBOT"];'),
    ("a.rs", b'fn f() { const __vstd_kinds__: &[&str] = &["ROBOT"]; }'),
    ("a.rs", b'const __vstd_kinds__: &[&str] = &["BOT"]; fn f() { expose(__vstd_kinds__); }'),
    ("a.sh", b'__vstd_kinds__=(ROBOT FINBOT)\nf() { :; }'),
    ("a.sh", b'__vstd_kinds__=$roles'),
])
def test_unresolved_marker_cannot_erase_necessary_roles(path: str, source: bytes, optional_parser: None) -> None:
    result = adapter.discover([(path, source)])
    assert result["surfaces"] and all(row["unresolved_marker"] for row in result["surfaces"])
    if b'ROBOT' in source:
        assert all("ROBOT" in row["source_kinds"] for row in result["surfaces"])


def test_subject_and_shadow_parser_never_execute(tmp_path: Path, optional_parser: None) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    marker = tmp_path / "executed.txt"
    (tmp_path / "subject.sh").write_text('printf unsafe > executed.txt\n', encoding="utf-8")
    (tmp_path / "subject.rs").write_text('fn main() { std::fs::write("executed.txt", "unsafe"); }', encoding="utf-8")
    (tmp_path / "tree_sitter_rust.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\nraise RuntimeError()\n", encoding="utf-8")
    report = discover(tmp_path)
    assert not marker.exists() and set(report["systems_mechanism"]["parsers"]) == {"rust", "bash"}


def test_one_missing_grammar_does_not_drop_other_language(monkeypatch: pytest.MonkeyPatch, optional_parser: None) -> None:
    original = adapter._run

    def selected(files: list, languages: list) -> dict:
        if languages == ["bash"]:
            raise ValueError("controlled grammar unavailable")
        return original(files, languages)

    monkeypatch.setattr(adapter, "_run", selected)
    report = adapter.discover([("a.rs", b'fn f() {}'), ("a.sh", b':')])
    assert set(report["mechanism"]["parsers"]) == {"rust"}
    assert {row["path"] for row in report["surfaces"]} == {"a.rs"}
    assert {row["path"] for row in report["gaps"]} == {"a.sh"}


def test_no_systems_files_does_not_launch_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "_run", lambda *args: pytest.fail("unexpected parser"))
    assert adapter.discover([]) == {"surfaces": [], "gaps": [], "mechanism": None}


def test_parser_timeout_preserves_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*args: Any, **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired("fixed-parser", 45)
    monkeypatch.setattr(adapter.subprocess, "run", timeout)
    assert adapter.discover([("a.rs", b'fn f() {}')])["gaps"][0]["code"] == "NAMESPACE_LANGUAGE_DISCOVERY_UNSUPPORTED"


def test_parser_recapture_detects_changed_bytes(monkeypatch: pytest.MonkeyPatch, optional_parser: None) -> None:
    mechanism = adapter.discover([("a.rs", b'fn f() {}')])["mechanism"]
    adapter.recapture(mechanism)
    changed = deepcopy(mechanism["parsers"]["rust"])
    changed["worker"] = "sha256:" + "0" * 64
    monkeypatch.setattr(adapter, "_run", lambda *args: {"mechanism": changed})
    with pytest.raises(ValueError, match="MECHANISM_CHANGED"):
        adapter.recapture(mechanism)


@pytest.mark.parametrize("fault", ["path", "source", "surface", "gap", "mechanism", "line", "form", "roles",
    "row-type", "surface-type", "gap-type", "duplicate", "empty", "line-range", "marker", "hints", "version", "files"])
def test_malformed_parser_response_is_not_coverage(monkeypatch: pytest.MonkeyPatch, fault: str, optional_parser: None) -> None:
    report = adapter._run([("a.rs", b'fn f() {}')], ["rust"])
    report["mechanism"].pop("worker")
    row = report["files"][0]
    if fault == "path":
        row["path"] = "other.rs"
    elif fault == "source":
        row["source_digest"] = "sha256:" + "0" * 64
    elif fault == "surface":
        row["surfaces"][0]["surface_id"] = "rust:other.rs:f"
    elif fault == "gap":
        row["gaps"] = [{"path": "other.rs", "code": "NAMESPACE_SYSTEMS_PARSE_UNAVAILABLE", "reason": "wrong"}]
    elif fault == "mechanism":
        report["mechanism"] = None
    elif fault == "line":
        row["surfaces"][0]["line"] = True
    elif fault == "form":
        row["surfaces"][0]["form"] = None
    elif fault == "roles":
        row["surfaces"][0]["source_kinds"] = [False]
    elif fault == "row-type":
        report["files"][0] = None
    elif fault == "surface-type":
        row["surfaces"][0] = None
    elif fault == "gap-type":
        row["gaps"] = [None]
    elif fault == "duplicate":
        row["surfaces"].append(deepcopy(row["surfaces"][0]))
    elif fault == "empty":
        row["surfaces"] = []
    elif fault == "line-range":
        row["surfaces"][0]["line"] = 999
    elif fault == "marker":
        row["surfaces"][0]["unresolved_marker"] = 1
    elif fault == "hints":
        row["surfaces"][0]["hints"] = ["ROBOT", "ROBOT"]
    elif fault == "version":
        report["mechanism"]["distributions"]["tree-sitter"]["version"] = "unselected"
    else:
        report["mechanism"]["distributions"]["tree-sitter"]["files"] = {}
    monkeypatch.setattr(adapter.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, json.dumps(report).encode(), b""))
    result = adapter.discover([("a.rs", b'fn f() {}')])
    assert not result["surfaces"] and result["gaps"]


@pytest.mark.parametrize("source,count", [
    (b'pub use crate::{a::{B,C as D}, e::F};', 3),
    (b'pub use crate::a::{self, A};', 2),
    (b'pub use crate::a::B;', 1),
])
def test_nested_export_qualifiers_are_not_extra_interfaces(source: bytes, count: int, optional_parser: None) -> None:
    rows = adapter.discover([("a.rs", source)])["surfaces"]
    assert sum(row["form"] == "RustExport" for row in rows) == count


def test_package_requirements_recheck_the_selected_parser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, optional_parser: None) -> None:
    from verifier.runtime.package_kind_requirements import KindRequirements
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "subject.rs").write_text('fn f() {}', encoding="utf-8")
    document = build_template(tmp_path)["manifest"]
    selected = KindRequirements(tmp_path, document)
    assert selected.report["systems_mechanism"] == adapter.discover([("subject.rs", b'fn f() {}')])["mechanism"]
    selected.recapture()
    original = adapter._run

    def changed(files: list, languages: list) -> dict:
        report = original(files, languages)
        report["mechanism"]["worker"] = "sha256:" + "0" * 64
        return report

    monkeypatch.setattr(adapter, "_run", changed)
    with pytest.raises(ValueError, match="NAMESPACE_SYSTEMS_MECHANISM_CHANGED"):
        selected.recapture()


def test_generated_rust_gap_targets_its_owner_and_evidence(tmp_path: Path, optional_parser: None) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "subject.rs").write_text('include!("generated.rs");', encoding="utf-8")
    document = build_template(tmp_path)["manifest"]
    save(tmp_path, document)
    report = assess(tmp_path)
    gap = next(row for row in report["findings"] if row["code"] == "NAMESPACE_RUST_EXPANSION_UNRESOLVED")
    assert gap["object_id"] == document["objects"][0]["object_id"]
    assert "macro/build inputs" in gap["next_action"] and "subject.rs" in gap["next_action"]
    assert gap["status"] == "UNKNOWN"
