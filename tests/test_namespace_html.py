"""Source markup coverage for Verifier Standard (VSTD).

Hypertext Markup Language (HTML) syntax is not browser execution evidence.
"""
from __future__ import annotations

from pathlib import Path
from importlib import metadata
import json
import subprocess
from typing import Any

import pytest

from verifier.runtime.namespace_discovery import discover
from verifier.runtime.namespace_admission import assess, build_template
from verifier.runtime import namespace_html, namespace_javascript
from verifier.runtime.tier_zero_profile import value_digest
from test_namespace_admission import save


@pytest.fixture
def javascript_parser() -> None:
    for name, version in (("tree-sitter", "0.25.2"), ("tree-sitter-javascript", "0.25.0")):
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            installed = None
        if installed != version:
            pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: embedded JavaScript requires the pinned discovery-javascript extra")


def repository(root: Path, source: str, name: str = "index.html") -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / name).write_text(source, encoding="utf-8")
    return root


@pytest.mark.usefixtures("javascript_parser")
def test_markup_and_inline_methods_are_owned_individually(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, '<html><body><script>class Ledger { post() {} }</script></body></html>'))
    assert any(row["form"] == "HTMLElement" for row in result["surfaces"])
    assert any(row["form"] == "method_definition" for row in result["surfaces"])
    assert not result["gaps"]


@pytest.mark.usefixtures("javascript_parser")
def test_decoded_event_handler_has_its_own_source_binding(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, '<button onclick="const f = () =&gt; 1; return f();">Go</button>'))
    assert any(row["form"] == "HTMLHandler" for row in result["surfaces"])
    assert any(row["form"] == "arrow_function" for row in result["surfaces"])
    assert result["embedded_sources"][0]["mode"] == "decoded-handler"


@pytest.mark.usefixtures("javascript_parser")
def test_source_kind_annotations_inherit_into_embedded_code(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, '<section data-vstd-kinds=\'["FINBOT"]\'><script>function decide() {}</script></section>'))
    function = next(row for row in result["surfaces"] if row["form"] == "function_declaration")
    assert function["source_kinds"] == ["FINBOT"]


@pytest.mark.usefixtures("javascript_parser")
def test_parent_and_script_roles_accumulate(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, '<section data-vstd-kinds=\'["BOT"]\'><script>const __vstd_kinds__ = ["FINBOT"]; function trade() {}</script></section>'))
    function = next(row for row in result["surfaces"] if row["form"] == "function_declaration")
    assert function["source_kinds"] == ["BOT", "FINBOT"]


@pytest.mark.usefixtures("javascript_parser")
def test_missing_handler_or_inline_method_fails_admission(tmp_path: Path) -> None:
    root = repository(tmp_path, '<button onclick="function hidden() {}">Run</button><script>class Ledger { post() {} }</script>')
    manifest = build_template(root)["manifest"]
    observed = discover(root)
    omitted = {row["surface_id"] for row in observed["surfaces"] if row["form"] in {"HTMLHandler", "method_definition"}}
    for owner in manifest["objects"]:
        owner["surfaces"] = [surface for surface in owner["surfaces"] if surface not in omitted]
    save(root, manifest)
    report = assess(root)
    failed = {row["surface_id"] for row in report["findings"] if row["code"] == "NAMESPACE_SURFACE_UNCOVERED"}
    assert omitted <= failed
    assert report["independent_reconciliation"]["status"] == "PASS"


def test_pure_markup_and_data_scripts_need_no_optional_parser(tmp_path: Path, monkeypatch: Any) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("optional parser unexpectedly launched")
    monkeypatch.setattr(namespace_javascript, "_run", forbidden)
    result = discover(repository(tmp_path, '<!doctype html><html><body><script type="application/json">{"example":"<script>"}</script></body></html>'))
    assert not result["gaps"] and not result["embedded_sources"]
    assert result["html_mechanism"] and result["javascript_mechanism"] is None


def test_empty_script_has_a_surface_without_an_optional_parser(tmp_path: Path, monkeypatch: Any) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("optional parser unexpectedly launched")
    monkeypatch.setattr(namespace_javascript, "_run", forbidden)
    result = discover(repository(tmp_path, '<script> \n </script>'))
    assert any(row["form"] == "HTMLScript" for row in result["surfaces"])
    assert not result["embedded_sources"] and not result["gaps"]


@pytest.mark.parametrize(("source", "code"), [
    ('<div><span></div>', "PARSE_UNRESOLVED"),
    ('<script>function notClosed() {}', "PARSE_UNRESOLVED"),
    ('<script/>', "PARSE_UNRESOLVED"),
    ('<button onclick="first()" onclick="second()"></button>', "PARSE_UNRESOLVED"),
    ('<iframe srcdoc="&lt;script&gt;hidden()&lt;/script&gt;"></iframe>', "EMBEDDED_DOCUMENT_UNRESOLVED"),
    ('<a href="java&#10;script:execute()">Go</a>', "EXECUTABLE_ADDRESS_UNRESOLVED"),
    ('<object data="data:text/html,hidden"></object>', "EXECUTABLE_ADDRESS_UNRESOLVED"),
    ('<script type="text/lua">function hidden() end</script>', "SCRIPT_TYPE_UNSUPPORTED"),
    ('<script type="importmap">{}</script>', "SCRIPT_TYPE_UNSUPPORTED"),
    ('<script language="vbscript">hidden()</script>', "SCRIPT_TYPE_UNSUPPORTED"),
    ('<noscript><button onclick="hidden()">Go</button></noscript>', "CONTEXT_UNRESOLVED"),
    ('<svg><script>hidden()</script></svg>', "CONTEXT_UNRESOLVED"),
    ('<?render template?><div></div>', "TEMPLATE_UNRESOLVED"),
    ('<div>{{generated_markup}}</div>', "TEMPLATE_UNRESOLVED"),
    ('<meta charset="windows-1252">', "ENCODING_UNRESOLVED"),
    ('<div>\x00</div>', "PARSE_UNRESOLVED"),
    ('<!--><script>function hidden() {}</script>', "PARSE_UNRESOLVED"),
    ('<![bogus]><script>function hidden() {}</script>', "PARSE_UNAVAILABLE"),
    ('<button :onclick="expression">Go</button>', "TEMPLATE_UNRESOLVED"),
    ('<custom-element></custom-element>', "CONTEXT_UNRESOLVED"),
])
def test_unsupported_interpretations_remain_explicit_gaps(tmp_path: Path, source: str, code: str) -> None:
    result = discover(repository(tmp_path, source))
    assert any(row["code"] == "NAMESPACE_HTML_" + code for row in result["gaps"])


@pytest.mark.parametrize(("source", "comment", "code"), [
    ("<!--><script>hidden()</script>", "", "NAMESPACE_HTML_PARSE_UNRESOLVED"),
    ("<![bogus]><script>hidden()</script>", "[bogus]", "NAMESPACE_HTML_PARSE_UNAVAILABLE"),
])
def test_recovered_malformed_comment_still_reports_gap(source: str, comment: str, code: str) -> None:
    # Newer HTMLParser versions may recover both forms as comments rather than
    # reporting an error; exercise that callback independent of interpreter version.
    from verifier.runtime.namespace_html import _Census
    parser = _Census("fixture.html", source, {})
    parser.handle_comment(comment)
    assert any(row["code"] == code for row in parser.gaps)


def test_literal_template_tokens_are_not_rendered_coverage(tmp_path: Path) -> None:
    root = repository(tmp_path, '<div>static source</div>', "home.html.in")
    manifest = build_template(root)["manifest"]
    save(root, manifest)
    report = assess(root)
    finding = next(row for row in report["findings"] if row["code"] == "NAMESPACE_HTML_TEMPLATE_UNRESOLVED")
    assert "generated markup" in finding["next_action"]
    assert "Install" not in finding["next_action"]


def test_template_binding_selects_current_renderer_and_closed_tokens(tmp_path: Path) -> None:
    source = ('<!-- vstd-template-binding {"mode":"literal-replacement",'
              '"reason":"A selected renderer replaces this one bounded token.",'
              '"renderer":"render.py","tokens":["{{release}}"]} -->'
              '<a href="{{release}}">release</a>')
    root = repository(tmp_path, source, "home.html.in")
    (root / "render.py").write_text('def render(value):\n    return value.replace("{{release}}", "1.0")\n',
                                    encoding="utf-8")
    result = discover(root)
    assert not result["gaps"]
    assert any(row["form"] == "HTMLTemplateBinding" for row in result["surfaces"])
    assert any(row["form"] == "HTMLTemplateToken" for row in result["surfaces"])
    reference = next(row for row in result["markup_code_references"]
                     if row["scope"] == "DECLARED_TEMPLATE_RENDERER_SOURCE_NOT_EXECUTION")
    assert reference["target_path"] == "render.py" and reference["target_source_digest"]


@pytest.mark.parametrize("fault", ["missing-renderer", "missing-token", "extra-token", "directive"])
def test_template_binding_drift_remains_explicit_unknown(tmp_path: Path, fault: str) -> None:
    renderer = "missing.py" if fault == "missing-renderer" else "render.py"
    tokens = [] if fault == "missing-token" else ["{{release}}", "{{unused}}"] if fault == "extra-token" else ["{{release}}"]
    suffix = "{% dynamic %}" if fault == "directive" else ""
    source = ('<!-- vstd-template-binding ' + json.dumps({
        "mode": "literal-replacement",
        "reason": "A selected renderer replaces the declared token.",
        "renderer": renderer,
        "tokens": tokens,
    }, separators=(",", ":")) + ' -->' + '<p>{{release}}</p>' + suffix)
    root = repository(tmp_path, source, "home.html.in")
    (root / "render.py").write_text("def render(value):\n    return value\n", encoding="utf-8")
    result = discover(root)
    assert any(row["code"] == "NAMESPACE_HTML_TEMPLATE_UNRESOLVED" for row in result["gaps"])


@pytest.mark.parametrize("address", ["https://example.invalid/script.js", "../outside.js", "/app.js", "app.js?variant=other", "app.js#fragment"])
def test_unbound_script_resources_are_not_fetched(tmp_path: Path, address: str) -> None:
    result = discover(repository(tmp_path, f'<script src="{address}"></script>'))
    assert any(row["code"] == "NAMESPACE_HTML_EXTERNAL_CODE_UNRESOLVED" for row in result["gaps"])
    assert not result["markup_code_references"]


@pytest.mark.usefixtures("javascript_parser")
def test_selected_relative_script_reference_binds_current_bytes(tmp_path: Path) -> None:
    root = repository(tmp_path, '<script src="app.js"></script>')
    target = root / "app.js"
    target.write_text("function first() {}", encoding="utf-8")
    before = discover(root)
    target.write_text("function changed() {}", encoding="utf-8")
    after = discover(root)
    assert not before["gaps"] and not after["gaps"]
    assert before["markup_code_references"][0]["target_source_digest"] != after["markup_code_references"][0]["target_source_digest"]
    assert after["markup_code_references"][0]["target_path"] == "app.js"


@pytest.mark.usefixtures("javascript_parser")
def test_base_address_invalidates_a_local_script_assumption(tmp_path: Path) -> None:
    root = repository(tmp_path, '<base href="https://example.invalid/"><script src="app.js"></script>')
    (root / "app.js").write_text("function local() {}", encoding="utf-8")
    result = discover(root)
    assert not result["markup_code_references"]
    assert any(row["code"] == "NAMESPACE_HTML_BASE_UNRESOLVED" for row in result["gaps"])


@pytest.mark.usefixtures("javascript_parser")
def test_fragment_identity_and_locations_bind_real_source(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, '<div>\n<script>\nfunction same() {}\n</script>\n<script>function same() {}</script>\n<button onclick="const f =&#10;() =&gt; 1;">Go</button>\n</div>'))
    functions = [row for row in result["surfaces"] if row["form"] == "function_declaration"]
    assert len(functions) == len({row["surface_id"] for row in functions}) == 2
    assert [row["line"] for row in functions] == [3, 5]
    assert all(row["path"] == "index.html" for row in result["surfaces"])
    callback = next(row for row in result["surfaces"] if row["form"] == "arrow_function")
    assert callback["line"] == 6 and callback["location_scope"] == "ENCLOSING_TAG"


def test_duplicate_role_attributes_cannot_erase_financial_consequences(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, '<section data-vstd-kinds=\'["FINBOT"]\' data-vstd-kinds=\'["BOT"]\'><button>Go</button></section>'))
    elements = [row for row in result["surfaces"] if row["form"] == "HTMLElement"]
    assert all(row["source_kinds"] == ["BOT", "FINBOT"] and row["unresolved_marker"] for row in elements)


def test_nonliteral_role_annotation_never_becomes_absence(tmp_path: Path) -> None:
    result = discover(repository(tmp_path, '<section data-vstd-kinds="{{roles}}"><button>Go</button></section>'))
    assert all(row["unresolved_marker"] for row in result["surfaces"] if row["form"] == "HTMLElement")


def test_markup_capacity_is_explicit_unknown(monkeypatch: Any) -> None:
    monkeypatch.setattr(namespace_html, "MAX_AST_BYTES", 8)
    report = namespace_html.discover("large.html", b"<div>larger than bound</div>", {})
    assert not report["surfaces"] and report["gaps"][0]["code"] == "NAMESPACE_HTML_PARSE_UNAVAILABLE"


def test_parser_bytes_are_recaptured(monkeypatch: Any) -> None:
    opening = namespace_html.mechanism()
    monkeypatch.setattr(namespace_html, "mechanism", lambda: {"changed": True})
    with pytest.raises(ValueError, match="NAMESPACE_HTML_MECHANISM_CHANGED"):
        namespace_html.recapture(opening)


def test_markup_attributes_are_individually_owned(tmp_path: Path) -> None:
    root = repository(tmp_path, '<button id="submit" class="action">Go</button>')
    result = discover(root)
    attributes = [row for row in result["surfaces"] if row["form"] == "HTMLAttribute"]
    assert len(attributes) == 2
    manifest = build_template(root)["manifest"]
    manifest["objects"][0]["surfaces"].remove(attributes[0]["surface_id"])
    save(root, manifest)
    assert any(row["code"] == "NAMESPACE_SURFACE_UNCOVERED" and row["surface_id"] == attributes[0]["surface_id"] for row in assess(root)["findings"])


@pytest.mark.usefixtures("javascript_parser")
def test_independent_reconciliation_binds_embedded_source_projection(tmp_path: Path, monkeypatch: Any) -> None:
    from verifier.runtime import namespace_admission
    root = repository(tmp_path, '<script>function exposed() {}</script>')
    save(root, build_template(root)["manifest"])
    baseline = assess(root)
    assert baseline["independent_reconciliation"]["status"] == "PASS"
    assert baseline["independent_reconciliation"]["receipt"]["markup_binding_digest"] == value_digest(baseline["markup_binding"])
    original = namespace_admission._run_bounded_reconciler
    def altered(command: list[str], wire: bytes, **kwargs: Any) -> Any:
        if any(str(part).endswith("namespace_reconcile.mjs") for part in command):
            payload = json.loads(wire)
            payload["markup_binding"]["embedded_sources"][0]["source_digest"] = "sha256:" + "0" * 64
            wire = json.dumps(payload).encode()
        return original(command, wire, **kwargs)
    monkeypatch.setattr(namespace_admission, "_run_bounded_reconciler", altered)
    assert assess(root)["independent_reconciliation"]["status"] == "FAIL"
