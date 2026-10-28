"""Executable-document source coverage for Verifier Standard (VSTD).

American Standard Code for Information Interchange (ASCII); Scalable Vector
Graphics (SVG); YAML Ain't Markup Language (YAML).
Source inventory never executes a workflow or establishes browser behavior.
"""
from __future__ import annotations

from pathlib import Path
from importlib import metadata
import json
import re
import subprocess
from typing import Any

import pytest

from verifier.runtime.namespace_discovery import discover
from verifier.runtime.namespace_admission import assess, build_template
from verifier.runtime import (
    namespace_javascript,
    namespace_svg,
    namespace_workflow_worker,
    namespace_workflows,
)
from verifier.runtime.self_polish_estate import bytes_digest
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
            pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: SVG scripts require the pinned discovery-javascript extra")


@pytest.fixture
def workflow_parser() -> None:
    try:
        installed = metadata.version("PyYAML")
    except metadata.PackageNotFoundError:
        installed = None
    if installed != "6.0.3":
        pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: workflow nodes require the pinned discovery-workflows extra")


@pytest.fixture
def workflow_shell_parser(workflow_parser: None) -> None:
    for name, version in (("tree-sitter", "0.25.2"), ("tree-sitter-bash", "0.25.1")):
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            installed = None
        if installed != version:
            pytest.skip("OPTIONAL_DEPENDENCY_ABSENT: literal commands require the pinned discovery-shell extra")


def repository(root: Path, name: str, source: str) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return root


@pytest.mark.usefixtures("javascript_parser")
def test_svg_scripts_have_individually_owned_functions(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, "image.svg",
        '<svg xmlns="http://www.w3.org/2000/svg"><script>function exposed() {}</script></svg>'))
    assert any(row["form"] == "SVGScript" for row in observed["surfaces"])
    assert any(row["form"] == "function_declaration" for row in observed["surfaces"])


@pytest.mark.usefixtures("workflow_shell_parser")
def test_workflow_commands_have_source_owned_boundaries(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, ".github/workflows/check.yml",
        'name: check\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo subject-process\n'))
    assert any(row["form"] == "WorkflowJob" for row in observed["surfaces"])
    assert any(row["form"] == "WorkflowRun" for row in observed["surfaces"])
    assert observed["workflow_binding"]["commands"]
    command = observed["workflow_binding"]["commands"][0]
    assert command["shell_candidates"] == ["bash"]
    assert command["programs"] == [{"program": "echo", "line": 7, "scope": "LITERAL_DISPATCH_NOT_EXECUTION"}]
    assert not any(row["code"] == "NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED" for row in observed["gaps"])


def test_inert_svg_has_no_optional_parser_dependency(tmp_path: Path, monkeypatch: Any) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("optional parser unexpectedly started")
    monkeypatch.setattr(namespace_javascript, "_run", forbidden)
    monkeypatch.setattr(namespace_workflows, "_run", forbidden)
    observed = discover(repository(tmp_path, "image.svg", '<svg xmlns="http://www.w3.org/2000/svg"><rect width="3"/></svg>'))
    assert not observed["gaps"] and observed["svg_mechanism"]
    assert any(row["form"] == "SVGAttribute" for row in observed["surfaces"])
    assert not any("\x1f" in row["surface_id"] for row in observed["surfaces"])


@pytest.mark.usefixtures("javascript_parser")
def test_svg_roles_accumulate_through_decoded_script_and_handler(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, "image.svg", '<svg xmlns="http://www.w3.org/2000/svg" data-vstd-kinds=\'["BOT"]\'>\n'
        '<g data-vstd-kinds=\'["FINBOT"]\' onload="const f=&#10;()=&gt;1;"><script><![CDATA[function trade() {}]]></script></g></svg>'))
    code = [row for row in observed["surfaces"] if row["form"] in {"function_declaration", "arrow_function"}]
    assert len(code) == 2 and all(row["source_kinds"] == ["BOT", "FINBOT"] for row in code)
    assert all(row["path"] == "image.svg" and row["line"] == 2 and row["location_scope"] == "ENCLOSING_TAG" for row in code)
    assert all(row["mode"] == "decoded-svg" for row in observed["embedded_sources"])


@pytest.mark.parametrize(("body", "code"), [
    ('<!DOCTYPE svg [<!ENTITY payload "hidden">]><svg/>', "PARSE_UNAVAILABLE"),
    ('<!DOCTYPE svg SYSTEM "https://example.invalid/schema"><svg/>', "PARSE_UNAVAILABLE"),
    ('<svg xmlns="http://www.w3.org/2000/svg" a="1" a="2"/>', "PARSE_UNAVAILABLE"),
    ('<svg xmlns="http://www.w3.org/2000/svg"><g></svg>', "PARSE_UNAVAILABLE"),
    ('<svg><g/></svg>', "CONTEXT_UNRESOLVED"),
    ('<svg xmlns="http://www.w3.org/2000/svg"><use href="#shape"/></svg>', "CONTEXT_UNRESOLVED"),
    ('<svg xmlns="http://www.w3.org/2000/svg"><set attributeName="href" to="external"/></svg>', "CONTEXT_UNRESOLVED"),
    ('<svg xmlns="http://www.w3.org/2000/svg"><script><g>function nested() {}</g></script></svg>', "CONTEXT_UNRESOLVED"),
    ('<svg xmlns="http://www.w3.org/2000/svg"><style>@import "external.css";</style></svg>', "STYLE_UNRESOLVED"),
    ('<?xml-stylesheet href="external.css"?><svg xmlns="http://www.w3.org/2000/svg"/>', "INSTRUCTION_UNRESOLVED"),
    ('<svg xmlns="http://www.w3.org/2000/svg"><script type="text/lua">hidden()</script></svg>', "SCRIPT_TYPE_UNSUPPORTED"),
])
def test_svg_unsupported_interpretation_is_not_coverage(body: str, code: str) -> None:
    result = namespace_svg.discover("image.svg", body.encode(), {})
    assert any(row["code"] == "NAMESPACE_SVG_" + code for row in result["gaps"])


@pytest.mark.usefixtures("javascript_parser")
def test_omitted_svg_function_fails_admission(tmp_path: Path) -> None:
    root = repository(tmp_path, "image.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>function owned() {}</script></svg>')
    observed = discover(root)
    missing = next(row["surface_id"] for row in observed["surfaces"] if row["form"] == "function_declaration")
    manifest = build_template(root)["manifest"]
    manifest["objects"][0]["surfaces"].remove(missing)
    save(root, manifest)
    report = assess(root)
    assert any(row["code"] == "NAMESPACE_SURFACE_UNCOVERED" and row["surface_id"] == missing for row in report["findings"])
    assert report["independent_reconciliation"]["status"] == "PASS"


def test_svg_external_sources_bind_only_unambiguous_selected_files() -> None:
    raw = b'<svg xmlns="http://www.w3.org/2000/svg"><script href="code.js"/></svg>'
    bound = namespace_svg.discover("images/image.svg", raw, {"images/code.js": "sha256:" + "a" * 64})
    assert bound["references"][0]["target_path"] == "images/code.js"
    unresolved = namespace_svg.discover("images/image.svg", raw.replace(b"code.js", b"https://example.invalid/code.js"), {})
    assert not unresolved["references"] and unresolved["gaps"]


def test_svg_parser_binding_is_recaptured(monkeypatch: Any) -> None:
    before = namespace_svg.mechanism()
    monkeypatch.setattr(namespace_svg, "mechanism", lambda: {})
    with pytest.raises(ValueError, match="SVG_MECHANISM_CHANGED"):
        namespace_svg.recapture(before)


def test_svg_namespace_declarations_are_owned(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, "image.svg", '<svg xmlns="http://www.w3.org/2000/svg" xmlns:x="http://www.w3.org/1999/xlink"/>'))
    assert len([row for row in observed["surfaces"] if row["form"] == "SVGNamespace"]) == 2


def test_svg_capacity_is_fail_closed(monkeypatch: Any) -> None:
    monkeypatch.setattr(namespace_svg, "MAX_AST_BYTES", 1)
    observed = namespace_svg.discover("image.svg", b"<svg/>", {})
    assert not observed["surfaces"] and observed["gaps"][0]["code"] == "NAMESPACE_SVG_PARSE_UNAVAILABLE"


@pytest.mark.usefixtures("workflow_parser")
def test_workflow_parser_bytes_are_recaptured(monkeypatch: Any) -> None:
    expected = {"mechanism": namespace_workflows._run([], {})["mechanism"]}
    monkeypatch.setattr(namespace_workflows, "_run", lambda *args: {"mechanism": {}})
    with pytest.raises(ValueError, match="WORKFLOW_MECHANISM_CHANGED"):
        namespace_workflows.recapture(expected)


@pytest.mark.usefixtures("workflow_parser")
def test_composite_steps_and_reusable_workflow_have_explicit_bindings(tmp_path: Path) -> None:
    root = repository(tmp_path, ".github/workflows/check.yml", 'jobs: {check: {uses: "./.github/workflows/child.yml"}}\n')
    (root / '.github/workflows/child.yml').write_text('jobs: {check: {steps: [{uses: "./action"}]}}\n', encoding='utf-8')
    action = root / 'action/action.yml'
    action.parent.mkdir()
    action.write_text('runs: {using: composite, steps: [{shell: bash, run: "echo subject"}]}\n', encoding='utf-8')
    observed = discover(root)
    assert {row["target_path"] for row in observed["workflow_binding"]["references"]} == {'.github/workflows/child.yml', 'action/action.yml'}
    assert observed["workflow_binding"]["commands"][0]["shell"] == 'bash'


@pytest.mark.usefixtures("workflow_parser")
def test_ambiguous_local_action_is_not_silently_selected(tmp_path: Path) -> None:
    root = repository(tmp_path, '.github/workflows/check.yml', 'jobs: {check: {steps: [{uses: "./action"}]}}\n')
    folder = root / 'action'
    folder.mkdir()
    for name in ('action.yml', 'action.yaml'):
        (folder / name).write_text('runs: {using: composite, steps: []}\n', encoding='utf-8')
    observed = discover(root)
    assert not observed["workflow_binding"]["references"]
    assert any(row["code"] == "NAMESPACE_WORKFLOW_REFERENCE_UNRESOLVED" for row in observed["gaps"])


@pytest.mark.usefixtures("workflow_parser")
@pytest.mark.parametrize("source", [
    'jobs: {}\njobs: {}\n',
    'jobs: &jobs {repeat: *jobs}\n',
    'jobs: !!python/object/apply:builtins.eval ["1/0"]\n',
    'jobs: {job: {steps: [{run: echo one, run: echo two}]}}\n',
    'jobs: {job: {<<: {steps: []}}}\n',
    'jobs: {}\n---\njobs: {}\n',
])
def test_workflow_ambiguous_yaml_is_refused(tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, ".github/workflows/check.yml", source))
    assert any(row["code"] == "NAMESPACE_WORKFLOW_PARSE_UNAVAILABLE" for row in observed["gaps"])
    assert not observed["workflow_binding"]["commands"]


@pytest.mark.usefixtures("workflow_parser")
def test_workflow_shells_and_repeated_steps_remain_distinct(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, ".github/workflows/check.yml",
        'defaults: {run: {shell: bash}}\njobs:\n  on:\n    steps:\n      - run: echo same\n      - run: echo same\n        shell: pwsh\n'))
    commands = observed["workflow_binding"]["commands"]
    assert len(commands) == 2 and commands[0]["source_digest"] == commands[1]["source_digest"]
    assert commands[0]["surface_id"] != commands[1]["surface_id"]
    assert [row["shell"] for row in commands] == ["bash", "pwsh"]
    assert any('"on"' in row["surface_id"] for row in observed["surfaces"] if row["form"] == "WorkflowJob")


@pytest.mark.usefixtures("workflow_parser")
def test_omitted_run_fails_even_with_owned_workflow_file(tmp_path: Path) -> None:
    root = repository(tmp_path, ".github/workflows/check.yml", 'jobs: {check: {steps: [{run: echo subject}]}}\n')
    observed = discover(root)
    missing = next(row["surface_id"] for row in observed["surfaces"] if row["form"] == "WorkflowRun")
    manifest = build_template(root)["manifest"]
    manifest["objects"][0]["surfaces"].remove(missing)
    save(root, manifest)
    report = assess(root)
    assert any(row["code"] == "NAMESPACE_SURFACE_UNCOVERED" and row["surface_id"] == missing for row in report["findings"])
    assert report["independent_reconciliation"]["status"] == "PASS"
    assert report["independent_reconciliation"]["receipt"]["workflow_binding_digest"] == value_digest(observed["workflow_binding"])


@pytest.mark.usefixtures("workflow_parser")
def test_workflow_folded_command_bytes_are_bound(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, ".github/workflows/check.yml",
        'jobs:\n  check:\n    steps:\n      - run: >\n          echo\n          subject\n'))
    assert observed["workflow_binding"]["commands"][0]["source_digest"] == bytes_digest(b"echo subject\n")


@pytest.mark.usefixtures("workflow_parser")
def test_selected_local_action_and_runtime_sources_are_bound(tmp_path: Path) -> None:
    root = repository(tmp_path, ".github/workflows/check.yml", 'jobs: {check: {steps: [{uses: "./local"}]}}\n')
    action = root / "local/action.yml"
    action.parent.mkdir()
    action.write_text('runs: {using: node24, main: main.js}\n', encoding="utf-8")
    # Empty source needs no optional JavaScript parse success for the binding.
    (action.parent / "main.js").write_bytes(b"")
    observed = discover(root)
    targets = {row["target_path"] for row in observed["workflow_binding"]["references"]}
    assert targets == {"local/action.yml", "local/main.js"}


@pytest.mark.usefixtures("workflow_parser")
def test_remote_action_and_expressions_are_not_downloaded_or_evaluated(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, ".github/workflows/check.yml",
        'jobs: {check: {steps: [{uses: "outside/action@v1"}, {run: "echo ${{ secrets.NOT_READ }}"}]}}\n'))
    codes = {row["code"] for row in observed["gaps"]}
    assert "NAMESPACE_WORKFLOW_REFERENCE_UNRESOLVED" in codes
    assert "NAMESPACE_WORKFLOW_EXPRESSION_UNRESOLVED" not in codes
    assert not observed["workflow_binding"]["references"]
    assert not observed["workflow_binding"]["external_references"]
    assert any(row["dependencies"] == ["secrets.NOT_READ"] and row["scope"] == "STATIC_SYNTAX_AND_CONTEXT_READS_NOT_EVALUATION"
               for row in observed["workflow_binding"]["expressions"])


@pytest.mark.usefixtures("workflow_parser")
def test_remote_action_commit_is_a_bounded_edge_not_selected_source(tmp_path: Path) -> None:
    commit = "a" * 40
    observed = discover(repository(tmp_path, ".github/workflows/check.yml",
        f'jobs: {{check: {{uses: "outside/repository/.github/workflows/check.yml@{commit}"}}}}\n'))
    assert not observed["workflow_binding"]["references"]
    assert not any(
        row["code"] == "NAMESPACE_WORKFLOW_REFERENCE_UNRESOLVED"
        for row in observed["gaps"]
    )
    assert observed["workflow_binding"]["external_references"] == [
        {
            "surface_id": 'workflow:.github/workflows/check.yml:job/"check"/uses',
            "path": ".github/workflows/check.yml",
            "line": 1,
            "repository": "outside/repository",
            "subpath": ".github/workflows/check.yml",
            "revision": commit,
            "scope": "DECLARED_PINNED_EXTERNAL_REFERENCE_NOT_SOURCE_ADMISSION_OR_EXECUTION",
        }
    ]
    assert any(
        row["form"] == "WorkflowExternalReference"
        for row in observed["surfaces"]
    )


@pytest.mark.usefixtures("workflow_shell_parser")
def test_computed_expression_and_dynamic_command_remain_gaps(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, ".github/workflows/check.yml",
        'jobs: {check: {runs-on: ubuntu-latest, steps: [{run: "${PROGRAM} ${{ github[event_name] }}"}]}}\n'))
    codes = {row["code"] for row in observed["gaps"]}
    assert {"NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED", "NAMESPACE_WORKFLOW_EXPRESSION_UNRESOLVED"} <= codes


@pytest.mark.usefixtures("workflow_shell_parser")
def test_current_ci_openssl_selection_has_a_literal_program_surface() -> None:
    root = Path(__file__).resolve().parents[1]
    path = ".github/workflows/ci.yml"
    raw = (root / path).read_bytes()
    observed = namespace_workflows.discover(
        [(path, raw)], {path: bytes_digest(raw)}
    )
    assert not any(
        row["code"] == "NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED"
        for row in observed["gaps"]
    )
    assert any(
        program["program"] == "openssl"
        for command in observed["binding"]["commands"]
        for program in command["programs"]
    )


@pytest.mark.usefixtures("workflow_shell_parser")
@pytest.mark.parametrize("command", ['eval "$PAYLOAD"', 'source "$RUNTIME_SOURCE"', 'bash -c "echo hidden"'])
def test_shell_dispatchers_remain_command_gaps(tmp_path: Path, command: str) -> None:
    observed = discover(repository(tmp_path, ".github/workflows/check.yml",
        "jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + json.dumps(command) + "\n"))
    assert any(row["code"] == "NAMESPACE_WORKFLOW_COMMAND_UNRESOLVED" for row in observed["gaps"])


@pytest.mark.usefixtures("workflow_shell_parser")
def test_literal_command_source_path_is_exactly_bound(tmp_path: Path) -> None:
    root = repository(tmp_path, ".github/workflows/check.yml",
        "jobs: {check: {runs-on: ubuntu-latest, steps: [{run: 'python scripts/check.py'}]}}\n")
    script = root / "scripts/check.py"
    script.parent.mkdir()
    script.write_text("print('bounded')\n", encoding="utf-8")
    (script.parent / "check.py.extra").write_text("not the target\n", encoding="utf-8")
    observed = discover(root)
    bindings = observed["workflow_binding"]["commands"][0]["source_bindings"]
    assert [row["target_path"] for row in bindings] == ["scripts/check.py"]
    assert bindings[0]["scope"] == "LEXICAL_EXACT_PATH_NOT_EXECUTION"


def _legacy_workflow_source_bindings(
    source: str,
    selected: dict[str, str],
) -> list[dict[str, str]]:
    """Reference the replaced matcher exactly; this is not production code."""
    rows = []
    for target, target_digest in sorted(selected.items()):
        variants = {target, "./" + target}
        if any(
            re.search(
                r"(?<![A-Za-z0-9_./+@-])"
                + re.escape(value)
                + r"(?![A-Za-z0-9_./+@-])",
                source,
            )
            for value in variants
        ):
            rows.append(
                {
                    "target_path": target,
                    "target_source_digest": target_digest,
                    "scope": "LEXICAL_EXACT_PATH_NOT_EXECUTION",
                }
            )
    return rows


@pytest.mark.parametrize(
    "source",
    [
        # Every legacy path character adjacent to the target rejects a match.
        " ".join(
            character + "scripts/check.py" for character in "AZaz09_./+@-"
        )
        + " "
        + " ".join(
            "scripts/check.py" + character for character in "AZaz09_./+@-"
        ),
        # Punctuation and non-ASCII characters are boundaries, exactly as in
        # the legacy ASCII lookaround. Direct and ./ spellings both bind.
        "(scripts/check.py) Ωscripts/check.pyλ ./literal[1]+?.py",
        # Overlapping targets and target/variant collisions remain distinct
        # selected rows while repeated occurrences remain deduplicated.
        "./alpha alpha ./alpha ././alpha",
        "目录/脚本.py 『目录/脚本.py』",
    ],
)
def test_workflow_source_path_index_matches_legacy_boundaries_and_order(
    source: str,
) -> None:
    selected = dict(
        reversed(
            [
                ("./alpha", "sha256:" + "a" * 64),
                ("alpha", "sha256:" + "b" * 64),
                ("literal[1]+?.py", "sha256:" + "c" * 64),
                ("scripts/check.py", "sha256:" + "d" * 64),
                ("scripts/check", "sha256:" + "e" * 64),
                ("目录/脚本.py", "sha256:" + "f" * 64),
            ]
        )
    )
    index = namespace_workflow_worker._ExactPathIndex(selected)
    assert index.scan(source) == _legacy_workflow_source_bindings(source, selected)


def test_workflow_source_path_index_consumes_selection_once_and_avoids_regex(
    monkeypatch: Any,
) -> None:
    class OneShotSelection(dict[str, str]):
        calls = 0

        def items(self) -> Any:
            self.calls += 1
            if self.calls != 1:
                raise AssertionError("selected.items() was consumed more than once")
            return super().items()

    selected = OneShotSelection(
        {
            "second.py": "sha256:" + "2" * 64,
            "first.py": "sha256:" + "1" * 64,
        }
    )
    index = namespace_workflow_worker._ExactPathIndex(selected)
    expected = _legacy_workflow_source_bindings(
        "first.py; ./second.py; first.py",
        dict(selected),
    )

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("the reusable path index must not call re.search")

    monkeypatch.setattr(namespace_workflow_worker.re, "search", forbidden)
    assert index.scan("first.py; ./second.py; first.py") == expected
    assert index.scan("first.py; ./second.py; first.py") == expected
    assert selected.calls == 1


@pytest.mark.usefixtures("workflow_parser")
def test_issue_form_and_config_dialects_are_structurally_bound(tmp_path: Path) -> None:
    root = repository(tmp_path, ".github/ISSUE_TEMPLATE/config.yml",
        "blank_issues_enabled: false\ncontact_links:\n  - name: Private report\n    url: https://example.invalid/report\n    about: Report privately.\n")
    form = root / ".github/ISSUE_TEMPLATE/report.yml"
    form.write_text("name: Report\ndescription: Bounded report\ntitle: '[report]: '\nlabels: [triage]\nbody:\n"
        "  - type: markdown\n    attributes: {value: Read this.}\n"
        "  - type: input\n    id: coordinate\n    attributes: {label: Exact coordinate}\n    validations: {required: true}\n",
        encoding="utf-8")
    observed = discover(root)
    dialects = {row["dialect"] for row in observed["workflow_binding"]["documents"]}
    assert dialects == {"GITHUB_ISSUE_CONFIG", "GITHUB_ISSUE_FORM"}
    assert not any(row["code"].startswith(("NAMESPACE_YAML_", "NAMESPACE_ISSUE_FORM_")) for row in observed["gaps"])
    assert any(row["form"] == "GitHubIssueFormControl" for row in observed["surfaces"])


@pytest.mark.usefixtures("workflow_parser")
@pytest.mark.parametrize("source", [
    "name: Missing body\ndescription: No body\n",
    "name: Bad control\ndescription: Bad\nbody: [{type: input, id: 'has space', attributes: {label: Value}}]\n",
    "name: Duplicate ids\ndescription: Bad\nbody:\n  - {type: input, id: same, attributes: {label: One}}\n  - {type: input, id: same, attributes: {label: Two}}\n",
])
def test_malformed_issue_form_remains_a_gap(tmp_path: Path, source: str) -> None:
    observed = discover(repository(tmp_path, ".github/ISSUE_TEMPLATE/report.yml", source))
    assert any(row["code"] == "NAMESPACE_ISSUE_FORM_SCHEMA_UNRESOLVED" for row in observed["gaps"])


@pytest.mark.usefixtures("workflow_parser")
def test_unknown_yaml_consumer_cannot_be_assumed_passive(tmp_path: Path) -> None:
    observed = discover(repository(tmp_path, "custom.yml", 'execute: hidden-command\n'))
    assert any(row["form"] == "YAMLNode" for row in observed["surfaces"])
    assert any(row["code"] == "NAMESPACE_YAML_INTERPRETATION_UNRESOLVED" for row in observed["gaps"])


def test_missing_yaml_parser_is_a_discovery_gap(tmp_path: Path, monkeypatch: Any) -> None:
    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise ValueError("parser absent")
    monkeypatch.setattr(namespace_workflows, "_run", unavailable)
    observed = discover(repository(tmp_path, ".github/workflows/check.yml", 'jobs: {}\n'))
    assert observed["workflow_binding"]["mechanism"] is None
    assert any(row["code"] == "NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE" for row in observed["gaps"])


def _workflow_response(files: list[dict[str, Any]] | None = None) -> bytes:
    return json.dumps({
        "schema_version": namespace_workflows.PROTOCOL,
        "mechanism": {},
        "files": list(files or []),
    }).encode("utf-8")


def _install_workflow_process(
    monkeypatch: Any,
    stdout_bytes: bytes,
    *,
    stderr_bytes: bytes = b"",
    running: bool = False,
) -> list[Any]:
    processes = []

    class Process:
        def __init__(self, command: list[str], *, stdin: Any, stdout: Any,
                     stderr: Any, cwd: Any) -> None:
            self.command = command
            self.returncode = None if running else 0
            self.killed = False
            stdout.write(stdout_bytes)
            stderr.write(stderr_bytes)
            stdout.flush()
            stderr.flush()
            processes.append(self)

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9

        def wait(self, timeout: float) -> int:
            assert timeout == 2
            return int(self.returncode or 0)

    monkeypatch.setattr(namespace_workflows.subprocess, "Popen", Process)
    return processes


def test_workflow_worker_accepts_exact_combined_capacity_with_trailing_whitespace(
    monkeypatch: Any,
) -> None:
    response = _workflow_response()
    wire = response + b" " * (namespace_workflows.LIMIT - len(response))
    processes = _install_workflow_process(monkeypatch, wire)

    observed = namespace_workflows._run([], {})

    assert observed["schema_version"] == namespace_workflows.PROTOCOL
    assert not processes[0].killed


def test_workflow_worker_kills_one_byte_stdout_over_capacity(
    monkeypatch: Any,
) -> None:
    processes = _install_workflow_process(
        monkeypatch,
        b" " * (namespace_workflows.LIMIT + 1),
    )

    with pytest.raises(ValueError, match="^NAMESPACE_WORKFLOW_OUTPUT_CAPACITY$"):
        namespace_workflows._run([], {})
    assert processes[0].killed


def test_workflow_worker_rejects_combined_stderr_overflow_below_stdout_cap(
    monkeypatch: Any,
) -> None:
    response = _workflow_response()
    processes = _install_workflow_process(
        monkeypatch,
        response,
        stderr_bytes=b"x" * (namespace_workflows.LIMIT - len(response) + 1),
    )

    with pytest.raises(ValueError, match="^NAMESPACE_WORKFLOW_OUTPUT_CAPACITY$"):
        namespace_workflows._run([], {})
    assert processes[0].killed


def test_workflow_worker_terminates_running_stderr_flood(monkeypatch: Any) -> None:
    processes = _install_workflow_process(
        monkeypatch,
        b"",
        stderr_bytes=b"x" * (namespace_workflows.LIMIT + 1),
        running=True,
    )

    with pytest.raises(ValueError, match="^NAMESPACE_WORKFLOW_OUTPUT_CAPACITY$"):
        namespace_workflows._run([], {})
    assert processes[0].killed


def test_workflow_worker_truncated_json_is_unavailable(monkeypatch: Any) -> None:
    _install_workflow_process(monkeypatch, b'{"schema_version":')
    raw = b"jobs: {}\n"
    path = ".github/workflows/check.yml"

    observed = namespace_workflows.discover(
        [(path, raw)],
        {path: bytes_digest(raw)},
    )

    assert observed["surfaces"] == []
    assert observed["binding"] == namespace_workflows.EMPTY
    assert observed["gaps"][0]["code"] == "NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE"


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("protocol", "NAMESPACE_WORKFLOW_PARSER_UNAVAILABLE"),
        ("path", "NAMESPACE_WORKFLOW_SOURCE_DIFFERS"),
        ("source_digest", "NAMESPACE_WORKFLOW_SOURCE_DIFFERS"),
    ],
)
def test_workflow_worker_still_rejects_wrong_response_bindings(
    monkeypatch: Any,
    change: str,
    expected: str,
) -> None:
    raw = b"jobs: {}\n"
    path = ".github/workflows/check.yml"
    row = {
        "path": path,
        "source_digest": bytes_digest(raw),
        "surfaces": [],
        "commands": [],
        "references": [],
        "external_references": [],
        "expressions": [],
        "documents": [],
        "gaps": [],
    }
    response = {
        "schema_version": namespace_workflows.PROTOCOL,
        "mechanism": {},
        "files": [row],
    }
    if change == "protocol":
        response["schema_version"] = "wrong"
    elif change == "path":
        row["path"] = "wrong.yml"
    else:
        row["source_digest"] = "sha256:" + "0" * 64
    _install_workflow_process(monkeypatch, json.dumps(response).encode("utf-8"))

    with pytest.raises(ValueError, match="^" + expected + "$"):
        namespace_workflows._run([(path, raw)], {path: bytes_digest(raw)})


def test_workflow_worker_has_a_finite_full_repository_deadline(
    monkeypatch: Any,
) -> None:
    processes = _install_workflow_process(monkeypatch, b"", running=True)
    timeout_seconds = namespace_workflows.TIMEOUT_SECONDS
    monkeypatch.setattr(namespace_workflows, "TIMEOUT_SECONDS", 0)
    with pytest.raises(subprocess.TimeoutExpired):
        namespace_workflows._run([], {})
    assert timeout_seconds == 120
    assert processes[0].killed


@pytest.mark.usefixtures("workflow_parser")
def test_repository_yaml_module_is_never_imported(tmp_path: Path) -> None:
    root = repository(tmp_path, ".github/workflows/check.yml", 'jobs: {check: {steps: [{run: echo subject}]}}\n')
    (root / "yaml.py").write_text('raise RuntimeError("subject import forbidden")\n', encoding="utf-8")
    assert discover(root)["workflow_binding"]["commands"]


@pytest.mark.usefixtures("workflow_parser")
def test_workflow_command_projection_tampering_fails_reconciliation(tmp_path: Path, monkeypatch: Any) -> None:
    from verifier.runtime import namespace_admission
    root = repository(tmp_path, ".github/workflows/check.yml", 'jobs: {check: {steps: [{run: echo subject}]}}\n')
    save(root, build_template(root)["manifest"])
    original = namespace_admission._run_bounded_reconciler
    def tamper(command: list[str], wire: bytes, **kwargs: Any) -> Any:
        if any(str(part).endswith("namespace_reconcile.mjs") for part in command):
            payload = json.loads(wire)
            payload["workflow_binding"]["commands"][0]["shell"] = "changed"
            wire = json.dumps(payload).encode()
        return original(command, wire, **kwargs)
    monkeypatch.setattr(namespace_admission, "_run_bounded_reconciler", tamper)
    assert assess(root)["independent_reconciliation"]["status"] == "FAIL"
