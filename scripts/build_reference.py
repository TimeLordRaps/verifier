#!/usr/bin/env python3
"""Terminology: application programming interface (API); command-line interface (CLI);
hash-based message authentication code (HMAC); International Organization for Standardization (ISO);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD); YAML Ain't Markup Language (YAML).

Generate the public CLI and top-level API reference page from the live implementation.

CLI names and options come from the argument parser; top-level Python names and
signatures come from the importable package. The pipeline map is a selected,
manually described set of import-checked dispatch targets, and summaries come
from source docstrings or a reviewed map of undocumented public members.
`scripts/check_presentation.py` and
`tests/test_presentation_surface.py` regenerate this file and fail closed when the
committed page drifts from the code."""

from __future__ import annotations

import argparse
import enum
import html
import importlib
import inspect
import json
import os
from pathlib import Path
import re
import sys
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
OUTPUT = ROOT / "docs/reference.html"
MEMBER_SUMMARIES = ROOT / "docs/API_MEMBER_SUMMARIES.json"
SOURCE_BASE = "https://github.com/TimeLordRaps/verifier/blob/main/"

# command -> the declared implementation stages it dispatches into. Every target is
# imported during generation, so a rename or removal breaks the build rather than
# silently publishing a stale pipeline map.
PIPELINE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "vstd start",
        "Prints the ordered, copy-pasteable path from an installed package to a "
        "checked result; runs nothing and writes nothing.",
        ("verifier.runtime.accessibility_cli:start_report",),
    ),
    (
        "vstd explain",
        "Restates a stored receipt or certificate in plain language, naming what "
        "was established, what was not and why; never re-evaluates evidence.",
        ("verifier.runtime.accessibility_cli:explain_report",),
    ),
    (
        "vstd certification catalog",
        "Lists the object-profile obligation catalogue and bounded native checker coverage.",
        ("verifier.core.profile_obligations:obligation_catalog",),
    ),
    (
        "vstd certification assess",
        "Executes externally admitted native obligation mechanisms and emits a new grounded certificate.",
        ("verifier.core.grounded_certification:build_grounded_certificate",),
    ),
    (
        "vstd certification check",
        "Rehashes and reruns a certificate against the consumer's expected request and admission policy.",
        ("verifier.core.grounded_certification:recheck_grounded_certificate",),
    ),
    (
        "vstd demo",
        "Runs the four adversarial specimens in-process and reports whether each "
        "defensive outcome matched its declared invariant.",
        ("verifier.runtime.demo:run_demo", "verifier.runtime.demo:demo_report"),
    ),
    (
        "vstd plan",
        "Resolves a manifest's command and declared paths without executing anything.",
        (
            "verifier.core.run_planning:load_manifest",
            "verifier.core.run_planning:describe_run_plan",
        ),
    ),
    (
        "vstd components inspect",
        "Loads a bounded stored component package and checks retained-byte bindings; "
        "does not extract, install, execute, or qualify its implementation.",
        ("verifier.interoperability.storage:load_component_package",),
    ),
    (
        "vstd components index inspect",
        "Loads one bounded local component index and checks its canonical identity; "
        "does not fetch packages or establish publisher identity or qualification.",
        ("verifier.interoperability.component_index:load_component_index",),
    ),
    (
        "vstd components index search",
        "Finds exact declared matches in one bounded local index without fetching, "
        "installing, executing, ranking, or selecting a latest version.",
        ("verifier.interoperability.component_index:load_component_index",),
    ),
    (
        "vstd surface analyze",
        "Strictly loads one VSTD-2 geometry and emits deterministic modeled-surface "
        "diagnostics; its optional experimental built-in or stored-package catalog "
        "plan remains nonexecuting.",
        (
            "verifier.core.geometry_io:load_verification_geometry",
            "verifier.interoperability.control_surface:analyze_verification_surface",
            "verifier.interoperability.reference_catalog:reference_component_registry",
            "verifier.interoperability.storage:load_component_package",
            "verifier.interoperability.control_surface:plan_validation",
        ),
    ),
    (
        "vstd run",
        "Executes a trusted manifest without sandboxing, captures the observed "
        "execution, and writes a canonically digested receipt.",
        (
            "verifier.core.run_planning:load_manifest",
            "verifier.core.run:capture_run",
            "verifier.core.receipt:compute_canonical_digest",
        ),
    ),
    (
        "vstd validate",
        "Dispatches on the receipt's serialized `schema_version` identifier and runs its implemented "
        "checks. Generic-run validation enforces its required structure and stable "
        "digest; other receipt kinds enforce their separately documented structure "
        "and evidence rules.",
        (
            "verifier.core.run_validation:validate_run_receipt",
            "verifier.data.receipt:validate_data_receipt",
            "verifier.hardware.validation:validate_vstd3_receipt",
        ),
    ),
    (
        "vstd inspect",
        "Prints the claim coordinate, digest, and verdict surface of a stored receipt.",
        (
            "verifier.core.run_inspection:inspect_run_receipt",
            "verifier.hardware.receipt:load_vstd3_receipt",
        ),
    ),
    (
        "vstd reproduce",
        "Replays only the mechanisms a stored receipt actually carries; physical "
        "hardware execution is refused rather than simulated.",
        (
            "verifier.core.run_reproduction:reproduce_run_receipt",
            "verifier.data.receipt:reproduce_data_receipt",
        ),
    ),
    (
        "vstd impact",
        "Finds stored run receipts whose recorded ancestry reaches a revoked "
        "provenance artifact.",
        ("verifier.core.run_impact:find_run_receipts_impacted_by_revocation",),
    ),
    (
        "vstd data",
        "Traces, renders, or exports the provenance hypergraph carried by a "
        "GRAPH receipt.",
        ("verifier.data.models:ProvenanceHypergraph",),
    ),
    (
        "vstd artifact",
        "Freezes exact regular-file bytes, adds or verifies finite self-closing "
        "seals, and creates observable copy-on-write thaw descendants.",
        (
            "verifier.artifact_control:freeze_artifact",
            "verifier.artifact_control:seal_artifact",
            "verifier.artifact_control:verify_frozen_artifact",
            "verifier.artifact_control:thaw_artifact",
        ),
    ),
    (
        "vstd experiment",
        "Validates experimental workflow manifests or maps normalized GitHub snapshots "
        "without granting a VSTD verdict.",
        (
            "verifier.runtime.experimental_workflow_cli:handle_experiment_command",
            "verifier.experimental_workflow.profile:load_manifest",
            "verifier.experimental_workflow.github:github_snapshot_to_events",
        ),
    ),
    (
        "vstd hardware / continuity / fleet / evidence / claims",
        "Evaluates VSTD-3 substrate-accountability receipts, their continuity and "
        "fleet evidence, and their declared claims.",
        (
            "verifier.runtime.hardware_cli:handle_vstd3_command",
            "verifier.hardware.validation:validate_vstd3_receipt",
        ),
    ),
    (
        "vstd publish",
        "Checks local inputs and submits a claim and receipt for authenticated storage pending human review.",
        ("verifier.interoperability.claim_garden:publish_claim",),
    ),
)


class ReferenceBuildError(RuntimeError):
    pass


def _resolve(target: str) -> tuple[object, str]:
    module_name, _, attribute = target.partition(":")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ReferenceBuildError(f"pipeline target is not importable: {target}: {exc}") from exc
    if not hasattr(module, attribute):
        raise ReferenceBuildError(f"pipeline target no longer exists: {target}")
    return getattr(module, attribute), module_name


def _source_link(module_name: str) -> str:
    relative = "src/" + module_name.replace(".", "/") + ".py"
    if not (ROOT / relative).is_file():
        package_relative = "src/" + module_name.replace(".", "/") + "/__init__.py"
        if not (ROOT / package_relative).is_file():
            raise ReferenceBuildError(f"cannot locate source file for {module_name}")
        relative = package_relative
    return SOURCE_BASE + relative


def _summary(obj: object) -> str:
    doc = inspect.getdoc(obj) or ""
    return doc.split("\n\n", 1)[0].strip().replace("\n", " ")


def _member_summaries() -> dict[tuple[str, str], str]:
    try:
        payload = json.loads(MEMBER_SUMMARIES.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReferenceBuildError(f"cannot load reviewed member summaries: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "source_files"}:
        raise ReferenceBuildError("member summary map has unexpected top-level fields")
    if payload["schema_version"] != 1 or not isinstance(payload["source_files"], dict):
        raise ReferenceBuildError("member summary map has an unsupported schema")
    summaries: dict[tuple[str, str], str] = {}
    for source, members in payload["source_files"].items():
        if (not isinstance(source, str) or not source.startswith("src/verifier/")
                or not (ROOT / source).is_file() or not isinstance(members, dict)):
            raise ReferenceBuildError(f"invalid member summary source: {source!r}")
        for name, summary in members.items():
            if not isinstance(name, str) or not isinstance(summary, str) or not summary.strip():
                raise ReferenceBuildError(f"invalid member summary: {source}:{name}")
            summaries[(source, name)] = summary.strip()
    return summaries


def _member_source(member: object) -> str:
    target = member.fget if isinstance(member, property) else member
    source = inspect.getsourcefile(target)
    if source is None:
        raise ReferenceBuildError(f"cannot locate source for public member {member!r}")
    try:
        return Path(source).resolve().relative_to(ROOT).as_posix()
    except ValueError as exc:
        raise ReferenceBuildError(f"public member source is outside repository: {source}") from exc


def _esc(text: str) -> str:
    return html.escape(text, quote=False)


def _subparser_actions(parser: argparse.ArgumentParser) -> list[argparse._SubParsersAction]:
    return [
        action
        for action in parser._actions  # noqa: SLF001 - argparse exposes no public walk
        if isinstance(action, argparse._SubParsersAction)  # noqa: SLF001
    ]


def _walk(parser: argparse.ArgumentParser, help_text: str = "") -> list[dict[str, object]]:
    arguments: list[dict[str, str]] = []
    for action in parser._actions:  # noqa: SLF001
        if isinstance(action, argparse._SubParsersAction) or action.dest == "help":  # noqa: SLF001
            continue
        name = ", ".join(action.option_strings) if action.option_strings else (
            action.metavar or action.dest
        )
        choices = ""
        if action.choices:
            choices = "one of: " + ", ".join(str(choice) for choice in action.choices)
        arguments.append(
            {
                "name": str(name),
                "kind": (
                    "required option"
                    if action.option_strings and action.required
                    else "optional"
                    if action.option_strings
                    else "positional"
                ),
                "choices": choices,
                "default": "" if action.default in (None, False, [], "") else str(action.default),
                "help": action.help or "",
            }
        )
    commands: list[dict[str, object]] = [
        {"prog": parser.prog, "help": help_text, "arguments": arguments}
    ]
    for action in _subparser_actions(parser):
        help_by_name = {
            choice.dest: choice.help or "" for choice in action._choices_actions  # noqa: SLF001
        }
        for name, subparser in action.choices.items():
            commands.extend(_walk(subparser, help_by_name.get(name, "")))
    return commands


def _cli_section() -> str:
    from verifier.runtime.public_cli import build_parser

    blocks: list[str] = []
    # The gate-attestation parser deliberately reads GitHub's live run metadata.
    # A published reference must show the fallback defaults, not the identity of
    # whichever runner happened to build it. Restore the caller's environment
    # immediately after constructing this read-only parser snapshot.
    without_github = {key: value for key, value in os.environ.items()
                      if not key.startswith("GITHUB_")}
    with patch.dict(os.environ, without_github, clear=True):
        commands = _walk(build_parser())
    for command in commands:
        prog = str(command["prog"])
        anchor = "cli-" + prog.replace(" ", "-")
        rows = ""
        for argument in command["arguments"]:  # type: ignore[union-attr]
            detail = " ".join(
                part
                for part in (
                    argument["help"],
                    f"({argument['choices']})" if argument["choices"] else "",
                    f"[default: {argument['default']}]" if argument["default"] else "",
                )
                if part
            )
            rows += (
                f"<tr><td><code>{_esc(argument['name'])}</code></td>"
                f"<td>{_esc(argument['kind'])}</td>"
                f"<td>{_esc(detail)}</td></tr>\n"
            )
        table = (
            "<table><thead><tr><th>Argument</th><th>Kind</th><th>Meaning</th></tr></thead>"
            f"<tbody>\n{rows}</tbody></table>"
            if rows
            else '<p class="ref-none">No arguments; this command only groups subcommands.</p>'
        )
        help_text = str(command["help"]) or "Subcommand group."
        blocks.append(
            f'<article class="ref-item" id="{_esc(anchor)}">\n'
            f"<h3><code>{_esc(prog)}</code></h3>\n"
            f'<p class="ref-help">{_esc(help_text)}</p>\n'
            f"{table}\n</article>"
        )
    return "\n".join(blocks)


def _api_section() -> str:
    package = importlib.import_module("verifier")
    blocks: list[str] = []
    member_summaries = _member_summaries()
    used_summaries: set[tuple[str, str]] = set()
    for name in sorted(package.__all__):
        value = getattr(package, name)
        module_name = value.__module__
        if inspect.isclass(value):
            kind = "enum" if issubclass(value, enum.Enum) else "class"
        elif inspect.isfunction(value):
            kind = "function"
        else:
            kind = type(value).__name__
        signature = ""
        if kind != "enum":
            try:
                signature = f"{name}{inspect.signature(value)}"
            except (TypeError, ValueError):
                signature = name
        members = ""
        if kind == "enum":
            values = ", ".join(member.name for member in value)
            members = f'<p class="ref-help">Members: <code>{_esc(values)}</code></p>'
        elif kind == "class":
            rows = ""
            for member_name, member in inspect.getmembers(value):
                if member_name.startswith("_"):
                    continue
                if isinstance(member, property):
                    member_signature = f"{member_name} (property)"
                elif inspect.isfunction(member) or inspect.ismethod(member):
                    try:
                        member_signature = f"{member_name}{inspect.signature(member)}"
                    except (TypeError, ValueError):
                        member_signature = member_name
                else:
                    continue
                member_summary = _summary(member)
                if not member_summary:
                    key = (_member_source(member), f"{name}.{member_name}")
                    member_summary = member_summaries.get(key, "")
                    if not member_summary:
                        raise ReferenceBuildError(
                            f"public member has no reviewed summary: {key[0]}:{key[1]}"
                        )
                    used_summaries.add(key)
                rows += (
                    f'<tr id="api-{_esc(name)}.{_esc(member_name)}">'
                    f"<td><code>{_esc(member_signature)}</code></td>"
                    f"<td>{_esc(member_summary)}</td></tr>\n"
                )
            if rows:
                members = (
                    "<table><thead><tr><th>Method</th><th>Summary</th></tr></thead>"
                    f"<tbody>\n{rows}</tbody></table>"
                )
        # Undocumented enums inherit either the default Enum summary or a
        # version-specific builtin ``str`` docstring. Publish neither as VSTD prose.
        summary = _summary(value)
        if kind == "enum" and (
            not summary or summary == "An enumeration." or summary.startswith("str(")
        ):
            summary = "Enumeration of the exported values."
        if not summary or summary.startswith(f"{name}("):
            # A dataclass with no docstring of its own repeats its signature; that is
            # not documentation, so say so instead of publishing the repetition.
            summary = (
                "No docstring is declared for this export; the signature above is its "
                "whole declared surface."
            )
        signature_html = (
            f'<pre class="ref-signature"><code>{_esc(signature)}</code></pre>\n'
            if signature
            else ""
        )
        blocks.append(
            f'<article class="ref-item" id="api-{_esc(name)}">\n'
            f'<h3><code>{_esc(name)}</code> <span class="ref-tag">{_esc(kind)}</span></h3>\n'
            + signature_html
            + f'<p class="ref-help">{_esc(summary)}</p>\n'
            f'<p class="ref-source">Defined in <a href="{_source_link(module_name)}">'
            f"<code>{_esc(module_name)}</code></a></p>\n"
            f"{members}\n</article>"
        )
    stale = set(member_summaries) - used_summaries
    if stale:
        raise ReferenceBuildError(f"unused member summaries: {sorted(stale)}")
    return "\n".join(blocks)


def _pipeline_section() -> str:
    rows = ""
    for command, description, targets in PIPELINE:
        links = []
        for target in targets:
            _, module_name = _resolve(target)
            links.append(f'<a href="{_source_link(module_name)}"><code>{_esc(target)}</code></a>')
        rows += (
            f"<tr><td><code>{_esc(command)}</code></td><td>{_esc(description)}</td>"
            f"<td>{'<br>'.join(links)}</td></tr>\n"
        )
    return (
        "<table><thead><tr><th>Command</th><th>What it does</th>"
        f"<th>Implementation entry points</th></tr></thead><tbody>\n{rows}</tbody></table>"
    )


def _source_coordinate(version: str, changelog: str) -> str:
    """Describe whether the package coordinate still carries unreleased changes."""

    unreleased = re.search(
        r"^## Unreleased\s*(.*?)(?=^## |\Z)",
        changelog,
        re.MULTILINE | re.DOTALL,
    )
    released = re.search(
        rf"^## {re.escape(version)} - \d{{4}}-\d{{2}}-\d{{2}}$",
        changelog,
        re.MULTILINE,
    )
    if released is not None and unreleased is not None and not unreleased.group(1).strip():
        return f"RELEASED SOURCE · package version {version}"
    return f"UNRELEASED SOURCE · base package version {version}"


def render() -> str:
    package = importlib.import_module("verifier")
    version = package.__version__
    standard = package.__standard__
    standard_status = package.__standard_status__
    source_coordinate = _source_coordinate(
        version,
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Generated reference for the Verifier Standard (VSTD).">
  <meta property="og:title" content="VSTD command-line and Python reference">
  <meta property="og:description" content="Generated command-line and Python application programming interface reference for the Verifier Standard.">
  <meta property="og:image" content="https://timelordraps.github.io/verifier/assets/vstd-overview.png">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://timelordraps.github.io/verifier/reference.html">
  <title>VSTD docs &mdash; command-line interface (CLI) and application programming interface (API) reference</title>
  <link rel="canonical" href="https://timelordraps.github.io/verifier/reference.html">
  <link rel="icon" href="assets/vstd-overview.svg" type="image/svg+xml">
  <link rel="stylesheet" href="assets/site.css">
</head>
<body>
  <a class="skip-link" href="#top">Skip to content</a>
  <header class="wrap">
    <nav aria-label="Primary">
      <a class="brand" href="index.html">VSTD</a>
      <div class="links">
        <a href="index.html">Overview</a>
        <a href="guides.html">Guides</a>
        <a href="reference.html" aria-current="page">Reference</a>
        <a href="https://timelordraps.github.io/verifier/components/">Components</a>
        <a href="https://github.com/TimeLordRaps/verifier#30-60-second-demonstration">Demo</a>
        <a href="standard/">Standard</a>
        <a href="experiments/">Experiments</a>
        <a href="project/ROADMAP.html">Project</a>
        <a href="https://github.com/TimeLordRaps/verifier">GitHub</a>
      </div>
    </nav>
  </header>

  <main id="top">
    <div class="wrap ref-hero">
      <div class="eyebrow">Reference &middot; {_esc(source_coordinate)} &middot; {_esc(standard)} {_esc(standard_status)}</div>
      <h1>Inspect the supported surface.</h1>
      <p class="terms"><strong>Terms used below:</strong> hash-based message authentication
      code (HMAC); International Organization for Standardization (ISO); JavaScript Object
      Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); and YAML Ain't Markup Language
      (YAML).</p>
      <p class="lead">The command and argument inventory comes from the parser; the Python
      export inventory and signatures come from <code>verifier.__all__</code> at build time.
      The pipeline map selects import-checked implementation targets. Summaries come from
      source docstrings or the reviewed public-member summary map. Presentation tests detect generated
      page drift from these sources; they do not prove the described behaviour correct.</p>
      <p class="status">This page states the declared public surface of one implementation. It
      does not cover experimental direct submodule imports. Public instance methods,
      class methods, and properties of exported classes are listed here. The page
      does not establish that an individual claim checked by these commands is true, nor
      that an external implementation exists.</p>
      <div class="actions">
        <a class="button primary" href="#pipeline">Pipeline map</a>
        <a class="button" href="#cli">CLI reference</a>
        <a class="button" href="#api">API reference</a>
        <a class="button" href="#wire">Wire and schemas</a>
      </div>
    </div>

    <section id="pipeline">
      <div class="wrap">
        <div class="eyebrow">Pipeline</div>
        <h2>Selected command-to-implementation paths.</h2>
        <p class="section-lead">Each entry point below is imported while this page is built. A
        rename, move, or deletion fails the build instead of publishing a stale map.</p>
        <div class="ref-table">{_pipeline_section()}</div>
      </div>
    </section>

    <section id="cli">
      <div class="wrap">
        <div class="eyebrow">CLI</div>
        <h2>The <code>vstd</code> command reference.</h2>
        <p class="section-lead">Extracted from the live argument parser in
        <a href="{SOURCE_BASE}src/verifier/runtime/public_cli.py"><code>verifier.runtime.public_cli</code></a>.
        <code>vstd</code> is the canonical cross-platform command; <code>verifier</code> is
        retained as an alias only on platforms where it is unambiguous. Defaults below
        show a run without GitHub environment variables; <code>vstd gate attest</code>
        reads those variables at execution when present.</p>
        <div class="ref-list">{_cli_section()}</div>
      </div>
    </section>

    <section id="api">
      <div class="wrap">
        <div class="eyebrow">API</div>
        <h2>Top-level Python exports.</h2>
        <p class="section-lead">The names in <code>verifier.__all__</code>, with their live
        signatures and declared docstrings, are the supported runtime surface under the
        <a href="{SOURCE_BASE}docs/API_STABILITY.md">Python API stability policy</a>.
        Subpackage imports are internal unless a published policy names them.</p>
        <div class="ref-list">{_api_section()}</div>
      </div>
    </section>

    <section id="wire">
      <div class="wrap">
        <div class="eyebrow">Wire</div>
        <h2>Canonical schemas and identifiers.</h2>
        <p class="section-lead">Receipt schemas are served from this site at their canonical
        <code>$id</code> routes, and their serialized `schema_version` identifiers are listed in the
        standard.</p>
        <div class="actions">
          <a class="button" href="standard/WIRE_IDENTIFIERS.html">Wire identifiers</a>
          <a class="button" href="{SOURCE_BASE}receipts/schema">Schema sources</a>
          <a class="button" href="docs/QUICKSTART.html">Quickstart</a>
          <a class="button" href="docs/CLAIMS_AND_LIMITS.html">Claim limits</a>
        </div>
      </div>
    </section>
  </main>

  <footer><div class="wrap">VSTD &middot; Apache-2.0 &middot; Reference generated from the implementation by <code>scripts/build_reference.py</code>.</div></footer>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail instead of writing when the committed page is out of date.",
    )
    args = parser.parse_args(argv)
    rendered = render().encode("utf-8")
    if args.check:
        current = OUTPUT.read_bytes() if OUTPUT.exists() else b""
        if current != rendered:
            print(
                "[REFERENCE DRIFT] docs/reference.html is stale; "
                "run python scripts/build_reference.py",
                file=sys.stderr,
            )
            return 1
        print("[REFERENCE OK] docs/reference.html matches the implementation")
        return 0
    OUTPUT.write_bytes(rendered)
    print(f"[REFERENCE OK] wrote {OUTPUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
