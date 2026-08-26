#!/usr/bin/env python3
"""Terminology: application programming interface (API); command-line interface (CLI);
hash-based message authentication code (HMAC); International Organization for Standardization (ISO);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD); YAML Ain't Markup Language (YAML).

Generate the public CLI and top-level API reference page from the live implementation.

Nothing on the generated page is hand-written prose about behaviour: every command,
option, top-level export, signature, and listed pipeline edge is read out of the
importable package at build time. `scripts/check_presentation.py` and
`tests/test_presentation_surface.py` regenerate this file and fail closed when the
committed page drifts from the code."""

from __future__ import annotations

import argparse
import enum
import html
import importlib
import inspect
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
OUTPUT = ROOT / "docs/reference.html"
SOURCE_BASE = "https://github.com/TimeLordRaps/verifier/blob/main/"

# command -> the declared implementation stages it dispatches into. Every target is
# imported during generation, so a rename or removal breaks the build rather than
# silently publishing a stale pipeline map.
PIPELINE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "vstd demo",
        "Runs the four adversarial specimens in-process and reports whether each "
        "defensive outcome matched its declared invariant.",
        ("verifier.runtime.demo:run_demo", "verifier.runtime.demo:demo_report"),
    ),
    (
        "vstd plan",
        "Resolves a manifest's command and declared paths without executing anything.",
        ("verifier.core.run:load_manifest", "verifier.core.run:describe_run_plan"),
    ),
    (
        "vstd run",
        "Executes a trusted manifest without sandboxing, captures the observed "
        "execution, and writes a canonically digested receipt.",
        (
            "verifier.core.run:load_manifest",
            "verifier.core.run:capture_run",
            "verifier.core.receipt:compute_canonical_digest",
        ),
    ),
    (
        "vstd validate",
        "Dispatches on the receipt's frozen wire identifier and runs its implemented "
        "checks. Generic-run validation enforces its required structure and stable "
        "digest; other receipt kinds enforce their separately documented structure "
        "and evidence rules.",
        (
            "verifier.core.run:validate_run_receipt",
            "verifier.data.receipt:validate_data_receipt",
            "verifier.hardware.validation:validate_vstd3_receipt",
        ),
    ),
    (
        "vstd inspect",
        "Prints the claim coordinate, digest, and verdict surface of a stored receipt.",
        (
            "verifier.core.run:inspect_run_receipt",
            "verifier.hardware.receipt:load_vstd3_receipt",
        ),
    ),
    (
        "vstd reproduce",
        "Replays only the mechanisms a stored receipt actually carries; physical "
        "hardware execution is refused rather than simulated.",
        (
            "verifier.core.run:reproduce_run_receipt",
            "verifier.data.receipt:reproduce_data_receipt",
        ),
    ),
    (
        "vstd impact",
        "Finds stored run receipts whose recorded ancestry reaches a revoked "
        "provenance artifact.",
        ("verifier.core.run:find_run_receipts_impacted_by_revocation",),
    ),
    (
        "vstd data",
        "Traces, renders, or exports the provenance hypergraph carried by a "
        "VSTD-Graph receipt.",
        ("verifier.data.models:ProvenanceHypergraph",),
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
        raise ReferenceBuildError(f"cannot locate source file for {module_name}")
    return SOURCE_BASE + relative


def _summary(obj: object) -> str:
    doc = inspect.getdoc(obj) or ""
    return doc.split("\n\n", 1)[0].strip().replace("\n", " ")


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
                "kind": "optional" if action.option_strings else "positional",
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
    for command in _walk(build_parser()):
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
            for member_name, member in sorted(inspect.getmembers(value, inspect.isfunction)):
                if member_name.startswith("_"):
                    continue
                try:
                    member_signature = f"{member_name}{inspect.signature(member)}"
                except (TypeError, ValueError):
                    member_signature = member_name
                rows += (
                    f"<tr><td><code>{_esc(member_signature)}</code></td>"
                    f"<td>{_esc(_summary(member))}</td></tr>\n"
                )
            if rows:
                members = (
                    "<table><thead><tr><th>Method</th><th>Summary</th></tr></thead>"
                    f"<tbody>\n{rows}</tbody></table>"
                )
        # ``str, Enum`` inherits a version-specific builtin ``str`` docstring on
        # Python 3.10, while later interpreters expose Enum's generic docstring.
        # Neither describes the public VSTD surface, so emit one stable summary.
        summary = "Enumeration of the exported result values." if kind == "enum" else _summary(value)
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


def render() -> str:
    package = importlib.import_module("verifier")
    version = package.__version__
    standard = package.__standard__
    standard_status = package.__standard_status__
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Generated reference for the Verifier Standard (VSTD).">
  <title>VSTD docs &mdash; command-line interface (CLI) and application programming interface (API) reference</title>
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
        <a href="https://github.com/TimeLordRaps/verifier#see-it-fail-correctly">Demo</a>
        <a href="guides.html#standards">Standards</a>
        <a href="guides.html#experiments">Experiments</a>
        <a href="guides.html#project">Project</a>
        <a href="https://github.com/TimeLordRaps/verifier">GitHub</a>
      </div>
    </nav>
  </header>

  <main id="top">
    <div class="wrap ref-hero">
      <div class="eyebrow">Reference &middot; verifier-standard {_esc(version)} &middot; {_esc(standard)} {_esc(standard_status)}</div>
      <h1>Inspect the whole pipeline.</h1>
      <p class="terms"><strong>Terms used below:</strong> hash-based message authentication
      code (HMAC); International Organization for Standardization (ISO); JavaScript Object
      Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); and YAML Ain't Markup Language
      (YAML).</p>
      <p class="lead">Every command, argument, top-level export, and listed dispatch edge below
      is read out of the installed package when this page is built, by
      <code>scripts/build_reference.py</code>, and the presentation tests fail closed when the
      committed page drifts &mdash; so it cannot describe behaviour the implementation no
      longer has.</p>
      <p class="status">This page states the declared public surface of one implementation. It
      does not establish that any individual claim checked by these commands is true, nor that
      an external implementation exists.</p>
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
        <h2>Command to implementation, without a gap.</h2>
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
        retained as an alias only on platforms where it is unambiguous.</p>
        <div class="ref-list">{_cli_section()}</div>
      </div>
    </section>

    <section id="api">
      <div class="wrap">
        <div class="eyebrow">API</div>
        <h2>Top-level Python exports.</h2>
        <p class="section-lead">The names in <code>verifier.__all__</code>, with their live
        signatures and declared docstrings. Public subpackage surfaces are not exhaustively
        listed here; use the <a href="{SOURCE_BASE}docs/ARCHITECTURE.md">architecture map</a>
        to reach their owning modules, schemas, and tests.</p>
        <div class="ref-list">{_api_section()}</div>
      </div>
    </section>

    <section id="wire">
      <div class="wrap">
        <div class="eyebrow">Wire</div>
        <h2>Canonical schemas and identifiers.</h2>
        <p class="section-lead">Receipt schemas are served from this site at their canonical
        <code>$id</code> routes, and the frozen wire identifiers they belong to are listed in the
        standard.</p>
        <div class="actions">
          <a class="button" href="{SOURCE_BASE}standard/WIRE_IDENTIFIERS.md">Wire identifiers</a>
          <a class="button" href="{SOURCE_BASE}receipts/schema">Schema sources</a>
          <a class="button" href="{SOURCE_BASE}docs/QUICKSTART.md">Quickstart</a>
          <a class="button" href="{SOURCE_BASE}docs/CLAIMS_AND_LIMITS.md">Claim limits</a>
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
    rendered = render()
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != rendered:
            print(
                "[REFERENCE DRIFT] docs/reference.html is stale; "
                "run python scripts/build_reference.py",
                file=sys.stderr,
            )
            return 1
        print("[REFERENCE OK] docs/reference.html matches the implementation")
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"[REFERENCE OK] wrote {OUTPUT.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
