#!/usr/bin/env python3
"""Terminology: Hypertext Markup Language (HTML); Hypertext Transfer Protocol Secure
(HTTPS); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); uniform resource locator (URL);
Verifier Standard (VSTD).

Build a host-neutral static component index from the exact public source checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
DEFAULT_BASE_URL = "https://timelordraps.github.io/verifier/"
FULL_COMMIT = re.compile(r"[0-9a-fA-F]{40}")
REVIEWED_CANDIDATE_SOURCE_PATHS = (
    "src/verifier/interoperability/authority_composition.py",
    "src/verifier/interoperability/claim_garden.py",
    "src/verifier/interoperability/formation_checker.py",
    "src/verifier/interoperability/formation_mechanism.py",
    "src/verifier/interoperability/formation_producer.py",
    "src/verifier/interoperability/formation_receipt.py",
    "src/verifier/interoperability/formation_storage.py",
    "src/verifier/interoperability/formation_wire.py",
    "src/verifier/interoperability/network.py",
    "src/verifier/interoperability/proposition_transfer.py",
    "src/verifier/profiles/proposition-transfer-rule-0.1.json",
    "src/verifier/profiles/typed-formation-0.1.json",
    "src/verifier/runtime/network_cli.py",
    "src/verifier/schemas/__init__.py",
    "src/verifier/schemas/artifact-control-1.schema.json",
    "src/verifier/schemas/graph-topology.schema.json",
    "src/verifier/schemas/vstd-artifact-network-0.1.schema.json",
    "src/verifier/schemas/vstd-authority-model-0.1.schema.json",
    "src/verifier/schemas/vstd-component-index-1.schema.json",
    "src/verifier/schemas/vstd-component-package-1.schema.json",
    "src/verifier/schemas/vstd-graph-assurance-1.schema.json",
    "src/verifier/schemas/vstd-proposition-transfer-0.1.schema.json",
    "src/verifier/schemas/vstd-push-request-0.1.schema.json",
    "src/verifier/schemas/vstd-self-derivation-mechanism-0.1.schema.json",
    "src/verifier/schemas/vstd-silo-assessment-0.1.schema.json",
    "src/verifier/schemas/vstd-silo-assessment-receipt-0.1.schema.json",
    "src/verifier/schemas/vstd-silo-composition-0.1.schema.json",
    "src/verifier/schemas/vstd-silo-composition-assessment-0.1.schema.json",
    "src/verifier/schemas/vstd-silo-composition-assessment-receipt-0.1.schema.json",
    "src/verifier/schemas/vstd-silo-formation-receipt-0.1.schema.json",
    "src/verifier/schemas/vstd-silo-transfer-0.1.schema.json",
    "src/verifier/schemas/vstd-typed-formation-0.1.schema.json",
    "src/verifier/specifications/FINITE_AUTHORITY_COMPOSITION.md",
    "src/verifier/specifications/PROPOSITION_TRANSFER.md",
    "src/verifier/specifications/FORMATION_RECEIPT.md",
    "src/verifier/specifications/TYPED_FORMATION.md",
)


class ComponentIndexBuildError(RuntimeError):
    """The static index cannot be bound to the requested source coordinate."""


def _project_version() -> str:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', project, re.MULTILINE)
    if match is None:
        raise ComponentIndexBuildError("project version is not readable")
    return match.group(1)


def _head() -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode or not FULL_COMMIT.fullmatch(result.stdout.strip()):
        raise ComponentIndexBuildError("component index requires an exact Git checkout")
    return result.stdout.strip().lower()


def _worktree_dirty() -> bool:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=normal"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ComponentIndexBuildError("component index requires readable Git status")
    return bool(result.stdout)


def _reviewed_untracked_candidate_sources() -> tuple[str, ...]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            *REVIEWED_CANDIDATE_SOURCE_PATHS,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ComponentIndexBuildError("cannot inspect reviewed candidate source state")
    return tuple(entry.decode("utf-8") for entry in result.stdout.split(b"\0") if entry)


def _package_version(source_ref: str) -> str:
    base = _project_version()
    if FULL_COMMIT.fullmatch(source_ref):
        return f"{base}+git.{source_ref[:12].lower()}"
    return base


def _base_url(value: str) -> str:
    if not value.startswith("https://") or not value.endswith("/"):
        raise ComponentIndexBuildError("public base URL must be absolute HTTPS with a trailing slash")
    if any(ord(char) < 32 or char.isspace() for char in value):
        raise ComponentIndexBuildError("public base URL contains whitespace or control characters")
    return value


def _reference_exporter() -> Any:
    path = ROOT / "examples/stored_components/build_reference_package.py"
    if str(SOURCE) not in sys.path:
        sys.path.insert(0, str(SOURCE))
    spec = importlib.util.spec_from_file_location("vstd_reference_package_exporter", path)
    if spec is None or spec.loader is None:
        raise ComponentIndexBuildError("cannot load the first-party package exporter")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise ComponentIndexBuildError("cannot initialize the first-party package exporter") from exc
    return module


def _render_html(index: Any, *, source_ref: str, base_url: str) -> str:
    report = index.inspect()
    rows: list[str] = []
    for package in index.packages:
        for component in package.registry.components:
            rows.append(
                "<tr>"
                f"<td><code>{html.escape(component.component_id)}</code></td>"
                f"<td>{html.escape(component.label)}</td>"
                f"<td>{html.escape(component.kind.value)}</td>"
                f"<td>{html.escape(component.lifecycle.value)}</td>"
                f"<td>{html.escape(', '.join(mode.value for mode in component.interaction_modes))}</td>"
                f"<td><code>{html.escape(package.package_sha256)}</code></td>"
                "</tr>"
            )
    canonical = base_url + "components/"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Exact, bounded VSTD component declarations from one static index.">
  <title>VSTD component index</title>
  <link rel="canonical" href="{html.escape(canonical, quote=True)}">
  <link rel="stylesheet" href="../assets/site.css">
</head>
<body>
  <a class="skip-link" href="#component-index">Skip to component index</a>
  <header class="wrap"><nav aria-label="Primary">
    <a class="brand" href="../index.html">VSTD</a><div class="links">
      <a href="../guides.html">Guides</a><a href="../reference.html">Reference</a>
      <a href="./" aria-current="page">Components</a>
      <a href="../standard/">Standard</a><a href="../project/ROADMAP.html">Project</a>
      <a href="https://github.com/TimeLordRaps/verifier">GitHub</a>
    </div>
  </nav></header>
  <main class="wrap doc-content" id="component-index">
    <p class="eyebrow">Static discovery · no fetching or execution</p>
    <h1>Component index</h1>
    <p>This page presents unsigned declarations from one exact, content-addressed index.
    Membership and matching do not establish availability, qualification, correctness,
    authorization, ecosystem completeness, or Verifier Standard conformance.</p>
    <dl>
      <dt>Source commit</dt><dd><code>{html.escape(source_ref)}</code></dd>
      <dt>Index digest</dt><dd><code>{html.escape(index.canonical_digest())}</code></dd>
      <dt>Packages</dt><dd>{report['package_count']}</dd>
      <dt>Components</dt><dd>{report['component_count']}</dd>
      <dt>Package availability</dt><dd><code>NOT_CHECKED</code></dd>
      <dt>Native qualification</dt><dd><code>NOT_ESTABLISHED</code></dd>
      <dt>Ecosystem completeness</dt><dd><code>UNKNOWN</code></dd>
    </dl>
    <p><a href="index.json">Canonical index JSON</a> ·
    <a href="index.sha256">Exact index SHA-256 digest</a> ·
    <a href="deployment-coordinate.json">Deployment coordinate</a> ·
    <a href="../docs/COMPONENT_HUB.html">Interpretation and command-line use</a></p>
    <div class="table-scroll"><table>
      <thead><tr><th>Component identifier</th><th>Declared label</th><th>Kind</th>
      <th>Lifecycle</th><th>Interaction modes</th><th>Package digest</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table></div>
    <p class="status">{html.escape(report['claim_boundary'])}</p>
  </main>
  <footer><div class="wrap">VSTD · Apache-2.0 · Maintainer-led alpha · No component execution or ranking.</div></footer>
</body>
</html>
"""


def build(
    output: Path,
    *,
    source_ref: str,
    base_url: str = DEFAULT_BASE_URL,
    include_untracked: Sequence[str] | None = None,
) -> tuple[Path, ...]:
    """Build the static surface into an absent directory and return its files."""

    from verifier.interoperability.component_index import (
        IndexedComponentPackage,
        StoredComponentIndex,
        load_component_index,
        save_component_index,
    )
    from verifier.interoperability.storage import load_component_package, save_component_package

    output = output.resolve()
    if output.exists():
        raise ComponentIndexBuildError("component index output must not already exist")
    source_ref = source_ref.strip()
    if not source_ref or len(source_ref) > 4096:
        raise ComponentIndexBuildError("source_ref must be nonempty bounded text")
    head = _head()
    if source_ref != "WORKTREE" and not FULL_COMMIT.fullmatch(source_ref):
        raise ComponentIndexBuildError("source_ref must be WORKTREE or a full Git commit")
    if FULL_COMMIT.fullmatch(source_ref):
        if source_ref.lower() != head:
            raise ComponentIndexBuildError("source_ref does not identify the exact checkout HEAD")
        if _worktree_dirty():
            raise ComponentIndexBuildError(
                "a commit-addressed component index requires a clean exact checkout"
            )
    public_base_url = _base_url(base_url)

    exporter = _reference_exporter()
    reviewed_untracked = (
        _reviewed_untracked_candidate_sources()
        if source_ref == "WORKTREE" and include_untracked is None
        else tuple(include_untracked or ())
    )
    if reviewed_untracked:
        package = exporter.build_package(
            ROOT,
            _package_version(source_ref),
            include_untracked=reviewed_untracked,
        )
    else:
        package = exporter.build_package(ROOT, _package_version(source_ref))
    entry = IndexedComponentPackage.from_package(package)
    index = StoredComponentIndex(
        index_id="timelordraps/verifier-reference-components",
        index_version=_package_version(source_ref),
        description=(
            "First-party VSTD reference declarations from one exact public source snapshot; "
            "static discovery only, with no fetching, installation, execution, ranking, "
            "latest-version selection, native qualification, or ecosystem-completeness claim."
        ),
        packages=(entry,),
    )

    package_path = output / Path(entry.package_path)
    package_path.parent.mkdir(parents=True)
    save_component_package(package, package_path)
    loaded_package = load_component_package(package_path, expected_digest=entry.package_sha256)
    entry.validate_package(loaded_package)

    index_path = output / "index.json"
    save_component_index(index, index_path)
    loaded_index = load_component_index(index_path, expected_digest=index.canonical_digest())
    if loaded_index != index:
        raise ComponentIndexBuildError("saved component index did not reproduce exactly")

    digest = hashlib.sha256(index_path.read_bytes()).hexdigest()
    if digest != index.canonical_digest():
        raise ComponentIndexBuildError("saved index bytes do not match canonical identity")
    digest_path = output / "index.sha256"
    digest_path.write_text(f"{digest}  index.json\n", encoding="ascii", newline="\n")
    coordinate_path = output / "deployment-coordinate.json"
    coordinate = {
        "schema_version": 1,
        "source_ref": source_ref,
        "base_url": public_base_url,
        "index_path": "index.json",
        "index_sha256": digest,
    }
    coordinate_path.write_text(
        json.dumps(coordinate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    html_path = output / "index.html"
    html_path.write_text(
        _render_html(index, source_ref=source_ref, base_url=public_base_url),
        encoding="utf-8",
        newline="\n",
    )
    return (html_path, index_path, digest_path, coordinate_path, package_path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    arguments = parser.parse_args(argv)
    try:
        written = build(
            arguments.output,
            source_ref=arguments.source_ref,
            base_url=arguments.base_url,
        )
    except (ComponentIndexBuildError, OSError, ValueError) as exc:
        parser.exit(2, f"Component index build refused: {exc}\n")
    print(
        f"[COMPONENT INDEX OK] wrote {len(written)} files; "
        f"index digest {Path(arguments.output, 'index.sha256').read_text(encoding='ascii').split()[0]}"
    )
    print("No package was fetched, installed, imported, executed, ranked, or selected as latest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
