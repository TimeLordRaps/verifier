#!/usr/bin/env python3
"""Terminology: Verifier Standard (VSTD).

Validate experimental manifests and build their deterministic public index."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from verifier.experimental_workflow import load_manifest, verify_repo_artifacts


EXPERIMENTS = ROOT / "examples" / "experimental_profiles"
INDEX = EXPERIMENTS / "INDEX.md"


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def discover(root: Path = ROOT) -> tuple[tuple[Path, dict[str, object]], ...]:
    """Load every intentional experiment manifest and verify bound repo artifacts."""

    experiments = root / "examples" / "experimental_profiles"
    records: list[tuple[Path, dict[str, object]]] = []
    for path in sorted(experiments.glob("**/experiment.json")):
        payload = load_manifest(path)
        verify_repo_artifacts(payload, root)
        records.append((path.relative_to(root), payload))
    if not records:
        raise RuntimeError("no examples/experimental_profiles/**/experiment.json manifests were found")
    return tuple(records)


def render(records: tuple[tuple[Path, dict[str, object]], ...]) -> str:
    """Render a stable, human-readable view without granting experiment verdicts."""

    lines = [
        "# Experimental work index",
        "",
        "> **Acronym:** Verifier Standard (VSTD).",
        "",
        "> **Experimental and non-normative.** Inclusion means that a profile manifest",
        "> is structurally valid and its `repo:` artifacts match their bound digests. It",
        "> does not establish a hypothesis, verifier, publication, or VSTD verdict.",
        "",
        "Regenerate or check this file with:",
        "",
        "```bash",
        "PYTHONPATH=src python scripts/build_experiment_index.py --check",
        "```",
        "",
        "| Experiment | State | Question | Publication | Open horizons | Manifest |",
        "|---|---|---|---|---:|---|",
    ]
    for relative, payload in records:
        experiment = payload["experiment"]
        publication = payload["publication"]
        horizons = payload["horizons"]
        digest = payload["manifest_digest"]
        assert isinstance(experiment, dict)
        assert isinstance(publication, dict)
        assert isinstance(horizons, list)
        assert isinstance(digest, str)
        unresolved = sum(
            1
            for horizon in horizons
            if isinstance(horizon, dict)
            and horizon.get("status") in {"UNKNOWN", "CONFLICTED", "BLOCKED"}
        )
        path_text = relative.as_posix()
        link_text = relative.relative_to("examples/experimental_profiles").as_posix()
        lines.append(
            "| {identifier} | {state} | {question} | {publication} | {horizons} | "
            "[`{path}`]({link})<br>`{digest}` |".format(
                identifier=_cell(experiment["id"]),
                state=_cell(experiment["state"]),
                question=_cell(experiment["question"]),
                publication=_cell(publication["state"]),
                horizons=unresolved,
                path=path_text,
                link=link_text,
                digest=digest,
            )
        )
    lines.extend(
        [
            "",
            "Platform events, including successful workflows and merges, retain",
            "`verification_effect = NONE` unless a separate native result is explicitly",
            "mapped through a bound VSTD receipt.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if INDEX.md is stale.")
    args = parser.parse_args(argv)
    expected = render(discover())
    if args.check:
        if not INDEX.is_file() or INDEX.read_text(encoding="utf-8") != expected:
            print("[EXPERIMENT INDEX FAILED] examples/experimental_profiles/INDEX.md is stale")
            return 1
        print("[EXPERIMENT INDEX OK] manifests and repository artifacts verified")
        return 0
    INDEX.write_text(expected, encoding="utf-8", newline="\n")
    print(f"[EXPERIMENT INDEX WRITTEN] {INDEX.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
