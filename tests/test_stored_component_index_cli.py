"""Stored component index command-line interface (CLI) regression tests.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from verifier.interoperability.catalog import (
    ComponentAvailability,
    ComponentKind,
    ComponentLifecycle,
    InteractionMode,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from verifier.interoperability.component_index import (
    IndexedComponentPackage,
    StoredComponentIndex,
    save_component_index,
)
from verifier.interoperability.storage import (
    ImplementationBinding,
    PackageArtifact,
    StoredComponentPackage,
)
from verifier.runtime import public_cli


def _index(tmp_path: Path) -> tuple[StoredComponentIndex, Path]:
    descriptor = InteroperabilityComponentDescriptor(
        component_id="component:index-cli-fixture",
        label="Local index fixture checker",
        kind=ComponentKind.CHECKER,
        lifecycle=ComponentLifecycle.EXPERIMENTAL,
        implementation_ref="inert_fixture:check",
        accepted_schema_ids=(),
        planning_surface_schema_ids=("VSTD-2",),
        supported_relations=("relation:fixture",),
        mechanism_ids=("mechanism:fixture",),
        interaction_modes=(InteractionMode.STATIC,),
        availability=ComponentAvailability.NOT_CHECKED,
        claim_boundary="Declared match only; native execution is not established.",
    )
    package = StoredComponentPackage(
        package_id="package:index-cli-fixture",
        package_version="1.0.0",
        publisher="Unsigned fixture declaration",
        license="Apache-2.0",
        description="Inert bytes for local index command tests.",
        registry=InteroperabilityComponentRegistry("index-cli-1", (descriptor,)),
        artifacts=(
            PackageArtifact(
                "src/inert_fixture.py",
                "text/x-python",
                b'raise AssertionError("index commands must not execute this")\n',
            ),
        ),
        implementations=(
            ImplementationBinding(
                descriptor.component_id,
                descriptor.implementation_ref,
                ("src/inert_fixture.py",),
            ),
        ),
    )
    index = StoredComponentIndex(
        index_id="index:cli-fixture",
        index_version="1",
        description="Bounded local fixture index; no ecosystem-completeness claim.",
        packages=(IndexedComponentPackage.from_package(package),),
    )
    path = tmp_path / "index.json"
    save_component_index(index, path)
    return index, path


def test_index_inspect_is_local_nonexecuting_and_claim_bounded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    index, path = _index(tmp_path)
    before = path.read_bytes()

    assert public_cli.main(
        ["components", "index", "inspect", str(path), "--json", "--expected-sha256", index.canonical_digest()]
    ) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)

    assert output.err == ""
    assert report == index.inspect()
    assert report["package_availability"] == "NOT_CHECKED"
    assert report["native_qualification"] == "NOT_ESTABLISHED"
    assert report["ecosystem_completeness"] == "UNKNOWN"
    assert report["execution_performed"] is False
    assert "index commands must not execute this" not in output.out
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_index_search_returns_exact_declarations_without_ranking(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    index, path = _index(tmp_path)
    arguments = [
        "components", "index", "search", str(path),
        "--schema-id", "VSTD-2", "--interaction-mode", "STATIC",
        "--relation-id", "relation:fixture", "--mechanism-id", "mechanism:fixture",
        "--expected-sha256", index.canonical_digest(), "--json",
    ]

    assert public_cli.main(arguments) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)

    assert output.err == ""
    assert report["result"] == "DECLARED_MATCHES"
    assert report["match_count"] == 1
    assert report["matches"][0]["component"]["component_id"] == "component:index-cli-fixture"
    assert report["matches"][0]["package_sha256"] == index.packages[0].package_sha256
    assert report["package_availability"] == "NOT_CHECKED"
    assert report["native_qualification"] == "NOT_ESTABLISHED"
    assert report["ecosystem_completeness"] == "UNKNOWN"
    assert report["execution_performed"] is False


def test_index_search_preserves_bounded_zero_match(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, path = _index(tmp_path)

    assert public_cli.main(
        [
            "components", "index", "search", str(path),
            "--schema-id", "VSTD-2", "--interaction-mode", "STATIC",
            "--mechanism-id", "mechanism:absent", "--json",
        ]
    ) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["result"] == "NO_DECLARED_MATCH_IN_THIS_INDEX"
    assert report["matches"] == []
    assert report["ecosystem_completeness"] == "UNKNOWN"
    assert "ecosystem absence" in report["claim_boundary"]


def test_index_search_requires_relation_or_mechanism_before_loading(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert public_cli.main(
        [
            "components", "index", "search", "absent.json",
            "--schema-id", "VSTD-2", "--interaction-mode", "STATIC", "--json",
        ]
    ) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "requires --relation-id or --mechanism-id" in output.err


def test_index_digest_mismatch_and_url_input_fail_without_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, path = _index(tmp_path)
    for source in (str(path), "https://example.invalid/index.json"):
        arguments = ["components", "index", "inspect", source, "--json"]
        if source == str(path):
            arguments.extend(("--expected-sha256", "0" * 64))
        assert public_cli.main(arguments) == 1
        output = capsys.readouterr()
        assert output.out == ""
        assert "[FAIL]" in output.err


def test_index_inspection_runs_without_optional_dependencies(tmp_path: Path) -> None:
    index, path = _index(tmp_path)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

    result = subprocess.run(
        [
            sys.executable, "-S", "-m", "verifier.runtime.public_cli",
            "components", "index", "inspect", str(path), "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == index.inspect()
