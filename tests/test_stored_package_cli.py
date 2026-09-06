"""Stored component package command-line interface (CLI) regression tests.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD).
"""

from __future__ import annotations

from dataclasses import replace
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from verifier.interoperability.catalog import (
    ComponentAvailability,
    ComponentKind,
    ComponentLifecycle,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from verifier.interoperability.storage import (
    ImplementationBinding,
    PackageArtifact,
    StoredComponentPackage,
    save_component_package,
)
from verifier.runtime import public_cli


def _package(tmp_path: Path) -> tuple[StoredComponentPackage, Path]:
    descriptor = InteroperabilityComponentDescriptor(
        component_id="component:stored-cli-fixture",
        label="Stored local fixture checker",
        kind=ComponentKind.CHECKER,
        lifecycle=ComponentLifecycle.EXPERIMENTAL,
        implementation_ref="stored_checker:check",
        accepted_schema_ids=(),
        planning_surface_schema_ids=("VSTD-2",),
        mechanism_ids=("mechanism:fixture-test",),
        availability=ComponentAvailability.NOT_CHECKED,
        claim_boundary="Stored declarations only; no native checking is established.",
    )
    package = StoredComponentPackage(
        package_id="package:cli-fixture",
        package_version="1",
        publisher="Local fixture publisher; unverified declaration",
        license="MIT",
        description="An inert implementation specimen for package CLI checks.",
        registry=InteroperabilityComponentRegistry("cli-fixture-1", (descriptor,)),
        artifacts=(
            PackageArtifact(
                path="src/stored_checker.py",
                media_type="text/x-python",
                content=b'raise AssertionError("stored implementation must never execute")\n',
            ),
        ),
        implementations=(
            ImplementationBinding(
                component_id=descriptor.component_id,
                implementation_ref=descriptor.implementation_ref,
                artifact_paths=("src/stored_checker.py",),
            ),
        ),
    )
    path = tmp_path / "component-package.json"
    save_component_package(package, path)
    return package, path


def _geometry(tmp_path: Path) -> Path:
    source = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "verification_geometry_residual"
        / "geometry.json"
    )
    path = tmp_path / "geometry.json"
    path.write_bytes(source.read_bytes())
    return path


def test_components_inspect_is_nonexecuting_and_content_free(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    package, path = _package(tmp_path)
    before = path.read_bytes()

    assert public_cli.main(["components", "inspect", str(path), "--json"]) == 0
    first = capsys.readouterr()
    assert public_cli.main(
        [
            "components", "inspect", str(path), "--json",
            "--expected-sha256", package.canonical_digest(),
        ]
    ) == 0
    second = capsys.readouterr()

    assert first.err == second.err == ""
    assert first.out == second.out
    report = json.loads(first.out)
    assert report == package.inspect()
    assert report["integrity_result"] == "PASS"
    assert "stored implementation must never execute" not in first.out
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_components_inspect_text_discloses_integrity_boundary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    package, path = _package(tmp_path)

    assert public_cli.main(["components", "inspect", str(path)]) == 0
    output = capsys.readouterr()
    assert "NO EXECUTION" in output.out
    assert package.canonical_digest() in output.out
    assert "does not establish availability, correctness" in output.out
    assert "authorship, authorization" in output.out
    assert output.err == ""


def test_components_inspect_runs_without_optional_runtime_dependencies(
    tmp_path: Path,
) -> None:
    package, path = _package(tmp_path)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

    result = subprocess.run(
        [
            sys.executable, "-S", "-m", "verifier.runtime.public_cli",
            "components", "inspect", str(path), "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == package.inspect()


@pytest.mark.parametrize("mode", ("inspect", "plan"))
def test_package_digest_mismatch_fails_without_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    _, path = _package(tmp_path)
    if mode == "inspect":
        command = ["components", "inspect", str(path), "--expected-sha256", "0" * 64]
    else:
        command = [
            "surface", "analyze", str(_geometry(tmp_path)), "--plan",
            "--package", str(path), "--expected-package-sha256", "0" * 64,
        ]

    assert public_cli.main([*command, "--json"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "[FAIL]" in output.err


@pytest.mark.parametrize("mode", ("inspect", "plan"))
def test_malformed_package_never_falls_back_to_builtin_registry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    path = tmp_path / "unsupported.json"
    path.write_text('{"schema_version":"NOT-A-COMPONENT-PACKAGE"}', encoding="utf-8")
    if mode == "inspect":
        command = ["components", "inspect", str(path)]
    else:
        command = [
            "surface", "analyze", str(_geometry(tmp_path)), "--plan", "--package", str(path)
        ]

    assert public_cli.main([*command, "--json"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "[FAIL]" in output.err


def test_surface_plan_uses_stored_registry_and_binds_package_digest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, path = _package(tmp_path)
    geometry = _geometry(tmp_path)
    before = {item.name: item.read_bytes() for item in tmp_path.iterdir()}

    def reject_builtin_registry() -> None:
        raise AssertionError("the requested stored registry must not be replaced")

    monkeypatch.setattr(public_cli, "reference_component_registry", reject_builtin_registry)
    assert public_cli.main(
        [
            "surface", "analyze", str(geometry), "--plan", "--package", str(path),
            "--expected-package-sha256", package.canonical_digest(), "--json",
        ]
    ) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)

    assert report["catalog"]["source"] == "STORED_COMPONENT_PACKAGE"
    assert report["catalog"]["package_digest"] == package.canonical_digest()
    assert report["catalog"]["registry_digest"] == package.registry.canonical_digest()
    assert report["catalog"]["component_count"] == 1
    assert "authorship, authorization" in report["catalog"]["claim_boundary"]
    assert "first-party" not in report["catalog"]["claim_boundary"]
    assert report["plan"]["registry_digest"] == package.registry.canonical_digest()
    assert report["plan"]["package_digest"] == package.canonical_digest()
    assert report["plan"]["binding_scope"] == "STORED_PACKAGE"
    assert report["plan"]["plan_only"] is True
    assert report["plan"]["execution_performed"] is False
    candidates = [
        candidate for candidate in report["plan"]["candidates"]
        if candidate["component_id"] == "component:stored-cli-fixture"
    ]
    assert candidates
    assert all(candidate["status"] != "CANDIDATE" for candidate in candidates)
    assert output.err == ""
    assert {item.name: item.read_bytes() for item in tmp_path.iterdir()} == before


def test_changed_payload_changes_cli_plan_even_with_the_same_registry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    package, path = _package(tmp_path)
    geometry = _geometry(tmp_path)
    changed = replace(
        package,
        artifacts=(replace(package.artifacts[0], content=b"# different inert bytes\n"),),
    )
    changed_path = tmp_path / "changed-package.json"
    save_component_package(changed, changed_path)
    plans = []
    for package_path in (path, changed_path):
        assert public_cli.main(
            ["surface", "analyze", str(geometry), "--plan", "--package",
             str(package_path), "--json"]
        ) == 0
        plans.append(json.loads(capsys.readouterr().out)["plan"])
    assert plans[0]["registry_digest"] == plans[1]["registry_digest"]
    assert plans[0]["package_digest"] != plans[1]["package_digest"]
    assert plans[0]["plan_id"] != plans[1]["plan_id"]
    assert all(plan["execution_performed"] is False for plan in plans)


def test_surface_package_text_discloses_source_boundary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    package, path = _package(tmp_path)
    assert public_cli.main(
        ["surface", "analyze", str(_geometry(tmp_path)), "--plan", "--package", str(path)]
    ) == 0
    output = capsys.readouterr()
    assert "NO EXECUTION" in output.out
    assert package.canonical_digest() in output.out
    assert "Source boundary:" in output.out
    assert "authorship, authorization" in output.out
    assert output.err == ""


@pytest.mark.parametrize(
    ("options", "message"),
    (
        (["--package", "absent.json"], "package options require --plan"),
        (["--package", ""], "package options require --plan"),
        (["--expected-package-sha256", "0" * 64], "package options require --plan"),
        (["--plan", "--expected-package-sha256", "0" * 64], "requires --package"),
        (["--plan", "--expected-package-sha256", ""], "requires --package"),
    ),
)
def test_package_option_dependencies_fail_before_geometry_loading(
    capsys: pytest.CaptureFixture[str], options: list[str], message: str
) -> None:
    assert public_cli.main(["surface", "analyze", "absent.json", *options, "--json"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert message in output.err


def test_default_surface_plan_catalog_shape_is_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert public_cli.main(
        ["surface", "analyze", str(_geometry(tmp_path)), "--plan", "--json"]
    ) == 0
    report = json.loads(capsys.readouterr().out)
    assert set(report["catalog"]) == {
        "registry_version", "registry_digest", "component_count",
        "implementation_family_count", "claim_boundary",
    }
    assert report["catalog"]["claim_boundary"] == public_cli.REFERENCE_CATALOG_CLAIM_BOUNDARY
