"""Generated static Verifier Standard (VSTD) component-index tests.

Terminology: Hypertext Markup Language (HTML); JavaScript Object Notation (JSON);
Hypertext Transfer Protocol Secure (HTTPS); Secure Hash Algorithm 256-bit (SHA-256);
uniform resource locator (URL).
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

from verifier.interoperability.catalog import (
    ComponentKind,
    ComponentLifecycle,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from verifier.interoperability.component_index import load_component_index
from verifier.interoperability.storage import (
    ImplementationBinding,
    PackageArtifact,
    StoredComponentPackage,
    load_component_package,
)


ROOT = Path(__file__).resolve().parents[1]


def _builder():
    path = ROOT / "scripts/build_component_index.py"
    spec = importlib.util.spec_from_file_location("build_component_index_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _head() -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def _package(version: str) -> StoredComponentPackage:
    descriptor = InteroperabilityComponentDescriptor(
        component_id="component:static-index-fixture",
        label="Static index fixture",
        kind=ComponentKind.CHECKER,
        lifecycle=ComponentLifecycle.EXPERIMENTAL,
        implementation_ref="fixture:check",
        accepted_schema_ids=(),
        planning_surface_schema_ids=("VSTD-2",),
        mechanism_ids=("mechanism:fixture",),
        claim_boundary="Declared fixture only; no execution or qualification is established.",
    )
    return StoredComponentPackage(
        package_id="package:static-index-fixture",
        package_version=version,
        publisher="Unsigned fixture declaration",
        license="Apache-2.0",
        description="Inert fixture package.",
        registry=InteroperabilityComponentRegistry("static-index-1", (descriptor,)),
        artifacts=(PackageArtifact("src/fixture.py", "text/x-python", b"pass\n"),),
        implementations=(ImplementationBinding(
            descriptor.component_id, descriptor.implementation_ref, ("src/fixture.py",),
        ),),
    )


def _use_fixture_exporter(module, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        module,
        "_reference_exporter",
        lambda: SimpleNamespace(build_package=lambda _root, version: _package(version)),
    )
    monkeypatch.setattr(module, "_worktree_dirty", lambda: False)


def test_static_component_surface_is_exact_host_neutral_and_nonexecuting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _builder()
    _use_fixture_exporter(module, monkeypatch)
    head = _head()
    output = tmp_path / "components"

    written = module.build(output, source_ref=head)
    index_bytes = (output / "index.json").read_bytes()
    digest = hashlib.sha256(index_bytes).hexdigest()
    index = load_component_index(output / "index.json", expected_digest=digest)
    entry = index.packages[0]
    package = load_component_package(output / entry.package_path, expected_digest=entry.package_sha256)

    assert set(written) == {
        output / "index.html",
        output / "index.json",
        output / "index.sha256",
        output / "deployment-coordinate.json",
        output / entry.package_path,
    }
    assert index.index_version == f"{module._project_version()}+git.{head[:12]}"
    assert entry.package_version == index.index_version
    assert entry.package_path == f"packages/sha256/{entry.package_sha256}.json"
    assert entry.package_size_bytes == len((output / entry.package_path).read_bytes())
    assert entry.validate_package(package) == entry.package_sha256
    assert (output / "index.sha256").read_text(encoding="ascii") == f"{digest}  index.json\n"

    coordinate = json.loads((output / "deployment-coordinate.json").read_text(encoding="utf-8"))
    assert coordinate == {
        "schema_version": 1,
        "source_ref": head,
        "base_url": "https://timelordraps.github.io/verifier/",
        "index_path": "index.json",
        "index_sha256": digest,
    }
    page = (output / "index.html").read_text(encoding="utf-8")
    assert "NOT_CHECKED" in page
    assert "NOT_ESTABLISHED" in page
    assert "UNKNOWN" in page
    assert "No component execution or ranking" in page
    assert entry.package_sha256 in page
    assert str(ROOT) not in page
    assert "packages/sha256/" not in index_bytes.decode("utf-8").replace(entry.package_path, "")


def test_static_component_surface_is_reproducible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _builder()
    _use_fixture_exporter(module, monkeypatch)
    head = _head()
    first = tmp_path / "first"
    second = tmp_path / "second"

    module.build(first, source_ref=head)
    module.build(second, source_ref=head)

    first_files = {
        path.relative_to(first).as_posix(): path.read_bytes()
        for path in first.rglob("*") if path.is_file()
    }
    second_files = {
        path.relative_to(second).as_posix(): path.read_bytes()
        for path in second.rglob("*") if path.is_file()
    }
    assert first_files == second_files


def test_builder_cli_binds_the_exact_checkout_without_pythonpath(tmp_path: Path) -> None:
    output = tmp_path / "components"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/build_component_index.py"),
            "--output",
            str(output),
            "--source-ref",
            "WORKTREE",
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "[COMPONENT INDEX OK]" in result.stdout
    assert (output / "index.json").is_file()


@pytest.mark.parametrize(
    ("source_ref", "base_url", "message"),
    (
        ("0" * 40, "https://timelordraps.github.io/verifier/", "exact checkout HEAD"),
        ("branch-name", "https://timelordraps.github.io/verifier/", "full Git commit"),
        ("WORKTREE", "http://example.invalid/", "absolute HTTPS"),
        ("WORKTREE", "https://example.invalid/no-trailing", "trailing slash"),
    ),
)
def test_builder_rejects_unbound_coordinates(
    tmp_path: Path, source_ref: str, base_url: str, message: str
) -> None:
    module = _builder()
    with pytest.raises(module.ComponentIndexBuildError, match=message):
        module.build(tmp_path / "components", source_ref=source_ref, base_url=base_url)


def test_builder_never_merges_into_existing_output(tmp_path: Path) -> None:
    module = _builder()
    output = tmp_path / "components"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep\n", encoding="utf-8")

    with pytest.raises(module.ComponentIndexBuildError, match="must not already exist"):
        module.build(output, source_ref=_head())

    assert marker.read_text(encoding="utf-8") == "keep\n"


def test_builder_main_reports_bounded_refusal_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _builder()

    with pytest.raises(SystemExit) as stopped:
        module.main(["--output", str(tmp_path), "--source-ref", "WORKTREE"])

    output = capsys.readouterr()
    assert stopped.value.code == 2
    assert output.out == ""
    assert "Component index build refused:" in output.err
    assert "Traceback" not in output.err


def test_worktree_index_retains_reviewed_hardware_and_proposition_transfer_sources(tmp_path: Path) -> None:
    module = _builder()
    required = {
        "src/verifier/domains/hardware.py",
        "src/verifier/interoperability/proposition_transfer.py",
        "src/verifier/profiles/proposition-transfer-rule-1.json",
        "src/verifier/schemas/verifier-proposition-transfer-1.schema.json",
        "src/verifier/standard/PROPOSITION_TRANSFER.md",
    }
    output = tmp_path / "components"

    module.build(output, source_ref="WORKTREE")

    index = load_component_index(output / "index.json")
    entry = index.packages[0]
    package = load_component_package(output / entry.package_path, expected_digest=entry.package_sha256)
    artifacts = {item.path: item.content for item in package.artifacts}
    assert required <= artifacts.keys()
    assert all(artifacts[name] == (ROOT / name).read_bytes() for name in required)
    assert required <= set(module.REVIEWED_CANDIDATE_SOURCE_PATHS)
    coordinate = json.loads((output / "deployment-coordinate.json").read_text(encoding="utf-8"))
    assert coordinate["source_ref"] == "WORKTREE"


def test_worktree_package_archive_retains_every_public_source_byte(tmp_path: Path) -> None:
    module = _builder()
    output = tmp_path / "components"
    module.build(output, source_ref="WORKTREE")
    index = load_component_index(output / "index.json")
    entry = index.packages[0]
    package = load_component_package(output / entry.package_path, expected_digest=entry.package_sha256)
    artifacts = {item.path: item for item in package.artifacts}
    archive = artifacts["source-archive/exact-public-source.zip"]
    assert archive.media_type == "application/zip"
    assert len(package.artifacts) <= 256

    tracked = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"])
    expected = {
        raw.decode("utf-8") for raw in tracked.split(b"\0") if raw
        and (raw.decode("utf-8") in {"pyproject.toml", "LICENSE", "NOTICE", "README.md"}
             or (raw.startswith(b"src/verifier/")
                 and Path(raw.decode("utf-8")).suffix in {".py", ".json", ".md"}))
    }
    direct_required = {"pyproject.toml", "LICENSE", "NOTICE", "README.md"}
    direct_required.update(
        path for path in expected if path.startswith("src/verifier/") and (
            path.endswith((".json", ".md"))
            or (path.startswith("src/verifier/domains/")
                and path.count("/") == 3 and path.endswith(".py"))
        )
    )
    for component in package.registry.components:
        module = "src/" + component.implementation_ref.split(":", 1)[0].replace(".", "/")
        direct_required.add(next(path for path in (module + ".py", module + "/__init__.py")
                                 if path in expected))
    with zipfile.ZipFile(io.BytesIO(archive.content)) as bundled:
        assert bundled.namelist() == ["source-inventory.json", *sorted(expected - direct_required)]
        manifest_bytes = bundled.read("source-inventory.json")
        manifest = json.loads(manifest_bytes)
        assert manifest_bytes == json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                                           ensure_ascii=True).encode("ascii")
        assert manifest == {
            "schema_version": "verifier-reference-source-archive-1",
            "files": [
                {"path": path, "size_bytes": len((ROOT / path).read_bytes()),
                 "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                 "location": "DIRECT" if path in direct_required else "ARCHIVE"}
                for path in sorted(expected)
            ],
        }
        for item in bundled.infolist():
            assert item.compress_type == zipfile.ZIP_STORED
            assert item.date_time == (1980, 1, 1, 0, 0, 0)
            assert ".." not in Path(item.filename).parts
            if item.filename != "source-inventory.json":
                assert bundled.read(item) == (ROOT / item.filename).read_bytes()
    assert set(artifacts) == direct_required | {"source-archive/exact-public-source.zip"}
    assert all(artifacts[path].content == (ROOT / path).read_bytes() for path in direct_required)
    assert all("source-archive/exact-public-source.zip" in binding.artifact_paths
               for binding in package.implementations)
    assert (output / entry.package_path).stat().st_size <= 8 * 1024 * 1024


def test_default_worktree_inventory_does_not_admit_an_unreviewed_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _builder()
    exporter = module._reference_exporter()
    actual_git = exporter._git
    unreviewed = "src/verifier/unreviewed_source.py"

    def git(root: Path, *arguments: str) -> bytes:
        result = actual_git(root, *arguments)
        if arguments == ("ls-files", "--others", "--exclude-standard", "-z"):
            return result + unreviewed.encode("utf-8") + b"\0"
        return result

    monkeypatch.setattr(exporter, "_git", git)
    monkeypatch.setattr(module, "_reference_exporter", lambda: exporter)
    output = tmp_path / "withheld"
    with pytest.raises(ValueError, match="untracked public source files require explicit"):
        module.build(output, source_ref="WORKTREE")
    assert not output.exists()
    assert unreviewed not in module.REVIEWED_CANDIDATE_SOURCE_PATHS


def test_explicit_worktree_inventory_cannot_silently_omit_reviewed_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _builder()
    exporter = module._reference_exporter()
    actual_git = exporter._git
    required = "src/verifier/interoperability/proposition_transfer.py"

    def git(root: Path, *arguments: str) -> bytes:
        result = actual_git(root, *arguments)
        if arguments == ("ls-files", "--others", "--exclude-standard", "-z"):
            names = [value for value in result.split(b"\0") if value]
            return b"\0".join(sorted(set(names) | {required.encode("utf-8")})) + b"\0"
        return result

    monkeypatch.setattr(exporter, "_git", git)
    monkeypatch.setattr(module, "_reference_exporter", lambda: exporter)
    selected = tuple(value for value in module._reviewed_untracked_candidate_sources() if value != required)
    output = tmp_path / "omitted"
    with pytest.raises(ValueError, match="untracked public source files require explicit"):
        module.build(output, source_ref="WORKTREE", include_untracked=selected)
    assert not output.exists()
