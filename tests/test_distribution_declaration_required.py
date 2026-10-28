"""Python artifacts cannot omit their distribution declaration to skip checks.

Source distribution (sdist); JavaScript Object Notation (JSON); ZIP archive
format (ZIP); Unicode Transformation Format, 8-bit (UTF-8). This test constructs
disposable Git objects with bounded local child commands. It builds no package,
installs nothing, and does not touch project history or assert hosted damage.
Schema payloads are name-only fixtures because their pre-existing gate checks
inventory; the selected normative specification has exact source-bound bytes.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

import pytest

from scripts import release_artifacts


SOURCE_FILES = {
    "src/verifier/__init__.py": b'__version__ = "2.0.0"\n',
    "src/verifier/standard/POLISH_REQUIREMENTS.md": b"# Finite fixture specification.\n",
}


# A current final-artifact fixture carries its selected core/WIP declaration.
# Historical source-only fixtures retain their original source map.
CURRENT_SOURCE_FILES = {
    **SOURCE_FILES,
    "src/verifier/standard/CORE_V2_RELEASE_SCOPE.md": (
        b"Core release target: `2.0.0`.\n"
        b"Core release scope: `verifier-core-release-scope-1`.\n"
        b"Core current-object semantics: `verifier-current-object-obligations-1`.\n"
        b"Included extension: `verifier-corrigibility-extension-wip-1`.\n"
        b"Extension selection schema: `verifier-corrigibility-extension-selection-1`.\n"
        b"Extension status: `WIP`.\n"
        b"Extension completion: `UNKNOWN`.\n"
        b"Extension core gate credit: `NONE`.\n"
    ),
}


def _source_objects(root: Path, source_files: dict[str, bytes]) -> tuple[Path, str]:
    repo = root / "fixture-repository"
    repo.mkdir()

    def git(*args: str, payload: bytes | None = None) -> bytes:
        return subprocess.run(
            ["git", *args], cwd=repo, input=payload, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=True,
        ).stdout

    git("init")
    for name, content in source_files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    # The disposable index supplies nested paths; no project commit is created.
    # Disable host line conversions so the Git oracle is the literal fixture.
    git("-c", "core.autocrlf=false", "add", "--all")
    tree = git("write-tree").strip()
    commit = git("hash-object", "-t", "commit", "-w", "--stdin", payload=(
        b"tree " + tree + b"\n"
        b"author Fixture <fixture> 1700000000 +0000\n"
        b"committer Fixture <fixture> 1700000000 +0000\n\n"
        b"Disposable unreferenced distribution-declaration fixture.\n"
    )).decode("ascii").strip()
    return repo, commit


def _python_archives(root: Path, source_files: dict[str, bytes]) -> dict[str, Path]:
    metadata = b"Metadata-Version: 2.4\nName: verifier-standard\nVersion: 2.0.0\n\n"
    entries = "[console_scripts]\n" + "".join(
        name + " = " + target + "\n"
        for name, target in release_artifacts.CONSOLE_SCRIPTS.items()
    )
    members = {name.removeprefix("src/verifier/"): content
               for name, content in source_files.items()}
    members.update({"schemas/" + name: b"{}\n"
                    for name in release_artifacts.PACKAGED_SCHEMA_NAMES})
    wheel = root / "verifier_standard-2.0.0-py3-none-any.whl"
    sdist = root / "verifier_standard-2.0.0.tar.gz"
    with zipfile.ZipFile(wheel, "w") as bundle:
        prefix = "verifier_standard-2.0.0.dist-info/"
        bundle.writestr(prefix + "METADATA", metadata)
        bundle.writestr(prefix + "entry_points.txt", entries.encode("utf-8"))
        for name, content in members.items():
            bundle.writestr("verifier/" + name, content)
    with tarfile.open(sdist, "w:gz") as bundle:
        prefix = "verifier_standard-2.0.0/"
        contents = [(prefix + "PKG-INFO", metadata)] + [
            (prefix + "src/verifier/" + name, content)
            for name, content in members.items()
        ]
        for name, content in contents:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))
    return {"wheel": wheel, "sdist": sdist}


def _manifest(root: Path, *, declaration: str, python_artifacts: tuple[str, ...],
              historical: bool = False) -> tuple[Path, Path]:
    source_files = SOURCE_FILES if historical else CURRENT_SOURCE_FILES
    repo, commit = _source_objects(root, source_files)
    release = "1.1.1" if historical else "2.0.0"
    stem = "verifiable-standard" if historical else "verifier-standard"
    prefix = f"{stem}-{release}/"
    source_archive = root / f"{stem}-{release}.zip"
    with zipfile.ZipFile(source_archive, "w") as bundle:
        for name, content in source_files.items():
            bundle.writestr(prefix + name, content)
    artifacts = {source_archive.name: release_artifacts._file_record(source_archive)}
    if python_artifacts:
        built = _python_archives(root, source_files)
        artifacts.update({built[kind].name: release_artifacts._file_record(built[kind])
                          for kind in python_artifacts})
    manifest = {
        "schema_version": release_artifacts.SCHEMA_VERSION,
        "release": release,
        "source": {"ref": commit, "commit": commit, "archive_prefix": prefix},
        "artifacts": artifacts,
        "files": release_artifacts._archive_inventory(source_archive, prefix),
    }
    if declaration == "canonical":
        manifest["distribution"] = {
            "name": "verifier-standard", "import_package": "verifier",
            "console_scripts": dict(release_artifacts.CONSOLE_SCRIPTS),
        }
    elif declaration == "null":
        manifest["distribution"] = None
    else:
        assert declaration == "absent"
    path = root / "fixture.manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return repo, path


def test_current_declared_python_artifacts_bind_selected_source(tmp_path: Path) -> None:
    release_artifacts.verify_manifest(*_manifest(
        tmp_path, declaration="canonical", python_artifacts=("wheel", "sdist"),
    ))


@pytest.mark.parametrize("declaration", ["absent", "null"])
def test_historical_source_only_manifests_preserve_optional_declaration(
    tmp_path: Path, declaration: str,
) -> None:
    release_artifacts.verify_manifest(*_manifest(
        tmp_path, declaration=declaration, python_artifacts=(), historical=True,
    ))


@pytest.mark.parametrize("declaration", ["absent", "null"])
@pytest.mark.parametrize("python_artifacts", [("wheel",), ("sdist",), ("wheel", "sdist")])
def test_known_python_artifacts_require_distribution_declaration(
    tmp_path: Path, declaration: str, python_artifacts: tuple[str, ...],
) -> None:
    repo, manifest = _manifest(tmp_path, declaration=declaration,
                               python_artifacts=python_artifacts)
    with pytest.raises(release_artifacts.ReleaseError, match="distribution"):
        release_artifacts.verify_manifest(repo, manifest)


def _replace_artifact_member(path: Path, member_name: str, raw: bytes) -> None:
    """Mutate one disposable artifact, retaining every other selected member."""
    if path.suffix in {".zip", ".whl"}:
        with zipfile.ZipFile(path) as bundle:
            members = [(info, bundle.read(info.filename)) for info in bundle.infolist()]
        assert sum(info.filename == member_name for info, _ in members) == 1
        with zipfile.ZipFile(path, "w") as bundle:
            for info, content in members:
                bundle.writestr(info, raw if info.filename == member_name else content)
    else:
        with tarfile.open(path, "r:gz") as bundle:
            members = [(info, bundle.extractfile(info).read()) for info in bundle.getmembers()]
        assert sum(info.name == member_name for info, _ in members) == 1
        with tarfile.open(path, "w:gz") as bundle:
            for info, content in members:
                selected = raw if info.name == member_name else content
                info.size = len(selected)
                bundle.addfile(info, io.BytesIO(selected))


@pytest.mark.parametrize("surface", ["source", "wheel", "sdist"])
def test_core_scope_bytes_bind_each_artifact_to_the_selected_source(
    tmp_path: Path, surface: str,
) -> None:
    repo, manifest_path = _manifest(
        tmp_path, declaration="canonical", python_artifacts=("wheel", "sdist"),
    )
    manifest = json.loads(manifest_path.read_bytes())
    name = "src/verifier/standard/CORE_V2_RELEASE_SCOPE.md"
    changed = CURRENT_SOURCE_FILES[name].replace(b"Extension status: `WIP`.",
                                                 b"Extension status: `wip`.")
    assert len(changed) == len(CURRENT_SOURCE_FILES[name])
    if surface == "source":
        path = tmp_path / "verifier-standard-2.0.0.zip"
        member = manifest["source"]["archive_prefix"] + name
    elif surface == "wheel":
        path = tmp_path / "verifier_standard-2.0.0-py3-none-any.whl"
        member = name.removeprefix("src/")
    else:
        path = tmp_path / "verifier_standard-2.0.0.tar.gz"
        member = "verifier_standard-2.0.0/" + name
    _replace_artifact_member(path, member, changed)
    # Recompute producer-supplied hashes: an internally consistent manifest still
    # cannot replace the specification selected by its actual Git source.
    manifest["artifacts"][path.name] = release_artifacts._file_record(path)
    if surface == "source":
        manifest["files"] = release_artifacts._archive_inventory(
            path, manifest["source"]["archive_prefix"],
        )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    expected = "Git blob" if surface == "source" else "specification bytes differ from selected source"
    with pytest.raises(release_artifacts.ReleaseError, match=expected):
        release_artifacts.verify_manifest(repo, manifest_path)
