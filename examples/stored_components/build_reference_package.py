"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Capture explicitly scoped public source bytes in a nonexecuting component package.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
from typing import Sequence

from verifier.interoperability import catalog as catalog_module
from verifier.interoperability import reference_catalog as reference_module
from verifier.interoperability.storage import (
    ImplementationBinding,
    PackageArtifact,
    PackageDependency,
    StoredComponentPackage,
    save_component_package,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE_SUFFIXES = {".py", ".json", ".md"}
FIXED_FILES = {"pyproject.toml", "LICENSE", "NOTICE", "README.md"}
PUBLIC_REMOTES = {
    "https://github.com/TimeLordRaps/verifier.git",
    "https://github.com/TimeLordRaps/verifier",
}


def _git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ValueError("source inventory requires a readable public Git checkout")
    return result.stdout


def _source_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        path.is_relative_to(PurePosixPath("src/verifier"))
        and path.suffix in SOURCE_SUFFIXES
        and ".." not in path.parts
        and "\\" not in value
        and path.as_posix() == value
    )


def _reject_links(path: Path, root: Path) -> None:
    """Reject links and Windows reparse points, including parent directories."""
    if not path.is_relative_to(root):
        raise ValueError("source artifact escaped the selected root")
    current = path
    while True:
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ValueError("source artifacts and their parent directories must not be links")
        if current == root:
            break
        current = current.parent


def _capture_snapshot(
    source_root: Path, include_untracked: Sequence[str] = ()
) -> tuple[dict[str, bytes], str, bool]:
    root = Path(os.path.abspath(source_root))
    _reject_links(root, root)
    if Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
        raise ValueError("source-root must be the exact public repository root")
    if _git(root, "remote", "get-url", "origin").decode().strip() not in PUBLIC_REMOTES:
        raise ValueError("source-root must identify the public TimeLordRaps/verifier repository")
    tracked: set[str] = set()
    for entry in _git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        if path not in FIXED_FILES and not _source_path(path):
            continue
        mode, _, stage = metadata.decode("ascii").split()
        if mode not in {"100644", "100755"} or stage != "0":
            raise ValueError("source inventory must contain only unconflicted regular files")
        tracked.add(path)
    if not FIXED_FILES <= tracked:
        raise ValueError("public source inventory lacks a required fixed metadata file")
    untracked = {
        entry.decode("utf-8")
        for entry in _git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
        if entry and _source_path(entry.decode("utf-8"))
    }
    selected = set(include_untracked)
    if len(selected) != len(include_untracked) or not selected <= untracked:
        raise ValueError("each include-untracked path must name one untracked public source file")
    if untracked - selected:
        raise ValueError(
            "untracked public source files require explicit --include-untracked paths; "
            "review and name each intended file or use a fully tracked checkout"
        )
    captured: dict[str, bytes] = {}
    for name in sorted(tracked | selected):
        path = root / name
        _reject_links(path, root)
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("source inventory contains a non-regular file")
        captured[name] = path.read_bytes()
    head = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    dirty = bool(_git(root, "status", "--porcelain=v1", "--untracked-files=normal"))
    return captured, head, dirty


def build_package(
    source_root: Path, package_version: str, include_untracked: Sequence[str] = ()
) -> StoredComponentPackage:
    """Retain bytes, not an installed runtime or independently qualified verifier."""
    captured, head, dirty = _capture_snapshot(source_root, include_untracked)
    for module in (catalog_module, reference_module):
        expected_path = "src/" + module.__name__.replace(".", "/") + ".py"
        if captured.get(expected_path) != Path(module.__file__).read_bytes():
            raise ValueError("captured catalog source differs from the exporting Python environment")
    registry = reference_module.reference_component_registry()
    family_count = len({family for component in registry.components for family in component.verifier_family_ids})
    source_paths = tuple(name for name in captured if name.startswith("src/verifier/"))
    for component in registry.components:
        module_name = component.implementation_ref.split(":", 1)[0]
        module_path = "src/" + module_name.replace(".", "/")
        if not any(name in captured for name in (module_path + ".py", module_path + "/__init__.py")):
            raise ValueError("a reference component has no retained implementation module")
    artifacts = tuple(
        PackageArtifact(
            path=name,
            media_type="application/json" if name.endswith(".json") else "text/plain",
            content=content,
        )
        for name, content in captured.items()
    )
    dependencies = (
        PackageDependency("python-runtime", "Python >=3.10; runtime not included", ("pyproject.toml",)),
        PackageDependency(
            "declared-optional-dependencies",
            "Conditional extras declared in retained pyproject.toml; not bundled or resolved",
            ("pyproject.toml",),
        ),
    )
    return StoredComponentPackage(
        package_id="timelordraps/verifier-reference-components",
        package_version=package_version,
        publisher="TimeLordRaps (unsigned declaration)",
        license="Apache-2.0",
        description=(
            f"Public source snapshot; Git HEAD {head}; working tree dirty={str(dirty).lower()}. "
            "Captured bytes, not HEAD alone, identify this snapshot. "
            f"{len(registry.components)} first-party entrypoints across {family_count} grouping labels, not independent integrations. "
            "Not a wheel, installation archive, runtime, or conformance result. "
            "Dependency closure NOT_ESTABLISHED; native runtime dependencies are not bundled."
        ),
        registry=registry,
        artifacts=artifacts,
        implementations=tuple(
            ImplementationBinding(
                component_id=component.component_id,
                implementation_ref=component.implementation_ref,
                artifact_paths=source_paths,
                dependency_ids=tuple(dependency.dependency_id for dependency in dependencies),
            )
            for component in registry.components
        ),
        dependencies=dependencies,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--include-untracked", action="append", default=[])
    arguments = parser.parse_args(argv)
    try:
        package = build_package(arguments.source_root, arguments.package_version, arguments.include_untracked)
        save_component_package(package, arguments.output)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Package export refused: {exc}\n")
    print(f"Stored {len(package.registry.components)} declared components; package digest {package.canonical_digest()}")
    print("No component was executed; dependency closure NOT_ESTABLISHED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
