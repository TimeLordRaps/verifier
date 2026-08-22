"""Build and verify public release artifacts from an exact public Git ref.

The release manifest is an artifact beside the source ZIP, not a tracked file inside
the source tree. That avoids a self-referential commit hash and makes ``source_commit``
both exact and publicly resolvable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "VSTD-PUBLIC-RELEASE-1.1"
# Archive stem for releases built from this tree. Releases up to and including v1.1.1
# were published as `verifiable-standard-<release>.zip`; their manifests carry that
# prefix and are still verified from the manifest itself.
ARCHIVE_STEM = "verifier-standard"


class ReleaseError(RuntimeError):
    """Release construction or verification failed closed."""


def _run(repo: Path, *args: str, env: dict[str, str] | None = None) -> bytes:
    completed = subprocess.run(
        list(args), cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseError(f"command failed ({' '.join(args)}): {detail}")
    return completed.stdout


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_record(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {"byte_size": len(data), "sha256": _sha256(data)}


def _resolved_commit(repo: Path, ref: str) -> str:
    return _run(repo, "git", "rev-parse", f"{ref}^{{commit}}").decode().strip()


def _repository_url(repo: Path) -> str:
    return _run(repo, "git", "remote", "get-url", "origin").decode().strip()


def _archive_inventory(archive: Path, prefix: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            if info.is_dir():
                continue
            if not info.filename.startswith(prefix):
                raise ReleaseError(f"archive member escapes declared prefix: {info.filename}")
            relative = info.filename[len(prefix) :]
            if not relative:
                raise ReleaseError("archive contains an empty relative path")
            data = bundle.read(info)
            result[relative] = {"byte_size": len(data), "sha256": _sha256(data)}
    return dict(sorted(result.items()))


def build_source(repo: Path, ref: str, release: str, output_dir: Path) -> tuple[Path, Path]:
    repo = repo.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    commit = _resolved_commit(repo, ref)
    prefix = f"{ARCHIVE_STEM}-{release}/"
    archive = output_dir / f"{ARCHIVE_STEM}-{release}.zip"
    manifest_path = output_dir / f"{ARCHIVE_STEM}-{release}.manifest.json"

    _run(
        repo,
        "git",
        "archive",
        "--format=zip",
        f"--prefix={prefix}",
        f"--output={archive}",
        commit,
    )

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "release": release,
        "scope": (
            "public VSTD specifications, schemas, target-neutral reference subset, "
            "examples, tests, and public project process"
        ),
        "source": {
            "repository": _repository_url(repo),
            "ref": ref,
            "commit": commit,
            "archive_prefix": prefix,
            "byte_semantics": "exact Git blob bytes as emitted by git archive",
        },
        "artifacts": {
            archive.name: _file_record(archive),
        },
        "files": _archive_inventory(archive, prefix),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return archive, manifest_path


def _build_wheel_once(source_archive: Path, prefix: str, destination: Path, epoch: str) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vstd-wheel-") as temporary:
        temporary_path = Path(temporary)
        with zipfile.ZipFile(source_archive) as bundle:
            bundle.extractall(temporary_path)
        source = temporary_path / prefix.rstrip("/")
        env = dict(os.environ)
        env["SOURCE_DATE_EPOCH"] = epoch
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--no-deps",
                "--wheel-dir",
                str(destination),
                str(source),
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode:
            raise ReleaseError(
                "wheel build failed: "
                + completed.stderr.decode("utf-8", errors="replace").strip()
            )
    wheels = sorted(destination.glob("*.whl"))
    if len(wheels) != 1:
        raise ReleaseError(f"expected one wheel, found {len(wheels)} in {destination}")
    return wheels[0]


def build_all(repo: Path, ref: str, release: str, output_dir: Path) -> tuple[Path, Path, Path]:
    archive, manifest_path = build_source(repo, ref, release, output_dir)
    commit = _resolved_commit(repo.resolve(), ref)
    epoch = _run(repo.resolve(), "git", "show", "-s", "--format=%ct", commit).decode().strip()
    prefix = f"{ARCHIVE_STEM}-{release}/"

    with tempfile.TemporaryDirectory(prefix="vstd-wheel-builds-") as temporary:
        temporary_path = Path(temporary)
        first = _build_wheel_once(archive, prefix, temporary_path / "first", epoch)
        second = _build_wheel_once(archive, prefix, temporary_path / "second", epoch)
        if first.name != second.name or first.read_bytes() != second.read_bytes():
            raise ReleaseError("two clean wheel builds were not byte-identical")
        wheel = output_dir / first.name
        shutil.copy2(first, wheel)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][wheel.name] = _file_record(wheel)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    verify_manifest(repo, manifest_path, output_dir)
    return archive, wheel, manifest_path


def verify_manifest(repo: Path, manifest_path: Path, artifact_dir: Path | None = None) -> None:
    repo = repo.resolve()
    manifest_path = manifest_path.resolve()
    artifact_dir = artifact_dir.resolve() if artifact_dir else manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseError(f"unsupported release manifest schema: {manifest.get('schema_version')}")

    source = manifest.get("source", {})
    ref = str(source.get("ref", ""))
    commit = str(source.get("commit", ""))
    if not ref or not commit:
        raise ReleaseError("manifest source ref and commit are required")
    resolved = _resolved_commit(repo, ref)
    if resolved != commit:
        raise ReleaseError(f"source ref resolves to {resolved}, manifest binds {commit}")

    artifacts = manifest.get("artifacts", {})
    for filename, expected in artifacts.items():
        path = artifact_dir / filename
        if not path.is_file() or _file_record(path) != expected:
            raise ReleaseError(f"artifact digest or byte size mismatch: {filename}")

    # Derive the archive name from the manifest, not from the current stem: releases
    # published before the package rename bind `verifiable-standard-<release>.zip`
    # and MUST stay verifiable.
    declared_prefix = str(source.get("archive_prefix", "")).rstrip("/")
    archive_name = (
        f"{declared_prefix}.zip"
        if declared_prefix
        else f"{ARCHIVE_STEM}-{manifest['release']}.zip"
    )
    archive = artifact_dir / archive_name
    if archive_name not in artifacts or not archive.is_file():
        raise ReleaseError(f"source archive is not bound: {archive_name}")
    prefix = str(source.get("archive_prefix", ""))
    inventory = _archive_inventory(archive, prefix)
    if inventory != manifest.get("files"):
        raise ReleaseError("source archive member inventory does not match the manifest")

    tracked = _run(repo, "git", "ls-tree", "-r", "--name-only", commit).decode().splitlines()
    if sorted(tracked) != sorted(inventory):
        raise ReleaseError("source archive file set does not match the bound Git commit")
    with zipfile.ZipFile(archive) as bundle:
        for relative, expected in inventory.items():
            archive_bytes = bundle.read(prefix + relative)
            git_bytes = _run(repo, "git", "show", f"{commit}:{relative}")
            if archive_bytes != git_bytes or _sha256(git_bytes) != expected["sha256"]:
                raise ReleaseError(f"archive bytes do not match Git blob: {relative}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest="command", required=True)

    for name in ("source", "build"):
        command = commands.add_parser(name)
        command.add_argument("--ref", required=True)
        command.add_argument("--release", required=True)
        command.add_argument("--output-dir", required=True, type=Path)

    verify = commands.add_parser("verify")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--artifact-dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "source":
            archive, manifest = build_source(args.repo, args.ref, args.release, args.output_dir)
            verify_manifest(args.repo, manifest, args.output_dir)
            print(f"[PASS] source archive: {archive}")
            print(f"[PASS] release manifest: {manifest}")
        elif args.command == "build":
            archive, wheel, manifest = build_all(
                args.repo, args.ref, args.release, args.output_dir
            )
            print(f"[PASS] source archive: {archive}")
            print(f"[PASS] reproducible wheel: {wheel}")
            print(f"[PASS] release manifest: {manifest}")
        else:
            verify_manifest(args.repo, args.manifest, args.artifact_dir)
            print(f"[PASS] release manifest verified: {args.manifest}")
    except (OSError, ReleaseError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
