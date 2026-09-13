"""Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Software Bill of Materials (SBOM); Unicode Transformation Format, 8-bit
(UTF-8); uniform resource locator (URL); Verifier Standard (VSTD); ZIP archive format (ZIP).

Build and verify public release artifacts from an exact public Git ref.

The release manifest is an artifact beside the source ZIP, not a tracked file inside
the source tree. That avoids a self-referential commit hash and makes ``source_commit``
both exact and publicly resolvable.
"""

from __future__ import annotations

import argparse
import base64
from configparser import ConfigParser
import csv
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Mapping

try:
    from scripts.classify_release_version import classify_release_version
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from classify_release_version import classify_release_version


SCHEMA_VERSION = "VSTD-PUBLIC-RELEASE-1.1"
CYCLONEDX_SPEC_VERSION = "1.6"
# Archive stem for releases built from this tree. Releases up to and including v1.1.1
# were published as `verifiable-standard-<release>.zip`; their manifests carry that
# prefix and are still verified from the manifest itself.
ARCHIVE_STEM = "verifier-standard"
DISTRIBUTION_NAME = "verifier-standard"
IMPORT_PACKAGE = "verifier"
CONSOLE_SCRIPTS = {
    "verifiable": "verifier.runtime.public_cli:main",
    "verifier": "verifier.runtime.public_cli:main",
    "vstd": "verifier.runtime.public_cli:main",
}
PACKAGED_SCHEMA_NAMES = frozenset(
    {
        "artifact-control-1.schema.json",
        "graph-topology.schema.json",
        "vstd-artifact-network-0.1.schema.json",
        "vstd-authority-model-0.1.schema.json",
        "vstd-component-index-1.schema.json",
        "vstd-component-package-1.schema.json",
        "vstd-graph-assurance-1.schema.json",
        "vstd-push-request-0.1.schema.json",
        "vstd-proposition-transfer-0.1.schema.json",
        "vstd-self-derivation-mechanism-0.1.schema.json",
        "vstd-silo-assessment-0.1.schema.json",
        "vstd-silo-assessment-receipt-0.1.schema.json",
        "vstd-silo-composition-0.1.schema.json",
        "vstd-silo-composition-assessment-0.1.schema.json",
        "vstd-silo-composition-assessment-receipt-0.1.schema.json",
        "vstd-silo-formation-receipt-0.1.schema.json",
        "vstd-silo-transfer-0.1.schema.json",
        "vstd-typed-formation-0.1.schema.json",
    }
)

_GENERATED_WHEEL_TEXT_NAMES = {
    "METADATA",
    "WHEEL",
    "entry_points.txt",
    "top_level.txt",
}


class ReleaseError(RuntimeError):
    """Release construction or verification failed closed."""


def _run(
    repo: Path, *args: str, env: dict[str, str] | None = None,
    input_data: bytes | None = None, timeout: float | None = None,
) -> bytes:
    try:
        completed = subprocess.run(
            list(args), cwd=repo, env=env, input=input_data, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReleaseError(f"command timed out ({' '.join(args)})") from exc
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseError(f"command failed ({' '.join(args)}): {detail}")
    return completed.stdout


def _git_blob_contents(repo: Path, commit: str) -> dict[str, bytes]:
    """Read exact tree-bound raw blobs, without archive attributes or filters."""

    tree = _run(repo, "git", "ls-tree", "-r", "-z", commit, timeout=30)
    if tree and not tree.endswith(b"\0"):
        raise ReleaseError("Git tree output lacks its null terminator")
    objects: dict[str, bytes] = {}
    for entry in tree.split(b"\0")[:-1]:
        metadata, separator, raw_path = entry.partition(b"\t")
        match = re.fullmatch(rb"[0-7]{6} blob ([0-9a-f]{40}|[0-9a-f]{64})", metadata)
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseError("Git tree path is not representable as archive text") from exc
        if not separator or not path or match is None or path in objects:
            raise ReleaseError("Git tree has a malformed, non-blob, or duplicate entry")
        objects[path] = match.group(1)
    if not objects:
        return {}
    output = _run(
        repo, "git", "cat-file", "--batch",
        input_data=b"\n".join(objects.values()) + b"\n", timeout=30,
    )
    contents: dict[str, bytes] = {}
    offset = 0
    for path, object_id in objects.items():
        end = output.find(b"\n", offset)
        header = output[offset:end].split(b" ") if end >= 0 else []
        if (
            len(header) != 3 or header[0] != object_id or header[1] != b"blob"
            or re.fullmatch(rb"0|[1-9][0-9]*", header[2]) is None
        ):
            raise ReleaseError(f"Git blob batch has a missing or mismatched header: {path}")
        try:
            size = int(header[2])
        except ValueError as exc:
            raise ReleaseError(f"Git blob batch has an invalid byte size: {path}") from exc
        offset = end + 1
        if size > len(output) - offset - 1 or output[offset + size:offset + size + 1] != b"\n":
            raise ReleaseError(f"Git blob batch has truncated bytes or a bad delimiter: {path}")
        contents[path] = output[offset:offset + size]
        offset += size + 1
    if offset != len(output):
        raise ReleaseError("Git blob batch has unexpected trailing bytes")
    return contents


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_record(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {"byte_size": len(data), "sha256": _sha256(data)}


def _cyclonedx_component(filename: str, record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "type": "file",
        "bom-ref": f"artifact:{filename}",
        "name": filename,
        "hashes": [{"alg": "SHA-256", "content": str(record["sha256"])}],
        "properties": [{"name": "vstd:byte-size", "value": str(record["byte_size"])}],
    }


def _cyclonedx_payload(
    *,
    commit: str,
    epoch: str,
    release: str,
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    timestamp = datetime.fromtimestamp(int(epoch), timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    root_ref = f"pkg:pypi/{DISTRIBUTION_NAME}@{release}"
    components = [
        _cyclonedx_component(name, artifacts[name]) for name in sorted(artifacts)
    ]
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "library",
                "bom-ref": root_ref,
                "name": DISTRIBUTION_NAME,
                "version": release,
                "purl": root_ref,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "properties": [{"name": "vstd:source-commit", "value": commit}],
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": root_ref,
                "dependsOn": [component["bom-ref"] for component in components],
            }
        ],
    }


def _write_cyclonedx_sbom(
    destination: Path,
    *,
    commit: str,
    epoch: str,
    release: str,
    artifacts: Mapping[str, Mapping[str, Any]],
) -> None:
    destination.write_text(
        json.dumps(
            _cyclonedx_payload(
                commit=commit, epoch=epoch, release=release, artifacts=artifacts
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _verify_cyclonedx_sbom(
    path: Path,
    *,
    commit: str,
    epoch: str,
    release: str,
    artifacts: Mapping[str, Mapping[str, Any]],
) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    expected = _cyclonedx_payload(
        commit=commit, epoch=epoch, release=release, artifacts=artifacts
    )
    if payload != expected:
        raise ReleaseError("CycloneDX SBOM bytes do not match the bound release subjects")


def _resolved_commit(repo: Path, ref: str) -> str:
    return _run(repo, "git", "rev-parse", f"{ref}^{{commit}}").decode().strip()


def _canonical_repository_url(value: str) -> str:
    """Return one stable public coordinate for common Git remote spellings."""

    candidate = value.strip().rstrip("/")
    scp_match = re.fullmatch(r"git@([^:]+):(.+)", candidate)
    ssh_match = re.fullmatch(r"ssh://git@([^/]+)/(.+)", candidate)
    if scp_match:
        candidate = f"https://{scp_match.group(1)}/{scp_match.group(2)}"
    elif ssh_match:
        candidate = f"https://{ssh_match.group(1)}/{ssh_match.group(2)}"
    if candidate.endswith(".git"):
        candidate = candidate[:-4]
    if not candidate:
        raise ReleaseError("origin repository URL is empty")
    return candidate


def _repository_url(repo: Path) -> str:
    raw = _run(repo, "git", "remote", "get-url", "origin").decode()
    return _canonical_repository_url(raw)


def _zip_timestamp(epoch: str) -> tuple[int, int, int, int, int, int]:
    timestamp = datetime.fromtimestamp(int(epoch), timezone.utc)
    if timestamp.year < 1980 or timestamp.year > 2107:
        raise ReleaseError(f"commit timestamp is outside the ZIP range: {epoch}")
    return (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second - (timestamp.second % 2),
    )


def _canonical_zip_info(name: str, epoch: str, *, is_dir: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_zip_timestamp(epoch))
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.flag_bits = 0
    info.compress_type = zipfile.ZIP_STORED
    info.comment = b""
    info.extra = b""
    info.internal_attr = 0
    mode = (stat.S_IFDIR | 0o755) if is_dir else (stat.S_IFREG | 0o644)
    info.external_attr = mode << 16
    if is_dir:
        info.external_attr |= 0x10
    return info


def _write_canonical_zip(
    destination: Path,
    members: dict[str, tuple[bytes, bool]],
    epoch: str,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_STORED, allowZip64=True
    ) as bundle:
        for name in sorted(members):
            data, is_dir = members[name]
            if (
                not name
                or name.startswith("/")
                or "\\" in name
                or ".." in Path(name).parts
            ):
                raise ReleaseError(f"unsafe ZIP member name: {name}")
            if is_dir and not name.endswith("/"):
                raise ReleaseError(f"ZIP directory lacks trailing slash: {name}")
            info = _canonical_zip_info(name, epoch, is_dir=is_dir)
            bundle.writestr(info, b"" if is_dir else data)


def _normalize_source_archive(source: Path, destination: Path, epoch: str) -> None:
    """Rewrite ``git archive`` output without host timezone or ZIP metadata."""

    with zipfile.ZipFile(source) as bundle:
        members: dict[str, tuple[bytes, bool]] = {}
        for info in bundle.infolist():
            if info.filename in members:
                raise ReleaseError(f"duplicate source ZIP member: {info.filename}")
            members[info.filename] = (bundle.read(info), info.is_dir())
    _write_canonical_zip(destination, members, epoch)


def _normalize_newlines(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _record_digest(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + encoded.decode("ascii")


def _normalize_wheel(source: Path, destination: Path, epoch: str) -> None:
    """Canonicalize generated metadata, RECORD, member order, modes, and timestamps."""

    with zipfile.ZipFile(source) as bundle:
        infos = bundle.infolist()
        record_paths = [
            info.filename for info in infos if info.filename.endswith(".dist-info/RECORD")
        ]
        signature_paths = [
            info.filename
            for info in infos
            if info.filename.endswith((".dist-info/RECORD.jws", ".dist-info/RECORD.p7s"))
        ]
        if len(record_paths) != 1:
            raise ReleaseError(f"wheel must contain exactly one RECORD: {source}")
        if signature_paths:
            raise ReleaseError("normalization does not accept pre-signed wheel RECORD files")
        record_path = record_paths[0]
        members: dict[str, tuple[bytes, bool]] = {}
        for info in infos:
            if info.filename == record_path:
                continue
            if info.filename in members:
                raise ReleaseError(f"duplicate wheel member: {info.filename}")
            data = bundle.read(info)
            leaf = info.filename.rsplit("/", 1)[-1]
            if ".dist-info/" in info.filename and leaf in _GENERATED_WHEEL_TEXT_NAMES:
                data = _normalize_newlines(data)
            members[info.filename] = (data, info.is_dir())

    rows = io.StringIO(newline="")
    writer = csv.writer(rows, lineterminator="\n")
    for name in sorted(members):
        data, is_dir = members[name]
        if not is_dir:
            writer.writerow((name, _record_digest(data), str(len(data))))
    writer.writerow((record_path, "", ""))
    members[record_path] = (rows.getvalue().encode("utf-8"), False)
    _write_canonical_zip(destination, members, epoch)


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
            if relative in result:
                raise ReleaseError(f"archive contains duplicate member: {relative}")
            data = bundle.read(info)
            result[relative] = {"byte_size": len(data), "sha256": _sha256(data)}
    return dict(sorted(result.items()))


def _canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _metadata_identity(payload: bytes, *, artifact: str) -> tuple[str, str]:
    metadata = BytesParser(policy=policy.default).parsebytes(payload)
    name = str(metadata.get("Name", ""))
    version = str(metadata.get("Version", ""))
    if not name or not version:
        raise ReleaseError(f"distribution metadata lacks Name or Version: {artifact}")
    return name, version


def _normalize_sdist(source: Path, destination: Path, epoch: str) -> None:
    """Rewrite an sdist with stable generated text, gzip, and tar metadata.

    Setuptools emits valid source distributions whose tar and gzip timestamps vary
    across clean builds. Its generated metadata also follows the host newline convention.
    The release builder canonicalizes those generated files, fixes timestamps to the
    source commit, clears host ownership, normalizes modes, and sorts members before
    comparing independent builds.
    """

    timestamp = int(epoch)
    with tarfile.open(source, "r:gz") as bundle:
        members = sorted(bundle.getmembers(), key=lambda item: item.name)
        roots = {member.name.split("/", 1)[0] for member in members if member.name}
        if len(roots) != 1:
            raise ReleaseError(f"sdist must contain exactly one root directory: {source}")

        materialized: list[tuple[tarfile.TarInfo, bytes | None]] = []
        for member in members:
            if member.isdir():
                data = None
            elif member.isfile():
                extracted = bundle.extractfile(member)
                if extracted is None:
                    raise ReleaseError(f"sdist member is unreadable: {member.name}")
                data = extracted.read()
                relative = member.name.split("/", 1)[1] if "/" in member.name else ""
                generated = (
                    relative in {"PKG-INFO", "setup.cfg"}
                    or ".egg-info/" in relative
                )
                if generated:
                    data = _normalize_newlines(data)
            else:
                raise ReleaseError(
                    f"sdist contains unsupported non-file member: {member.name}"
                )
            materialized.append((member, data))

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, compresslevel=0, mtime=timestamp
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
            ) as normalized:
                for original, data in materialized:
                    member = tarfile.TarInfo(original.name)
                    member.mtime = timestamp
                    member.uid = 0
                    member.gid = 0
                    member.uname = ""
                    member.gname = ""
                    if data is None:
                        member.type = tarfile.DIRTYPE
                        member.mode = 0o755
                        member.size = 0
                        normalized.addfile(member)
                    else:
                        member.type = tarfile.REGTYPE
                        member.mode = 0o644
                        member.size = len(data)
                        normalized.addfile(member, io.BytesIO(data))


def _verify_python_distributions(wheel: Path, sdist: Path, release: str) -> None:
    expected_name = _canonical_distribution_name(DISTRIBUTION_NAME)

    with zipfile.ZipFile(wheel) as bundle:
        names = bundle.namelist()
        metadata_paths = [name for name in names if name.endswith(".dist-info/METADATA")]
        entry_paths = [
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        ]
        if len(metadata_paths) != 1 or len(entry_paths) != 1:
            raise ReleaseError("wheel must contain one METADATA and one entry_points.txt")
        name, version = _metadata_identity(
            bundle.read(metadata_paths[0]), artifact=wheel.name
        )
        parser = ConfigParser(interpolation=None)
        parser.read_string(bundle.read(entry_paths[0]).decode("utf-8"))
        scripts = (
            dict(parser["console_scripts"])
            if parser.has_section("console_scripts")
            else {}
        )
        if f"{IMPORT_PACKAGE}/__init__.py" not in names:
            raise ReleaseError(f"wheel lacks import package {IMPORT_PACKAGE}")
        if any(path.startswith("verifiable/") for path in names):
            raise ReleaseError("wheel reintroduces the retired import package")
        wheel_schemas = {
            Path(path).name
            for path in names
            if path.startswith(f"{IMPORT_PACKAGE}/schemas/") and path.endswith(".json")
        }
        if wheel_schemas != PACKAGED_SCHEMA_NAMES:
            raise ReleaseError(
                "wheel packaged schema inventory differs from the canonical release set"
            )

    if _canonical_distribution_name(name) != expected_name or version != release:
        raise ReleaseError(
            f"wheel identity mismatch: expected {DISTRIBUTION_NAME} {release}, "
            f"found {name} {version}"
        )
    if scripts != CONSOLE_SCRIPTS:
        raise ReleaseError(f"wheel console scripts differ from the frozen set: {scripts}")

    with tarfile.open(sdist, "r:gz") as bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        roots = {path.split("/", 1)[0] for path in names if path}
        if len(roots) != 1:
            raise ReleaseError("sdist must contain exactly one root directory")
        root = next(iter(roots))
        metadata_members = [
            member for member in members if member.name == f"{root}/PKG-INFO"
        ]
        if len(metadata_members) != 1:
            raise ReleaseError("sdist must contain one root PKG-INFO")
        metadata_file = bundle.extractfile(metadata_members[0])
        if metadata_file is None:
            raise ReleaseError("sdist PKG-INFO is unreadable")
        sdist_name, sdist_version = _metadata_identity(
            metadata_file.read(), artifact=sdist.name
        )
        if f"{root}/src/{IMPORT_PACKAGE}/__init__.py" not in names:
            raise ReleaseError(f"sdist lacks import package {IMPORT_PACKAGE}")
        if any(path.startswith(f"{root}/src/verifiable/") for path in names):
            raise ReleaseError("sdist reintroduces the retired import package")
        sdist_schema_prefix = f"{root}/src/{IMPORT_PACKAGE}/schemas/"
        sdist_schemas = {
            Path(path).name
            for path in names
            if path.startswith(sdist_schema_prefix) and path.endswith(".json")
        }
        if sdist_schemas != PACKAGED_SCHEMA_NAMES:
            raise ReleaseError(
                "sdist packaged schema inventory differs from the canonical release set"
            )

    if (
        _canonical_distribution_name(sdist_name) != expected_name
        or sdist_version != release
    ):
        raise ReleaseError(
            f"sdist identity mismatch: expected {DISTRIBUTION_NAME} {release}, "
            f"found {sdist_name} {sdist_version}"
        )


def build_source(repo: Path, ref: str, release: str, output_dir: Path) -> tuple[Path, Path]:
    repo = repo.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    commit = _resolved_commit(repo, ref)
    prefix = f"{ARCHIVE_STEM}-{release}/"
    archive = output_dir / f"{ARCHIVE_STEM}-{release}.zip"
    manifest_path = output_dir / f"{ARCHIVE_STEM}-{release}.manifest.json"
    epoch = _run(repo, "git", "show", "-s", "--format=%ct", commit).decode().strip()

    with tempfile.TemporaryDirectory(prefix="vstd-source-archive-") as temporary:
        raw_archive = Path(temporary) / "raw.zip"
        _run(
            repo,
            "git",
            "archive",
            "--format=zip",
            f"--prefix={prefix}",
            f"--output={raw_archive}",
            commit,
        )
        _normalize_source_archive(raw_archive, archive, epoch)

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
            "byte_semantics": (
                "exact Git blob member bytes in a platform-independent canonical ZIP"
            ),
        },
        "distribution": {
            "name": DISTRIBUTION_NAME,
            "import_package": IMPORT_PACKAGE,
            "console_scripts": dict(sorted(CONSOLE_SCRIPTS.items())),
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
        raw_output = temporary_path / "raw"
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
                str(raw_output),
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
        wheels = sorted(raw_output.glob("*.whl"))
        if len(wheels) != 1:
            raise ReleaseError(f"expected one raw wheel, found {len(wheels)} in {raw_output}")
        normalized = destination / wheels[0].name
        _normalize_wheel(wheels[0], normalized, epoch)
    return normalized


def _build_sdist_once(
    source_archive: Path,
    prefix: str,
    destination: Path,
    epoch: str,
) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vstd-sdist-") as temporary:
        temporary_path = Path(temporary)
        with zipfile.ZipFile(source_archive) as bundle:
            bundle.extractall(temporary_path / "source")
        source = temporary_path / "source" / prefix.rstrip("/")
        raw_output = temporary_path / "raw"
        env = dict(os.environ)
        env["SOURCE_DATE_EPOCH"] = epoch
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--sdist",
                "--outdir",
                str(raw_output),
                str(source),
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode:
            raise ReleaseError(
                "sdist build failed: "
                + completed.stderr.decode("utf-8", errors="replace").strip()
            )
        sdists = sorted(raw_output.glob("*.tar.gz"))
        if len(sdists) != 1:
            raise ReleaseError(
                f"expected one raw sdist, found {len(sdists)} in {raw_output}"
            )
        normalized = destination / sdists[0].name
        _normalize_sdist(sdists[0], normalized, epoch)
    return normalized


def build_all(
    repo: Path, ref: str, release: str, output_dir: Path
) -> tuple[Path, Path, Path, Path, Path]:
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

    with tempfile.TemporaryDirectory(prefix="vstd-sdist-builds-") as temporary:
        temporary_path = Path(temporary)
        first = _build_sdist_once(archive, prefix, temporary_path / "first", epoch)
        second = _build_sdist_once(archive, prefix, temporary_path / "second", epoch)
        if first.name != second.name or first.read_bytes() != second.read_bytes():
            raise ReleaseError("two normalized clean sdist builds were not byte-identical")
        sdist = output_dir / first.name
        shutil.copy2(first, sdist)

    _verify_python_distributions(wheel, sdist, release)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][wheel.name] = _file_record(wheel)
    manifest["artifacts"][sdist.name] = _file_record(sdist)
    sbom = output_dir / f"{ARCHIVE_STEM}-{release}.cdx.json"
    _write_cyclonedx_sbom(
        sbom,
        commit=commit,
        epoch=epoch,
        release=release,
        artifacts=manifest["artifacts"],
    )
    manifest["sbom"] = {
        "filename": sbom.name,
        "format": "CycloneDX",
        "spec_version": CYCLONEDX_SPEC_VERSION,
        "subjects": sorted(manifest["artifacts"]),
    }
    manifest["artifacts"][sbom.name] = _file_record(sbom)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    verify_manifest(repo, manifest_path, output_dir)
    return archive, wheel, sdist, sbom, manifest_path


def compare_artifact_directories(first: Path, second: Path) -> int:
    """Fail unless two build directories contain the same byte-identical files."""

    first = first.resolve()
    second = second.resolve()
    first_files = {
        path.relative_to(first).as_posix(): path
        for path in first.rglob("*")
        if path.is_file()
    }
    second_files = {
        path.relative_to(second).as_posix(): path
        for path in second.rglob("*")
        if path.is_file()
    }
    if set(first_files) != set(second_files):
        missing_first = sorted(set(second_files) - set(first_files))
        missing_second = sorted(set(first_files) - set(second_files))
        raise ReleaseError(
            "artifact file sets differ: "
            f"missing from first={missing_first}, missing from second={missing_second}"
        )
    if not first_files:
        raise ReleaseError("artifact directories are empty")
    for name in sorted(first_files):
        first_record = _file_record(first_files[name])
        second_record = _file_record(second_files[name])
        if first_record != second_record:
            raise ReleaseError(
                f"artifact bytes differ for {name}: {first_record} != {second_record}"
            )
    return len(first_files)


def _load_canonical_release_manifest(path: Path) -> dict[str, Any]:
    """Load one deterministic manifest and reject alternate byte encodings."""

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseError(f"release manifest contains duplicate key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ReleaseError(f"release manifest contains non-finite value: {value}")

    document = path.read_bytes()
    try:
        text = document.decode("utf-8")
        manifest = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("release manifest is not strict UTF-8 JSON") from exc
    if not isinstance(manifest, dict):
        raise ReleaseError("release manifest must be a JSON object")
    canonical = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    if document != canonical:
        raise ReleaseError("release manifest bytes are not canonical")
    return manifest


def compare_retagged_artifact_directories(candidate: Path, tagged: Path) -> int:
    """Require byte-identical artifacts and only the intended manifest ref change."""

    candidate = candidate.resolve()
    tagged = tagged.resolve()
    candidate_files = {
        path.relative_to(candidate).as_posix(): path
        for path in candidate.rglob("*")
        if path.is_file()
    }
    tagged_files = {
        path.relative_to(tagged).as_posix(): path
        for path in tagged.rglob("*")
        if path.is_file()
    }
    if set(candidate_files) != set(tagged_files):
        raise ReleaseError("candidate and tagged artifact file sets differ")
    manifests = sorted(
        name for name in candidate_files if name.endswith(".manifest.json")
    )
    if len(manifests) != 1:
        raise ReleaseError(
            f"expected one release manifest in each directory, found {len(manifests)}"
        )
    manifest_name = manifests[0]
    artifact_names = sorted(set(candidate_files) - {manifest_name})
    if not artifact_names:
        raise ReleaseError("candidate and tagged directories contain no release artifacts")
    for name in artifact_names:
        if _file_record(candidate_files[name]) != _file_record(tagged_files[name]):
            raise ReleaseError(f"retagged artifact bytes differ for {name}")

    candidate_manifest = _load_canonical_release_manifest(candidate_files[manifest_name])
    tagged_manifest = _load_canonical_release_manifest(tagged_files[manifest_name])
    candidate_source = candidate_manifest.get("source")
    tagged_source = tagged_manifest.get("source")
    if not isinstance(candidate_source, dict) or not isinstance(tagged_source, dict):
        raise ReleaseError("release manifests must contain source objects")
    commit = candidate_source.get("commit")
    release = candidate_manifest.get("release")
    if (
        not isinstance(commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or not isinstance(release, str)
        or candidate_source.get("ref") != commit
        or tagged_source.get("commit") != commit
        or tagged_source.get("ref") != f"refs/tags/v{release}"
    ):
        raise ReleaseError("candidate and tagged manifests do not bind the expected refs")
    try:
        classify_release_version(release)
    except ValueError as exc:
        raise ReleaseError("candidate manifest release is unsupported") from exc
    if manifest_name != f"{ARCHIVE_STEM}-{release}.manifest.json":
        raise ReleaseError("release manifest filename does not match the release")
    for label, manifest, files in (
        ("candidate", candidate_manifest, candidate_files),
        ("tagged", tagged_manifest, tagged_files),
    ):
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != set(artifact_names):
            raise ReleaseError(
                f"{label} manifest artifacts do not exactly bind the directory"
            )
        for name in artifact_names:
            if artifacts[name] != _file_record(files[name]):
                raise ReleaseError(f"{label} manifest artifact binding differs for {name}")
    tagged_source["ref"] = commit
    if candidate_manifest != tagged_manifest:
        raise ReleaseError("retagged manifest changed beyond source.ref")
    return len(artifact_names)


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

    sbom_record = manifest.get("sbom")
    if sbom_record is not None:
        sbom_name = str(sbom_record.get("filename", ""))
        subjects = sorted(name for name in artifacts if name != sbom_name)
        if sbom_record != {
            "filename": sbom_name,
            "format": "CycloneDX",
            "spec_version": CYCLONEDX_SPEC_VERSION,
            "subjects": subjects,
        }:
            raise ReleaseError("release manifest SBOM binding is not canonical")
        if not sbom_name.endswith(".cdx.json") or sbom_name not in artifacts:
            raise ReleaseError("release manifest does not bind its declared SBOM")
        _verify_cyclonedx_sbom(
            artifact_dir / sbom_name,
            commit=commit,
            epoch=_run(repo, "git", "show", "-s", "--format=%ct", commit)
            .decode()
            .strip(),
            release=str(manifest["release"]),
            artifacts={name: artifacts[name] for name in subjects},
        )

    distribution = manifest.get("distribution")
    if distribution is not None:
        expected_distribution = {
            "name": DISTRIBUTION_NAME,
            "import_package": IMPORT_PACKAGE,
            "console_scripts": dict(sorted(CONSOLE_SCRIPTS.items())),
        }
        if distribution != expected_distribution:
            raise ReleaseError("release manifest distribution identity is not canonical")
        wheels = [artifact_dir / name for name in artifacts if name.endswith(".whl")]
        sdists = [artifact_dir / name for name in artifacts if name.endswith(".tar.gz")]
        if wheels or sdists:
            if len(wheels) != 1 or len(sdists) != 1:
                raise ReleaseError(
                    "a Python distribution release must bind one wheel and one sdist"
                )
            _verify_python_distributions(wheels[0], sdists[0], str(manifest["release"]))

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

    tracked = _git_blob_contents(repo, commit)
    if sorted(tracked) != sorted(inventory):
        raise ReleaseError("source archive file set does not match the bound Git commit")
    with zipfile.ZipFile(archive) as bundle:
        for relative, expected in inventory.items():
            archive_bytes = bundle.read(prefix + relative)
            git_bytes = tracked[relative]
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

    compare = commands.add_parser("compare")
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)
    compare_retagged = commands.add_parser("compare-retagged")
    compare_retagged.add_argument("candidate", type=Path)
    compare_retagged.add_argument("tagged", type=Path)
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
            archive, wheel, sdist, sbom, manifest = build_all(
                args.repo, args.ref, args.release, args.output_dir
            )
            print(f"[PASS] source archive: {archive}")
            print(f"[PASS] reproducible wheel: {wheel}")
            print(f"[PASS] reproducible sdist: {sdist}")
            print(f"[PASS] CycloneDX SBOM: {sbom}")
            print(f"[PASS] release manifest: {manifest}")
        elif args.command == "verify":
            verify_manifest(args.repo, args.manifest, args.artifact_dir)
            print(f"[PASS] release manifest verified: {args.manifest}")
        elif args.command == "compare":
            count = compare_artifact_directories(args.first, args.second)
            print(f"[PASS] {count} release artifacts are byte-identical")
        else:
            count = compare_retagged_artifact_directories(args.candidate, args.tagged)
            print(
                f"[PASS] {count} retagged artifacts are byte-identical and only "
                "manifest source.ref changed"
            )
    except (OSError, ReleaseError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
