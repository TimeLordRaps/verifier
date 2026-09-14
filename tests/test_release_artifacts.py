"""Terminology: identifier (ID); Verifier Standard (VSTD); ZIP archive format (ZIP).

The public source archive must bind exact, publicly resolvable Git bytes."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
import zipfile

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "release_artifacts.py"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
TIME_GATE = REPO_ROOT / "scripts" / "check_time_status.py"
RELEASE_METADATA_GATE = REPO_ROOT / "scripts" / "check_release_metadata.py"
RELEASE_NOTES = REPO_ROOT / "scripts" / "extract_release_notes.py"
RELEASE_VERSION_CLASSIFIER = REPO_ROOT / "scripts" / "classify_release_version.py"

SPEC = importlib.util.spec_from_file_location("vstd_release_artifacts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_artifacts)

METADATA_SPEC = importlib.util.spec_from_file_location(
    "vstd_release_metadata", RELEASE_METADATA_GATE
)
assert METADATA_SPEC is not None and METADATA_SPEC.loader is not None
release_metadata = importlib.util.module_from_spec(METADATA_SPEC)
METADATA_SPEC.loader.exec_module(release_metadata)

NOTES_SPEC = importlib.util.spec_from_file_location("vstd_release_notes", RELEASE_NOTES)
assert NOTES_SPEC is not None and NOTES_SPEC.loader is not None
release_notes = importlib.util.module_from_spec(NOTES_SPEC)
NOTES_SPEC.loader.exec_module(release_notes)

CLASSIFIER_SPEC = importlib.util.spec_from_file_location(
    "vstd_release_version_classifier", RELEASE_VERSION_CLASSIFIER
)
assert CLASSIFIER_SPEC is not None and CLASSIFIER_SPEC.loader is not None
release_version_classifier = importlib.util.module_from_spec(CLASSIFIER_SPEC)
CLASSIFIER_SPEC.loader.exec_module(release_version_classifier)


def _git_object_fixture(root: Path, files: dict[str, bytes]) -> tuple[Path, str]:
    """Build unreferenced synthetic objects, never a commit in project history."""

    repo = root / "objects.git"

    def git(*args: str, content: bytes | None = None) -> bytes:
        result = subprocess.run(
            ["git", *args], cwd=root, input=content, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=True,
        )
        return result.stdout

    git("init", "--bare", str(repo))
    entries = []
    for name, content in sorted(files.items()):
        oid = git("--git-dir", str(repo), "hash-object", "-w", "--stdin", content=content).strip()
        entries.append(b"100644 blob " + oid + b"\t" + name.encode("utf-8") + b"\0")
    tree = git("--git-dir", str(repo), "mktree", "-z", content=b"".join(entries)).strip()
    commit = git("--git-dir", str(repo), "hash-object", "-t", "commit", "-w", "--stdin", content=(
        b"tree " + tree + b"\n"
        b"author Fixture <fixture> 1700000000 +0000\n"
        b"committer Fixture <fixture> 1700000000 +0000\n\n"
        b"Disposable unreferenced release-verification fixture.\n"
    )).decode().strip()
    git("--git-dir", str(repo), "config", "remote.origin.url", "https://github.com/example/fixture.git")
    return repo, commit


def test_manifest_verification_uses_one_bounded_raw_blob_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, commit = _git_object_fixture(tmp_path, {"one.bin": b"\0\xff\n", "two.txt": b"two\r\n"})
    _, manifest = release_artifacts.build_source(repo, commit, "test", tmp_path / "release")
    original = release_artifacts._run
    calls = []

    def recording(root: Path, *args: str, **kwargs: object) -> bytes:
        calls.append((args, kwargs))
        return original(root, *args, **kwargs)

    monkeypatch.setattr(release_artifacts, "_run", recording)
    release_artifacts.verify_manifest(repo, manifest)
    batches = [(args, kwargs) for args, kwargs in calls if args[:2] == ("git", "cat-file")]
    assert len(batches) == 1
    assert batches[0][0] == ("git", "cat-file", "--batch")
    assert batches[0][1]["timeout"] == 30
    assert not any(args[:2] == ("git", "show") for args, _ in calls)


def test_raw_blob_batch_preserves_binary_and_null_delimited_filename_binding(tmp_path: Path) -> None:
    files = {
        "space name.bin": bytes(range(256)),
        "tab\tname.txt": b"tab\tdata\n",
        "line\nbreak.txt": b"line\n\0break\r\n",
        "quote\"name.txt": b"same payload",
        "back\\slash.txt": b"same payload",
        "empty.txt": b"",
    }
    repo, commit = _git_object_fixture(tmp_path, files)
    assert release_artifacts._git_blob_contents(repo, commit) == files


def test_manifest_checks_exact_tree_paths_without_archive_builder_filename_assumptions(tmp_path: Path) -> None:
    # ZIP reading does not extract these names. Git-for-Windows archive creation
    # may reject names that remain valid raw tree entries; do not relax it here.
    files = {"space name": b"\0\xff", "tab\tname": b"same", "line\nname": b"same", "empty": b""}
    repo, commit = _git_object_fixture(tmp_path, files)
    archive = tmp_path / "fixture.zip"
    prefix = "fixture/"
    with zipfile.ZipFile(archive, "w") as bundle:
        for path, content in files.items():
            bundle.writestr(prefix + path, content)
    manifest = tmp_path / "fixture.manifest.json"
    manifest.write_text(json.dumps({
        "schema_version": release_artifacts.SCHEMA_VERSION, "release": "test",
        "source": {"ref": commit, "commit": commit, "archive_prefix": prefix},
        "artifacts": {archive.name: release_artifacts._file_record(archive)},
        "files": release_artifacts._archive_inventory(archive, prefix),
    }), encoding="utf-8")
    release_artifacts.verify_manifest(repo, manifest)


@pytest.mark.parametrize("attribute", ["export-subst", "export-ignore"])
def test_archive_export_attributes_cannot_replace_raw_git_blob_oracle(tmp_path: Path, attribute: str) -> None:
    files = {".gitattributes": f"subject.txt {attribute}\n".encode(), "subject.txt": b"$Format:%H$\n"}
    repo, commit = _git_object_fixture(tmp_path, files)
    assert release_artifacts._git_blob_contents(repo, commit) == files
    _, manifest = release_artifacts.build_source(repo, commit, "test", tmp_path / "release")
    expected = "archive bytes do not match Git blob" if attribute == "export-subst" else "file set does not match"
    with pytest.raises(release_artifacts.ReleaseError, match=expected):
        release_artifacts.verify_manifest(repo, manifest)


@pytest.mark.parametrize("fault", [
    "missing", "wrong-id", "reordered", "wrong-type", "long-size", "short-size",
    "negative-size", "noncanonical-size", "truncated-header", "truncated-payload",
    "missing-delimiter", "missing-response", "trailing-bytes",
])
def test_raw_blob_batch_rejects_malformed_or_misbound_responses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    first, second = b"1" * 40, b"2" * 40
    tree = b"100644 blob " + first + b"\tfirst\0" + b"100644 blob " + second + b"\tsecond\0"
    first_record = first + b" blob 3\nA\0B\n"
    second_record = second + b" blob 2\n\xff\n\n"
    output = first_record + second_record
    if fault == "missing":
        output = first + b" missing\n" + second_record
    elif fault == "wrong-id":
        output = output.replace(first, b"3" * 40, 1)
    elif fault == "reordered":
        output = second_record + first_record
    elif fault == "wrong-type":
        output = output.replace(b" blob ", b" tree ", 1)
    elif fault in {"long-size", "short-size", "negative-size", "noncanonical-size"}:
        size = {"long-size": b"9999999999999999999999999", "short-size": b"2", "negative-size": b"-3", "noncanonical-size": b"03"}[fault]
        output = output.replace(b" blob 3\n", b" blob " + size + b"\n", 1)
    elif fault == "truncated-header":
        output = first + b" blob 3"
    elif fault == "truncated-payload":
        output = first + b" blob 3\nA"
    elif fault == "missing-delimiter":
        output = first_record[:-1] + second_record
    elif fault == "missing-response":
        output = first_record
    else:
        output += b"undeclared output"

    def fake_run(root: Path, *args: str, **kwargs: object) -> bytes:
        if args[:2] == ("git", "ls-tree"):
            assert "-z" in args
            return tree
        assert args == ("git", "cat-file", "--batch")
        assert kwargs["input_data"] == first + b"\n" + second + b"\n"
        return output

    monkeypatch.setattr(release_artifacts, "_run", fake_run)
    with pytest.raises(release_artifacts.ReleaseError, match="Git blob batch"):
        release_artifacts._git_blob_contents(tmp_path, "fixture")


@pytest.mark.parametrize("tree", [
    b"100644 blob " + b"1" * 40 + b"\tunterminated",
    b"100644 blob " + b"1" * 40 + b"\t\0",
    b"160000 commit " + b"1" * 40 + b"\tsubmodule\0",
    b"100644 blob invalid\tfile\0",
    (b"100644 blob " + b"1" * 40 + b"\tduplicate\0") * 2,
])
def test_raw_blob_batch_rejects_ambiguous_tree_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tree: bytes,
) -> None:
    def fake_run(root: Path, *args: str, **kwargs: object) -> bytes:
        assert args[:2] == ("git", "ls-tree"), "malformed tree must not trigger a batch read"
        return tree

    monkeypatch.setattr(release_artifacts, "_run", fake_run)
    with pytest.raises(release_artifacts.ReleaseError, match="Git tree"):
        release_artifacts._git_blob_contents(tmp_path, "fixture")


def test_raw_blob_batch_timeout_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def timed_out(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(release_artifacts.subprocess, "run", timed_out)
    with pytest.raises(release_artifacts.ReleaseError, match="timed out"):
        release_artifacts._git_blob_contents(tmp_path, "fixture")


def test_source_release_manifest_binds_head_and_exact_archive_bytes(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(REPO_ROOT),
            "source",
            "--ref",
            "HEAD",
            "--release",
            "test",
            "--output-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    manifest_path = tmp_path / "verifier-standard-test.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
    ).strip()
    assert manifest["source"]["commit"] == expected_commit
    assert manifest["source"]["ref"] == "HEAD"
    assert "RELEASE-MANIFEST.json" not in manifest["files"]
    assert manifest["source"]["repository"] == "https://github.com/TimeLordRaps/verifier"
    assert manifest["source"]["byte_semantics"] == (
        "exact Git blob member bytes in a platform-independent canonical ZIP"
    )
    assert manifest["distribution"] == {
        "name": "verifier-standard",
        "import_package": "verifier",
        "console_scripts": {
            "verifiable": "verifier.runtime.public_cli:main",
            "verifier": "verifier.runtime.public_cli:main",
            "vstd": "verifier.runtime.public_cli:main",
        },
    }

    verify = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(REPO_ROOT),
            "verify",
            str(manifest_path),
        ],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stderr

    epoch = subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", expected_commit],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    timestamp = datetime.fromtimestamp(int(epoch), timezone.utc)
    expected_zip_time = (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second - (timestamp.second % 2),
    )
    with zipfile.ZipFile(tmp_path / "verifier-standard-test.zip") as bundle:
        assert bundle.infolist()
        for info in bundle.infolist():
            assert info.date_time == expected_zip_time
            assert info.create_system == 3
            assert info.compress_type == zipfile.ZIP_STORED


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "https://github.com/TimeLordRaps/verifier.git",
            "https://github.com/TimeLordRaps/verifier",
        ),
        (
            "https://github.com/TimeLordRaps/verifier/",
            "https://github.com/TimeLordRaps/verifier",
        ),
        (
            "git" + "@github.com:TimeLordRaps/verifier.git",
            "https://github.com/TimeLordRaps/verifier",
        ),
        (
            "ssh://git" + "@github.com/TimeLordRaps/verifier.git",
            "https://github.com/TimeLordRaps/verifier",
        ),
    ],
    ids=("https-git-suffix", "https-trailing-slash", "scp-style", "ssh-scheme"),
)
def test_repository_url_spellings_are_canonical(raw: str, expected: str) -> None:
    assert release_artifacts._canonical_repository_url(raw) == expected


def _write_raw_wheel(path: Path, *, newline: bytes, reverse: bool) -> None:
    dist_info = "verifier_standard-1.2.0.dist-info"
    members = [
        ("verifier/__init__.py", b'__version__ = "1.2.0"\n'),
        (
            f"{dist_info}/METADATA",
            newline.join(
                [
                    b"Metadata-Version: 2.4",
                    b"Name: verifier-standard",
                    b"Version: 1.2.0",
                    b"",
                    b"Canonical metadata.",
                    b"",
                ]
            ),
        ),
        (
            f"{dist_info}/WHEEL",
            newline.join(
                [
                    b"Wheel-Version: 1.0",
                    b"Generator: test",
                    b"Root-Is-Purelib: true",
                    b"Tag: py3-none-any",
                    b"",
                ]
            ),
        ),
        (
            f"{dist_info}/entry_points.txt",
            newline.join(
                [
                    b"[console_scripts]",
                    b"verifiable = verifier.runtime.public_cli:main",
                    b"verifier = verifier.runtime.public_cli:main",
                    b"vstd = verifier.runtime.public_cli:main",
                    b"",
                ]
            ),
        ),
        (f"{dist_info}/RECORD", b"host-generated-record"),
    ]
    if reverse:
        members.reverse()
    with zipfile.ZipFile(path, "w") as bundle:
        for name, data in members:
            info = zipfile.ZipInfo(name, (2024, 1, 2, 3, 4, 4))
            info.create_system = 0 if reverse else 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0 if reverse else (0o100755 << 16)
            bundle.writestr(info, data)


def test_wheel_normalization_removes_host_newlines_and_zip_metadata(tmp_path: Path) -> None:
    first_raw = tmp_path / "first.whl"
    second_raw = tmp_path / "second.whl"
    first = tmp_path / "first-normalized.whl"
    second = tmp_path / "second-normalized.whl"
    _write_raw_wheel(first_raw, newline=b"\r\n", reverse=False)
    _write_raw_wheel(second_raw, newline=b"\n", reverse=True)

    epoch = "1787446816"
    release_artifacts._normalize_wheel(first_raw, first, epoch)
    release_artifacts._normalize_wheel(second_raw, second, epoch)
    assert first.read_bytes() == second.read_bytes()

    with zipfile.ZipFile(first) as bundle:
        infos = bundle.infolist()
        assert all(info.create_system == 3 for info in infos)
        assert all(info.compress_type == zipfile.ZIP_STORED for info in infos)
        metadata_name = "verifier_standard-1.2.0.dist-info/METADATA"
        assert b"\r" not in bundle.read(metadata_name)
        record_name = "verifier_standard-1.2.0.dist-info/RECORD"
        rows = list(csv.reader(io.StringIO(bundle.read(record_name).decode("utf-8"))))
        records = {row[0]: row[1:] for row in rows}
        for info in infos:
            if info.is_dir() or info.filename == record_name:
                continue
            data = bundle.read(info)
            assert records[info.filename] == [
                release_artifacts._record_digest(data),
                str(len(data)),
            ]
        assert records[record_name] == ["", ""]


def _write_raw_sdist(path: Path, *, newline: bytes, reverse: bool) -> None:
    root = "verifier_standard-1.2.0"
    members = [
        (
            f"{root}/PKG-INFO",
            newline.join(
                [
                    b"Metadata-Version: 2.4",
                    b"Name: verifier-standard",
                    b"Version: 1.2.0",
                    b"",
                ]
            ),
        ),
        (f"{root}/setup.cfg", newline.join([b"[egg_info]", b"tag_build =", b""])),
        (
            f"{root}/src/verifier_standard.egg-info/PKG-INFO",
            newline.join(
                [
                    b"Metadata-Version: 2.4",
                    b"Name: verifier-standard",
                    b"Version: 1.2.0",
                    b"",
                ]
            ),
        ),
        (f"{root}/README.md", b"Source bytes stay unchanged.\n"),
    ]
    if reverse:
        members.reverse()
    with tarfile.open(path, "w:gz") as bundle:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.mtime = 1 if reverse else 2
            info.uid = 1000
            info.gid = 1000
            info.mode = 0o600 if reverse else 0o664
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))


def test_sdist_normalization_removes_host_newlines_and_tar_metadata(tmp_path: Path) -> None:
    first_raw = tmp_path / "first.tar.gz"
    second_raw = tmp_path / "second.tar.gz"
    first = tmp_path / "first-normalized.tar.gz"
    second = tmp_path / "second-normalized.tar.gz"
    _write_raw_sdist(first_raw, newline=b"\r\n", reverse=False)
    _write_raw_sdist(second_raw, newline=b"\n", reverse=True)

    epoch = "1787446816"
    release_artifacts._normalize_sdist(first_raw, first, epoch)
    release_artifacts._normalize_sdist(second_raw, second, epoch)
    assert first.read_bytes() == second.read_bytes()

    with tarfile.open(first, "r:gz") as bundle:
        files = {member.name: member for member in bundle.getmembers()}
        root = "verifier_standard-1.2.0"
        metadata = bundle.extractfile(files[f"{root}/PKG-INFO"])
        assert metadata is not None and b"\r" not in metadata.read()
        readme = bundle.extractfile(files[f"{root}/README.md"])
        assert readme is not None and readme.read() == b"Source bytes stay unchanged.\n"
        assert all(member.mtime == int(epoch) for member in files.values())
        assert all(member.uid == 0 and member.gid == 0 for member in files.values())


def test_artifact_directory_comparison_fails_closed(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "artifact.bin").write_bytes(b"same")
    (second / "artifact.bin").write_bytes(b"same")
    assert release_artifacts.compare_artifact_directories(first, second) == 1

    (second / "artifact.bin").write_bytes(b"different")
    with pytest.raises(release_artifacts.ReleaseError, match="artifact bytes differ"):
        release_artifacts.compare_artifact_directories(first, second)


@pytest.mark.parametrize("release", ("1.3.0", "1.4.0a1"))
def test_retagged_comparison_allows_only_the_expected_manifest_ref_change(
    tmp_path: Path, release: str,
) -> None:
    candidate = tmp_path / "candidate"
    tagged = tmp_path / "tagged"
    candidate.mkdir()
    tagged.mkdir()
    for directory in (candidate, tagged):
        (directory / "artifact.bin").write_bytes(b"same")
    commit = "a" * 40
    artifacts = {"artifact.bin": release_artifacts._file_record(candidate / "artifact.bin")}
    candidate_manifest = {
        "artifacts": artifacts,
        "release": release,
        "source": {"commit": commit, "ref": commit},
    }
    tagged_manifest = {
        "artifacts": artifacts,
        "release": release,
        "source": {"commit": commit, "ref": f"refs/tags/v{release}"},
    }
    for directory, manifest in (
        (candidate, candidate_manifest),
        (tagged, tagged_manifest),
    ):
        (directory / f"verifier-standard-{release}.manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    assert release_artifacts.compare_retagged_artifact_directories(candidate, tagged) == 1

    tagged_manifest["scope"] = "substituted"
    (tagged / f"verifier-standard-{release}.manifest.json").write_text(
        json.dumps(tagged_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(release_artifacts.ReleaseError, match="beyond source.ref"):
        release_artifacts.compare_retagged_artifact_directories(candidate, tagged)


def test_retagged_comparison_refuses_an_empty_artifact_set(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    tagged = tmp_path / "tagged"
    candidate.mkdir()
    tagged.mkdir()
    commit = "a" * 40
    for directory, ref in (
        (candidate, commit),
        (tagged, "refs/tags/v1.3.0"),
    ):
        (directory / "verifier-standard-1.3.0.manifest.json").write_text(
            json.dumps(
                {"release": "1.3.0", "source": {"commit": commit, "ref": ref}},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
    with pytest.raises(release_artifacts.ReleaseError, match="no release artifacts"):
        release_artifacts.compare_retagged_artifact_directories(candidate, tagged)


@pytest.mark.parametrize("drift", ("formatting", "duplicate-key"))
def test_retagged_comparison_rejects_noncanonical_manifest_bytes(
    tmp_path: Path, drift: str
) -> None:
    candidate = tmp_path / "candidate"
    tagged = tmp_path / "tagged"
    candidate.mkdir()
    tagged.mkdir()
    for directory in (candidate, tagged):
        (directory / "artifact.bin").write_bytes(b"same")
    commit = "a" * 40
    candidate_manifest = {
        "artifacts": {"artifact.bin": release_artifacts._file_record(candidate / "artifact.bin")},
        "release": "1.3.0",
        "source": {"commit": commit, "ref": commit},
    }
    tagged_manifest = {
        "artifacts": {"artifact.bin": release_artifacts._file_record(tagged / "artifact.bin")},
        "release": "1.3.0",
        "source": {"commit": commit, "ref": "refs/tags/v1.3.0"},
    }
    name = "verifier-standard-1.3.0.manifest.json"
    (candidate / name).write_text(
        json.dumps(candidate_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    tagged_text = json.dumps(tagged_manifest, indent=2, sort_keys=True) + "\n"
    if drift == "formatting":
        tagged_text = json.dumps(tagged_manifest)
    else:
        tagged_text = tagged_text.replace(
            '  "release": "1.3.0",',
            '  "release": "1.3.0",\n  "release": "1.3.0",',
        )
    (tagged / name).write_text(tagged_text, encoding="utf-8", newline="\n")

    with pytest.raises(
        release_artifacts.ReleaseError, match="canonical|duplicate key"
    ):
        release_artifacts.compare_retagged_artifact_directories(candidate, tagged)


def test_retagged_comparison_refuses_unbound_directory_artifacts(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    tagged = tmp_path / "tagged"
    candidate.mkdir()
    tagged.mkdir()
    for directory in (candidate, tagged):
        (directory / "artifact.bin").write_bytes(b"same")
        (directory / "unbound.bin").write_bytes(b"also-same")
    commit = "a" * 40
    artifacts = {"artifact.bin": release_artifacts._file_record(candidate / "artifact.bin")}
    for directory, ref in (
        (candidate, commit),
        (tagged, "refs/tags/v1.3.0"),
    ):
        manifest = {
            "artifacts": artifacts,
            "release": "1.3.0",
            "source": {"commit": commit, "ref": ref},
        }
        (directory / "verifier-standard-1.3.0.manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    with pytest.raises(release_artifacts.ReleaseError, match="exactly bind"):
        release_artifacts.compare_retagged_artifact_directories(candidate, tagged)


def test_release_instructions_do_not_claim_the_workflow_creates_the_tag() -> None:
    instructions = (REPO_ROOT / "RELEASING.md").read_text(encoding="utf-8")
    assert 'git tag -a "v$VERSION" FULL_PUBLIC_COMMIT_SHA' in instructions
    assert "workflow requires\n   that existing tag and never creates one" in instructions
    assert "compare-retagged dist/candidate dist/tagged" in instructions


def test_cyclonedx_sbom_is_deterministic_bound_and_non_self_referential(
    tmp_path: Path,
) -> None:
    artifacts = {
        "verifier-standard-1.2.0.zip": {
            "byte_size": 3,
            "sha256": release_artifacts._sha256(b"zip"),
        },
        "verifier_standard-1.2.0-py3-none-any.whl": {
            "byte_size": 5,
            "sha256": release_artifacts._sha256(b"wheel"),
        },
    }
    arguments = {
        "commit": "a" * 40,
        "epoch": "1787446816",
        "release": "1.2.0",
        "artifacts": artifacts,
    }
    first = tmp_path / "first.cdx.json"
    second = tmp_path / "second.cdx.json"
    release_artifacts._write_cyclonedx_sbom(first, **arguments)
    release_artifacts._write_cyclonedx_sbom(second, **arguments)

    assert first.read_bytes() == second.read_bytes()
    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["specVersion"] == "1.6"
    assert {component["name"] for component in payload["components"]} == set(artifacts)
    assert first.name not in {component["name"] for component in payload["components"]}
    release_artifacts._verify_cyclonedx_sbom(first, **arguments)

    payload["components"][0]["hashes"][0]["content"] = "0" * 64
    first.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(release_artifacts.ReleaseError, match="bound release subjects"):
        release_artifacts._verify_cyclonedx_sbom(first, **arguments)


def test_release_notes_use_the_github_tag_object_verification() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert 'git/tags/$TAG_OBJECT' in workflow
    assert ".verification.verified" in workflow
    assert ".verification.reason" in workflow
    assert "SIGNED_AND_GITHUB_VERIFIED" in workflow
    assert 'git verify-tag "$GITHUB_REF_NAME"' not in workflow


def test_release_is_drafted_with_attested_sbom_before_publication() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    create = workflow.index('gh release create "$RELEASE_TAG"')
    publish = workflow.index('gh release edit "$RELEASE_TAG"')

    assert "dist/*.cdx.json" in workflow
    assert "--draft" in workflow[create:publish]
    assert "--draft=false" in workflow[publish:]
    assert create < publish


@pytest.mark.parametrize(
    "status", ["OPEN", "CONFLICTED", "", "CLEAR\nStatus: CLEAR", "CLEAR\nStatus: open"]
)
def test_release_time_gate_rejects_every_non_exact_clear_state(
    tmp_path: Path, status: str
) -> None:
    time_file = tmp_path / "TIME.md"
    time_file.write_text(f"# TIME\n\nStatus: {status}\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(TIME_GATE), str(time_file)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert "[TIME BLOCKED]" in result.stderr


def test_tag_release_requires_clear_time_from_the_exact_checkout(tmp_path: Path) -> None:
    time_file = tmp_path / "TIME.md"
    time_file.write_text("# TIME\n\nStatus: CLEAR\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(TIME_GATE), str(time_file)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "[TIME CLEAR]" in result.stdout

    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "Require TIME CLEAR in the exact tagged checkout" in workflow
    assert "python scripts/check_time_status.py" in workflow
    assert workflow.index("python scripts/check_time_status.py") < workflow.index(
        "python -u -m pytest -vv -s --durations=10 --timeout=60"
    )


def _write_final_release_metadata(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        '[project]\nname = "verifier-standard"\nversion = "1.2.0"\n',
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n## 1.2.0 - 2026-08-26\n", encoding="utf-8"
    )
    (root / "CITATION.cff").write_text(
        'cff-version: 1.2.0\nmessage: "Cite this published release."\n'
        "version: 1.2.0\ndate-released: 2026-08-26\n",
        encoding="utf-8",
    )
    (root / ".zenodo.json").write_text(
        json.dumps(
            {
                "version": "1.2.0",
                "publication_date": "2026-08-26",
                "description": "Final publication metadata.",
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "fault",
    (
        "unreleased_changelog",
        "missing_citation_date",
        "mismatched_citation_date",
        "candidate_citation",
        "candidate_zenodo",
        "mismatched_zenodo_date",
        "package_version",
    ),
)
def test_release_metadata_gate_rejects_unfinalized_or_inconsistent_state(
    tmp_path: Path, fault: str
) -> None:
    _write_final_release_metadata(tmp_path)
    if fault == "unreleased_changelog":
        path = tmp_path / "CHANGELOG.md"
        path.write_text(path.read_text().replace("2026-08-26", "UNRELEASED"))
    elif fault == "missing_citation_date":
        path = tmp_path / "CITATION.cff"
        path.write_text(path.read_text().replace("date-released: 2026-08-26\n", ""))
    elif fault == "mismatched_citation_date":
        path = tmp_path / "CITATION.cff"
        path.write_text(path.read_text().replace("2026-08-26", "2026-08-25"))
    elif fault == "candidate_citation":
        path = tmp_path / "CITATION.cff"
        path.write_text(path.read_text().replace("published release", "release candidate"))
    elif fault == "candidate_zenodo":
        path = tmp_path / ".zenodo.json"
        path.write_text(
            json.dumps(
                {
                    "version": "1.2.0",
                    "publication_date": "2026-08-26",
                    "description": "Release-candidate metadata.",
                }
            )
        )
    elif fault == "mismatched_zenodo_date":
        path = tmp_path / ".zenodo.json"
        path.write_text(path.read_text().replace("2026-08-26", "2026-08-25"))
    else:
        path = tmp_path / "pyproject.toml"
        path.write_text(path.read_text().replace("1.2.0", "1.1.3"))

    with pytest.raises(ValueError):
        release_metadata.require_finalized(tmp_path, "1.2.0")


def test_release_metadata_gate_accepts_one_final_consistent_coordinate(tmp_path: Path) -> None:
    _write_final_release_metadata(tmp_path)
    release_metadata.require_finalized(tmp_path, "1.2.0")


def test_release_contract_binds_tag_owner_preflight_and_final_metadata() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    required = (
        "workflow_dispatch:",
        "Existing annotated release tag to publish",
        "immutable_releases_preflight:",
        "repository_checks_run_id:",
        "ref: ${{ env.RELEASE_TAG }}",
        "actions: read",
        'test "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH"',
        'git merge-base --is-ancestor "$SOURCE_COMMIT" "origin/$DEFAULT_BRANCH"',
        'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"',
        'test "$VERSION" = "$PACKAGE_VERSION"',
        'RELEASE_KIND="$(python scripts/classify_release_version.py "$VERSION")"',
        'echo "release_kind=$RELEASE_KIND"',
        'actions/runs/$REPOSITORY_CHECKS_RUN_ID',
        "'.name')\" = \"repository-checks\"",
        "'.path')\" = \".github/workflows/ci.yml\"",
        "'.event')\" = \"push\"",
        "'.head_branch')\" = \"$DEFAULT_BRANCH\"",
        "'.head_sha')\" = \"$SOURCE_COMMIT\"",
        'select(.name == "conformance-gate" and .conclusion == "success")',
        'test "$GITHUB_ACTOR" = "$GITHUB_REPOSITORY_OWNER"',
        'test "$IMMUTABLE_RELEASES_PREFLIGHT" = "true"',
        'python scripts/check_release_metadata.py --version "${RELEASE_TAG#v}"',
        'python -m pip install ".[test,release,seal,scitt]"',
        'vstd surface analyze "$GITHUB_WORKSPACE/examples/verification_geometry_residual/geometry.json"',
        'examples/artifact-network/build_specimen.py',
        'vstd network export',
        'vstd network rebuild',
        'vstd network push',
        'push["transport_performed"] is False',
        '"load_verification_geometry"',
        '"analyze_verification_surface"',
        "prepare_platform_release_evidence.py",
        "platform-python-contracts-${{ steps.release-source.outputs.run_id }}",
        "platform-component-contract-${{ steps.release-source.outputs.run_id }}",
        "verifier-standard-$VERSION-platform-evidence.zip",
        "The platform-evidence ZIP has its own internal manifest",
        'python scripts/extract_release_notes.py --version "$VERSION"',
        'gh release create "$RELEASE_TAG"',
        'RELEASE_FLAGS+=(--prerelease)',
        '"${RELEASE_FLAGS[@]}"',
        'releases/tags/$RELEASE_TAG',
        "--jq '.immutable')\" = true",
    )
    for fragment in required:
        assert fragment in workflow
    assert "repos/$GITHUB_REPOSITORY/immutable-releases" not in workflow
    assert "awk -v version" not in workflow
    assert workflow.index("actions/runs/$REPOSITORY_CHECKS_RUN_ID") < workflow.index(
        "prepare_platform_release_evidence.py"
    )
    assert workflow.index("prepare_platform_release_evidence.py") < workflow.index(
        "check_release_boundary.py"
    )
    assert workflow.index("prepare_platform_release_evidence.py") < workflow.index(
        "actions/attest@"
    )
    assert workflow.index('test "$IMMUTABLE_RELEASES_PREFLIGHT" = "true"') < workflow.index(
        'gh release create "$RELEASE_TAG"'
    )
    assert workflow.index('gh release create "$RELEASE_TAG"') < workflow.index(
        "--jq '.immutable')\" = true"
    )


@pytest.mark.parametrize("version", ("1.4.0a1", "1.4.0b2", "1.4.0rc3"))
def test_release_version_classifier_marks_prereleases(version: str) -> None:
    assert release_version_classifier.classify_release_version(version) == "prerelease"


@pytest.mark.parametrize("version", ("0.1.0", "1.4.0", "12.34.56"))
def test_release_version_classifier_preserves_stable_releases(version: str) -> None:
    assert release_version_classifier.classify_release_version(version) == "stable"


@pytest.mark.parametrize(
    "version",
    (
        "v1.4.0a1",
        "1.4",
        "1.4.0-alpha1",
        "1.4.0dev1",
        "1.4.0.post1",
        "1.4.0+lab1",
        "01.4.0",
        "1.4.0a",
    ),
)
def test_release_version_classifier_rejects_ambiguous_versions(version: str) -> None:
    with pytest.raises(ValueError, match="unsupported release version"):
        release_version_classifier.classify_release_version(version)


def test_release_notes_select_exact_version_heading_without_regex_substitution() -> None:
    changelog = """# Changelog

## Unreleased

## 1x3y0 - 2026-09-07

- wrong section

## 1.3.0 - 2026-09-08

- exact section

## 1.2.0 - 2026-09-01

- old section
"""

    assert release_notes.extract_release_notes(changelog, "1.3.0") == (
        "- exact section\n"
    )
    with pytest.raises(release_notes.ReleaseNotesError, match="invalid release version"):
        release_notes.extract_release_notes(changelog, "1x3y0")


@pytest.mark.parametrize("version", ("1.4.0", "1.4.0a1", "1.4.0b2", "1.4.0rc3"))
def test_release_version_classifier_accepts_supported_coordinates(version: str) -> None:
    expected = "stable" if version == "1.4.0" else "prerelease"
    assert release_version_classifier.classify_release_version(version) == expected


@pytest.mark.parametrize(
    "version",
    ("v1.4.0a1", "1.4", "1.4.0-alpha1", "01.4.0", "1.4.0post1", "1.4.0a"),
)
def test_release_version_classifier_rejects_noncanonical_coordinates(version: str) -> None:
    with pytest.raises(ValueError, match="unsupported release version"):
        release_version_classifier.classify_release_version(version)


def test_release_notes_accept_exact_alpha_prerelease_heading() -> None:
    changelog = "# Changelog\n\n## 1.4.0a1 - 2026-09-13\n\n- alpha\n"
    assert release_notes.extract_release_notes(changelog, "1.4.0a1") == "- alpha\n"


def test_release_notes_reject_missing_or_empty_exact_section() -> None:
    with pytest.raises(release_notes.ReleaseNotesError, match="found 0"):
        release_notes.extract_release_notes("## 1.2.0 - 2026-09-01\n- old\n", "1.3.0")
    with pytest.raises(release_notes.ReleaseNotesError, match="is empty"):
        release_notes.extract_release_notes("## 1.3.0 - 2026-09-08\n", "1.3.0")
