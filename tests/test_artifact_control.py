"""Adversarial tests for exact-byte freezing and finite self-closing seals.

Terminology: JavaScript Object Notation (JSON); Privacy-Enhanced Mail (PEM);
Verifier Standard (VSTD).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import verifier.artifact_control as artifact_control_module
from verifier.artifact_control import (
    ArtifactControlError,
    freeze_artifact,
    seal_artifact,
    thaw_artifact,
    thawed_artifact_status,
    verify_frozen_artifact,
)
from verifier.runtime.public_cli import main


ROOT = Path(__file__).resolve().parents[1]


def _private_key(path: Path) -> Path:
    cryptography = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    ed25519 = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519"
    )
    key = ed25519.Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            encoding=cryptography.Encoding.PEM,
            format=cryptography.PrivateFormat.PKCS8,
            encryption_algorithm=cryptography.NoEncryption(),
        )
    )
    return path


def _writable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IWUSR)


def _sealed_file(tmp_path: Path, name: str = "case") -> tuple[Path, dict[str, object]]:
    source = tmp_path / f"{name}.bin"
    source.write_bytes(b"\x00exact\r\nbytes\xff")
    bundle = tmp_path / f"{name}.vstd-artifact"
    freeze_artifact(source, bundle, media_type="application/x-test")
    seal = seal_artifact(bundle, _private_key(tmp_path / f"{name}.pem"))
    return bundle, seal


def _seal_path(bundle: Path) -> Path:
    return next((bundle / "seals").glob("*.json"))


def _dual_id(kind: str, payload: bytes) -> str:
    return (
        f"vstd-{kind}-1:sha256:{hashlib.sha256(payload).hexdigest()}:"
        f"sha3-256:{hashlib.sha3_256(payload).hexdigest()}"
    )


def _fake_dual_id(kind: str, digit: str = "0") -> str:
    return f"vstd-{kind}-1:sha256:{digit * 64}:sha3-256:{digit * 64}"


def _reclose_thaw_record(path: Path, **changes: object) -> dict[str, object]:
    record = json.loads(path.read_text(encoding="utf-8"))
    record.update(changes)
    stable = {key: record[key] for key in record if key != "thaw_id"}
    canonical = json.dumps(
        stable,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    record["thaw_id"] = _dual_id("thaw", canonical)
    path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return record


def _thawed_file(tmp_path: Path, name: str = "thaw") -> tuple[Path, Path, Path]:
    bundle, _ = _sealed_file(tmp_path, name)
    descendant = tmp_path / f"{name}-descendant.bin"
    record = thaw_artifact(bundle, descendant)
    return bundle, descendant, Path(str(record["record_path"]))


def _symlink_or_skip(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")


def _fifo_or_skip(path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("first-in, first-out special objects are unavailable")
    try:
        os.mkfifo(path)
    except OSError as exc:
        pytest.skip(f"first-in, first-out special-object creation is unavailable: {exc}")


def test_freeze_preserves_exact_file_bytes_without_claiming_a_seal(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"\x00\r\n\xff")
    bundle = tmp_path / "bundle"

    manifest = freeze_artifact(source, bundle, media_type="application/x-bytes")

    assert (bundle / "payload").read_bytes() == source.read_bytes()
    assert manifest["artifact_id"].startswith("vstd-artifact-1:sha256:")
    assert manifest["content_id"].startswith("vstd-content-1:sha256:")
    assert verify_frozen_artifact(bundle).state == "NOT_ESTABLISHED"
    result = verify_frozen_artifact(bundle, require_seal=False)
    assert result.state == "FROZEN_UNSEALED"
    assert result.freeze_valid and result.guard_valid and not result.sealed


def test_freeze_preserves_directory_paths_files_and_empty_directories(tmp_path: Path) -> None:
    source = tmp_path / "tree"
    (source / "empty").mkdir(parents=True)
    (source / "nested").mkdir()
    (source / "nested" / "value.txt").write_bytes(b"value\n")

    bundle = tmp_path / "tree.vstd-artifact"
    manifest = freeze_artifact(source, bundle)

    assert (bundle / "payload" / "empty").is_dir()
    assert (bundle / "payload" / "nested" / "value.txt").read_bytes() == b"value\n"
    assert [entry["path"] for entry in manifest["entries"]] == [
        "empty",
        "nested",
        "nested/value.txt",
    ]
    assert verify_frozen_artifact(bundle, require_seal=False).freeze_valid


@pytest.mark.parametrize("target_kind", ("file", "directory", "dangling"))
def test_freeze_refuses_top_level_source_symlink_without_creating_bundle(
    tmp_path: Path, target_kind: str
) -> None:
    target = tmp_path / "target"
    if target_kind == "file":
        target.write_bytes(b"target")
    elif target_kind == "directory":
        target.mkdir()
        (target / "value").write_bytes(b"target")
    link = tmp_path / "source-link"
    _symlink_or_skip(link, target, target_is_directory=target_kind == "directory")
    bundle = tmp_path / "bundle"

    with pytest.raises(ArtifactControlError, match="symbolic links"):
        freeze_artifact(link, bundle)

    assert link.is_symlink()
    assert not os.path.lexists(bundle)


def test_freeze_refuses_nested_symlink_without_leaving_partial_bundle(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "ordinary").write_bytes(b"ordinary")
    _symlink_or_skip(source / "nested-link", tmp_path / "absent")
    bundle = tmp_path / "bundle"

    with pytest.raises(ArtifactControlError, match="symbolic links"):
        freeze_artifact(source, bundle)

    assert not os.path.lexists(bundle)


@pytest.mark.parametrize("target_kind", ("file", "directory", "dangling"))
def test_freeze_refuses_symlink_bundle_destination_without_mutating_target(
    tmp_path: Path, target_kind: str
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    target = tmp_path / "target"
    if target_kind == "file":
        target.write_bytes(b"unchanged")
    elif target_kind == "directory":
        target.mkdir()
        (target / "unchanged").write_bytes(b"unchanged")
    bundle = tmp_path / "bundle-link"
    _symlink_or_skip(bundle, target, target_is_directory=target_kind == "directory")

    with pytest.raises(ArtifactControlError, match="already exists"):
        freeze_artifact(source, bundle)

    assert bundle.is_symlink()
    if target_kind == "file":
        assert target.read_bytes() == b"unchanged"
    elif target_kind == "directory":
        assert (target / "unchanged").read_bytes() == b"unchanged"
    else:
        assert not target.exists()


def test_linked_external_freeze_manifest_is_structural_failure(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path, "linked-external-freeze")
    freeze_path = bundle / "freeze.json"
    external = tmp_path / "external-freeze.json"
    _writable(freeze_path)
    freeze_path.replace(external)
    external.chmod(external.stat().st_mode & ~stat.S_IWUSR)
    _symlink_or_skip(freeze_path, external)

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert freeze_path.is_symlink()
    assert not bool(external.stat().st_mode & stat.S_IWUSR)
    assert any("freeze manifest must not" in error for error in result.errors)


def test_linked_in_bundle_freeze_manifest_fails_even_with_identical_bytes(
    tmp_path: Path,
) -> None:
    bundle, _ = _sealed_file(tmp_path, "linked-in-bundle-freeze")
    freeze_path = bundle / "freeze.json"
    target = bundle / "seals" / "freeze-manifest-copy"
    _writable(freeze_path)
    freeze_path.replace(target)
    target.chmod(target.stat().st_mode & ~stat.S_IWUSR)
    _symlink_or_skip(freeze_path, target)

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert any("freeze manifest must not" in error for error in result.errors)


def test_dangling_freeze_manifest_link_is_structural_failure(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path, "dangling-freeze")
    freeze_path = bundle / "freeze.json"
    _writable(freeze_path)
    freeze_path.unlink()
    _symlink_or_skip(freeze_path, tmp_path / "absent-freeze.json")

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert any("freeze manifest must not" in error for error in result.errors)


@pytest.mark.parametrize("replacement", ("directory", "fifo"))
def test_nonregular_freeze_manifest_is_structural_failure(
    tmp_path: Path, replacement: str
) -> None:
    bundle, _ = _sealed_file(tmp_path, f"nonregular-freeze-{replacement}")
    freeze_path = bundle / "freeze.json"
    _writable(freeze_path)
    freeze_path.unlink()
    if replacement == "directory":
        freeze_path.mkdir()
    else:
        _fifo_or_skip(freeze_path)

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert any("freeze manifest must be an ordinary file" in error for error in result.errors)


def test_missing_and_nonobject_freeze_manifests_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    missing_bundle = tmp_path / "missing-bundle"
    freeze_artifact(source, missing_bundle)
    freeze_path = missing_bundle / "freeze.json"
    _writable(freeze_path)
    freeze_path.unlink()
    assert verify_frozen_artifact(missing_bundle, require_seal=False).state == "FAIL"

    nonobject_bundle = tmp_path / "nonobject-bundle"
    freeze_artifact(source, nonobject_bundle)
    freeze_path = nonobject_bundle / "freeze.json"
    _writable(freeze_path)
    freeze_path.write_text("[]\n", encoding="utf-8")
    result = verify_frozen_artifact(nonobject_bundle, require_seal=False)
    assert result.state == "FAIL"
    assert any("one JSON object" in error for error in result.errors)


def test_internal_snapshot_fails_if_open_or_identity_changes_after_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    freeze_artifact(source, bundle)
    freeze_path = bundle / "freeze.json"
    original_open = artifact_control_module.os.open

    def refuse_open(path: object, flags: int) -> int:
        if Path(path) == freeze_path:
            raise OSError("simulated no-follow refusal")
        return original_open(path, flags)

    monkeypatch.setattr(artifact_control_module.os, "open", refuse_open)
    assert verify_frozen_artifact(bundle, require_seal=False).state == "FAIL"
    monkeypatch.setattr(artifact_control_module.os, "open", original_open)

    original_fstat = artifact_control_module.os.fstat

    def changed_fstat(descriptor: int) -> SimpleNamespace:
        observed = original_fstat(descriptor)
        return SimpleNamespace(
            st_mode=observed.st_mode,
            st_dev=observed.st_dev,
            st_ino=observed.st_ino + 1,
        )

    monkeypatch.setattr(artifact_control_module.os, "fstat", changed_fstat)
    result = verify_frozen_artifact(bundle, require_seal=False)
    assert result.state == "FAIL"
    assert any("changed during lexical classification" in error for error in result.errors)


def test_missing_generic_json_alias_reports_read_failure(tmp_path: Path) -> None:
    with pytest.raises(ArtifactControlError, match="cannot read"):
        artifact_control_module._read_json_object(tmp_path / "absent.json", "record")


def test_missing_and_special_sources_fail_without_creating_bundle(tmp_path: Path) -> None:
    missing_bundle = tmp_path / "missing-bundle"
    with pytest.raises(ArtifactControlError, match="cannot inspect artifact source"):
        freeze_artifact(tmp_path / "absent", missing_bundle)
    assert not os.path.lexists(missing_bundle)

    special = tmp_path / "special"
    _fifo_or_skip(special)
    special_bundle = tmp_path / "special-bundle"
    with pytest.raises(ArtifactControlError, match="regular file or directory"):
        freeze_artifact(special, special_bundle)
    assert not os.path.lexists(special_bundle)


def test_nested_special_or_uninspectable_source_entry_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    special = source / "special"
    _fifo_or_skip(special)
    with pytest.raises(ArtifactControlError, match="special filesystem object"):
        freeze_artifact(source, tmp_path / "special-bundle")

    special.unlink()
    ordinary = source / "ordinary"
    ordinary.write_bytes(b"ordinary")
    original_lstat = Path.lstat

    def refuse_entry(path: Path):
        if path == ordinary:
            raise OSError("simulated entry race")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", refuse_entry)
    with pytest.raises(ArtifactControlError, match="cannot inspect frozen artifact entry"):
        freeze_artifact(source, tmp_path / "uninspectable-bundle")


def test_payload_mutation_and_guard_removal_fail_closed(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path)
    payload = bundle / "payload"
    _writable(payload)
    payload.write_bytes(b"forged")

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert not result.freeze_valid
    assert not result.guard_valid
    assert any("payload" in error or "inventory" in error for error in result.errors)


def test_linked_payload_member_remains_structural_failure(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path, "linked-payload")
    payload = bundle / "payload"
    external = tmp_path / "external-payload"
    _writable(payload)
    payload.replace(external)
    external.chmod(external.stat().st_mode & ~stat.S_IWUSR)
    _symlink_or_skip(payload, external)

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert any("payload must not" in error for error in result.errors)


def test_directory_addition_requires_breaking_the_tree_guard_and_fails(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "original").write_bytes(b"original")
    bundle = tmp_path / "bundle"
    freeze_artifact(source, bundle)
    payload = bundle / "payload"
    _writable(payload)
    (payload / "added").write_bytes(b"added")

    result = verify_frozen_artifact(bundle, require_seal=False)

    assert result.state == "FAIL"
    assert not result.freeze_valid
    assert not result.guard_valid


def test_seal_is_finite_self_closing_and_artifact_carried(tmp_path: Path) -> None:
    bundle, seal = _sealed_file(tmp_path)

    result = verify_frozen_artifact(
        bundle,
        expected_artifact_id=seal["seal_payload"]["artifact_id"],
        expected_key_id=seal["seal_payload"]["key_id"],
    )

    assert result.state == "SEALED"
    assert result.sealed and result.freeze_valid and result.guard_valid
    assert result.external_anchor == "ARTIFACT_AND_KEY_MATCHED"
    assert result.valid_seal_ids == (seal["seal_id"],)
    assert seal["signature_base64"] is not None
    assert seal["seal_id"] is not None


@pytest.mark.parametrize(
    "field",
    (
        "artifact_id",
        "closure_rule",
        "public_key_base64",
        "signature_base64",
        "seal_id",
    ),
)
def test_each_closed_seal_surface_rejects_substitution(tmp_path: Path, field: str) -> None:
    bundle, _ = _sealed_file(tmp_path, field)
    path = _seal_path(bundle)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    if field in {"artifact_id", "closure_rule"}:
        envelope["seal_payload"][field] += "-tampered"
    elif field == "public_key_base64":
        envelope[field] = base64.b64encode(b"x" * 32).decode("ascii")
    elif field == "signature_base64":
        envelope[field] = base64.b64encode(b"x" * 64).decode("ascii")
    else:
        envelope[field] += "-tampered"
    _writable(path)
    path.write_text(json.dumps(envelope), encoding="utf-8")
    path.chmod(path.stat().st_mode & ~stat.S_IWUSR)

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert not result.valid_seal_ids


def test_bundle_substitution_requires_an_external_coordinate(tmp_path: Path) -> None:
    first, first_seal = _sealed_file(tmp_path, "first")
    second, _ = _sealed_file(tmp_path, "second")

    self_result = verify_frozen_artifact(second)
    anchored_result = verify_frozen_artifact(
        second,
        expected_artifact_id=first_seal["seal_payload"]["artifact_id"],
        expected_key_id=first_seal["seal_payload"]["key_id"],
    )

    assert self_result.state == "SEALED"
    assert anchored_result.state == "FAIL"
    assert anchored_result.external_anchor == "MISMATCH"
    assert first != second


def test_one_external_anchor_match_cannot_hide_the_other_mismatch(tmp_path: Path) -> None:
    first, _ = _sealed_file(tmp_path, "first")
    second, second_seal = _sealed_file(tmp_path, "second")
    expected = str(second_seal["seal_payload"]["artifact_id"])
    mismatched_artifact_id = expected[:-1] + ("0" if expected[-1] != "0" else "1")

    result = verify_frozen_artifact(
        second,
        expected_artifact_id=mismatched_artifact_id,
        expected_key_id=second_seal["seal_payload"]["key_id"],
    )

    assert result.state == "FAIL"
    assert result.external_anchor == "MISMATCH"
    assert first != second


def test_duplicate_seal_does_not_multiply_assurance(tmp_path: Path) -> None:
    bundle, seal = _sealed_file(tmp_path)
    original = _seal_path(bundle)
    duplicate = original.with_name("duplicate.json")
    duplicate.write_bytes(original.read_bytes())
    duplicate.chmod(duplicate.stat().st_mode & ~stat.S_IWUSR)

    result = verify_frozen_artifact(bundle)

    assert result.state == "SEALED"
    assert result.valid_seal_ids == (seal["seal_id"],)
    assert len(result.key_ids) == 1


def test_valid_and_invalid_seals_remain_conflicted(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path)
    invalid = bundle / "seals" / "invalid.json"
    invalid.write_text("{}\n", encoding="utf-8")
    invalid.chmod(invalid.stat().st_mode & ~stat.S_IWUSR)

    result = verify_frozen_artifact(bundle)

    assert result.state == "CONFLICTED"
    assert result.valid_seal_ids
    assert result.errors
    with pytest.raises(ArtifactControlError, match="cleanly frozen"):
        seal_artifact(bundle, _private_key(tmp_path / "other.pem"))


@pytest.mark.parametrize("target_location", ("external", "internal"))
def test_linked_seals_container_is_structural_failure(
    tmp_path: Path, target_location: str
) -> None:
    if target_location == "external":
        bundle, _ = _sealed_file(tmp_path, "external-seals-container")
        target = tmp_path / "external-seals"
    else:
        source = tmp_path / "directory-source"
        (source / "seal-store").mkdir(parents=True)
        (source / "value").write_bytes(b"value")
        bundle = tmp_path / "internal-seals-container"
        freeze_artifact(source, bundle)
        seal_artifact(bundle, _private_key(tmp_path / "internal-seals.pem"))
        target = bundle / "payload" / "seal-store"
        _writable(bundle / "payload")
        _writable(target)
        target.rmdir()
    seals = bundle / "seals"
    if target_location == "external":
        seals.replace(target)
    else:
        target.mkdir()
        for seal_path in seals.iterdir():
            seal_path.replace(target / seal_path.name)
        seals.rmdir()
    _symlink_or_skip(seals, target, target_is_directory=True)

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert any("seals container must not" in error for error in result.errors)


def test_dangling_seals_container_link_is_structural_failure(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "dangling-seals-container"
    freeze_artifact(source, bundle)
    _symlink_or_skip(bundle / "seals", tmp_path / "absent-seals", target_is_directory=True)

    result = verify_frozen_artifact(bundle, require_seal=False)

    assert result.state == "FAIL"
    assert any("seals container must not" in error for error in result.errors)


@pytest.mark.parametrize("replacement", ("file", "fifo"))
def test_non_directory_seals_container_is_structural_failure(
    tmp_path: Path, replacement: str
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / f"non-directory-seals-{replacement}"
    freeze_artifact(source, bundle)
    seals = bundle / "seals"
    if replacement == "file":
        seals.write_bytes(b"not a directory")
    else:
        _fifo_or_skip(seals)

    result = verify_frozen_artifact(bundle, require_seal=False)

    assert result.state == "FAIL"
    assert any("seals container must be an ordinary directory" in error for error in result.errors)


def test_linked_external_seal_member_is_structural_failure(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path, "external-seal-member")
    seal_path = _seal_path(bundle)
    external = tmp_path / "external-seal.json"
    _writable(seal_path)
    seal_path.replace(external)
    external.chmod(external.stat().st_mode & ~stat.S_IWUSR)
    _symlink_or_skip(seal_path, external)

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert seal_path.is_symlink()
    assert not bool(external.stat().st_mode & stat.S_IWUSR)
    assert any("seal member" in error and "must not" in error for error in result.errors)


def test_linked_internal_identical_seal_member_is_structural_failure(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path, "internal-seal-member")
    seal_path = _seal_path(bundle)
    target = seal_path.with_name("identical-target.json")
    target.write_bytes(seal_path.read_bytes())
    target.chmod(target.stat().st_mode & ~stat.S_IWUSR)
    _writable(seal_path)
    seal_path.unlink()
    _symlink_or_skip(seal_path, target)

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert any("seal member" in error and "must not" in error for error in result.errors)


def test_dangling_seal_member_link_is_structural_failure(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path, "dangling-seal-member")
    seal_path = _seal_path(bundle)
    _writable(seal_path)
    seal_path.unlink()
    _symlink_or_skip(seal_path, tmp_path / "absent-seal.json")

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert any("seal member" in error and "must not" in error for error in result.errors)


@pytest.mark.parametrize("replacement", ("directory", "fifo"))
def test_nonregular_seal_member_is_structural_failure(
    tmp_path: Path, replacement: str
) -> None:
    bundle, _ = _sealed_file(tmp_path, f"nonregular-seal-{replacement}")
    seal_path = _seal_path(bundle)
    _writable(seal_path)
    seal_path.unlink()
    if replacement == "directory":
        seal_path.mkdir()
    else:
        _fifo_or_skip(seal_path)

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert any("seal member" in error for error in result.errors)


def test_unexpected_non_json_seal_member_is_structural_failure(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path, "unexpected-seal-member")
    (bundle / "seals" / "unexpected.txt").write_bytes(b"unexpected")

    result = verify_frozen_artifact(bundle)

    assert result.state == "FAIL"
    assert any("unsupported entry" in error for error in result.errors)


def test_absent_seals_container_preserves_zero_seal_semantics(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "unsealed"
    freeze_artifact(source, bundle)

    assert not os.path.lexists(bundle / "seals")
    assert verify_frozen_artifact(bundle, require_seal=False).state == "FROZEN_UNSEALED"
    assert verify_frozen_artifact(bundle, require_seal=True).state == "NOT_ESTABLISHED"


def test_seal_creation_refuses_existing_linked_valid_target_without_mutating_it(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")
    freeze_artifact(source, bundle)
    seal_artifact(bundle, key)
    target = _seal_path(bundle)
    external = tmp_path / "external-envelope.json"
    _writable(target)
    target.replace(external)
    external.chmod(external.stat().st_mode & ~stat.S_IWUSR)
    before = external.read_bytes()
    _symlink_or_skip(target, external)

    with pytest.raises(ArtifactControlError, match="cleanly frozen"):
        seal_artifact(bundle, key)

    assert target.is_symlink()
    assert external.read_bytes() == before


@pytest.mark.parametrize("target_state", ("dangling", "different"))
def test_seal_creation_refuses_nonordinary_or_different_deterministic_target(
    tmp_path: Path, target_state: str
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"same source")
    key = _private_key(tmp_path / "key.pem")
    probe = tmp_path / "probe"
    freeze_artifact(source, probe)
    seal_artifact(probe, key)
    filename = _seal_path(probe).name

    bundle = tmp_path / "bundle"
    freeze_artifact(source, bundle)
    seals = bundle / "seals"
    seals.mkdir()
    target = seals / filename
    if target_state == "dangling":
        external = tmp_path / "absent-envelope.json"
        _symlink_or_skip(target, external)
    else:
        target.write_bytes(b"{}")

    with pytest.raises(ArtifactControlError, match="cleanly frozen"):
        seal_artifact(bundle, key)

    if target_state == "dangling":
        assert target.is_symlink()
        assert not external.exists()
    else:
        assert target.read_bytes() == b"{}"


@pytest.mark.parametrize("target_state", ("directory", "dangling"))
def test_seal_creation_refuses_linked_seals_container_without_writing_through_it(
    tmp_path: Path, target_state: str
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")
    freeze_artifact(source, bundle)
    target = tmp_path / "seals-target"
    if target_state == "directory":
        target.mkdir()
    seals = bundle / "seals"
    _symlink_or_skip(seals, target, target_is_directory=True)

    with pytest.raises(ArtifactControlError, match="cleanly frozen"):
        seal_artifact(bundle, key)

    assert seals.is_symlink()
    if target_state == "directory":
        assert list(target.iterdir()) == []
    else:
        assert not target.exists()


def test_seal_creation_deduplicates_only_an_ordinary_identical_envelope(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")
    freeze_artifact(source, bundle)

    first = seal_artifact(bundle, key)
    path = _seal_path(bundle)
    before = path.read_bytes()
    second = seal_artifact(bundle, key)

    assert second == first
    assert path.read_bytes() == before
    assert not path.is_symlink()


def test_seal_creation_recovers_from_directory_creation_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")
    freeze_artifact(source, bundle)
    seals = bundle / "seals"
    original_mkdir = Path.mkdir

    def raced_mkdir(path: Path, *args: object, **kwargs: object) -> None:
        if path == seals:
            original_mkdir(path)
            raise FileExistsError("simulated directory race")
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", raced_mkdir)

    envelope = seal_artifact(bundle, key)

    assert verify_frozen_artifact(bundle).state == "SEALED"
    assert envelope["seal_id"] in verify_frozen_artifact(bundle).valid_seal_ids


def test_seal_creation_compares_existing_ordinary_target_before_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"same source")
    key = _private_key(tmp_path / "key.pem")
    probe = tmp_path / "probe"
    freeze_artifact(source, probe)
    seal_artifact(probe, key)
    filename = _seal_path(probe).name

    bundle = tmp_path / "bundle"
    freeze_artifact(source, bundle)
    seals = bundle / "seals"
    seals.mkdir()
    target = seals / filename
    target.write_text("{}\n", encoding="utf-8")
    original_verify = artifact_control_module.verify_frozen_artifact
    first = True

    def allow_initial_inspection(*args: object, **kwargs: object):
        nonlocal first
        if first:
            first = False
            return artifact_control_module.ArtifactVerification(
                state="FROZEN_UNSEALED",
                artifact_id=None,
                content_id=None,
                freeze_id=None,
                freeze_valid=True,
                guard_valid=True,
                valid_seal_ids=(),
                key_ids=(),
                external_anchor="NOT_CHECKED",
                errors=(),
                warnings=(),
            )
        return original_verify(*args, **kwargs)

    monkeypatch.setattr(
        artifact_control_module, "verify_frozen_artifact", allow_initial_inspection
    )

    with pytest.raises(ArtifactControlError, match="different bytes"):
        seal_artifact(bundle, key)

    assert target.read_text(encoding="utf-8") == "{}\n"


def test_seal_creation_failure_before_target_ownership_removes_created_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")
    freeze_artifact(source, bundle)

    def refuse_write(*args: object, **kwargs: object) -> None:
        raise ArtifactControlError("simulated exclusive-write refusal")

    monkeypatch.setattr(artifact_control_module, "_write_json_exclusive", refuse_write)

    with pytest.raises(ArtifactControlError, match="exclusive-write refusal"):
        seal_artifact(bundle, key)

    assert not os.path.lexists(bundle / "seals")


def test_failed_seal_creation_removes_only_created_target_and_empty_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")
    freeze_artifact(source, bundle)
    original_verify = artifact_control_module.verify_frozen_artifact
    calls = 0

    def fail_final_verification(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_verify(*args, **kwargs)
        return artifact_control_module.ArtifactVerification(
            state="FAIL",
            artifact_id=None,
            content_id=None,
            freeze_id=None,
            freeze_valid=False,
            guard_valid=False,
            valid_seal_ids=(),
            key_ids=(),
            external_anchor="NOT_CHECKED",
            errors=("simulated final failure",),
            warnings=(),
        )

    monkeypatch.setattr(
        artifact_control_module, "verify_frozen_artifact", fail_final_verification
    )

    with pytest.raises(ArtifactControlError, match="did not produce"):
        seal_artifact(bundle, key)

    assert not os.path.lexists(bundle / "seals")


def test_seal_cleanup_unlinks_replacement_link_without_touching_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")
    freeze_artifact(source, bundle)
    external = tmp_path / "replacement-target"
    external.write_bytes(b"unchanged")
    original_make_read_only = artifact_control_module._make_read_only

    def replace_then_fail(path: Path) -> None:
        if path.parent.name == "seals":
            path.unlink()
            _symlink_or_skip(path, external)
            raise ArtifactControlError("simulated seal cleanup")
        original_make_read_only(path)

    monkeypatch.setattr(artifact_control_module, "_make_read_only", replace_then_fail)

    with pytest.raises(ArtifactControlError, match="simulated seal cleanup"):
        seal_artifact(bundle, key)

    assert external.read_bytes() == b"unchanged"
    assert not os.path.lexists(bundle / "seals")


def test_seal_cleanup_unlinks_replacement_container_alias_without_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")
    freeze_artifact(source, bundle)
    external = tmp_path / "replacement-container"
    external.mkdir()
    marker = external / "unchanged"
    marker.write_bytes(b"unchanged")
    original_make_read_only = artifact_control_module._make_read_only

    def replace_container_then_fail(path: Path) -> None:
        if path.parent.name == "seals":
            path.unlink()
            path.parent.rmdir()
            _symlink_or_skip(path.parent, external, target_is_directory=True)
            raise ArtifactControlError("simulated container replacement")
        original_make_read_only(path)

    monkeypatch.setattr(
        artifact_control_module, "_make_read_only", replace_container_then_fail
    )

    with pytest.raises(ArtifactControlError, match="container replacement"):
        seal_artifact(bundle, key)

    assert marker.read_bytes() == b"unchanged"
    assert not os.path.lexists(bundle / "seals")


def test_cleanup_handles_reparse_directory_branch_and_chmod_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "junction-shaped"
    directory.mkdir()
    monkeypatch.setattr(artifact_control_module, "_is_link_like", lambda entry: True)
    artifact_control_module._remove_created_entry(directory)
    assert not directory.exists()

    monkeypatch.undo()
    file_path = tmp_path / "ordinary"
    file_path.write_bytes(b"ordinary")
    original_chmod = Path.chmod

    def refuse_chmod(path: Path, mode: int) -> None:
        if path == file_path:
            raise OSError("simulated chmod refusal")
        original_chmod(path, mode)

    monkeypatch.setattr(Path, "chmod", refuse_chmod)
    artifact_control_module._remove_created_entry(file_path)
    assert not file_path.exists()


def test_seal_cleanup_preserves_precise_failure_when_empty_container_cannot_be_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")
    freeze_artifact(source, bundle)
    original_verify = artifact_control_module.verify_frozen_artifact
    original_rmdir = Path.rmdir
    calls = 0

    def fail_final_verification(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_verify(*args, **kwargs)
        return artifact_control_module.ArtifactVerification(
            state="FAIL",
            artifact_id=None,
            content_id=None,
            freeze_id=None,
            freeze_valid=False,
            guard_valid=False,
            valid_seal_ids=(),
            key_ids=(),
            external_anchor="NOT_CHECKED",
            errors=("simulated final failure",),
            warnings=(),
        )

    def refuse_seals_rmdir(path: Path) -> None:
        if path == bundle / "seals":
            raise OSError("simulated inaccessible cleanup path")
        original_rmdir(path)

    monkeypatch.setattr(
        artifact_control_module, "verify_frozen_artifact", fail_final_verification
    )
    monkeypatch.setattr(Path, "rmdir", refuse_seals_rmdir)

    with pytest.raises(ArtifactControlError, match="did not produce"):
        seal_artifact(bundle, key)

    assert (bundle / "seals").is_dir()
    assert list((bundle / "seals").iterdir()) == []


def test_thaw_is_copy_on_write_and_dirtying_is_observable(tmp_path: Path) -> None:
    unsealed_source = tmp_path / "unsealed.bin"
    unsealed_source.write_bytes(b"unsealed")
    unsealed = tmp_path / "unsealed"
    freeze_artifact(unsealed_source, unsealed)
    with pytest.raises(ArtifactControlError, match="cleanly sealed"):
        thaw_artifact(unsealed, tmp_path / "blocked")

    bundle, _ = _sealed_file(tmp_path, "sealed")
    parent_before = (bundle / "payload").read_bytes()
    descendant = tmp_path / "descendant.bin"
    record = thaw_artifact(bundle, descendant)

    assert descendant.read_bytes() == parent_before
    sidecar_only = thawed_artifact_status(descendant)
    assert sidecar_only["state"] == "NOT_ESTABLISHED"
    assert sidecar_only["recorded_identity_match"] is True
    assert sidecar_only["lineage_state"] == "NOT_ESTABLISHED"
    assert thawed_artifact_status(
        descendant, parent_bundle=bundle
    )["state"] == "THAWED_CLEAN"
    descendant.write_bytes(b"changed")
    assert thawed_artifact_status(descendant)["state"] == "NOT_ESTABLISHED"
    assert thawed_artifact_status(
        descendant, parent_bundle=bundle
    )["state"] == "THAWED_DIRTY"
    assert (bundle / "payload").read_bytes() == parent_before
    assert record["parent_artifact_id"] == verify_frozen_artifact(bundle).artifact_id


@pytest.mark.parametrize("target_kind", ("file", "directory", "dangling"))
def test_thaw_refuses_symlink_destination_without_mutating_target(
    tmp_path: Path, target_kind: str
) -> None:
    bundle, _ = _sealed_file(tmp_path, f"destination-{target_kind}")
    target = tmp_path / "target"
    if target_kind == "file":
        target.write_bytes(b"unchanged")
    elif target_kind == "directory":
        target.mkdir()
        (target / "unchanged").write_bytes(b"unchanged")
    destination = tmp_path / "descendant-link"
    _symlink_or_skip(
        destination, target, target_is_directory=target_kind == "directory"
    )

    with pytest.raises(ArtifactControlError, match="already exists"):
        thaw_artifact(bundle, destination)

    assert destination.is_symlink()
    assert not os.path.lexists(Path(str(destination) + ".vstd-thaw.json"))
    assert not os.path.lexists(Path(str(target) + ".vstd-thaw.json"))
    if target_kind == "file":
        assert target.read_bytes() == b"unchanged"
    elif target_kind == "directory":
        assert (target / "unchanged").read_bytes() == b"unchanged"
    else:
        assert not target.exists()


@pytest.mark.parametrize("destination_kind", ("file", "directory"))
def test_thaw_refuses_existing_ordinary_destination(
    tmp_path: Path, destination_kind: str
) -> None:
    bundle, _ = _sealed_file(tmp_path, f"existing-{destination_kind}")
    destination = tmp_path / "existing"
    if destination_kind == "file":
        destination.write_bytes(b"unchanged")
    else:
        destination.mkdir()

    with pytest.raises(ArtifactControlError, match="already exists"):
        thaw_artifact(bundle, destination)

    assert destination.is_file() if destination_kind == "file" else destination.is_dir()


@pytest.mark.parametrize("target_kind", ("file", "dangling"))
def test_thaw_refuses_symlink_record_destination_without_mutating_target(
    tmp_path: Path, target_kind: str
) -> None:
    bundle, _ = _sealed_file(tmp_path, f"record-{target_kind}")
    destination = tmp_path / "descendant"
    record_path = Path(str(destination) + ".vstd-thaw.json")
    target = tmp_path / "record-target"
    if target_kind == "file":
        target.write_bytes(b"unchanged")
    _symlink_or_skip(record_path, target)

    with pytest.raises(ArtifactControlError, match="already exists"):
        thaw_artifact(bundle, destination)

    assert not os.path.lexists(destination)
    assert record_path.is_symlink()
    if target_kind == "file":
        assert target.read_bytes() == b"unchanged"
    else:
        assert not target.exists()


def test_thaw_directory_succeeds_and_mutation_becomes_dirty(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "empty").mkdir(parents=True)
    (source / "value").write_bytes(b"value")
    bundle = tmp_path / "bundle"
    freeze_artifact(source, bundle)
    seal_artifact(bundle, _private_key(tmp_path / "key.pem"))
    destination = tmp_path / "descendant"

    record = thaw_artifact(bundle, destination)
    record_path = Path(str(record["record_path"]))
    clean = thawed_artifact_status(destination, record_path, parent_bundle=bundle)
    (destination / "value").write_bytes(b"changed")
    dirty = thawed_artifact_status(destination, record_path, parent_bundle=bundle)

    assert (destination / "empty").is_dir()
    assert clean["state"] == "THAWED_CLEAN"
    assert dirty["state"] == "THAWED_DIRTY"


def test_failed_thaw_cleanup_unlinks_replacement_symlink_without_touching_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, _ = _sealed_file(tmp_path, "cleanup")
    destination = tmp_path / "descendant"
    record_path = Path(str(destination) + ".vstd-thaw.json")
    replacement_target = tmp_path / "replacement-target"
    replacement_target.write_bytes(b"unchanged")

    def fail_after_creation(*args: object, **kwargs: object) -> dict[str, object]:
        destination.unlink()
        _symlink_or_skip(destination, replacement_target)
        raise ArtifactControlError("simulated post-copy refusal")

    monkeypatch.setattr(
        artifact_control_module, "thawed_artifact_status", fail_after_creation
    )

    with pytest.raises(ArtifactControlError, match="simulated post-copy refusal"):
        thaw_artifact(bundle, destination)

    assert not os.path.lexists(destination)
    assert not os.path.lexists(record_path)
    assert replacement_target.read_bytes() == b"unchanged"


def test_exclusive_sidecar_write_removes_a_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "record.json"
    original = json.dumps

    def fail_serialization(*args: object, **kwargs: object) -> str:
        if kwargs.get("indent") == 2:
            raise RuntimeError("simulated serialization failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(artifact_control_module.json, "dumps", fail_serialization)

    with pytest.raises(RuntimeError, match="simulated serialization failure"):
        artifact_control_module._write_json_exclusive(target, {"value": 1})

    assert not os.path.lexists(target)


def test_exclusive_sidecar_write_never_removes_a_preexisting_file(tmp_path: Path) -> None:
    target = tmp_path / "record.json"
    target.write_bytes(b"preexisting")

    with pytest.raises(FileExistsError):
        artifact_control_module._write_json_exclusive(target, {"value": 1})

    assert target.read_bytes() == b"preexisting"


def test_cleanup_tolerates_an_already_absent_invocation_entry(tmp_path: Path) -> None:
    missing = tmp_path / "already-absent"

    artifact_control_module._remove_created_entry(missing)

    assert not os.path.lexists(missing)


def test_failed_sidecar_creation_cleans_the_created_descendant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, _ = _sealed_file(tmp_path, "sidecar-cleanup")
    destination = tmp_path / "descendant"

    def refuse_sidecar(*args: object, **kwargs: object) -> None:
        raise ArtifactControlError("simulated sidecar refusal")

    monkeypatch.setattr(artifact_control_module, "_write_json_exclusive", refuse_sidecar)

    with pytest.raises(ArtifactControlError, match="simulated sidecar refusal"):
        thaw_artifact(bundle, destination)

    assert not os.path.lexists(destination)
    assert not os.path.lexists(Path(str(destination) + ".vstd-thaw.json"))


def test_raced_file_destination_is_not_deleted_when_exclusive_creation_refuses_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, _ = _sealed_file(tmp_path, "raced-destination")
    destination = tmp_path / "descendant"
    original_open = Path.open

    def raced_open(path: Path, mode: str = "r", *args: object, **kwargs: object):
        if path == destination and mode == "xb":
            path.write_bytes(b"raced")
            raise FileExistsError("simulated concurrent destination")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", raced_open)

    with pytest.raises(FileExistsError, match="concurrent destination"):
        thaw_artifact(bundle, destination)

    assert destination.read_bytes() == b"raced"
    assert not os.path.lexists(Path(str(destination) + ".vstd-thaw.json"))


def test_post_copy_nonclean_status_removes_created_descendant_and_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, _ = _sealed_file(tmp_path, "nonclean-post-copy")
    destination = tmp_path / "descendant"

    monkeypatch.setattr(
        artifact_control_module,
        "thawed_artifact_status",
        lambda *args, **kwargs: {"state": "THAWED_DIRTY"},
    )

    with pytest.raises(ArtifactControlError, match="did not match"):
        thaw_artifact(bundle, destination)

    assert not os.path.lexists(destination)
    assert not os.path.lexists(Path(str(destination) + ".vstd-thaw.json"))


def test_failed_directory_post_check_cleans_only_created_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    (source / "empty").mkdir(parents=True)
    bundle = tmp_path / "bundle"
    freeze_artifact(source, bundle)
    seal_artifact(bundle, _private_key(tmp_path / "directory-cleanup.pem"))
    destination = tmp_path / "descendant"

    def refuse_status(*args: object, **kwargs: object) -> dict[str, object]:
        raise ArtifactControlError("simulated directory post-check refusal")

    monkeypatch.setattr(artifact_control_module, "thawed_artifact_status", refuse_status)

    with pytest.raises(ArtifactControlError, match="post-check refusal"):
        thaw_artifact(bundle, destination)

    assert not os.path.lexists(destination)
    assert not os.path.lexists(Path(str(destination) + ".vstd-thaw.json"))


def test_directory_thaw_rejects_a_link_injected_during_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "value").write_bytes(b"value")
    bundle = tmp_path / "bundle"
    freeze_artifact(source, bundle)
    seal_artifact(bundle, _private_key(tmp_path / "injected-link.pem"))
    destination = tmp_path / "descendant"
    original_copytree = artifact_control_module.shutil.copytree

    def inject_link(*args: object, **kwargs: object) -> Path:
        copied = original_copytree(*args, **kwargs)
        _symlink_or_skip(destination / "injected", tmp_path / "absent")
        return copied

    monkeypatch.setattr(artifact_control_module.shutil, "copytree", inject_link)

    with pytest.raises(ArtifactControlError, match="did not match"):
        thaw_artifact(bundle, destination)

    assert not os.path.lexists(destination)
    assert not os.path.lexists(Path(str(destination) + ".vstd-thaw.json"))


def test_sealed_parent_and_context_bindings_are_explicit_and_deduplicated(
    tmp_path: Path,
) -> None:
    parent, _ = _sealed_file(tmp_path, "parent")
    context, _ = _sealed_file(tmp_path, "realm")
    child_source = tmp_path / "child.bin"
    child_source.write_bytes(b"child")
    child = tmp_path / "child"

    manifest = freeze_artifact(
        child_source,
        child,
        parent_bundles=[parent],
        context_bundles=[context],
    )

    assert manifest["lineage"] == [verify_frozen_artifact(parent).artifact_id]
    assert manifest["bound_contexts"] == [verify_frozen_artifact(context).artifact_id]
    with pytest.raises(ArtifactControlError, match="duplicate"):
        freeze_artifact(
            child_source,
            tmp_path / "duplicate",
            context_bundles=[context, context],
        )


def test_fabricated_thaw_sidecar_without_parent_never_establishes_lineage(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "fabricated.bin"
    artifact.write_bytes(b"fabricated")
    probe = tmp_path / "probe"
    manifest = freeze_artifact(artifact, probe, media_type="application/x-fabricated")
    record_path = tmp_path / "fabricated.bin.vstd-thaw.json"
    record_path.write_text(
        json.dumps(
            {
                "schema_version": "VSTD-ARTIFACT-THAW-1",
                "parent_artifact_id": manifest["artifact_id"],
                "parent_content_id": _fake_dual_id("content"),
                "parent_freeze_id": _fake_dual_id("freeze"),
                "parent_seal_ids": [_fake_dual_id("seal")],
                "artifact_kind": "file",
                "media_type": "application/x-fabricated",
                "thaw_id": _fake_dual_id("thaw"),
            }
        ),
        encoding="utf-8",
    )
    _reclose_thaw_record(record_path)

    result = thawed_artifact_status(artifact, record_path)

    assert result["state"] == "NOT_ESTABLISHED"
    assert result["recorded_identity_match"] is True
    assert result["verified_parent_identity_match"] is None
    assert result["lineage_state"] == "NOT_ESTABLISHED"
    assert result["historical_operation"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("parent_content_id", _fake_dual_id("content")),
        ("parent_freeze_id", _fake_dual_id("freeze")),
        ("parent_seal_ids", [_fake_dual_id("seal")]),
    ),
)
def test_reclosed_false_parent_coordinates_do_not_establish_clean_lineage(
    tmp_path: Path, field: str, replacement: object
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, field)
    _reclose_thaw_record(record_path, **{field: replacement})

    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert result["state"] == "FAIL"
    assert result["lineage_state"] == "NOT_ESTABLISHED"
    assert result["historical_operation"] == "NOT_ESTABLISHED"


def test_fabricated_parent_artifact_and_matching_descendant_need_actual_parent(
    tmp_path: Path,
) -> None:
    _, descendant, record_path = _thawed_file(tmp_path, "fabricated-parent")
    descendant.write_bytes(b"neighboring fabricated descendant")
    probe = tmp_path / "fabricated-parent-probe"
    manifest = freeze_artifact(
        descendant, probe, media_type="application/x-test"
    )
    _reclose_thaw_record(record_path, parent_artifact_id=manifest["artifact_id"])

    result = thawed_artifact_status(descendant, record_path)

    assert result["recorded_identity_match"] is True
    assert result["state"] == "NOT_ESTABLISHED"
    assert result["parent_verification_state"] == "NOT_CHECKED"


def test_neighboring_sealed_parent_bundle_is_refused(tmp_path: Path) -> None:
    _, descendant, record_path = _thawed_file(tmp_path, "original-parent")
    neighbor, _ = _sealed_file(tmp_path, "neighbor-parent")

    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=neighbor
    )

    assert result["state"] == "FAIL"
    assert any("seal" in error for error in result["errors"])


def test_recorded_seal_must_be_valid_on_supplied_parent(tmp_path: Path) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "invalid-recorded-seal")
    _reclose_thaw_record(record_path, parent_seal_ids=[_fake_dual_id("seal", "1")])

    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert result["state"] == "FAIL"
    assert any("not valid" in error for error in result["errors"])


def test_later_additional_valid_parent_seal_preserves_thaw_lineage(
    tmp_path: Path,
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "additional-seal")
    original = json.loads(record_path.read_text(encoding="utf-8"))["parent_seal_ids"]
    seal_artifact(bundle, _private_key(tmp_path / "additional-seal-later.pem"))

    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert result["state"] == "THAWED_CLEAN"
    assert set(original).issubset(verify_frozen_artifact(bundle).valid_seal_ids)


def test_unsealed_parent_cannot_establish_thaw_lineage(tmp_path: Path) -> None:
    source = tmp_path / "unsealed-parent.bin"
    source.write_bytes(b"unsealed")
    unsealed = tmp_path / "unsealed-parent"
    freeze_artifact(source, unsealed, media_type="application/x-test")
    _, descendant, record_path = _thawed_file(tmp_path, "sealed-origin")

    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=unsealed
    )

    assert result["state"] == "FAIL"
    assert result["parent_verification_state"] == "NOT_ESTABLISHED"


def test_conflicted_parent_cannot_establish_thaw_lineage(tmp_path: Path) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "conflicted-parent")
    invalid = bundle / "seals" / "invalid.json"
    invalid.write_text("{}\n", encoding="utf-8")
    invalid.chmod(invalid.stat().st_mode & ~stat.S_IWUSR)

    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert result["state"] == "FAIL"
    assert result["parent_verification_state"] == "CONFLICTED"


@pytest.mark.parametrize(
    ("anchor_name", "anchor_value"),
    (
        ("expected_artifact_id", _fake_dual_id("artifact")),
        ("expected_key_id", "vstd-seal-key-1:sha256:" + "0" * 64),
    ),
)
def test_parent_external_anchor_mismatch_refuses_thaw_lineage(
    tmp_path: Path, anchor_name: str, anchor_value: str
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, anchor_name)

    result = thawed_artifact_status(
        descendant,
        record_path,
        parent_bundle=bundle,
        **{anchor_name: anchor_value},
    )

    assert result["state"] == "FAIL"
    assert result["external_anchor_state"] == "MISMATCH"


def test_verified_parent_distinguishes_clean_and_dirty_without_claiming_history(
    tmp_path: Path,
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "verified-parent")

    clean = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )
    descendant.write_bytes(b"dirty descendant")
    dirty = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert clean["state"] == "THAWED_CLEAN"
    assert clean["lineage_state"] == "PARENT_COORDINATES_ESTABLISHED"
    assert clean["verified_parent_identity_match"] is True
    assert dirty["state"] == "THAWED_DIRTY"
    assert dirty["lineage_state"] == "PARENT_COORDINATES_ESTABLISHED"
    assert dirty["verified_parent_identity_match"] is False
    assert clean["historical_operation"] == dirty["historical_operation"] == "NOT_ESTABLISHED"
    assert any("historical" in warning for warning in clean["warnings"])


@pytest.mark.parametrize(
    ("field", "replacement"),
    (("artifact_kind", "directory"), ("media_type", "application/x-neighbor")),
)
def test_sidecar_kind_and_media_type_must_match_authoritative_parent_metadata(
    tmp_path: Path, field: str, replacement: str
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, field)
    _reclose_thaw_record(record_path, **{field: replacement})

    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert result["state"] == "FAIL"
    assert result["identity_basis"] == "VERIFIED_PARENT_METADATA"
    assert any(field in error for error in result["errors"])


def test_status_check_does_not_modify_parent_bytes_seals_or_modes(tmp_path: Path) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "parent-immutability")

    def snapshot() -> list[tuple[str, bytes | None, int]]:
        return [
            (
                path.relative_to(bundle).as_posix(),
                path.read_bytes() if path.is_file() else None,
                stat.S_IMODE(path.stat().st_mode),
            )
            for path in sorted(bundle.rglob("*"), key=lambda item: item.as_posix())
        ]

    before = snapshot()
    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )
    after = snapshot()

    assert result["state"] == "THAWED_CLEAN"
    assert after == before


@pytest.mark.parametrize(
    "mutation",
    (
        "schema",
        "identifier",
        "empty_seals",
        "invalid_seal",
        "duplicate_seal",
        "kind",
        "media_type",
        "thaw_id",
    ),
)
def test_malformed_thaw_sidecar_fields_fail_closed(
    tmp_path: Path, mutation: str
) -> None:
    _, descendant, record_path = _thawed_file(tmp_path, f"malformed-{mutation}")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if mutation == "schema":
        record["schema_version"] = "UNKNOWN"
    elif mutation == "identifier":
        record["parent_content_id"] = "not-an-identifier"
    elif mutation == "empty_seals":
        record["parent_seal_ids"] = []
    elif mutation == "invalid_seal":
        record["parent_seal_ids"] = ["not-a-seal"]
    elif mutation == "duplicate_seal":
        record["parent_seal_ids"] = record["parent_seal_ids"] * 2
    elif mutation == "kind":
        record["artifact_kind"] = "device"
    elif mutation == "media_type":
        record["media_type"] = ""
    else:
        record["thaw_id"] = _fake_dual_id("thaw")
    record_path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(ArtifactControlError):
        thawed_artifact_status(descendant, record_path)


def test_verified_parent_kind_change_is_dirty_not_clean(tmp_path: Path) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "kind-change")
    descendant.unlink()
    descendant.mkdir()

    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert result["state"] == "THAWED_DIRTY"
    assert result["verified_parent_identity_match"] is False


def test_symlink_descendant_cannot_match_recorded_or_verified_parent(
    tmp_path: Path,
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "symlink-descendant")
    target = tmp_path / "symlink-target.bin"
    target.write_bytes(descendant.read_bytes())
    descendant.unlink()
    try:
        descendant.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    sidecar_only = thawed_artifact_status(descendant, record_path)
    verified = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert sidecar_only["state"] == "NOT_ESTABLISHED"
    assert sidecar_only["recorded_identity_match"] is False
    assert verified["state"] == "THAWED_DIRTY"
    assert verified["verified_parent_identity_match"] is False


def test_unreadable_descendant_inventory_cannot_match_any_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "unreadable-descendant")
    original = artifact_control_module._source_entries

    def refuse_descendant(path: Path) -> list[dict[str, object]]:
        if path.resolve() == descendant.resolve():
            raise ArtifactControlError("simulated unsupported descendant")
        return original(path)

    monkeypatch.setattr(artifact_control_module, "_source_entries", refuse_descendant)

    sidecar_only = thawed_artifact_status(descendant, record_path)
    verified = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert sidecar_only["recorded_identity_match"] is False
    assert verified["state"] == "THAWED_DIRTY"
    assert verified["verified_parent_identity_match"] is False


def test_matching_external_parent_anchors_are_reported_without_claiming_history(
    tmp_path: Path,
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "matching-anchors")
    parent = verify_frozen_artifact(bundle)

    result = thawed_artifact_status(
        descendant,
        record_path,
        parent_bundle=bundle,
        expected_artifact_id=parent.artifact_id,
        expected_key_id=parent.key_ids[0],
    )

    assert result["state"] == "THAWED_CLEAN"
    assert result["external_anchor_state"] == "ARTIFACT_AND_KEY_MATCHED"
    assert not any("external continuity was not checked" in item for item in result["warnings"])
    assert result["historical_operation"] == "NOT_ESTABLISHED"


def test_outer_parent_bundle_alias_remains_an_accepted_read_only_coordinate(
    tmp_path: Path,
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "outer-parent-alias")
    alias = tmp_path / "parent-alias"
    _symlink_or_skip(alias, bundle, target_is_directory=True)

    verification = verify_frozen_artifact(alias)
    status = thawed_artifact_status(
        descendant, record_path, parent_bundle=alias
    )

    assert verification.state == "SEALED"
    assert status["state"] == "THAWED_CLEAN"
    assert status["historical_operation"] == "NOT_ESTABLISHED"


def test_explicit_thaw_record_alias_remains_readable_without_authenticating_history(
    tmp_path: Path,
) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "record-alias")
    external = tmp_path / "external-record.json"
    record_path.replace(external)
    _symlink_or_skip(record_path, external)

    status = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert status["state"] == "THAWED_CLEAN"
    assert status["historical_operation"] == "NOT_ESTABLISHED"


def test_hard_linked_internal_json_members_remain_regular_file_semantics(
    tmp_path: Path,
) -> None:
    bundle, _ = _sealed_file(tmp_path, "hard-linked-members")
    freeze_path = bundle / "freeze.json"
    seal_path = _seal_path(bundle)
    external_freeze = tmp_path / "hard-freeze.json"
    external_seal = tmp_path / "hard-seal.json"
    _writable(freeze_path)
    _writable(seal_path)
    freeze_path.replace(external_freeze)
    seal_path.replace(external_seal)
    try:
        os.link(external_freeze, freeze_path)
        os.link(external_seal, seal_path)
    except OSError as exc:
        pytest.skip(f"hard-link creation is unavailable: {exc}")
    external_freeze.chmod(external_freeze.stat().st_mode & ~stat.S_IWUSR)
    external_seal.chmod(external_seal.stat().st_mode & ~stat.S_IWUSR)

    result = verify_frozen_artifact(bundle)

    assert result.state == "SEALED"
    assert not freeze_path.is_symlink()
    assert not seal_path.is_symlink()
    assert freeze_path.stat().st_ino == external_freeze.stat().st_ino
    assert seal_path.stat().st_ino == external_seal.stat().st_ino


def test_parent_mutation_after_thaw_refuses_current_lineage(tmp_path: Path) -> None:
    bundle, descendant, record_path = _thawed_file(tmp_path, "mutated-parent")
    payload = bundle / "payload"
    _writable(payload)
    payload.write_bytes(b"mutated parent")

    result = thawed_artifact_status(
        descendant, record_path, parent_bundle=bundle
    )

    assert result["state"] == "FAIL"
    assert result["parent_verification_state"] == "FAIL"


def test_unknown_bundle_or_manifest_fields_fail_closed(tmp_path: Path) -> None:
    bundle, _ = _sealed_file(tmp_path)
    (bundle / "surprise.txt").write_text("not part of the format", encoding="utf-8")
    assert verify_frozen_artifact(bundle).state == "FAIL"

    (bundle / "surprise.txt").unlink()
    freeze_path = bundle / "freeze.json"
    _writable(freeze_path)
    text = freeze_path.read_text(encoding="utf-8")
    freeze_path.write_text(text.replace("{", '{"schema_version":"duplicate",', 1))
    assert verify_frozen_artifact(bundle).state == "FAIL"


def test_published_and_packaged_schemas_are_identical_and_accept_emitted_objects(
    tmp_path: Path,
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    public_path = ROOT / "standard/schemas/artifact-control-1.schema.json"
    packaged_path = ROOT / "src/verifier/artifact_control/artifact-control-1.schema.json"
    assert public_path.read_bytes() == packaged_path.read_bytes()
    schema = json.loads(public_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)

    bundle, seal = _sealed_file(tmp_path)
    freeze = json.loads((bundle / "freeze.json").read_text(encoding="utf-8"))
    descendant = tmp_path / "descendant"
    record = thaw_artifact(bundle, descendant)
    record.pop("record_path")

    validator.validate(freeze)
    validator.validate(seal)
    validator.validate(record)


def test_public_cli_exposes_the_complete_artifact_lifecycle(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"cli")
    bundle = tmp_path / "bundle"
    key = _private_key(tmp_path / "key.pem")

    assert main(["artifact", "freeze", str(source), str(bundle), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "FROZEN_UNSEALED"
    assert main(["artifact", "verify", str(bundle), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["state"] == "NOT_ESTABLISHED"
    assert main(
        ["artifact", "seal", str(bundle), "--private-key", str(key), "--json"]
    ) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "SEALED"
    assert main(["artifact", "verify", str(bundle), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "SEALED"

    descendant = tmp_path / "descendant.bin"
    assert main(
        ["artifact", "thaw", str(bundle), str(descendant), "--json"]
    ) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "THAWED_CLEAN"
    assert main(["artifact", "status", str(descendant), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["state"] == "NOT_ESTABLISHED"
    assert main(
        [
            "artifact",
            "status",
            str(descendant),
            "--parent-bundle",
            str(bundle),
            "--json",
        ]
    ) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "THAWED_CLEAN"
    descendant.write_bytes(b"dirty")
    assert main(
        [
            "artifact",
            "status",
            str(descendant),
            "--parent-bundle",
            str(bundle),
            "--json",
        ]
    ) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "THAWED_DIRTY"
