"""Adversarial tests for exact-byte freezing and finite self-closing seals.

Terminology: Privacy-Enhanced Mail (PEM); Verifier Standard (VSTD).
"""

from __future__ import annotations

import base64
import json
import stat
from pathlib import Path

import pytest

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
    assert thawed_artifact_status(descendant)["state"] == "THAWED_CLEAN"
    descendant.write_bytes(b"changed")
    assert thawed_artifact_status(descendant)["state"] == "THAWED_DIRTY"
    assert (bundle / "payload").read_bytes() == parent_before
    assert record["parent_artifact_id"] == verify_frozen_artifact(bundle).artifact_id


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
    descendant.write_bytes(b"dirty")
    assert main(["artifact", "status", str(descendant), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "THAWED_DIRTY"
