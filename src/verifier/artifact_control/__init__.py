"""Artifact preservation, self-closing seals, and copy-on-write thawing.

Terminology: American Standard Code for Information Interchange (ASCII);
identifier (ID); JavaScript Object Notation (JSON); Privacy-Enhanced Mail (PEM); Secure Hash
Algorithm 256-bit (SHA-256); Secure Hash Algorithm 3 256-bit (SHA3-256);
Verifier Standard (VSTD).

Freezing preserves exact bytes. Sealing is a separate action that closes a
verified freeze manifest with a finite Ed25519 construction; it is not
encryption. Thawing creates a mutable descendant and never changes the frozen
parent. A valid seal establishes only artifact identity and closure under the
declared mechanisms. It does not establish correctness, freshness, ownership,
authorization, or actor reputation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


FREEZE_SCHEMA = "VSTD-ARTIFACT-FREEZE-1"
SEAL_SCHEMA = "VSTD-ARTIFACT-SEAL-1"
SEAL_PAYLOAD_SCHEMA = "VSTD-ARTIFACT-SEAL-CLOSURE-1"
THAW_SCHEMA = "VSTD-ARTIFACT-THAW-1"
CANONICALIZATION = "VSTD-ARTIFACT-CANONICAL-1"
SIGNATURE_ALGORITHM = "Ed25519"
_DIGEST_NAMES = ("sha256", "sha3-256")
_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_DUAL_ID = re.compile(
    r"vstd-(?:artifact|content|freeze|seal|thaw)-1:sha256:[0-9a-f]{64}:"
    r"sha3-256:[0-9a-f]{64}\Z"
)
_MECHANISM = {
    "name": "vstd-reference-freezer",
    "version": "1",
    "canonicalization": CANONICALIZATION,
    "write_guard": "PORTABLE_READ_ONLY_TREE",
}


class ArtifactControlError(ValueError):
    """Raised when an artifact-control action cannot fail closed."""


@dataclass(frozen=True)
class ArtifactVerification:
    """Result of independently recomputing a frozen artifact and its seals."""

    state: str
    artifact_id: str | None
    content_id: str | None
    freeze_id: str | None
    freeze_valid: bool
    guard_valid: bool
    valid_seal_ids: tuple[str, ...]
    key_ids: tuple[str, ...]
    external_anchor: str
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def sealed(self) -> bool:
        return self.state == "SEALED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "artifact_id": self.artifact_id,
            "content_id": self.content_id,
            "freeze_id": self.freeze_id,
            "freeze_valid": self.freeze_valid,
            "guard_valid": self.guard_valid,
            "valid_seal_ids": list(self.valid_seal_ids),
            "key_ids": list(self.key_ids),
            "external_anchor": self.external_anchor,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digests_bytes(value: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(value).hexdigest(),
        "sha3-256": hashlib.sha3_256(value).hexdigest(),
    }


def _digests_file(path: Path) -> tuple[dict[str, str], int]:
    sha256 = hashlib.sha256()
    sha3 = hashlib.sha3_256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            sha256.update(block)
            sha3.update(block)
    return {"sha256": sha256.hexdigest(), "sha3-256": sha3.hexdigest()}, size


def _identity(prefix: str, value: bytes) -> str:
    digests = _digests_bytes(value)
    return (
        f"{prefix}:sha256:{digests['sha256']}:"
        f"sha3-256:{digests['sha3-256']}"
    )


def _strict_object(
    value: Any, expected: set[str], label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ArtifactControlError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unknown " + ", ".join(extra))
        raise ArtifactControlError(f"{label} has invalid fields: {'; '.join(detail)}")
    return value


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ArtifactControlError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ArtifactControlError(f"{label} contains non-finite number {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except OSError as exc:
        raise ArtifactControlError(f"cannot read {label}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ArtifactControlError(f"{label} is not readable JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ArtifactControlError(f"{label} must contain one JSON object")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _source_entries(source: Path) -> list[dict[str, Any]]:
    if source.is_symlink():
        raise ArtifactControlError("symbolic links are not accepted as frozen artifacts")
    if source.is_file():
        digests, size = _digests_file(source)
        return [{"kind": "file", "path": ".", "byte_size": size, "digests": digests}]
    if not source.is_dir():
        raise ArtifactControlError("artifact source must be a regular file or directory")

    entries: list[dict[str, Any]] = []
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
        if path.is_symlink():
            raise ArtifactControlError(
                f"symbolic links are not accepted as frozen artifacts: {_relative_posix(path, source)}"
            )
        relative = _relative_posix(path, source)
        if path.is_dir():
            entries.append({"kind": "directory", "path": relative})
        elif path.is_file():
            digests, size = _digests_file(path)
            entries.append(
                {
                    "kind": "file",
                    "path": relative,
                    "byte_size": size,
                    "digests": digests,
                }
            )
        else:
            raise ArtifactControlError(f"special filesystem object is not supported: {relative}")
    return entries


def _descriptor(kind: str, media_type: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "canonicalization": CANONICALIZATION,
        "artifact_kind": kind,
        "media_type": media_type,
        "entries": entries,
    }


def _content_descriptor(kind: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "canonicalization": CANONICALIZATION,
        "artifact_kind": kind,
        "entries": entries,
    }


def _make_read_only(path: Path) -> None:
    path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _make_writable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IWUSR)


def _is_read_only(path: Path) -> bool:
    return not bool(path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def _set_bundle_guard(bundle: Path) -> None:
    payload = bundle / "payload"
    if payload.is_file():
        _make_read_only(payload)
    else:
        for path in payload.rglob("*"):
            if path.is_file():
                _make_read_only(path)
        for path in sorted(
            (item for item in payload.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            _make_read_only(path)
        _make_read_only(payload)
    _make_read_only(bundle / "freeze.json")


def _guard_errors(bundle: Path) -> list[str]:
    errors: list[str] = []
    guarded = [bundle / "freeze.json"]
    payload = bundle / "payload"
    if payload.is_file():
        guarded.append(payload)
    elif payload.is_dir():
        guarded.append(payload)
        guarded.extend(
            path for path in payload.rglob("*") if path.is_file() or path.is_dir()
        )
    for path in guarded:
        if path.exists() and not _is_read_only(path):
            errors.append(f"write guard is not active: {path.relative_to(bundle).as_posix()}")
    return errors


def _validate_entries(entries: Any) -> list[dict[str, Any]]:
    if not isinstance(entries, list):
        raise ArtifactControlError("freeze.entries must be an array")
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ArtifactControlError(f"freeze.entries[{index}] must be an object")
        kind = entry.get("kind")
        expected = {"kind", "path"} if kind == "directory" else {
            "kind",
            "path",
            "byte_size",
            "digests",
        }
        _strict_object(entry, expected, f"freeze.entries[{index}]")
        path = entry["path"]
        if kind not in {"file", "directory"} or not isinstance(path, str):
            raise ArtifactControlError(f"freeze.entries[{index}] has invalid kind or path")
        if path in seen:
            raise ArtifactControlError(f"freeze.entries contains duplicate path {path!r}")
        seen.add(path)
        if path != ".":
            candidate = Path(path)
            if candidate.is_absolute() or ".." in candidate.parts or candidate.as_posix() != path:
                raise ArtifactControlError(f"freeze.entries[{index}] path is not portable")
        if kind == "file":
            if type(entry["byte_size"]) is not int or entry["byte_size"] < 0:
                raise ArtifactControlError(f"freeze.entries[{index}].byte_size is invalid")
            digests = _strict_object(
                entry["digests"], set(_DIGEST_NAMES), f"freeze.entries[{index}].digests"
            )
            for name in _DIGEST_NAMES:
                value = digests[name]
                if not isinstance(value, str) or _HEX_256.fullmatch(value) is None:
                    raise ArtifactControlError(
                        f"freeze.entries[{index}].digests.{name} is invalid"
                    )
        validated.append(dict(entry))
    order = sorted(validated, key=lambda item: item["path"])
    if order != validated:
        raise ArtifactControlError("freeze.entries must be sorted by portable path")
    return validated


def _load_freeze(bundle: Path) -> dict[str, Any]:
    freeze = _read_json_object(bundle / "freeze.json", "freeze manifest")
    _strict_object(
        freeze,
        {
            "schema_version",
            "artifact_id",
            "content_id",
            "artifact_kind",
            "media_type",
            "entries",
            "lineage",
            "bound_contexts",
            "mechanism",
            "freeze_id",
        },
        "freeze manifest",
    )
    if freeze["schema_version"] != FREEZE_SCHEMA:
        raise ArtifactControlError(f"unsupported freeze schema {freeze['schema_version']!r}")
    if freeze["artifact_kind"] not in {"file", "directory"}:
        raise ArtifactControlError("freeze.artifact_kind is invalid")
    if not isinstance(freeze["media_type"], str) or not freeze["media_type"]:
        raise ArtifactControlError("freeze.media_type must be a nonempty string")
    freeze["entries"] = _validate_entries(freeze["entries"])
    if freeze["artifact_kind"] == "file" and not (
        len(freeze["entries"]) == 1
        and freeze["entries"][0]["kind"] == "file"
        and freeze["entries"][0]["path"] == "."
    ):
        raise ArtifactControlError("a frozen file must have exactly one '.' file entry")
    if freeze["artifact_kind"] == "directory" and any(
        entry["path"] == "." for entry in freeze["entries"]
    ):
        raise ArtifactControlError("a frozen directory must not contain a '.' entry")
    for name in ("artifact_id", "content_id", "freeze_id"):
        if not isinstance(freeze[name], str) or _DUAL_ID.fullmatch(freeze[name]) is None:
            raise ArtifactControlError(f"freeze.{name} is invalid")
    if not isinstance(freeze["lineage"], list) or not all(
        isinstance(item, str) for item in freeze["lineage"]
    ):
        raise ArtifactControlError("freeze.lineage must be an array of artifact identifiers")
    if len(set(freeze["lineage"])) != len(freeze["lineage"]):
        raise ArtifactControlError("freeze.lineage must not contain duplicates")
    if any(
        not item.startswith("vstd-artifact-1:") or _DUAL_ID.fullmatch(item) is None
        for item in freeze["lineage"]
    ):
        raise ArtifactControlError("freeze.lineage contains a non-artifact identifier")
    contexts = freeze["bound_contexts"]
    if not isinstance(contexts, list) or not all(isinstance(item, str) for item in contexts):
        raise ArtifactControlError("freeze.bound_contexts must be an array of artifact identifiers")
    if len(set(contexts)) != len(contexts):
        raise ArtifactControlError("freeze.bound_contexts must not contain duplicates")
    if any(
        not item.startswith("vstd-artifact-1:") or _DUAL_ID.fullmatch(item) is None
        for item in contexts
    ):
        raise ArtifactControlError("freeze.bound_contexts contains a non-artifact identifier")
    mechanism = _strict_object(
        freeze["mechanism"],
        {"name", "version", "canonicalization", "write_guard"},
        "freeze.mechanism",
    )
    if mechanism != _MECHANISM:
        raise ArtifactControlError("freeze.mechanism is unsupported")
    return freeze


def _stable_freeze(freeze: Mapping[str, Any]) -> dict[str, Any]:
    return {key: freeze[key] for key in freeze if key != "freeze_id"}


def _observed_bundle_entries(bundle: Path, kind: str) -> list[dict[str, Any]]:
    payload = bundle / "payload"
    if kind == "file":
        if not payload.is_file() or payload.is_symlink():
            raise ArtifactControlError("frozen file payload is missing or not a regular file")
    else:
        if not payload.is_dir() or payload.is_symlink():
            raise ArtifactControlError("frozen directory payload is missing or not a directory")
    return _source_entries(payload)


def _seal_dependencies() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise ArtifactControlError(
            "artifact sealing requires verifier-standard[seal]; no substitute was used"
        ) from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def _seal_projection(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Return the finite self-closing projection with both closure holes empty."""

    projected = dict(envelope)
    projected["signature_base64"] = None
    projected["seal_id"] = None
    return projected


def _seal_identity_projection(envelope: Mapping[str, Any]) -> dict[str, Any]:
    projected = dict(envelope)
    projected["seal_id"] = None
    return projected


def _seal_payload(
    freeze: Mapping[str, Any], freeze_bytes: bytes, key_id: str
) -> dict[str, Any]:
    return {
        "schema_version": SEAL_PAYLOAD_SCHEMA,
        "artifact_id": freeze["artifact_id"],
        "content_id": freeze["content_id"],
        "freeze_id": freeze["freeze_id"],
        "freeze_manifest_digests": _digests_bytes(freeze_bytes),
        "key_id": key_id,
        "algorithm": SIGNATURE_ALGORITHM,
        "closure_rule": (
            "canonicalize the entire envelope with signature_base64 and seal_id set to null; "
            "verify the signature; then canonicalize with only seal_id null and recompute seal_id"
        ),
    }


def _seal_file_paths(bundle: Path) -> list[Path]:
    seals = bundle / "seals"
    if not seals.exists():
        return []
    if not seals.is_dir() or seals.is_symlink():
        raise ArtifactControlError("seals must be a regular directory")
    unexpected = [path for path in seals.iterdir() if not path.is_file() or path.suffix != ".json"]
    if unexpected:
        raise ArtifactControlError("seals directory contains an unsupported entry")
    return sorted(seals.glob("*.json"), key=lambda path: path.name)


def freeze_artifact(
    source: str | Path,
    bundle: str | Path,
    *,
    media_type: str = "application/octet-stream",
    parent_bundles: Iterable[str | Path] = (),
    context_bundles: Iterable[str | Path] = (),
) -> dict[str, Any]:
    """Preserve exact bytes in a new guarded bundle without creating a seal."""

    source_path = Path(source).resolve()
    bundle_path = Path(bundle).resolve()
    if not isinstance(media_type, str) or not media_type:
        raise ArtifactControlError("media_type must be a nonempty string")
    if bundle_path.exists():
        raise ArtifactControlError(f"freeze bundle already exists: {bundle_path}")
    if source_path.is_dir():
        try:
            bundle_path.relative_to(source_path)
        except ValueError:
            pass
        else:
            raise ArtifactControlError("freeze bundle cannot be created inside its source directory")

    lineage: list[str] = []
    for parent in parent_bundles:
        result = verify_frozen_artifact(parent, require_seal=True)
        if not result.sealed or result.artifact_id is None:
            raise ArtifactControlError(f"parent bundle is not cleanly sealed: {parent}")
        lineage.append(result.artifact_id)
    contexts: list[str] = []
    for context in context_bundles:
        result = verify_frozen_artifact(context, require_seal=True)
        if not result.sealed or result.artifact_id is None:
            raise ArtifactControlError(f"context bundle is not cleanly sealed: {context}")
        contexts.append(result.artifact_id)
    if len(set(lineage)) != len(lineage) or len(set(contexts)) != len(contexts):
        raise ArtifactControlError("duplicate parent or context bundles do not add assurance")

    kind = "file" if source_path.is_file() else "directory" if source_path.is_dir() else ""
    entries = _source_entries(source_path)
    descriptor = _descriptor(kind, media_type, entries)
    artifact_id = _identity("vstd-artifact-1", _canonical_bytes(descriptor))
    content_id = _identity(
        "vstd-content-1", _canonical_bytes(_content_descriptor(kind, entries))
    )
    freeze: dict[str, Any] = {
        "schema_version": FREEZE_SCHEMA,
        "artifact_id": artifact_id,
        "content_id": content_id,
        "artifact_kind": kind,
        "media_type": media_type,
        "entries": entries,
        "lineage": sorted(lineage),
        "bound_contexts": sorted(contexts),
        "mechanism": dict(_MECHANISM),
    }
    freeze["freeze_id"] = _identity("vstd-freeze-1", _canonical_bytes(freeze))

    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{bundle_path.name}.freeze-", dir=bundle_path.parent)
    )
    try:
        payload = staging / "payload"
        if kind == "file":
            shutil.copyfile(source_path, payload)
        else:
            shutil.copytree(source_path, payload)
        _write_json(staging / "freeze.json", freeze)
        _set_bundle_guard(staging)
        observed = _observed_bundle_entries(staging, kind)
        if observed != entries:
            raise ArtifactControlError("preserved payload differs from the source inventory")
        staging.replace(bundle_path)
    except Exception:
        if staging.exists():
            for path in sorted(staging.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                try:
                    _make_writable(path)
                except OSError:
                    pass
            shutil.rmtree(staging, ignore_errors=True)
        raise
    return freeze


def seal_artifact(bundle: str | Path, private_key: str | Path) -> dict[str, Any]:
    """Add one deterministic, readable, self-closing Ed25519 seal."""

    bundle_path = Path(bundle).resolve()
    verification = verify_frozen_artifact(bundle_path, require_seal=False)
    if verification.state not in {"FROZEN_UNSEALED", "SEALED"}:
        raise ArtifactControlError("artifact must be cleanly frozen before it can be sealed")
    freeze = _load_freeze(bundle_path)
    freeze_bytes = (bundle_path / "freeze.json").read_bytes()

    _, serialization, Ed25519PrivateKey, _ = _seal_dependencies()
    key_bytes = Path(private_key).read_bytes()
    try:
        key = serialization.load_pem_private_key(key_bytes, password=None)
    except (TypeError, ValueError) as exc:
        raise ArtifactControlError("seal private key is not a readable unencrypted PEM key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ArtifactControlError("seal private key must use Ed25519")
    public_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "vstd-seal-key-1:sha256:" + hashlib.sha256(public_raw).hexdigest()
    payload = _seal_payload(freeze, freeze_bytes, key_id)
    envelope: dict[str, Any] = {
        "schema_version": SEAL_SCHEMA,
        "seal_payload": payload,
        "public_key_base64": base64.b64encode(public_raw).decode("ascii"),
        "signature_base64": None,
        "seal_id": None,
    }
    signature = key.sign(_canonical_bytes(_seal_projection(envelope)))
    envelope["signature_base64"] = base64.b64encode(signature).decode("ascii")
    envelope["seal_id"] = _identity(
        "vstd-seal-1", _canonical_bytes(_seal_identity_projection(envelope))
    )

    seals = bundle_path / "seals"
    seals.mkdir(exist_ok=True)
    filename = hashlib.sha256(_canonical_bytes(envelope)).hexdigest() + ".json"
    target = seals / filename
    if target.exists():
        if _read_json_object(target, "seal") != envelope:
            raise ArtifactControlError("existing seal filename contains different bytes")
        return envelope
    _write_json(target, envelope)
    _make_read_only(target)
    final = verify_frozen_artifact(bundle_path, require_seal=True)
    if not final.sealed or envelope["seal_id"] not in final.valid_seal_ids:
        raise ArtifactControlError(
            f"seal did not produce a cleanly sealed artifact; observed {final.state}"
        )
    return envelope


def _verify_seal(
    seal: Mapping[str, Any], freeze: Mapping[str, Any], freeze_bytes: bytes
) -> tuple[str, str]:
    InvalidSignature, serialization, _, Ed25519PublicKey = _seal_dependencies()
    _strict_object(
        seal,
        {"schema_version", "seal_payload", "public_key_base64", "signature_base64", "seal_id"},
        "seal",
    )
    if seal["schema_version"] != SEAL_SCHEMA:
        raise ArtifactControlError(f"unsupported seal schema {seal['schema_version']!r}")
    public_encoded = seal["public_key_base64"]
    signature_encoded = seal["signature_base64"]
    if not isinstance(public_encoded, str) or not isinstance(signature_encoded, str):
        raise ArtifactControlError("seal public key and signature must be base64 strings")
    try:
        public_raw = base64.b64decode(public_encoded, validate=True)
        signature = base64.b64decode(signature_encoded, validate=True)
    except ValueError as exc:
        raise ArtifactControlError("seal public key or signature is not canonical base64") from exc
    if len(public_raw) != 32 or len(signature) != 64:
        raise ArtifactControlError("seal public key or signature has the wrong length")
    if (
        base64.b64encode(public_raw).decode("ascii") != public_encoded
        or base64.b64encode(signature).decode("ascii") != signature_encoded
    ):
        raise ArtifactControlError("seal public key or signature is not canonical base64")
    key_id = "vstd-seal-key-1:sha256:" + hashlib.sha256(public_raw).hexdigest()
    expected_payload = _seal_payload(freeze, freeze_bytes, key_id)
    if seal["seal_payload"] != expected_payload:
        raise ArtifactControlError("seal payload does not close the current freeze manifest")
    seal_id = seal["seal_id"]
    if not isinstance(seal_id, str) or seal_id != _identity(
        "vstd-seal-1", _canonical_bytes(_seal_identity_projection(seal))
    ):
        raise ArtifactControlError("seal identity does not close the signature-bearing envelope")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature, _canonical_bytes(_seal_projection(seal))
        )
    except InvalidSignature as exc:
        raise ArtifactControlError("self-closing seal signature did not verify") from exc
    return seal_id, key_id


def verify_frozen_artifact(
    bundle: str | Path,
    *,
    expected_artifact_id: str | None = None,
    expected_key_id: str | None = None,
    require_seal: bool = True,
) -> ArtifactVerification:
    """Recompute preserved bytes, write guards, closure, and optional external anchors."""

    bundle_path = Path(bundle).resolve()
    errors: list[str] = []
    warnings: list[str] = []
    artifact_id: str | None = None
    content_id: str | None = None
    freeze_id: str | None = None
    valid_seals: list[str] = []
    key_ids: list[str] = []
    invalid_seals = 0
    freeze_valid = False
    guard_valid = False
    freeze_errors: list[str] = []
    guard_errors: list[str] = []
    seal_errors: list[str] = []
    anchor_errors: list[str] = []
    try:
        if not bundle_path.is_dir() or bundle_path.is_symlink():
            raise ArtifactControlError("artifact bundle must be a regular directory")
        allowed = {"payload", "freeze.json", "seals"}
        unexpected = sorted(path.name for path in bundle_path.iterdir() if path.name not in allowed)
        if unexpected:
            raise ArtifactControlError(
                "artifact bundle contains unsupported top-level entries: "
                + ", ".join(unexpected)
            )
        freeze = _load_freeze(bundle_path)
        artifact_id = freeze["artifact_id"]
        content_id = freeze["content_id"]
        freeze_id = freeze["freeze_id"]
        entries = _observed_bundle_entries(bundle_path, freeze["artifact_kind"])
        descriptor = _descriptor(freeze["artifact_kind"], freeze["media_type"], entries)
        observed_artifact_id = _identity("vstd-artifact-1", _canonical_bytes(descriptor))
        observed_content_id = _identity(
            "vstd-content-1",
            _canonical_bytes(_content_descriptor(freeze["artifact_kind"], entries)),
        )
        if entries != freeze["entries"]:
            freeze_errors.append("preserved payload inventory differs from freeze.entries")
        if observed_artifact_id != artifact_id:
            freeze_errors.append("preserved payload does not match artifact_id")
        if observed_content_id != content_id:
            freeze_errors.append("preserved payload does not match content_id")
        expected_freeze_id = _identity(
            "vstd-freeze-1", _canonical_bytes(_stable_freeze(freeze))
        )
        if freeze_id != expected_freeze_id:
            freeze_errors.append("freeze_id does not close the freeze manifest")
        freeze_valid = not freeze_errors
        guard_errors.extend(_guard_errors(bundle_path))
        guard_valid = not guard_errors
        freeze_bytes = (bundle_path / "freeze.json").read_bytes()
        for seal_path in _seal_file_paths(bundle_path):
            try:
                seal = _read_json_object(seal_path, "seal")
                seal_id, key_id = _verify_seal(seal, freeze, freeze_bytes)
                valid_seals.append(seal_id)
                key_ids.append(key_id)
                if not _is_read_only(seal_path):
                    guard_errors.append(
                        f"write guard is not active: {seal_path.relative_to(bundle_path).as_posix()}"
                    )
            except ArtifactControlError as exc:
                invalid_seals += 1
                seal_errors.append(f"{seal_path.name}: {exc}")
        guard_valid = not guard_errors
    except ArtifactControlError as exc:
        freeze_errors.append(str(exc))

    errors.extend(freeze_errors)
    errors.extend(guard_errors)
    errors.extend(seal_errors)

    artifact_anchor = "NOT_CHECKED"
    if expected_artifact_id is not None:
        if artifact_id == expected_artifact_id:
            artifact_anchor = "MATCHED"
        else:
            anchor_errors.append("artifact_id does not match the expected external coordinate")
            artifact_anchor = "MISMATCH"
    key_anchor = "NOT_CHECKED"
    if expected_key_id is not None:
        if expected_key_id in key_ids:
            key_anchor = "MATCHED"
        else:
            anchor_errors.append("no valid seal matches the expected external key coordinate")
            key_anchor = "MISMATCH"

    if "MISMATCH" in {artifact_anchor, key_anchor}:
        external_anchor = "MISMATCH"
    elif artifact_anchor == key_anchor == "MATCHED":
        external_anchor = "ARTIFACT_AND_KEY_MATCHED"
    elif artifact_anchor == "MATCHED":
        external_anchor = "ARTIFACT_ID_MATCHED"
    elif key_anchor == "MATCHED":
        external_anchor = "KEY_MATCHED"
    else:
        external_anchor = "NOT_CHECKED"
    errors.extend(anchor_errors)

    if freeze_errors or guard_errors or anchor_errors:
        state = "FAIL"
    elif invalid_seals and valid_seals:
        state = "CONFLICTED"
    elif errors:
        state = "FAIL"
    elif valid_seals:
        state = "SEALED"
    else:
        state = "FROZEN_UNSEALED"
        warnings.append("artifact identity is not seal-backed")
        if require_seal:
            state = "NOT_ESTABLISHED"
    return ArtifactVerification(
        state=state,
        artifact_id=artifact_id,
        content_id=content_id,
        freeze_id=freeze_id,
        freeze_valid=freeze_valid,
        guard_valid=guard_valid,
        valid_seal_ids=tuple(sorted(set(valid_seals))),
        key_ids=tuple(sorted(set(key_ids))),
        external_anchor=external_anchor,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def thaw_artifact(
    bundle: str | Path,
    destination: str | Path,
    *,
    expected_artifact_id: str | None = None,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    """Create a mutable descendant from a cleanly sealed frozen artifact."""

    bundle_path = Path(bundle).resolve()
    destination_path = Path(destination).resolve()
    result = verify_frozen_artifact(
        bundle_path,
        expected_artifact_id=expected_artifact_id,
        expected_key_id=expected_key_id,
        require_seal=True,
    )
    if not result.sealed:
        raise ArtifactControlError(
            f"thaw requires a cleanly sealed artifact; observed {result.state}"
        )
    if destination_path.exists():
        raise ArtifactControlError(f"thaw destination already exists: {destination_path}")
    record_path = destination_path.with_name(destination_path.name + ".vstd-thaw.json")
    if record_path.exists():
        raise ArtifactControlError(f"thaw record already exists: {record_path}")
    freeze = _load_freeze(bundle_path)
    payload = bundle_path / "payload"
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if freeze["artifact_kind"] == "file":
        shutil.copyfile(payload, destination_path)
        _make_writable(destination_path)
    else:
        shutil.copytree(payload, destination_path)
        for path in destination_path.rglob("*"):
            if path.is_file() or path.is_dir():
                _make_writable(path)
        _make_writable(destination_path)
    record: dict[str, Any] = {
        "schema_version": THAW_SCHEMA,
        "parent_artifact_id": result.artifact_id,
        "parent_content_id": result.content_id,
        "parent_freeze_id": result.freeze_id,
        "parent_seal_ids": list(result.valid_seal_ids),
        "artifact_kind": freeze["artifact_kind"],
        "media_type": freeze["media_type"],
    }
    record["thaw_id"] = _identity("vstd-thaw-1", _canonical_bytes(record))
    try:
        _write_json(record_path, record)
        status = thawed_artifact_status(
            destination_path,
            record_path,
            parent_bundle=bundle_path,
            expected_artifact_id=expected_artifact_id,
            expected_key_id=expected_key_id,
        )
        if status["state"] != "THAWED_CLEAN":
            raise ArtifactControlError("thawed descendant did not match the sealed parent")
    except Exception:
        if record_path.exists():
            record_path.unlink()
        if destination_path.is_dir():
            shutil.rmtree(destination_path, ignore_errors=True)
        elif destination_path.exists():
            destination_path.unlink()
        raise
    return {**record, "record_path": str(record_path)}


def thawed_artifact_status(
    artifact: str | Path,
    thaw_record: str | Path | None = None,
    *,
    parent_bundle: str | Path | None = None,
    expected_artifact_id: str | None = None,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    """Assess current descendant equality without authenticating the historical copy.

    A sidecar alone can report only agreement with its own recorded metadata. A
    ``THAWED_CLEAN`` or ``THAWED_DIRTY`` result requires an actual supplied parent
    bundle whose freeze and seals verify and whose exact coordinates match the
    sidecar. Even that result does not prove that the historical copy operation was
    independently observed.
    """

    artifact_path = Path(artifact).resolve()
    record_path = (
        Path(thaw_record).resolve()
        if thaw_record is not None
        else artifact_path.with_name(artifact_path.name + ".vstd-thaw.json")
    )
    record = _read_json_object(record_path, "thaw record")
    _strict_object(
        record,
        {
            "schema_version",
            "parent_artifact_id",
            "parent_content_id",
            "parent_freeze_id",
            "parent_seal_ids",
            "artifact_kind",
            "media_type",
            "thaw_id",
        },
        "thaw record",
    )
    if record["schema_version"] != THAW_SCHEMA:
        raise ArtifactControlError(f"unsupported thaw schema {record['schema_version']!r}")
    identifier_fields = {
        "parent_artifact_id": "vstd-artifact-1:",
        "parent_content_id": "vstd-content-1:",
        "parent_freeze_id": "vstd-freeze-1:",
        "thaw_id": "vstd-thaw-1:",
    }
    for name, prefix in identifier_fields.items():
        value = record[name]
        if (
            not isinstance(value, str)
            or not value.startswith(prefix)
            or _DUAL_ID.fullmatch(value) is None
        ):
            raise ArtifactControlError(f"thaw record {name} is invalid")
    seal_ids = record["parent_seal_ids"]
    if not isinstance(seal_ids, list) or not seal_ids:
        raise ArtifactControlError("thaw record parent_seal_ids must be a nonempty array")
    if not all(
        isinstance(value, str)
        and value.startswith("vstd-seal-1:")
        and _DUAL_ID.fullmatch(value) is not None
        for value in seal_ids
    ):
        raise ArtifactControlError("thaw record parent_seal_ids contains an invalid seal ID")
    if len(set(seal_ids)) != len(seal_ids):
        raise ArtifactControlError("thaw record parent_seal_ids must not contain duplicates")
    if record["artifact_kind"] not in {"file", "directory"}:
        raise ArtifactControlError("thaw record artifact_kind is invalid")
    if not isinstance(record["media_type"], str) or not record["media_type"]:
        raise ArtifactControlError("thaw record media_type must be a nonempty string")
    stable = {key: record[key] for key in record if key != "thaw_id"}
    if record["thaw_id"] != _identity("vstd-thaw-1", _canonical_bytes(stable)):
        raise ArtifactControlError("thaw_id does not close the thaw record")

    observed_kind = (
        "file"
        if artifact_path.is_file()
        else "directory"
        if artifact_path.is_dir()
        else ""
    )

    recorded_observed_id: str | None = None
    try:
        if observed_kind == record["artifact_kind"]:
            recorded_observed_id = _identity(
                "vstd-artifact-1",
                _canonical_bytes(
                    _descriptor(
                        observed_kind,
                        record["media_type"],
                        _source_entries(artifact_path),
                    )
                ),
            )
    except ArtifactControlError:
        recorded_observed_id = None
    recorded_identity_match = recorded_observed_id == record["parent_artifact_id"]

    result: dict[str, Any] = {
        "state": "NOT_ESTABLISHED",
        "lineage_state": "NOT_ESTABLISHED",
        "recorded_identity_match": recorded_identity_match,
        "verified_parent_identity_match": None,
        "identity_basis": "SIDECAR_RECORDED_METADATA",
        "parent_verification_state": "NOT_CHECKED",
        "external_anchor_state": "NOT_CHECKED",
        "historical_operation": "NOT_ESTABLISHED",
        "parent_artifact_id": record["parent_artifact_id"],
        "observed_artifact_id": recorded_observed_id,
        "thaw_id": record["thaw_id"],
        "errors": [],
        "warnings": [
            "sidecar agreement does not establish an actual sealed parent or historical thaw operation"
        ],
    }
    if parent_bundle is None:
        return result

    parent_path = Path(parent_bundle).resolve()
    parent_verification = verify_frozen_artifact(
        parent_path,
        expected_artifact_id=expected_artifact_id,
        expected_key_id=expected_key_id,
        require_seal=True,
    )
    result["parent_verification_state"] = parent_verification.state
    result["external_anchor_state"] = parent_verification.external_anchor
    result["errors"] = list(parent_verification.errors)
    if not parent_verification.sealed:
        result["state"] = "FAIL"
        result["errors"].append(
            "supplied parent bundle is not cleanly sealed"
        )
        return result

    parent_freeze = _load_freeze(parent_path)
    coordinate_errors: list[str] = []
    comparisons = (
        ("parent_artifact_id", parent_verification.artifact_id),
        ("parent_content_id", parent_verification.content_id),
        ("parent_freeze_id", parent_verification.freeze_id),
        ("artifact_kind", parent_freeze["artifact_kind"]),
        ("media_type", parent_freeze["media_type"]),
    )
    for name, expected in comparisons:
        if record[name] != expected:
            coordinate_errors.append(
                f"thaw record {name} does not match the supplied sealed parent"
            )
    valid_parent_seals = set(parent_verification.valid_seal_ids)
    missing_seals = sorted(set(seal_ids) - valid_parent_seals)
    if missing_seals:
        coordinate_errors.append(
            "thaw record names a seal that is not valid on the supplied parent: "
            + ", ".join(missing_seals)
        )

    authoritative_observed_id: str | None = None
    try:
        if observed_kind == parent_freeze["artifact_kind"]:
            authoritative_observed_id = _identity(
                "vstd-artifact-1",
                _canonical_bytes(
                    _descriptor(
                        observed_kind,
                        parent_freeze["media_type"],
                        _source_entries(artifact_path),
                    )
                ),
            )
    except ArtifactControlError:
        authoritative_observed_id = None

    result["identity_basis"] = "VERIFIED_PARENT_METADATA"
    result["observed_artifact_id"] = authoritative_observed_id
    result["verified_parent_identity_match"] = (
        authoritative_observed_id == parent_verification.artifact_id
    )
    result["warnings"] = [
        "current equality does not prove that the historical thaw operation was independently observed"
    ]
    if parent_verification.external_anchor == "NOT_CHECKED":
        result["warnings"].append(
            "supplied parent is internally consistent; external continuity was not checked"
        )
    if coordinate_errors:
        result["state"] = "FAIL"
        result["errors"].extend(coordinate_errors)
        return result

    result["lineage_state"] = "PARENT_COORDINATES_ESTABLISHED"
    result["state"] = (
        "THAWED_CLEAN"
        if result["verified_parent_identity_match"]
        else "THAWED_DIRTY"
    )
    return result


__all__ = [
    "ArtifactControlError",
    "ArtifactVerification",
    "freeze_artifact",
    "seal_artifact",
    "thaw_artifact",
    "thawed_artifact_status",
    "verify_frozen_artifact",
]
