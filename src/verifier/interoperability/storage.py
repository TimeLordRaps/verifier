"""Stored Verifier Standard (VSTD) component packages; no numbered-profile verdict.

This experimental JavaScript Object Notation (JSON) interchange retains artifact
bytes using base64 and binds descriptors to them with Secure Hash Algorithm
256-bit (SHA-256) digests. A digest identifies canonical package content, not its
publisher, implementation correctness, dependency completeness, or permission to
execute. Loading never imports an entry point, extracts, fetches, or installs.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Optional

from .catalog import (
    AWARENESS_CLAIM_BOUNDARY,
    CATALOG_SCHEMA_VERSION,
    CatalogError,
    InteroperabilityComponentRegistry,
)


COMPONENT_PACKAGE_SCHEMA_VERSION = "VSTD-COMPONENT-PACKAGE-1"
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_CONTENT_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_ITEMS = 256
PACKAGE_CLAIM_BOUNDARY = (
    "Package integrity binds retained bytes and declarations only. Publisher and "
    "license are unsigned declarations. Implementation correctness, dependency "
    "completeness, runtime availability, native-platform qualification, authorship, "
    "and authorization are NOT_ESTABLISHED. Import and planning execute nothing. "
    + AWARENESS_CLAIM_BOUNDARY
)


class ComponentPackageError(ValueError):
    """The stored component package is malformed, unbound, or outside bounds."""


def _text(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 4096
        or any(
            ord(char) < 32 or 127 <= ord(char) <= 159 or 0xD800 <= ord(char) <= 0xDFFF
            for char in value
        )
    ):
        raise ComponentPackageError(f"{field} must be nonempty bounded text without control characters")
    return value


def _path(value: Any) -> str:
    value = _text(value, "artifact path")
    if len(value) > 240:
        raise ComponentPackageError("artifact path exceeds 240 characters")
    for part in value.split("/"):
        stem = part.split(".", 1)[0].upper()
        if (
            not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
            or part in {".", ".."}
            or part.endswith(".")
            or stem in {"CON", "PRN", "AUX", "NUL"}
            or re.fullmatch(r"(?:COM|LPT)[1-9]", stem)
        ):
            raise ComponentPackageError("artifact paths must use portable relative file names")
    return value


def _keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ComponentPackageError(f"{label} must have exactly its defined fields")
    return value


def _array(value: Any, label: str) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_PACKAGE_ITEMS:
        raise ComponentPackageError(f"{label} must be an array of at most {MAX_PACKAGE_ITEMS} items")
    return tuple(value)


def _strings(value: Any, label: str, *, paths: bool = False) -> tuple[str, ...]:
    values = tuple(_path(item) if paths else _text(item, label) for item in _array(value, label))
    if len(set(values)) != len(values):
        raise ComponentPackageError(f"{label} contains duplicate references")
    return tuple(sorted(values))


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ComponentPackageError("digest must be 64 lowercase hexadecimal characters")
    return value


def _bounded_registry(value: Any) -> None:
    """Apply package transport limits without changing the standalone catalog."""

    if isinstance(value, str):
        if value:  # Several catalog scalar fields intentionally allow empty text.
            _text(value, "stored registry text")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _text(key, "stored registry field name")
            _bounded_registry(item)
    elif isinstance(value, (list, tuple)):
        for item in _array(value, "stored registry array"):
            _bounded_registry(item)


@dataclass(frozen=True)
class PackageArtifact:
    """An immutable captured byte string, not a path to read later."""

    path: str
    media_type: str
    content: bytes

    def __post_init__(self) -> None:
        _path(self.path)
        _text(self.media_type, "media_type")
        if not isinstance(self.content, bytes) or len(self.content) > MAX_CONTENT_BYTES:
            raise ComponentPackageError("artifact content must be bounded immutable bytes")

    def to_dict(self, *, include_content: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "path": self.path,
            "media_type": self.media_type,
            "size_bytes": len(self.content),
            "sha256": _sha256(self.content),
        }
        if include_content:
            result["content_base64"] = base64.b64encode(self.content).decode("ascii")
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PackageArtifact:
        value = _keys(value, {"path", "media_type", "size_bytes", "sha256", "content_base64"}, "artifact")
        size = value["size_bytes"]
        encoded = value["content_base64"]
        if type(size) is not int or not 0 <= size <= MAX_CONTENT_BYTES:
            raise ComponentPackageError("artifact size_bytes must be a bounded nonnegative integer")
        if not isinstance(encoded, str) or len(encoded) != 4 * ((size + 2) // 3):
            raise ComponentPackageError("artifact base64 length does not match declared size")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ComponentPackageError("artifact content is not valid base64") from exc
        if base64.b64encode(content).decode("ascii") != encoded:
            raise ComponentPackageError("artifact base64 must use canonical padding and pad bits")
        if len(content) != size or _sha256(content) != _digest(value["sha256"]):
            raise ComponentPackageError("artifact content does not match its declared size and digest")
        return cls(value["path"], value["media_type"], content)


@dataclass(frozen=True)
class ImplementationBinding:
    """Declared entry point bound to retained bytes, not checked for reachability."""

    component_id: str
    implementation_ref: str
    artifact_paths: tuple[str, ...]
    dependency_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.component_id, "component_id")
        _text(self.implementation_ref, "implementation_ref")
        object.__setattr__(self, "artifact_paths", _strings(self.artifact_paths, "artifact_paths", paths=True))
        object.__setattr__(self, "dependency_ids", _strings(self.dependency_ids, "dependency_ids"))
        if not self.artifact_paths:
            raise ComponentPackageError("every implementation must bind retained artifact bytes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "implementation_ref": self.implementation_ref,
            "artifact_paths": list(self.artifact_paths),
            "dependency_ids": list(self.dependency_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ImplementationBinding:
        value = _keys(value, {"component_id", "implementation_ref", "artifact_paths", "dependency_ids"}, "implementation")
        return cls(**value)


@dataclass(frozen=True)
class PackageDependency:
    """A literal requirement and optional retained files; not an installation lock."""

    dependency_id: str
    requirement: str
    artifact_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.dependency_id, "dependency_id")
        _text(self.requirement, "requirement")
        object.__setattr__(self, "artifact_paths", _strings(self.artifact_paths, "artifact_paths", paths=True))

    def to_dict(self) -> dict[str, Any]:
        return {
            "dependency_id": self.dependency_id,
            "requirement": self.requirement,
            "artifact_paths": list(self.artifact_paths),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PackageDependency:
        value = _keys(value, {"dependency_id", "requirement", "artifact_paths"}, "dependency")
        return cls(**value)


def _portable_inventory(paths: tuple[str, ...]) -> None:
    prefixes: dict[str, str] = {}
    files = set(paths)
    for path in paths:
        parts = path.split("/")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            previous = prefixes.setdefault(prefix.casefold(), prefix)
            if previous != prefix or (index < len(parts) and prefix in files):
                raise ComponentPackageError("artifact inventory has case collisions or file/directory conflicts")


@dataclass(frozen=True)
class StoredComponentPackage:
    """Self-contained storage envelope; all declarations remain untrusted."""

    package_id: str
    package_version: str
    publisher: str
    license: str
    description: str
    registry: InteroperabilityComponentRegistry
    artifacts: tuple[PackageArtifact, ...]
    implementations: tuple[ImplementationBinding, ...]
    dependencies: tuple[PackageDependency, ...] = ()
    schema_version: str = COMPONENT_PACKAGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != COMPONENT_PACKAGE_SCHEMA_VERSION:
            raise ComponentPackageError("unsupported component package schema_version")
        for field in ("package_id", "package_version", "publisher", "license", "description"):
            _text(getattr(self, field), field)
        if not isinstance(self.registry, InteroperabilityComponentRegistry):
            raise ComponentPackageError("registry must be an interoperability component registry")
        _bounded_registry(self.registry.to_dict())
        if not 1 <= len(self.registry.components) <= MAX_PACKAGE_ITEMS:
            raise ComponentPackageError("package must describe between 1 and 256 components")
        for field, expected_type, key in (
            ("artifacts", PackageArtifact, "path"),
            ("implementations", ImplementationBinding, "component_id"),
            ("dependencies", PackageDependency, "dependency_id"),
        ):
            entries = _array(getattr(self, field), field)
            if not all(isinstance(item, expected_type) for item in entries):
                raise ComponentPackageError(f"{field} contains an unexpected record type")
            identifiers = [getattr(item, key) for item in entries]
            if len(set(identifiers)) != len(identifiers):
                raise ComponentPackageError(f"{field} contains duplicate identifiers")
            object.__setattr__(self, field, tuple(sorted(entries, key=lambda item: getattr(item, key))))
        if sum(len(item.content) for item in self.artifacts) > MAX_CONTENT_BYTES:
            raise ComponentPackageError("total retained artifact bytes exceed the package bound")
        paths = tuple(item.path for item in self.artifacts)
        _portable_inventory(paths)
        path_set = set(paths)
        descriptors = {item.component_id: item for item in self.registry.components}
        if {item.component_id for item in self.implementations} != set(descriptors):
            raise ComponentPackageError("every catalog component requires exactly one implementation binding")
        dependency_ids = {item.dependency_id for item in self.dependencies}
        for binding in self.implementations:
            if binding.implementation_ref != descriptors[binding.component_id].implementation_ref:
                raise ComponentPackageError("implementation_ref differs from the catalog descriptor")
            if not set(binding.dependency_ids) <= dependency_ids:
                raise ComponentPackageError("implementation references an undeclared dependency")
        for binding in self.implementations:
            if not set(binding.artifact_paths) <= path_set:
                raise ComponentPackageError("binding references an absent artifact")
        for dependency in self.dependencies:
            if not set(dependency.artifact_paths) <= path_set:
                raise ComponentPackageError("binding references an absent artifact")
        if len(self.canonical_json_bytes()) > MAX_PACKAGE_BYTES:
            raise ComponentPackageError("encoded package exceeds the storage bound")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "package_id": self.package_id,
            "package_version": self.package_version,
            "publisher": self.publisher,
            "license": self.license,
            "description": self.description,
            "registry": self.registry.to_dict(),
            "registry_sha256": self.registry.canonical_digest(),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "implementations": [item.to_dict() for item in self.implementations],
            "dependencies": [item.to_dict() for item in self.dependencies],
        }

    def canonical_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")

    def canonical_digest(self) -> str:
        return _sha256(self.canonical_json_bytes())

    def validated_binding_digest(
        self, registry: InteroperabilityComponentRegistry,
    ) -> str:
        """Revalidate retained bytes and bind them to the exact planning registry.

        This checks package structure and byte identity, not executable behavior,
        native qualification, or permission. A caller-supplied digest alone is
        not a substitute for the retained package.
        """

        validated = StoredComponentPackage.from_dict(self.to_dict())
        if (
            not isinstance(registry, InteroperabilityComponentRegistry)
            or validated.registry.canonical_json_bytes() != registry.canonical_json_bytes()
        ):
            raise ComponentPackageError("package registry does not match the exact planning registry")
        return validated.canonical_digest()

    def inspect(self) -> dict[str, Any]:
        """Expose declarations and byte integrity without rendering payload content."""

        result = self.to_dict()
        result["artifacts"] = [item.to_dict(include_content=False) for item in self.artifacts]
        result.update(
            package_digest=self.canonical_digest(),
            component_count=len(self.registry.components),
            integrity_result="PASS",
            native_qualification="NOT_ESTABLISHED",
            dependency_completeness="NOT_ESTABLISHED",
            claim_boundary=PACKAGE_CLAIM_BOUNDARY,
        )
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StoredComponentPackage:
        value = _keys(value, {
            "schema_version", "package_id", "package_version", "publisher", "license",
            "description", "registry", "registry_sha256", "artifacts", "implementations",
            "dependencies",
        }, "component package")
        if value["schema_version"] != COMPONENT_PACKAGE_SCHEMA_VERSION:
            raise ComponentPackageError("unsupported component package schema_version")
        raw_registry = value["registry"]
        if not isinstance(raw_registry, Mapping) or raw_registry.get("schema_version") != CATALOG_SCHEMA_VERSION:
            raise ComponentPackageError("stored packages require the exact current catalog schema; no migration")
        _bounded_registry(raw_registry)
        _array(raw_registry.get("components"), "components")
        try:
            registry = InteroperabilityComponentRegistry.from_dict(raw_registry)
        except CatalogError as exc:
            raise ComponentPackageError("invalid stored component registry") from exc
        if registry.to_dict() != raw_registry:
            raise ComponentPackageError("stored registry must already be in canonical descriptor form")
        if registry.canonical_digest() != _digest(value["registry_sha256"]):
            raise ComponentPackageError("stored registry digest mismatch")
        return cls(
            package_id=value["package_id"], package_version=value["package_version"],
            publisher=value["publisher"], license=value["license"], description=value["description"],
            registry=registry,
            artifacts=tuple(PackageArtifact.from_dict(item) for item in _array(value["artifacts"], "artifacts")),
            implementations=tuple(ImplementationBinding.from_dict(item) for item in _array(value["implementations"], "implementations")),
            dependencies=tuple(PackageDependency.from_dict(item) for item in _array(value["dependencies"], "dependencies")),
            schema_version=value["schema_version"],
        )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ComponentPackageError("duplicate object key in stored package")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ComponentPackageError("non-finite numbers are not allowed in stored packages")


def load_component_package(
    path: str | Path, *, expected_digest: Optional[str] = None,
) -> StoredComponentPackage:
    """Read bounded local bytes once; check an optional externally supplied identity.

    The expected digest covers canonical package bytes, not formatting of the
    transport file. It must come from an independently selected coordinate to
    detect whole-package substitution; the package cannot authenticate itself.
    """

    if expected_digest is not None:
        _digest(expected_digest)
    try:
        source = Path(path)
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or (
            getattr(before, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ComponentPackageError("stored package source must be an ordinary non-link file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(source, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (
                before.st_dev, before.st_ino
            ) != (opened.st_dev, opened.st_ino):
                raise ComponentPackageError("stored package source changed or is not an ordinary file")
            data = stream.read(MAX_PACKAGE_BYTES + 1)
        if len(data) > MAX_PACKAGE_BYTES:
            raise ComponentPackageError("stored package exceeds the input byte bound")
        document = json.loads(
            data.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        package = StoredComponentPackage.from_dict(document)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, ComponentPackageError):
            raise
        raise ComponentPackageError("cannot read a valid bounded component package") from exc
    if expected_digest is not None and package.canonical_digest() != expected_digest:
        raise ComponentPackageError("component package does not match the expected digest")
    return package


def save_component_package(package: StoredComponentPackage, path: str | Path) -> None:
    """Save canonical bytes to an absent destination; never overwrite a package."""

    if not isinstance(package, StoredComponentPackage):
        raise ComponentPackageError("package must be a StoredComponentPackage")
    data = package.canonical_json_bytes()
    try:
        with Path(path).open("xb") as stream:
            stream.write(data)
    except OSError as exc:
        raise ComponentPackageError("cannot save package to an absent writable destination") from exc


__all__ = [
    "COMPONENT_PACKAGE_SCHEMA_VERSION", "ComponentPackageError", "ImplementationBinding",
    "PackageArtifact", "PackageDependency", "StoredComponentPackage",
    "load_component_package", "save_component_package",
]
