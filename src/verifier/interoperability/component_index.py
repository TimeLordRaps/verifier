"""Experimental Verifier Standard (VSTD) component discovery index.

The JavaScript Object Notation (JSON) index binds complete component catalogs to
content-addressed stored-package coordinates using Secure Hash Algorithm 256-bit
(SHA-256) digests. Loading and searching never fetch, import, install, or execute
a package. Index membership and digest integrity do not establish publisher
identity, license authenticity, implementation correctness, availability,
ecosystem completeness, native-platform qualification, or authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Optional

from .catalog import (
    CATALOG_SCHEMA_VERSION,
    CatalogError,
    InteractionMode,
    InteroperabilityComponentRegistry,
)
from .storage import (
    MAX_PACKAGE_BYTES,
    ComponentPackageError,
    StoredComponentPackage,
)


COMPONENT_INDEX_SCHEMA_VERSION = "VSTD-COMPONENT-INDEX-1"
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_INDEX_PACKAGES = 4096
INDEX_CLAIM_BOUNDARY = (
    "The index records bounded unsigned declarations and content-addressed package "
    "coordinates. A match establishes only that a descriptor in this exact index "
    "declares the queried capability. Package availability is NOT_CHECKED; publisher "
    "identity, license authenticity, implementation correctness, dependency "
    "completeness, native-platform qualification, authorization, and ecosystem "
    "completeness are NOT_ESTABLISHED or UNKNOWN. No package is fetched, imported, "
    "installed, or executed. Zero matches do not establish ecosystem absence."
)


class ComponentIndexError(ValueError):
    """The component index is malformed, ambiguous, or outside its bounds."""


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
        raise ComponentIndexError(
            f"{field} must be nonempty bounded text without control characters"
        )
    return value


def _digest(value: Any, field: str = "digest") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ComponentIndexError(
            f"{field} must be 64 lowercase hexadecimal characters"
        )
    return value


def _keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ComponentIndexError(f"{label} must have exactly its defined fields")
    return value


def _bounded_registry(value: Any) -> None:
    if isinstance(value, str):
        if value:
            _text(value, "indexed registry text")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _text(key, "indexed registry field name")
            _bounded_registry(item)
    elif isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise ComponentIndexError("indexed registry arrays are limited to 256 items")
        for item in value:
            _bounded_registry(item)


def _package_path(value: Any, digest: str) -> str:
    expected = f"packages/sha256/{digest}.json"
    if value != expected:
        raise ComponentIndexError(
            "package_path must be the exact content-addressed relative package path"
        )
    return expected


@dataclass(frozen=True)
class IndexedComponentPackage:
    """One stored package coordinate plus its exact catalog; never a resolver."""

    package_id: str
    package_version: str
    package_sha256: str
    package_size_bytes: int
    package_path: str
    publisher: str
    license: str
    description: str
    registry: InteroperabilityComponentRegistry
    registry_sha256: str

    def __post_init__(self) -> None:
        for field in ("package_id", "package_version", "publisher", "license", "description"):
            _text(getattr(self, field), field)
        digest = _digest(self.package_sha256, "package_sha256")
        _package_path(self.package_path, digest)
        if (
            type(self.package_size_bytes) is not int
            or not 1 <= self.package_size_bytes <= MAX_PACKAGE_BYTES
        ):
            raise ComponentIndexError("package_size_bytes must be a bounded positive integer")
        if not isinstance(self.registry, InteroperabilityComponentRegistry):
            raise ComponentIndexError("registry must be an interoperability component registry")
        _bounded_registry(self.registry.to_dict())
        if not 1 <= len(self.registry.components) <= 256:
            raise ComponentIndexError("indexed package must describe between 1 and 256 components")
        if self.registry.schema_version != CATALOG_SCHEMA_VERSION:
            raise ComponentIndexError("indexed packages require the exact current catalog schema")
        if self.registry.canonical_digest() != _digest(
            self.registry_sha256, "registry_sha256"
        ):
            raise ComponentIndexError("indexed registry digest mismatch")

    @classmethod
    def from_package(
        cls,
        package: StoredComponentPackage,
        package_path: Optional[str] = None,
    ) -> "IndexedComponentPackage":
        """Bind an already constructed stored package without executing its contents."""

        if not isinstance(package, StoredComponentPackage):
            raise ComponentIndexError("package must be a stored component package")
        try:
            package = StoredComponentPackage.from_dict(package.to_dict())
        except ComponentPackageError as exc:
            raise ComponentIndexError("package is not a valid stored component package") from exc
        digest = package.canonical_digest()
        return cls(
            package_id=package.package_id,
            package_version=package.package_version,
            package_sha256=digest,
            package_size_bytes=len(package.canonical_json_bytes()),
            package_path=package_path or f"packages/sha256/{digest}.json",
            publisher=package.publisher,
            license=package.license,
            description=package.description,
            registry=package.registry,
            registry_sha256=package.registry.canonical_digest(),
        )

    def validate_package(self, package: StoredComponentPackage) -> str:
        """Check that a supplied package is the exact indexed object; execute nothing."""

        candidate = IndexedComponentPackage.from_package(package)
        if candidate != self:
            raise ComponentIndexError("stored component package does not match its index entry")
        return self.package_sha256

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "package_version": self.package_version,
            "package_sha256": self.package_sha256,
            "package_size_bytes": self.package_size_bytes,
            "package_path": self.package_path,
            "publisher": self.publisher,
            "license": self.license,
            "description": self.description,
            "registry": self.registry.to_dict(),
            "registry_sha256": self.registry_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IndexedComponentPackage":
        value = _keys(
            value,
            {
                "package_id", "package_version", "package_sha256",
                "package_size_bytes", "package_path", "publisher", "license",
                "description", "registry", "registry_sha256",
            },
            "indexed component package",
        )
        raw_registry = value["registry"]
        if (
            not isinstance(raw_registry, Mapping)
            or raw_registry.get("schema_version") != CATALOG_SCHEMA_VERSION
        ):
            raise ComponentIndexError(
                "indexed packages require the exact current catalog schema; no migration"
            )
        _bounded_registry(raw_registry)
        try:
            registry = InteroperabilityComponentRegistry.from_dict(raw_registry)
        except CatalogError as exc:
            raise ComponentIndexError("invalid indexed component registry") from exc
        if registry.to_dict() != raw_registry:
            raise ComponentIndexError("indexed registry must already be in canonical form")
        return cls(
            package_id=value["package_id"],
            package_version=value["package_version"],
            package_sha256=value["package_sha256"],
            package_size_bytes=value["package_size_bytes"],
            package_path=value["package_path"],
            publisher=value["publisher"],
            license=value["license"],
            description=value["description"],
            registry=registry,
            registry_sha256=value["registry_sha256"],
        )


@dataclass(frozen=True)
class StoredComponentIndex:
    """A deterministic static index of content-addressed stored packages."""

    index_id: str
    index_version: str
    description: str
    packages: tuple[IndexedComponentPackage, ...]
    schema_version: str = COMPONENT_INDEX_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != COMPONENT_INDEX_SCHEMA_VERSION:
            raise ComponentIndexError("unsupported component index schema_version")
        for field in ("index_id", "index_version", "description"):
            _text(getattr(self, field), field)
        if not isinstance(self.packages, (tuple, list)) or not 1 <= len(self.packages) <= MAX_INDEX_PACKAGES:
            raise ComponentIndexError(
                f"packages must contain between 1 and {MAX_INDEX_PACKAGES} entries"
            )
        packages = tuple(self.packages)
        if not all(isinstance(item, IndexedComponentPackage) for item in packages):
            raise ComponentIndexError("packages contain an unexpected record type")
        for label, keys in (
            ("package coordinates", [(item.package_id, item.package_version) for item in packages]),
            ("package digests", [item.package_sha256 for item in packages]),
            ("package paths", [item.package_path for item in packages]),
        ):
            if len(set(keys)) != len(keys):
                raise ComponentIndexError(f"duplicate {label} are not allowed")
        object.__setattr__(
            self,
            "packages",
            tuple(sorted(packages, key=lambda item: (item.package_id, item.package_version))),
        )
        if len(self.canonical_json_bytes()) > MAX_INDEX_BYTES:
            raise ComponentIndexError("encoded component index exceeds the storage bound")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "index_id": self.index_id,
            "index_version": self.index_version,
            "description": self.description,
            "packages": [item.to_dict() for item in self.packages],
        }

    def canonical_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    def canonical_digest(self) -> str:
        return hashlib.sha256(self.canonical_json_bytes()).hexdigest()

    def inspect(self) -> dict[str, Any]:
        result = self.to_dict()
        result.update(
            index_digest=self.canonical_digest(),
            package_count=len(self.packages),
            component_count=sum(len(item.registry.components) for item in self.packages),
            integrity_result="PASS",
            package_availability="NOT_CHECKED",
            native_qualification="NOT_ESTABLISHED",
            ecosystem_completeness="UNKNOWN",
            execution_performed=False,
            claim_boundary=INDEX_CLAIM_BOUNDARY,
        )
        return result

    def search_exact(
        self,
        *,
        schema_id: str,
        interaction_mode: InteractionMode,
        relation_id: Optional[str] = None,
        mechanism_id: Optional[str] = None,
        package_id: Optional[str] = None,
        package_version: Optional[str] = None,
    ) -> dict[str, Any]:
        """Return all exact declarations, not a ranking or availability verdict."""

        _text(schema_id, "schema_id")
        if relation_id is None and mechanism_id is None:
            raise ComponentIndexError("exact search requires relation_id or mechanism_id")
        if relation_id is not None:
            _text(relation_id, "relation_id")
        if mechanism_id is not None:
            _text(mechanism_id, "mechanism_id")
        if package_id is not None:
            _text(package_id, "package_id")
        if package_version is not None:
            _text(package_version, "package_version")
        try:
            mode = InteractionMode(interaction_mode)
        except (TypeError, ValueError) as exc:
            raise ComponentIndexError("invalid interaction_mode") from exc
        matches: list[dict[str, Any]] = []
        for package in self.packages:
            if package_id is not None and package.package_id != package_id:
                continue
            if package_version is not None and package.package_version != package_version:
                continue
            for component in package.registry.match_exact(
                schema_id=schema_id,
                interaction_mode=mode,
                relation_id=relation_id,
                mechanism_id=mechanism_id,
            ):
                matches.append(
                    {
                        "package_id": package.package_id,
                        "package_version": package.package_version,
                        "package_sha256": package.package_sha256,
                        "package_size_bytes": package.package_size_bytes,
                        "package_path": package.package_path,
                        "registry_sha256": package.registry_sha256,
                        "component": component.to_dict(),
                    }
                )
        query = {
            "schema_id": schema_id,
            "interaction_mode": mode.value,
            "relation_id": relation_id,
            "mechanism_id": mechanism_id,
            "package_id": package_id,
            "package_version": package_version,
        }
        return {
            "schema_version": self.schema_version,
            "index_id": self.index_id,
            "index_version": self.index_version,
            "index_digest": self.canonical_digest(),
            "query": query,
            "result": "DECLARED_MATCHES" if matches else "NO_DECLARED_MATCH_IN_THIS_INDEX",
            "match_count": len(matches),
            "matches": matches,
            "package_availability": "NOT_CHECKED",
            "native_qualification": "NOT_ESTABLISHED",
            "ecosystem_completeness": "UNKNOWN",
            "execution_performed": False,
            "claim_boundary": INDEX_CLAIM_BOUNDARY,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StoredComponentIndex":
        value = _keys(
            value,
            {"schema_version", "index_id", "index_version", "description", "packages"},
            "component index",
        )
        if value["schema_version"] != COMPONENT_INDEX_SCHEMA_VERSION:
            raise ComponentIndexError("unsupported component index schema_version")
        packages = value["packages"]
        if not isinstance(packages, list) or not 1 <= len(packages) <= MAX_INDEX_PACKAGES:
            raise ComponentIndexError(
                f"packages must contain between 1 and {MAX_INDEX_PACKAGES} entries"
            )
        index = cls(
            index_id=value["index_id"],
            index_version=value["index_version"],
            description=value["description"],
            packages=tuple(IndexedComponentPackage.from_dict(item) for item in packages),
            schema_version=value["schema_version"],
        )
        if index.to_dict() != value:
            raise ComponentIndexError("component index must already be in canonical record order")
        return index


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ComponentIndexError("duplicate object key in stored component index")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ComponentIndexError("non-finite numbers are not allowed in component indexes")


def load_component_index(
    path: str | Path,
    *,
    expected_digest: Optional[str] = None,
) -> StoredComponentIndex:
    """Read one bounded local index; never dereference its package paths."""

    if expected_digest is not None:
        _digest(expected_digest, "expected_digest")
    try:
        source = Path(path)
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or (
            getattr(before, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ComponentIndexError("component index source must be an ordinary non-link file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(source, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (
                before.st_dev,
                before.st_ino,
            ) != (opened.st_dev, opened.st_ino):
                raise ComponentIndexError(
                    "component index source changed or is not an ordinary file"
                )
            data = stream.read(MAX_INDEX_BYTES + 1)
        if len(data) > MAX_INDEX_BYTES:
            raise ComponentIndexError("component index exceeds the input byte bound")
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        index = StoredComponentIndex.from_dict(document)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, ComponentIndexError):
            raise
        raise ComponentIndexError("cannot read a valid bounded component index") from exc
    if expected_digest is not None and index.canonical_digest() != expected_digest:
        raise ComponentIndexError("component index does not match the expected digest")
    return index


def save_component_index(index: StoredComponentIndex, path: str | Path) -> None:
    """Save canonical index bytes to an absent destination; never overwrite."""

    if not isinstance(index, StoredComponentIndex):
        raise ComponentIndexError("index must be a stored component index")
    destination = Path(path)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(destination, flags, 0o600), "wb") as stream:
            stream.write(index.canonical_json_bytes())
    except OSError as exc:
        raise ComponentIndexError("cannot create component index without overwriting") from exc


__all__ = [
    "COMPONENT_INDEX_SCHEMA_VERSION",
    "ComponentIndexError",
    "IndexedComponentPackage",
    "StoredComponentIndex",
    "load_component_index",
    "save_component_index",
]
