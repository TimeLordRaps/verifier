"""Stored Verifier Standard (VSTD) package byte and declaration boundaries.

JavaScript Object Notation (JSON) formatting does not alter canonical identity;
Secure Hash Algorithm 256-bit (SHA-256) digests do not establish correctness.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from verifier.interoperability import storage
from verifier.interoperability.catalog import (
    ComponentKind,
    ComponentLifecycle,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from verifier.interoperability.storage import (
    ComponentPackageError,
    ImplementationBinding,
    PackageArtifact,
    PackageDependency,
    StoredComponentPackage,
    load_component_package,
    save_component_package,
)


def sample_package() -> StoredComponentPackage:
    descriptor = InteroperabilityComponentDescriptor(
        component_id="component:ordering", label="Bounded ordering check",
        kind=ComponentKind.CHECKER, lifecycle=ComponentLifecycle.EXPERIMENTAL,
        implementation_ref="uninstalled_ordering:check",
        accepted_schema_ids=("ORDERING-1",), planning_surface_schema_ids=("VSTD-2",),
        mechanism_ids=("mechanism:ordering",),
        claim_boundary="Descriptor only; native results are not checked on import.",
    )
    return StoredComponentPackage(
        package_id="package:ordering", package_version="0.1.0", publisher="example",
        license="Apache-2.0", description="A benign ordering specimen, not qualification.",
        registry=InteroperabilityComponentRegistry("example-1", (descriptor,)),
        artifacts=(PackageArtifact("src/check.py", "text/x-python", b"raise RuntimeError('must not execute')\r\n"),),
        implementations=(ImplementationBinding(
            descriptor.component_id, descriptor.implementation_ref, ("src/check.py",), ("runtime:python",),
        ),),
        dependencies=(PackageDependency("runtime:python", "Python >=3.10"),),
    )


def test_exact_roundtrip_after_transport_and_without_source(tmp_path: Path) -> None:
    package = sample_package()
    source = tmp_path / "package.json"
    save_component_package(package, source)
    assert source.read_bytes() == package.canonical_json_bytes()
    destination = tmp_path / "transport" / "different-name"
    destination.parent.mkdir()
    source.rename(destination)
    loaded = load_component_package(destination, expected_digest=package.canonical_digest())
    assert loaded == package
    assert loaded.artifacts[0].content.endswith(b"\r\n")
    assert loaded.registry.canonical_digest() == package.registry.canonical_digest()
    assert loaded.registry.get("component:ordering").availability.value == "NOT_CHECKED"
    assert not (tmp_path / "src").exists()


def test_freezes_captured_bytes_not_live_source(tmp_path: Path) -> None:
    path = tmp_path / "source"
    path.write_bytes(b"first capture")
    artifact = PackageArtifact("source", "application/octet-stream", path.read_bytes())
    path.write_bytes(b"replacement")
    assert artifact.content == b"first capture"
    with pytest.raises(FrozenInstanceError):
        artifact.content = b"mutated"  # type: ignore[misc]
    with pytest.raises(ComponentPackageError):
        PackageArtifact("source", "application/octet-stream", bytearray(b"mutable"))  # type: ignore[arg-type]


def test_ordering_and_json_formatting_preserve_canonical_digest(tmp_path: Path) -> None:
    package = sample_package()
    artifacts = (*package.artifacts, PackageArtifact("LICENSE", "text/plain", b"specimen"))
    first = replace(package, artifacts=artifacts)
    second = replace(package, artifacts=tuple(reversed(artifacts)))
    assert first.canonical_json_bytes() == second.canonical_json_bytes()
    path = tmp_path / "pretty.json"
    path.write_text(json.dumps(first.to_dict(), indent=3, ensure_ascii=False), encoding="utf-8")
    assert load_component_package(path, expected_digest=first.canonical_digest()) == first


def test_host_independent_golden_canonical_identity() -> None:
    # The same literal fixture and digest run on every configured native host.
    # This is a serialization contract, not native-verifier equivalence.
    assert sample_package().canonical_digest() == (
        "87d2d2e61e1926e68ec2e3d4f99fdb48e23382eae1e039e70bc46500b2302f68"
    )


def test_binary_implementation_bytes_survive_without_decoding_or_execution(tmp_path: Path) -> None:
    package = sample_package()
    binary = replace(package.artifacts[0], content=bytes(range(256)), media_type="application/octet-stream")
    package = replace(package, artifacts=(binary,))
    path = tmp_path / "binary-component.json"
    save_component_package(package, path)
    assert load_component_package(path).artifacts[0].content == bytes(range(256))


def test_inspection_is_bounded_to_integrity_not_authorship_or_qualification() -> None:
    result = sample_package().inspect()
    assert result["integrity_result"] == "PASS"
    assert result["native_qualification"] == "NOT_ESTABLISHED"
    assert result["dependency_completeness"] == "NOT_ESTABLISHED"
    assert "content_base64" not in result["artifacts"][0]
    assert "unsigned declarations" in result["claim_boundary"]
    # Omission from this inspection view does not establish secrecy or non-inference.
    assert "does not establish non-inferability" in result["claim_boundary"]
    assert "does not establish confidentiality of awareness" in result["claim_boundary"]


@pytest.mark.parametrize("field", ["publisher", "license", "description", "package_version"])
def test_expected_coordinate_detects_changed_metadata(field: str, tmp_path: Path) -> None:
    package = sample_package()
    changed = replace(package, **{field: "changed"})
    path = tmp_path / "changed.json"
    save_component_package(changed, path)
    assert load_component_package(path) == changed  # Internal integrity cannot authenticate itself.
    with pytest.raises(ComponentPackageError, match="expected digest"):
        load_component_package(path, expected_digest=package.canonical_digest())


def test_dependency_and_implementation_bytes_are_inside_package_identity() -> None:
    package = sample_package()
    changed_dependency = replace(package.dependencies[0], requirement="Python ==3.12.10")
    changed_artifact = replace(package.artifacts[0], content=b"different implementation")
    assert replace(package, dependencies=(changed_dependency,)).canonical_digest() != package.canonical_digest()
    assert replace(package, artifacts=(changed_artifact,)).canonical_digest() != package.canonical_digest()


@pytest.mark.parametrize("path", [
    "../check.py", "/check.py", "src/../check.py", "src//check.py", "src/./check.py",
    "src\\check.py", "drive:check.py", "src/check.py.", "NUL", "con.txt", "src/LPT9.py",
    "src/COM1", "src/check.py ", "src/\x00check.py", "src/é.py", "a" * 241,
], ids=lambda value: "portable-case-" + str(len(value)))
def test_nonportable_artifact_names_are_rejected(path: str) -> None:
    with pytest.raises(ComponentPackageError):
        PackageArtifact(path, "application/octet-stream", b"content")


@pytest.mark.parametrize("path", ["SRC/second.py", "SRC/check.py", "src", "src/check.py/child"])
def test_inventory_rejects_directory_case_and_file_collisions(path: str) -> None:
    package = sample_package()
    with pytest.raises(ComponentPackageError):
        replace(package, artifacts=(*package.artifacts, PackageArtifact(path, "text/plain", b"other")))


@pytest.mark.parametrize("section", ["artifacts", "implementations", "dependencies"])
def test_duplicate_inventory_identifiers_rejected(section: str) -> None:
    package = sample_package()
    entries = getattr(package, section)
    with pytest.raises(ComponentPackageError, match="duplicate"):
        replace(package, **{section: (*entries, *entries)})


def test_every_component_requires_its_literal_entrypoint_and_retained_bytes() -> None:
    package = sample_package()
    with pytest.raises(ComponentPackageError):
        replace(package, implementations=())
    with pytest.raises(ComponentPackageError):
        replace(package, artifacts=())
    with pytest.raises(ComponentPackageError):
        replace(package, implementations=(replace(package.implementations[0], implementation_ref="other:check"),))
    with pytest.raises(ComponentPackageError):
        replace(package.implementations[0], artifact_paths=())
    with pytest.raises(ComponentPackageError):
        replace(package, implementations=(replace(package.implementations[0], component_id="unlisted"),))


def test_dependency_and_artifact_references_must_exist() -> None:
    package = sample_package()
    with pytest.raises(ComponentPackageError):
        replace(package, dependencies=())
    with pytest.raises(ComponentPackageError):
        replace(package, dependencies=(replace(package.dependencies[0], artifact_paths=("absent.lock",)),))
    with pytest.raises(ComponentPackageError):
        replace(package, implementations=(replace(package.implementations[0], artifact_paths=("absent.py",)),))


@pytest.mark.parametrize("section", [None, "registry", "artifacts", "implementations", "dependencies"])
def test_unknown_nested_fields_rejected(section: str | None) -> None:
    value = sample_package().to_dict()
    target = value if section is None else value[section]
    if isinstance(target, list):
        target = target[0]
    target["silently_execute"] = True
    with pytest.raises(ComponentPackageError):
        StoredComponentPackage.from_dict(value)


@pytest.mark.parametrize("section", ["schema_version", "registry", "registry_sha256", "artifacts", "implementations", "dependencies"])
def test_missing_fields_rejected(section: str) -> None:
    value = sample_package().to_dict()
    del value[section]
    with pytest.raises(ComponentPackageError):
        StoredComponentPackage.from_dict(value)


def test_no_implicit_catalog_migration_or_array_normalization() -> None:
    value = sample_package().to_dict()
    value["registry"]["schema_version"] = "VSTD-INTEROPERABILITY-CATALOG-1.0"
    with pytest.raises(ComponentPackageError, match="no migration"):
        StoredComponentPackage.from_dict(value)
    value = sample_package().to_dict()
    value["registry"]["components"][0]["planning_surface_schema_ids"] = []
    with pytest.raises(ComponentPackageError, match="canonical"):
        StoredComponentPackage.from_dict(value)
    value = sample_package().to_dict()
    value["registry"]["components"][0]["label"] = "changed"
    with pytest.raises(ComponentPackageError, match="registry digest"):
        StoredComponentPackage.from_dict(value)


@pytest.mark.parametrize(("field", "changed"), [
    ("size_bytes", True), ("size_bytes", -1), ("size_bytes", 1.0),
    ("sha256", "0" * 64), ("content_base64", "%%%="), ("content_base64", "AAAA"),
])
def test_artifact_tampering_rejected(field: str, changed: object) -> None:
    value = sample_package().to_dict()
    value["artifacts"][0][field] = changed
    with pytest.raises(ComponentPackageError):
        StoredComponentPackage.from_dict(value)


def test_noncanonical_base64_pad_bits_rejected() -> None:
    value = PackageArtifact("one", "application/octet-stream", b"\0").to_dict()
    value["content_base64"] = "AB=="
    with pytest.raises(ComponentPackageError, match="pad bits"):
        PackageArtifact.from_dict(value)


@pytest.mark.parametrize("content", [
    b'{"schema_version":"first","schema_version":"second"}',
    b'{"nested":{"a":1,"a":2}}', b'{"a":NaN}', b'{"a":Infinity}',
    b"\xff", b"{} {}", b"[]", b"null", b"[" * 3000,
])
def test_malformed_or_ambiguous_transport_rejected(content: bytes, tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(content)
    with pytest.raises(ComponentPackageError):
        load_component_package(path)


def test_unknown_package_schema_fails_closed() -> None:
    value = sample_package().to_dict()
    value["schema_version"] = "VSTD-COMPONENT-PACKAGE-2"
    with pytest.raises(ComponentPackageError, match="schema_version"):
        StoredComponentPackage.from_dict(value)


@pytest.mark.parametrize(("field", "value"), [
    ("registry_version", "external\x1b[31mregistry"),
    ("label", "unsafe\x1b[31mlabel"),
    ("registry_version", "external\x9b31mregistry"),
    ("claim_boundary", "x" * 4097),
    ("mechanism_ids", tuple(f"mechanism:{index:03d}" for index in range(257))),
    ("label", "unpaired\ud800surrogate"),
])
def test_embedded_registry_cannot_bypass_transport_bounds(field: str, value: object) -> None:
    package = sample_package()
    if field == "registry_version":
        registry = replace(package.registry, registry_version=value)
    else:
        descriptor = replace(package.registry.components[0], **{field: value})
        registry = replace(package.registry, components=(descriptor,))
    with pytest.raises(ComponentPackageError):
        replace(package, registry=registry)
    document = package.to_dict()
    document["registry"] = registry.to_dict()
    document["registry_sha256"] = registry.canonical_digest()
    with pytest.raises(ComponentPackageError):
        StoredComponentPackage.from_dict(document)


def test_resource_bounds_apply_on_constructor_and_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = sample_package()
    path = tmp_path / "package.json"
    save_component_package(package, path)
    monkeypatch.setattr(storage, "MAX_PACKAGE_BYTES", 16)
    with pytest.raises(ComponentPackageError, match="input byte bound"):
        load_component_package(path)
    with pytest.raises(ComponentPackageError, match="storage bound"):
        replace(package, package_version="different")
    monkeypatch.setattr(storage, "MAX_CONTENT_BYTES", 2)
    with pytest.raises(ComponentPackageError):
        PackageArtifact("large", "application/octet-stream", b"123")
    with pytest.raises(ComponentPackageError, match="total retained"):
        replace(package, package_version="different")


def test_save_never_overwrites_existing_bytes(tmp_path: Path) -> None:
    path = tmp_path / "existing"
    path.write_bytes(b"preserve user work")
    with pytest.raises(ComponentPackageError):
        save_component_package(sample_package(), path)
    assert path.read_bytes() == b"preserve user work"


def test_missing_source_and_invalid_expected_digest_fail(tmp_path: Path) -> None:
    with pytest.raises(ComponentPackageError):
        load_component_package(tmp_path / "missing")
    with pytest.raises(ComponentPackageError, match="lowercase"):
        load_component_package(tmp_path / "missing", expected_digest="ABC")


@pytest.mark.parametrize("mode", [stat.S_IFIFO, stat.S_IFCHR, stat.S_IFDIR, stat.S_IFSOCK, stat.S_IFLNK])
def test_nonregular_source_rejected_before_open(mode: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "lstat", lambda _: SimpleNamespace(st_mode=mode))
    def must_not_open(*args: object, **kwargs: object) -> None:
        pytest.fail("nonregular source reached open")
    monkeypatch.setattr(os, "open", must_not_open)
    with pytest.raises(ComponentPackageError, match="ordinary non-link file"):
        load_component_package(tmp_path / "not-regular")


def test_changed_source_identity_rejected_on_opened_handle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = sample_package()
    path = tmp_path / "package.json"
    save_component_package(package, path)
    original = os.fstat
    def changed(fd: int) -> SimpleNamespace:
        metadata = original(fd)
        return SimpleNamespace(st_mode=metadata.st_mode, st_dev=metadata.st_dev, st_ino=metadata.st_ino + 1)
    monkeypatch.setattr(os, "fstat", changed)
    with pytest.raises(ComponentPackageError, match="source changed"):
        load_component_package(path)


def test_windows_reparse_source_rejected_before_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "lstat", lambda _: SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400))
    with pytest.raises(ComponentPackageError, match="ordinary non-link file"):
        load_component_package(tmp_path / "reparse")
