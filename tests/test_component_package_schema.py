"""Bounded shape and runtime checks for experimental stored component packages.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD).
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

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
)
from verifier.interoperability.reference_catalog import reference_component_registry


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "standard" / "schemas" / "vstd-component-package-1.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


def _package() -> StoredComponentPackage:
    components = tuple(
        InteroperabilityComponentDescriptor(
            component_id=f"component:fixture-{name}", label=f"Fixture {name}",
            kind=ComponentKind.CHECKER, lifecycle=ComponentLifecycle.EXPERIMENTAL,
            implementation_ref="specimen:check", accepted_schema_ids=(),
            planning_surface_schema_ids=("VSTD-2",),
            mechanism_ids=("mechanism:fixture-equality",),
            claim_boundary="Schema fixture only; implementation reachability is not checked.",
        )
        for name in ("one", "two")
    )
    return StoredComponentPackage(
        package_id="package:schema-fixture", package_version="1",
        publisher="Unsigned fixture publisher", license="MIT",
        description="A nonexecuting fixture for stored-package shape checks.",
        registry=InteroperabilityComponentRegistry("fixture-1", components),
        artifacts=(PackageArtifact("source/check.py", "text/x-python", b"f"),),
        implementations=tuple(
            ImplementationBinding(
                component.component_id, component.implementation_ref,
                ("source/check.py",), ("dependency:fixture",),
            )
            for component in components
        ),
        dependencies=(PackageDependency("dependency:fixture", "fixture-support==1"),),
    )


def _node(document: dict[str, Any], path: tuple[str | int, ...]) -> Any:
    value: Any = document
    for key in path:
        value = value[key]
    return value


def test_package_schema_is_self_contained_and_accepts_canonical_runtime_output() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$id"] == (
        "https://timelordraps.github.io/verifier/schemas/" + SCHEMA_PATH.name
    )
    pending: list[Any] = [SCHEMA]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "$ref" in value:
                assert value["$ref"].startswith("#/$defs/")
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    package = _package()
    VALIDATOR.validate(package.to_dict())
    assert StoredComponentPackage.from_dict(package.to_dict()) == package


def test_package_schema_covers_every_reference_catalog_descriptor() -> None:
    registry = reference_component_registry()
    package = replace(
        _package(), registry=registry,
        implementations=tuple(
            ImplementationBinding(
                component.component_id, component.implementation_ref, ("source/check.py",)
            )
            for component in registry.components
        ),
    )
    # These bytes are a shape fixture, not implementations of the named entry points.
    VALIDATOR.validate(package.to_dict())
    assert StoredComponentPackage.from_dict(package.to_dict()) == package


@pytest.mark.parametrize(
    "path",
    (
        (), ("registry",), ("registry", "components", 0),
        ("artifacts", 0), ("implementations", 0), ("dependencies", 0),
    ),
    ids=("package", "registry", "descriptor", "artifact", "implementation", "dependency"),
)
@pytest.mark.parametrize("fault", ("extra", "missing"))
def test_package_schema_requires_exact_nested_keys(
    path: tuple[str | int, ...], fault: str
) -> None:
    document = _package().to_dict()
    value = _node(document, path)
    if fault == "extra":
        value["unexpected"] = True
    else:
        value.pop(next(iter(value)))
    assert not VALIDATOR.is_valid(document)
    with pytest.raises(ComponentPackageError):
        StoredComponentPackage.from_dict(document)


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("schema_version",), "VSTD-1"),
        (("schema_version",), "VSTD-COMPONENT-PACKAGE-2"),
        (("registry", "schema_version"), "VSTD-INTEROPERABILITY-CATALOG-1.0"),
        (("registry", "components", 0, "kind"), "NATIVE_MAGIC"),
        (("registry", "components", 0, "lifecycle"), "RELEASED"),
        (("registry", "components", 0, "availability"), "VERIFIED"),
        (("registry", "components", 0, "interaction_modes"), ["UNKNOWN"]),
        (("registry", "components", 0, "planning_surface_schema_ids"), []),
        (("registry", "components", 0, "mechanism_ids"), []),
        (("artifacts", 0, "size_bytes"), True),
        (("artifacts", 0, "content_base64"), "***="),
        (("artifacts", 0, "path"), "../outside.py"),
        (("artifacts", 0, "path"), "source/CON.txt"),
        (("registry_sha256",), "A" * 64),
        (("package_id",), "fixture\n"),
        (("registry", "components", 0, "label"), "fixture\n"),
        (("artifacts", 0, "path"), "source/check.py\n"),
        (("artifacts", 0, "content_base64"), "Zg==\n"),
    ),
    ids=("receipt-route", "future-route", "legacy-catalog", "kind", "lifecycle",
         "availability", "interaction", "no-planning-schema", "no-mechanism",
         "boolean-size", "base64-alphabet", "parent-path", "reserved-path", "digest-case",
         "package-whitespace", "descriptor-whitespace", "path-whitespace", "base64-whitespace"),
)
def test_package_schema_rejects_wrong_routes_enums_and_shapes(
    path: tuple[str | int, ...], value: Any
) -> None:
    document = _package().to_dict()
    _node(document, path[:-1])[path[-1]] = value
    assert not VALIDATOR.is_valid(document)
    with pytest.raises(ComponentPackageError):
        StoredComponentPackage.from_dict(document)


@pytest.mark.parametrize(
    "fault",
    (
        "artifact_digest", "registry_digest", "decoded_size", "base64_pad_bits",
        "missing_artifact", "missing_dependency", "missing_implementation",
        "wrong_implementation_ref", "case_collision", "file_directory_conflict",
        "registry_order", "descriptor_order",
    ),
)
def test_shape_valid_packages_still_require_runtime_mechanism_checks(fault: str) -> None:
    document = _package().to_dict()
    if fault == "artifact_digest":
        document["artifacts"][0]["sha256"] = "0" * 64
    elif fault == "registry_digest":
        document["registry_sha256"] = "0" * 64
    elif fault == "decoded_size":
        document["artifacts"][0]["size_bytes"] = 2
    elif fault == "base64_pad_bits":
        document["artifacts"][0]["content_base64"] = "Zh=="
    elif fault == "missing_artifact":
        document["implementations"][0]["artifact_paths"] = ["source/absent.py"]
    elif fault == "missing_dependency":
        document["implementations"][0]["dependency_ids"] = ["dependency:absent"]
    elif fault == "missing_implementation":
        document["implementations"].pop()
    elif fault == "wrong_implementation_ref":
        document["implementations"][0]["implementation_ref"] = "other:check"
    elif fault in {"case_collision", "file_directory_conflict"}:
        artifact = deepcopy(document["artifacts"][0])
        artifact["path"] = "Source/check.py" if fault == "case_collision" else "source"
        document["artifacts"].append(artifact)
    elif fault == "registry_order":
        document["registry"]["components"].reverse()
    else:
        document["registry"]["components"][0]["domain_tags"] = ["z", "a"]
    VALIDATOR.validate(document)
    with pytest.raises(ComponentPackageError):
        StoredComponentPackage.from_dict(document)


def test_package_schema_rejects_catalog_migration_and_inspection_output() -> None:
    package = _package()
    document = package.to_dict()
    del document["registry"]["components"][0]["planning_surface_schema_ids"]
    assert not VALIDATOR.is_valid(document)
    with pytest.raises(ComponentPackageError):
        StoredComponentPackage.from_dict(document)
    assert not VALIDATOR.is_valid(package.inspect())


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("registry_version",), "fixture" + chr(27) + "version"),
        (("components", 0, "label"), "fixture" + chr(27) + "label"),
        (("components", 0, "claim_boundary"), "x" * 4097),
        (("components", 0, "mechanism_ids"), [f"mechanism:{index:03}" for index in range(257)]),
        (("components", 0, "native_system"), "fixture" + chr(0xD800)),
        (("components", 0, "claim_boundary"), " surrounding whitespace "),
    ),
    ids=("registry-control", "label-control", "scalar-bound", "array-bound",
         "surrogate", "optional-text-whitespace"),
)
def test_embedded_catalog_bounds_apply_before_digest_or_catalog_migration(
    path: tuple[str | int, ...], value: Any
) -> None:
    document = _package().to_dict()
    registry = document["registry"]
    _node(registry, path[:-1])[path[-1]] = value
    document["registry_sha256"] = hashlib.sha256(
        json.dumps(registry, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False).encode("utf-8")
    ).hexdigest()
    assert not VALIDATOR.is_valid(document)
    with pytest.raises(ComponentPackageError):
        StoredComponentPackage.from_dict(document)


def test_embedded_catalog_accepts_exact_bounds_and_permitted_empty_strings() -> None:
    package = _package()
    first = replace(
        package.registry.components[0], claim_boundary="x" * 4096,
        mechanism_ids=tuple(f"mechanism:{index:03}" for index in range(256)),
    )
    registry = replace(package.registry, components=(first, package.registry.components[1]))
    package = replace(package, registry=registry)
    assert first.native_system == ""
    VALIDATOR.validate(package.to_dict())
    assert StoredComponentPackage.from_dict(package.to_dict()) == package
