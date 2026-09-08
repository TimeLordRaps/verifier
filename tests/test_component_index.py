"""Adversarial checks for the experimental stored component index.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD).
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import verifier.interoperability.component_index as component_index_module
from verifier.interoperability.catalog import (
    ComponentKind,
    ComponentLifecycle,
    InteractionMode,
    InteroperabilityComponentDescriptor,
    InteroperabilityComponentRegistry,
)
from verifier.interoperability.component_index import (
    COMPONENT_INDEX_SCHEMA_VERSION,
    ComponentIndexError,
    IndexedComponentPackage,
    StoredComponentIndex,
    load_component_index,
    save_component_index,
)
from verifier.interoperability.storage import (
    ImplementationBinding,
    PackageArtifact,
    StoredComponentPackage,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "standard" / "schemas" / "vstd-component-index-1.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


def _package(package_id: str = "package:fixture", version: str = "1") -> StoredComponentPackage:
    descriptor = InteroperabilityComponentDescriptor(
        component_id=f"component:{package_id}",
        label="Fixture checker",
        kind=ComponentKind.CHECKER,
        lifecycle=ComponentLifecycle.EXPERIMENTAL,
        implementation_ref="fixture:check",
        accepted_schema_ids=(),
        planning_surface_schema_ids=("VSTD-FIXTURE-1",),
        supported_relations=("relation:equal",),
        mechanism_ids=("mechanism:fixture",),
        interaction_modes=(InteractionMode.STATIC,),
        domain_tags=("discovery-only",),
        claim_boundary="Fixture declaration only; native correctness is not established.",
    )
    registry = InteroperabilityComponentRegistry(
        f"registry:{package_id}:{version}", (descriptor,)
    )
    return StoredComponentPackage(
        package_id=package_id,
        package_version=version,
        publisher="Unsigned fixture publisher",
        license="Apache-2.0",
        description="Nonexecuting index fixture.",
        registry=registry,
        artifacts=(PackageArtifact("source/check.py", "text/x-python", b"raise SystemExit"),),
        implementations=(
            ImplementationBinding(descriptor.component_id, descriptor.implementation_ref, ("source/check.py",)),
        ),
    )


def _index() -> StoredComponentIndex:
    return StoredComponentIndex(
        "index:fixture", "1", "A bounded static discovery fixture.",
        (IndexedComponentPackage.from_package(_package()),),
    )


def test_index_schema_and_runtime_roundtrip_are_canonical_and_deterministic(tmp_path: Path) -> None:
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$id"] == "https://timelordraps.github.io/verifier/schemas/" + SCHEMA_PATH.name
    index = _index()
    VALIDATOR.validate(index.to_dict())
    assert StoredComponentIndex.from_dict(index.to_dict()) == index
    destination = tmp_path / "index.json"
    save_component_index(index, destination)
    assert destination.read_bytes() == index.canonical_json_bytes()
    assert load_component_index(destination, expected_digest=index.canonical_digest()) == index
    assert b"\n" not in index.canonical_json_bytes()


def test_index_sorts_packages_and_rejects_noncanonical_wire_order() -> None:
    second = IndexedComponentPackage.from_package(_package("package:a", "2"))
    first = IndexedComponentPackage.from_package(_package("package:a", "1"))
    index = StoredComponentIndex("index:x", "1", "Fixture.", (second, first))
    assert [(item.package_id, item.package_version) for item in index.packages] == [
        ("package:a", "1"), ("package:a", "2")
    ]
    document = index.to_dict()
    document["packages"].reverse()
    VALIDATOR.validate(document)
    with pytest.raises(ComponentIndexError, match="canonical record order"):
        StoredComponentIndex.from_dict(document)


@pytest.mark.parametrize("collision", ("coordinate", "digest", "path"))
def test_index_rejects_ambiguous_package_identities(collision: str) -> None:
    first = IndexedComponentPackage.from_package(_package("package:a", "1"))
    other = IndexedComponentPackage.from_package(_package("package:b", "1"))
    if collision == "coordinate":
        other = replace(other, package_id=first.package_id, package_version=first.package_version)
    elif collision == "digest":
        other = replace(
            other,
            package_sha256=first.package_sha256,
            package_path=first.package_path,
        )
    else:
        object.__setattr__(other, "package_path", first.package_path)
    with pytest.raises(ComponentIndexError, match="duplicate"):
        StoredComponentIndex("index:x", "1", "Fixture.", (first, other))


def test_content_addressed_path_and_registry_digest_fail_closed() -> None:
    entry = IndexedComponentPackage.from_package(_package())
    with pytest.raises(ComponentIndexError, match="content-addressed"):
        replace(entry, package_path="packages/latest.json")
    with pytest.raises(ComponentIndexError, match="registry digest"):
        replace(entry, registry_sha256="0" * 64)


def test_validate_package_binds_every_indexed_declaration() -> None:
    package = _package()
    entry = IndexedComponentPackage.from_package(package)
    assert entry.validate_package(package) == package.canonical_digest()
    changed = replace(package, description="Different unsigned description.")
    with pytest.raises(ComponentIndexError, match="does not match"):
        entry.validate_package(changed)


def test_from_package_revalidates_supplied_package_state() -> None:
    package = _package()
    object.__setattr__(package, "publisher", "unsafe\nvalue")
    with pytest.raises(ComponentIndexError, match="not a valid stored component package"):
        IndexedComponentPackage.from_package(package)


def test_inspection_preserves_claim_boundaries() -> None:
    result = _index().inspect()
    assert result["integrity_result"] == "PASS"
    assert result["package_availability"] == "NOT_CHECKED"
    assert result["native_qualification"] == "NOT_ESTABLISHED"
    assert result["ecosystem_completeness"] == "UNKNOWN"
    assert result["execution_performed"] is False
    assert "Zero matches do not establish ecosystem absence" in result["claim_boundary"]


def test_exact_search_binds_query_package_registry_and_component() -> None:
    index = _index()
    result = index.search_exact(
        schema_id="VSTD-FIXTURE-1",
        interaction_mode=InteractionMode.STATIC,
        relation_id="relation:equal",
        mechanism_id="mechanism:fixture",
    )
    entry = index.packages[0]
    assert result["result"] == "DECLARED_MATCHES"
    assert result["match_count"] == 1
    assert result["index_digest"] == index.canonical_digest()
    assert result["matches"][0]["package_sha256"] == entry.package_sha256
    assert result["matches"][0]["registry_sha256"] == entry.registry_sha256
    assert result["matches"][0]["component"] == entry.registry.components[0].to_dict()
    assert result["package_availability"] == "NOT_CHECKED"
    assert result["native_qualification"] == "NOT_ESTABLISHED"
    assert result["execution_performed"] is False


def test_search_requires_semantic_coordinate_and_never_uses_domain_tags() -> None:
    index = _index()
    with pytest.raises(ComponentIndexError, match="requires relation_id or mechanism_id"):
        index.search_exact(schema_id="VSTD-FIXTURE-1", interaction_mode=InteractionMode.STATIC)
    result = index.search_exact(
        schema_id="VSTD-FIXTURE-1",
        interaction_mode=InteractionMode.STATIC,
        mechanism_id="discovery-only",
    )
    assert result["result"] == "NO_DECLARED_MATCH_IN_THIS_INDEX"
    assert result["match_count"] == 0
    assert result["ecosystem_completeness"] == "UNKNOWN"
    assert "Zero matches do not establish ecosystem absence" in result["claim_boundary"]


def test_package_filters_are_exact_and_do_not_imply_ecosystem_absence() -> None:
    result = _index().search_exact(
        schema_id="VSTD-FIXTURE-1",
        interaction_mode=InteractionMode.STATIC,
        mechanism_id="mechanism:fixture",
        package_id="package:absent",
    )
    assert result["result"] == "NO_DECLARED_MATCH_IN_THIS_INDEX"
    assert result["query"]["package_id"] == "package:absent"
    assert result["ecosystem_completeness"] == "UNKNOWN"


@pytest.mark.parametrize(
    "content",
    (
        b'{"schema_version":"first","schema_version":"second"}',
        b'{"nested":{"a":1,"a":2}}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"\xff",
        b"{} {}",
        b"[]",
        b"null",
        b"[" * 3000,
    ),
)
def test_malformed_or_ambiguous_transport_rejected(content: bytes, tmp_path: Path) -> None:
    source = tmp_path / "invalid.json"
    source.write_bytes(content)
    with pytest.raises(ComponentIndexError):
        load_component_index(source)


@pytest.mark.parametrize("fault", ("extra", "missing", "route", "registry_order", "path_digest"))
def test_schema_valid_documents_still_require_runtime_mechanisms(fault: str) -> None:
    document = _index().to_dict()
    if fault == "extra":
        document["packages"][0]["unexpected"] = True
        assert not VALIDATOR.is_valid(document)
    elif fault == "missing":
        del document["packages"][0]["publisher"]
        assert not VALIDATOR.is_valid(document)
    elif fault == "route":
        document["schema_version"] = "VSTD-COMPONENT-INDEX-2"
        assert not VALIDATOR.is_valid(document)
    elif fault == "registry_order":
        descriptor = document["packages"][0]["registry"]["components"][0]
        descriptor["domain_tags"] = ["z", "a"]
        document["packages"][0]["registry_sha256"] = "0" * 64
        assert VALIDATOR.is_valid(document)
    else:
        document["packages"][0]["package_path"] = "packages/sha256/" + "0" * 64 + ".json"
        assert VALIDATOR.is_valid(document)
    with pytest.raises(ComponentIndexError):
        StoredComponentIndex.from_dict(document)


def test_expected_digest_and_save_overwrite_fail_closed(tmp_path: Path) -> None:
    index = _index()
    path = tmp_path / "index.json"
    save_component_index(index, path)
    with pytest.raises(ComponentIndexError, match="expected_digest"):
        load_component_index(path, expected_digest="ABC")
    with pytest.raises(ComponentIndexError, match="expected digest"):
        load_component_index(path, expected_digest="0" * 64)
    with pytest.raises(ComponentIndexError, match="without overwriting"):
        save_component_index(index, path)
    assert path.read_bytes() == index.canonical_json_bytes()


def test_save_requests_owner_only_initial_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    requested_modes: list[int] = []
    actual_open = component_index_module.os.open

    def observed_open(path: object, flags: int, mode: int) -> int:
        requested_modes.append(mode)
        return actual_open(path, flags, mode)

    monkeypatch.setattr(component_index_module.os, "open", observed_open)
    save_component_index(_index(), tmp_path / "index.json")
    assert requested_modes == [0o600]


def test_index_loader_never_reads_or_executes_package_path(tmp_path: Path) -> None:
    index = _index()
    path = tmp_path / "index.json"
    save_component_index(index, path)
    loaded = load_component_index(path)
    assert loaded.packages[0].package_path.startswith("packages/sha256/")
    assert not (tmp_path / loaded.packages[0].package_path).exists()
    result = loaded.search_exact(
        schema_id="VSTD-FIXTURE-1",
        interaction_mode=InteractionMode.STATIC,
        mechanism_id="mechanism:fixture",
    )
    assert result["match_count"] == 1
    assert result["package_availability"] == "NOT_CHECKED"


def test_schema_identifier_and_package_format_remain_separate() -> None:
    assert COMPONENT_INDEX_SCHEMA_VERSION == "VSTD-COMPONENT-INDEX-1"
    assert COMPONENT_INDEX_SCHEMA_VERSION != "VSTD-COMPONENT-PACKAGE-1"
