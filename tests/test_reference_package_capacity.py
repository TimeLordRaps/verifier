"""Verifier Standard (VSTD) reference-source packing preserves every selected byte.

Terminology: JavaScript Object Notation (JSON); ZIP archive format (ZIP).
Packing is nonexecuting storage, not dependency completeness or qualification.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import zipfile

import pytest
from examples.stored_components import build_reference_package


ROOT = Path(__file__).resolve().parents[1]
FIXED = {"pyproject.toml", "LICENSE", "NOTICE", "README.md"}
HARDWARE = "src/verifier/domains/hardware.py"
ENTRYPOINT = "src/verifier/interoperability/selected.py"


def _exporter() -> ModuleType:
    return build_reference_package


def _capture() -> tuple[dict[str, bytes], SimpleNamespace, set[str], set[str]]:
    captured = {name: name.encode("ascii") for name in FIXED}
    contracts = {f"src/verifier/standard/CONTRACT_{index:03}.md" for index in range(220)}
    unrelated = {f"src/verifier/domains/contracts/helper_{index:03}.py" for index in range(40)}
    native_domains = {f"src/verifier/domains/adapter_{index:03}.py" for index in range(3)}
    captured.update({name: name.encode("ascii") for name in contracts | unrelated | native_domains})
    captured[HARDWARE] = b"# Retained reviewed hardware source.\n"
    captured[ENTRYPOINT] = b"# Declared entrypoint; never executed.\n"
    registry = SimpleNamespace(components=(SimpleNamespace(
        implementation_ref="verifier.interoperability.selected:check",
        verifier_family_ids=("selected-fixture",),
    ),))
    return captured, registry, FIXED | contracts | native_domains | {HARDWARE, ENTRYPOINT}, unrelated


def test_all_native_domains_stay_direct_and_nested_helpers_may_be_archived() -> None:
    exporter = _exporter()
    captured, registry, required, unrelated = _capture()

    direct = exporter._direct_source_paths(captured, registry)

    assert len(captured) > exporter.MAX_PACKAGE_ITEMS
    assert direct == required
    assert len(direct) + 1 <= exporter.MAX_PACKAGE_V2_ARTIFACTS
    assert direct.isdisjoint(unrelated)


def test_archived_domain_remainder_and_full_inventory_are_exact() -> None:
    exporter = _exporter()
    captured, registry, required, unrelated = _capture()
    direct = exporter._direct_source_paths(captured, registry)
    archive_bytes = exporter._source_archive(captured, set(captured) - direct)

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        assert archive.namelist() == ["source-inventory.json", *sorted(unrelated)]
        inventory = json.loads(archive.read("source-inventory.json"))
        assert {row["path"] for row in inventory["files"]} == set(captured)
        for row in inventory["files"]:
            name = row["path"]
            assert row["location"] == ("DIRECT" if name in required else "ARCHIVE")
            retained = captured[name] if row["location"] == "DIRECT" else archive.read(name)
            assert retained == captured[name]
            assert row["size_bytes"] == len(retained)
            assert row["sha256"] == exporter.hashlib.sha256(retained).hexdigest()


def test_missing_declared_entrypoint_is_refused() -> None:
    exporter = _exporter()
    captured, registry, _required, _unrelated = _capture()
    del captured[ENTRYPOINT]

    with pytest.raises(ValueError, match="no retained implementation module"):
        exporter._direct_source_paths(captured, registry)


@pytest.mark.parametrize("version,maximum", [("verifier-component-package-1",256), ("verifier-component-package-2",512)])
def test_mandatory_contract_overflow_still_refuses(monkeypatch: pytest.MonkeyPatch, version: str, maximum: int) -> None:
    exporter = _exporter()
    captured, registry, _required, _unrelated = _capture()
    captured.update({f"src/verifier/standard/EXTRA_{index:03}.md": b"required contract"
                     for index in range(maximum)})
    for module in (exporter.catalog_module, exporter.reference_module):
        name = "src/" + module.__name__.replace(".", "/") + ".py"
        captured[name] = Path(module.__file__).read_bytes()
    monkeypatch.setattr(exporter, "_capture_snapshot", lambda _root, _untracked: (captured, "0" * 40, True))
    monkeypatch.setattr(exporter.reference_module, "reference_component_registry", lambda: registry)

    with pytest.raises(ValueError, match="direct contract and implementation artifacts exceed"):
        exporter.build_package(ROOT, "capacity-fixture", package_schema_version=version)


@pytest.mark.parametrize("count", [257,512])
def test_v2_all_direct_inventory_above_v1_limit_needs_no_archive(monkeypatch: pytest.MonkeyPatch, count: int) -> None:
    from dataclasses import replace

    exporter = _exporter()
    registry = exporter.reference_module.reference_component_registry()
    template = registry.components[0]
    components = tuple(replace(template, component_id="fixture:"+str(index),
        implementation_ref=module.__name__+":retained_only")
        for index,module in enumerate((exporter.catalog_module,exporter.reference_module)))
    registry = replace(registry,components=components)
    captured = {name:b"fixture metadata" for name in FIXED}
    for module in (exporter.catalog_module,exporter.reference_module):
        captured["src/"+module.__name__.replace(".","/")+".py"] = Path(module.__file__).read_bytes()
    captured.update({f"src/verifier/standard/BOUND_{index:03}.md":b"mandatory"
                     for index in range(count-len(captured))})
    assert exporter._direct_source_paths(captured,registry) == set(captured)
    monkeypatch.setattr(exporter,"_capture_snapshot",lambda _root,_untracked:(captured,"0"*40,True))
    monkeypatch.setattr(exporter.reference_module,"reference_component_registry",lambda:registry)
    package = exporter.build_package(ROOT,"all-direct-boundary")
    assert package.schema_version == "verifier-component-package-2"
    assert {artifact.path:artifact.content for artifact in package.artifacts} == captured
    assert exporter.SOURCE_ARCHIVE_PATH not in {artifact.path for artifact in package.artifacts}
