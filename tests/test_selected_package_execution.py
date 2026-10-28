"""Stored-source selected execution for Verifier Standard (VSTD).

Byte correspondence to a host builtin does not qualify a package or publisher.
"""

from __future__ import annotations

from pathlib import Path
from copy import deepcopy
from dataclasses import replace
import hashlib
import sys

import pytest

from verifier.core import evidence as evidence_module
from verifier.core.evidence import BytesDigestMechanism, EvidenceBounds, EvidenceStore
from verifier.interoperability.control_surface import analyze_verification_surface, plan_validation
from verifier.interoperability.selected_execution import (
    DigestHostPolicy, SelectedExecutionError, execute_selected_validation, prepare_digest_validation,
    replay_selected_validation,
)
from verifier.interoperability.storage import (
    ImplementationBinding, PackageArtifact, PackageDependency, StoredComponentPackage,
    load_component_package, save_component_package,
)
from verifier.runtime import package_execution
from test_selected_execution import EXPECTED, PAYLOAD, request_for, specimen


SOURCE_PATH = "src/verifier/core/evidence.py"


def test_package_obligation_annotation_preserves_exception_identity() -> None:
    error = ValueError("protocol-visible")
    selected = package_execution._obligation(
        error, "UNKNOWN", "PACKAGE_EXECUTION_FIXTURE_UNKNOWN"
    )
    assert selected is error
    assert error.vstd_obligation == (
        "UNKNOWN",
        "PACKAGE_EXECUTION_FIXTURE_UNKNOWN",
    )
    assert package_execution._obligation_result(error, "FAIL") == (
        "UNKNOWN",
        "PACKAGE_EXECUTION_FIXTURE_UNKNOWN",
    )


def package_specimen() -> StoredComponentPackage:
    _, registry = specimen()
    return StoredComponentPackage(
        "selected-digest-source", "1", "test publisher declaration", "test license declaration",
        "One retained source correspondence specimen, not a runtime qualification.", registry,
        (PackageArtifact(SOURCE_PATH, "text/x-python", Path(evidence_module.__file__).read_bytes()),
         PackageArtifact("notes.txt", "text/plain", b"Unselected retained artifact.")),
        (ImplementationBinding("builtin-digest", "verifier.core.evidence:BytesDigestMechanism", (SOURCE_PATH,)),),
    )


def request_for_package(package: StoredComponentPackage) -> tuple[dict, EvidenceStore]:
    geometry, _ = specimen()
    store = EvidenceStore()
    reference = store.add(PAYLOAD)
    plan = plan_validation(analyze_verification_surface(geometry), package.registry, package=package)
    request = prepare_digest_validation(
        geometry, package.registry, plan, coordinate_id="digest", expected_digest=EXPECTED,
        evidence_ref=reference, bounds=EvidenceBounds(1, 100), package=package,
    )
    return request, store


def test_saved_loaded_package_executes_and_replays_without_loading_its_code(tmp_path: Path) -> None:
    package = package_specimen()
    location = tmp_path / "component.json"
    save_component_package(package, location)
    loaded = load_component_package(location)
    request, store = request_for_package(loaded)
    policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    record = execute_selected_validation(request, store, policy=policy)
    assert record["schema_version"] == "verifier-selected-digest-execution-2"
    assert request["package"] == loaded.to_dict()
    assert request["plan"]["package_digest"] == loaded.canonical_digest()
    assert request["plan"]["binding_scope"] == "STORED_PACKAGE"
    assert record["evaluation"]["outcome"] == "PASS"
    assert record["updated_geometry"]["judgments"][1]["status"] == "UNSUPPORTED"
    assert replay_selected_validation(record, policy=policy) == record


def rebind_request(request: dict, package: StoredComponentPackage) -> dict:
    """Adversarially rebuild public identities without asking the executor to prepare."""
    changed = deepcopy(request)
    geometry, _ = specimen()
    changed["package"] = package.to_dict()
    changed["registry"] = package.registry.to_dict()
    changed["plan"] = plan_validation(analyze_verification_surface(geometry), package.registry, package=package).to_dict()
    return changed


@pytest.mark.parametrize("update_proposition", [False, True])
def test_substituted_retained_source_cannot_be_approved_after_rehash_and_replan(update_proposition: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    package = package_specimen()
    request, store = request_for_package(package)
    policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    changed_source = b"raise RuntimeError('never execute this package source')\n"
    changed_package = replace(package, artifacts=tuple(
        replace(item, content=changed_source) if item.path == SOURCE_PATH else item
        for item in package.artifacts
    ))
    changed = rebind_request(request, changed_package)
    if update_proposition:
        changed["proposition"]["mechanism_digest"] = "sha256:" + hashlib.sha256(changed_source).hexdigest()
    def forbidden(*args, **kwargs):
        pytest.fail("substituted source caused execution")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    with pytest.raises(SelectedExecutionError, match="retained source"):
        DigestHostPolicy((changed,), mechanism=BytesDigestMechanism())
    with pytest.raises(SelectedExecutionError, match="retained source"):
        execute_selected_validation(changed, store, policy=policy)


def test_correct_global_source_must_be_bound_to_selected_implementation() -> None:
    package = package_specimen()
    request, _ = request_for_package(package)
    changed_package = replace(package, implementations=(replace(package.implementations[0], artifact_paths=("notes.txt",)),))
    with pytest.raises(SelectedExecutionError, match="does not bind"):
        DigestHostPolicy((rebind_request(request, changed_package),), mechanism=BytesDigestMechanism())


@pytest.mark.parametrize("field", ["unused_artifact", "license", "dependency", "registry"])
def test_whole_package_changes_invalidate_old_host_approval(field: str) -> None:
    package = package_specimen()
    request, store = request_for_package(package)
    policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    if field == "unused_artifact":
        changed_package = replace(package, artifacts=tuple(replace(item, content=b"changed notes") if item.path == "notes.txt" else item for item in package.artifacts))
    elif field == "license":
        changed_package = replace(package, license="different license declaration")
    elif field == "dependency":
        changed_package = replace(package, dependencies=(PackageDependency("unused", "not resolved"),))
    else:
        changed_package = replace(package, registry=replace(package.registry, registry_version="changed"))
    changed = rebind_request(request, changed_package)
    with pytest.raises(SelectedExecutionError, match="authorization denied"):
        execute_selected_validation(changed, store, policy=policy)
    # New explicit host approval may accept unrelated inventory declarations;
    # a digest PASS remains only about the input bytes, not those declarations.
    new_policy = DigestHostPolicy((changed,), mechanism=BytesDigestMechanism())
    assert execute_selected_validation(changed, store, policy=new_policy)["evaluation"]["outcome"] == "PASS"


def test_selected_attached_dependencies_are_not_resolved_by_retained_bytes() -> None:
    package = package_specimen()
    request, _ = request_for_package(package)
    changed_package = replace(package,
        dependencies=(PackageDependency("dependency", "host must resolve", ("notes.txt",)),),
        implementations=(replace(package.implementations[0], dependency_ids=("dependency",)),),
    )
    with pytest.raises(SelectedExecutionError, match="dependencies remain unresolved"):
        request_for_package(changed_package)
    changed = rebind_request(request, changed_package)
    with pytest.raises(SelectedExecutionError, match="dependencies remain unresolved"):
        DigestHostPolicy((changed,), mechanism=BytesDigestMechanism())
    for candidate in changed["plan"]["candidates"]:
        candidate["execution_prerequisites"] = [item for item in candidate["execution_prerequisites"] if not item.startswith("PACKAGE_DEPENDENCY:")]
    with pytest.raises(SelectedExecutionError, match="stale or substituted"):
        DigestHostPolicy((changed,), mechanism=BytesDigestMechanism())


def test_unselected_dependency_inventory_and_plan_obligations_survive_execution() -> None:
    package = package_specimen()
    geometry, _ = specimen()
    geometry.mechanisms.append(replace(geometry.mechanisms[0], mechanism_id="meaning-checker"))
    geometry.judgments[1] = replace(geometry.judgments[1], mechanism_ids=("meaning-checker",))
    other_component = replace(package.registry.components[0], component_id="unselected", mechanism_ids=("meaning-checker",), implementation_ref="unselected:entry")
    registry = replace(package.registry, components=(*package.registry.components, other_component))
    package = replace(package, registry=registry,
        dependencies=(PackageDependency("dependency", "not resolved", ("notes.txt",)),),
        implementations=(*package.implementations, ImplementationBinding("unselected", "unselected:entry", ("notes.txt",), ("dependency",))),
    )
    plan = plan_validation(analyze_verification_surface(geometry), registry, package=package)
    request = prepare_digest_validation(geometry, registry, plan, coordinate_id="digest", expected_digest=EXPECTED, evidence_ref=EXPECTED, bounds=EvidenceBounds(1, 100), package=package)
    store = EvidenceStore()
    store.add(PAYLOAD)
    record = execute_selected_validation(request, store, policy=DigestHostPolicy((request,), mechanism=BytesDigestMechanism()))
    other = next(item for item in record["request"]["plan"]["candidates"] if item["component_id"] == "unselected")
    assert f"PACKAGE_DEPENDENCY:{package.canonical_digest()}:dependency" in other["execution_prerequisites"]
    assert record["request"]["package"]["dependencies"] == package.to_dict()["dependencies"]
    assert record["updated_geometry"]["judgments"][1] == geometry.to_dict()["judgments"][1]
    assert not record["updated_analysis"]["ordinary_closed"]
    assert not record["updated_analysis"]["self_closed"]


@pytest.mark.parametrize("value", [None, "sha256:" + "0" * 64, {}, True, []])
def test_explicit_malformed_package_never_falls_back_to_registry_only(value: object, monkeypatch: pytest.MonkeyPatch) -> None:
    request, store, _ = request_for()
    policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    request["package"] = value
    def forbidden(*args, **kwargs):
        pytest.fail("malformed package invoked mechanism")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    with pytest.raises(ValueError):
        execute_selected_validation(request, store, policy=policy)


def test_package_bound_plan_cannot_be_stripped_or_downgraded_under_old_approval() -> None:
    request, store = request_for_package(package_specimen())
    policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    stripped = deepcopy(request)
    del stripped["package"]
    with pytest.raises(SelectedExecutionError, match="stale or substituted"):
        execute_selected_validation(stripped, store, policy=policy)
    registry_request, _, _ = request_for()
    with pytest.raises(SelectedExecutionError, match="authorization denied"):
        execute_selected_validation(registry_request, store, policy=policy)
    # A separately approved registry-only operation remains a distinct v1 path.
    record = execute_selected_validation(registry_request, store, policy=DigestHostPolicy((registry_request,), mechanism=BytesDigestMechanism()))
    assert record["schema_version"] == "verifier-selected-digest-execution-1"
    assert set(record["request"]) == {"geometry", "registry", "plan", "candidate_id", "coordinate_id", "proposition"}


@pytest.mark.parametrize("package_mode", [False, True])
def test_mixed_record_request_versions_rejected_before_invocation(package_mode: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    if package_mode:
        request, store = request_for_package(package_specimen())
    else:
        request, store, _ = request_for()
    policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    record = execute_selected_validation(request, store, policy=policy)
    record["schema_version"] = "verifier-selected-digest-execution-1" if package_mode else "verifier-selected-digest-execution-2"
    def forbidden(*args, **kwargs):
        pytest.fail("mixed format invoked mechanism")
    monkeypatch.setattr(BytesDigestMechanism, "evaluate", forbidden)
    with pytest.raises(SelectedExecutionError, match="unsupported execution record"):
        replay_selected_validation(record, policy=policy)


def test_noncanonical_package_order_and_unrehashed_bytes_are_rejected() -> None:
    request, store = request_for_package(package_specimen())
    policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    reversed_package = deepcopy(request)
    reversed_package["package"]["artifacts"].reverse()
    with pytest.raises(SelectedExecutionError, match="canonical record"):
        execute_selected_validation(reversed_package, store, policy=policy)
    mutated_bytes = deepcopy(request)
    mutated_bytes["package"]["artifacts"][0]["content_base64"] = "AA=="
    with pytest.raises(ValueError):
        execute_selected_validation(mutated_bytes, store, policy=policy)


def test_approved_package_execution_and_replay_do_not_dynamically_import(monkeypatch: pytest.MonkeyPatch) -> None:
    request, store = request_for_package(package_specimen())
    policy = DigestHostPolicy((request,), mechanism=BytesDigestMechanism())
    monkeypatch.setitem(sys.modules, "verifier.core.evidence", None)
    record = execute_selected_validation(request, store, policy=policy)
    assert replay_selected_validation(record, policy=policy) == record


@pytest.mark.parametrize("missing", ["mechanism", "evidence", "byte_budget"])
def test_package_binding_does_not_upgrade_unknown_execution(missing: str) -> None:
    request, store = request_for_package(package_specimen())
    if missing == "evidence":
        store = EvidenceStore()
    if missing == "byte_budget":
        request["proposition"]["bounds"]["max_evidence_bytes"] = 0
    policy = DigestHostPolicy((request,), mechanism=None if missing == "mechanism" else BytesDigestMechanism())
    record = execute_selected_validation(request, store, policy=policy)
    assert record["schema_version"] == "verifier-selected-digest-execution-2"
    assert record["evaluation"]["outcome"] == "UNKNOWN"
    assert record["updated_geometry"]["judgments"][0]["status"] == "INDETERMINATE"
    assert replay_selected_validation(record, policy=policy) == record


# Duplicate or malformed mechanism identifiers are dispatch-ambiguous and fail closed.
_ADAPTER_OWNERS = (
    ("local_ledger_execution", "manifest_write_execution"),
    ("emulator_control_execution", "worker_protocol_execution"),
)


def _mechanism_modules() -> dict:
    from verifier.runtime import (
        emulator_control_execution, local_ledger_execution, manifest_write_execution, worker_protocol_execution,
    )
    return {
        "local_ledger_execution": local_ledger_execution,
        "manifest_write_execution": manifest_write_execution,
        "emulator_control_execution": emulator_control_execution,
        "worker_protocol_execution": worker_protocol_execution,
    }


@pytest.mark.parametrize("owner,victim", _ADAPTER_OWNERS)
def test_duplicate_adapter_identifier_fails_closed_before_dispatch(monkeypatch: pytest.MonkeyPatch,
        owner: str, victim: str) -> None:
    """RED before the change: the dispatch dict silently kept only the last module with an ADAPTER."""
    modules = _mechanism_modules()
    monkeypatch.setattr(modules[owner], "ADAPTER", modules[victim].ADAPTER)
    with pytest.raises(ValueError, match=r"^PACKAGE_EXECUTION_MECHANISM_ADAPTER_DUPLICATED$"):
        package_execution.mechanisms()
    with pytest.raises(ValueError, match=r"^PACKAGE_EXECUTION_MECHANISM_ADAPTER_DUPLICATED$"):
        package_execution.catalog()
    with pytest.raises(ValueError, match=r"^PACKAGE_EXECUTION_MECHANISM_ADAPTER_DUPLICATED$"):
        package_execution.implementation(modules[victim].ADAPTER)
    route = dict(modules[victim].catalog()[0])
    with pytest.raises(ValueError, match=r"^PACKAGE_EXECUTION_MECHANISM_ADAPTER_DUPLICATED$"):
        package_execution.route_mechanism(route)


@pytest.mark.parametrize("bad", [None, 7, ""], ids=["none", "integer", "empty"])
def test_malformed_adapter_identifier_fails_closed(monkeypatch: pytest.MonkeyPatch, bad: object) -> None:
    """RED before the change: a non-string adapter identifier became a silent dispatch key."""
    monkeypatch.setattr(_mechanism_modules()["local_ledger_execution"], "ADAPTER", bad)
    with pytest.raises(ValueError, match=r"^PACKAGE_EXECUTION_MECHANISM_ADAPTER_INVALID$"):
        package_execution.mechanisms()


def test_shipped_adapter_identifiers_are_unique_and_dispatch_to_seven_mechanisms() -> None:
    """Control: the installed dispatch registers every mechanism exactly once."""
    identifiers = [module.ADAPTER for module in package_execution.mechanisms().values()]
    assert len(identifiers) == len(set(identifiers)) == 7
