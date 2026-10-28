"""Finite native operation metadata controls; tests confer no replay qualification.

Verifier Standard (VSTD); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256). All effects and obligation census remain
unqualified even when metadata and exported schemas agree.
"""
from __future__ import annotations

from typing import Any
from copy import deepcopy
from asyncio import CancelledError
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import object_facets, subject_security, verifier_composed_security
from verifier.runtime import native_operation_contracts as operations


ZERO = "sha256:" + "0" * 64


def lookup(**changes: Any) -> dict[str, Any]:
    selector = {"semantic_version": operations.HISTORICAL, "objective": "OBJECT-1.1",
                "represented_kind": "VERIFIER"}
    selector.update(changes)
    return operations.lookup_native_replay_operation(**selector)


def schema(version: str) -> dict[str, Any]:
    return json.loads(operations.export_native_operation_schema(version))


def validator(version: str) -> Draft202012Validator:
    return Draft202012Validator(schema(version))


def test_separate_closed_catalogs_preserve_408_and_two_native_routes() -> None:
    old = operations.native_replay_operation_catalog()
    new = operations.native_replay_operation_catalog(semantic_version=operations.TEN_TIER)
    assert old["status"] == new["status"] == "PASS"
    assert len(old["routes"]) == 408 and len(new["routes"]) == 2
    assert {row["semantic_version"] for row in old["routes"]} == {operations.HISTORICAL}
    assert {r["objective"] for r in new["routes"]} == {"VERIFIER-6.1", "VERIFIER-10.1"}
    assert old["native_replay"] == new["native_replay"] == "NOT_RUN"
    assert old["mandatory_obligation_census"] == new["mandatory_obligation_census"] == "UNKNOWN"


@pytest.mark.parametrize("version", [operations.DESCRIPTOR, operations.LOOKUP])
def test_exported_schemas_are_actual_closed_valid_canonical_json(version: str) -> None:
    raw = operations.export_native_operation_schema(version)
    selected = json.loads(raw)
    Draft202012Validator.check_schema(selected)
    assert canonical_bytes(selected) == raw
    assert selected["$id"] == operations._SCHEMA_BASE + operations._SCHEMAS[version].split("/")[-1]
    assert selected["properties"]["schema_version"] == {"const": version}
    assert selected["additionalProperties"] is False


@pytest.mark.parametrize("selector", [
    {}, {"represented_kind": "MODEL"},
    {"objective": "HARDWARE-1.1", "represented_kind": "HARDWARE"},
    {"objective": "VERIFIER-9.1"},
    {"semantic_version": operations.TEN_TIER, "objective": "VERIFIER-6.1"},
    {"semantic_version": operations.TEN_TIER, "objective": "VERIFIER-10.1"},
])
def test_actual_selected_metadata_schema_signature_pins_and_boundaries(selector: dict[str, str]) -> None:
    result = lookup(**selector)
    assert result["status"] == "PASS" and result["metadata_status"] == "AVAILABLE"
    validator(operations.LOOKUP).validate(result)
    descriptor = result["descriptor"]
    validator(operations.DESCRIPTOR).validate(descriptor)
    assert result["descriptor_digest"] == "sha256:" + hashlib.sha256(canonical_bytes(descriptor)).hexdigest()
    assert [p["name"] for p in descriptor["native_signature"]["parameters"]] == [
        "certificate_bytes", "expected_request", "policy"]
    assert descriptor["native_signature"]["parameters"][1]["kind"] == "KEYWORD_ONLY"
    assert len(descriptor["binding"]["sources"]) == 9
    assert descriptor["transport_limits"]["certificate_bytes"] == operations.routes.MAX_CERTIFICATE_BYTES
    assert descriptor["transport_limits"]["native_additional_bounds"] == "UNKNOWN"
    assert descriptor["qualification"]["runtime_availability"] == "UNKNOWN"
    assert descriptor["qualification"]["full_execution"] == "UNKNOWN"
    assert descriptor["qualification"]["mandatory_obligation_census"] == "UNKNOWN"
    assert descriptor["qualification"]["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert descriptor["schemas"]["native_evidence"] == "UNSUPPORTED"
    for name, version in (("descriptor", operations.DESCRIPTOR), ("lookup_result", operations.LOOKUP)):
        assert descriptor["schemas"][name]["digest"] == "sha256:" + hashlib.sha256(
            operations.export_native_operation_schema(version)).hexdigest()


def test_metadata_lookup_never_enters_registered_certificate_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse_entry(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("native replay entered during metadata lookup")
    monkeypatch.setattr(operations.routes, "replay_current_object_certificate", refuse_entry)
    # A substituted wrapper cannot furnish its registered source/annotation signature.
    result = lookup()
    assert result["native_replay"] == "NOT_RUN"


def test_native_lookup_calls_selected_kind_mechanism_without_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = subject_security.mechanism_digest("VERIFIER")
    calls = []
    def binding(kind: str) -> str:
        calls.append(kind)
        return expected
    monkeypatch.setattr(subject_security, "mechanism_digest", binding)
    result = lookup(objective="VERIFIER-9.1")
    assert result["status"] == "PASS" and calls == ["VERIFIER"]


@pytest.mark.parametrize("changes", [
    {"semantic_version": "legacy"}, {"semantic_version": operations.TEN_TIER + "-changed"},
    {"semantic_version": operations.TEN_TIER, "objective": "VERIFIER-10.2"},
    {"semantic_version": operations.TEN_TIER, "objective": "VERIFIER-9.1"},
    {"semantic_version": operations.TEN_TIER, "objective": "VERIFIER-6.1", "represented_kind": "MODEL"},
    {"represented_kind": "NOT-A-KIND"}, {"objective": "SIM.step"},
    {"objective": "MODEL.infer"}, {"objective": "TRAIN.run"},
    {"objective": "SIM-5.1", "represented_kind": "VERIFIER"},
    {"objective": "VERIFIER-10.1"}, {"objective": True},
])
def test_known_wrong_selectors_refuse_before_support_file_io(monkeypatch: pytest.MonkeyPatch, changes: Any) -> None:
    def prohibited(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("support file read before known selector refusal")
    monkeypatch.setattr(operations, "_read_package", prohibited)
    with pytest.raises(operations.NativeOperationRefusal):
        lookup(**changes)


@pytest.mark.parametrize("field", ["expected_descriptor_digest", "expected_mechanism_digest"])
def test_substituted_external_pins_are_refuted(field: str) -> None:
    result = lookup(**{field: ZERO})
    assert result["status"] == "FAIL" and result["pin_comparison"] == "DIFFERS"
    validator(operations.LOOKUP).validate(result)


def test_exact_external_source_mechanism_and_descriptor_pins_reproduce() -> None:
    first = lookup()
    descriptor = first["descriptor"]
    result = lookup(expected_source_bindings=descriptor["binding"]["sources"],
                    expected_mechanism_digest=descriptor["binding"]["mechanism_digest"],
                    expected_descriptor_digest=first["descriptor_digest"])
    assert result["status"] == "PASS" and result["pin_comparison"] == "MATCH"
    assert result["descriptor"] == descriptor


@pytest.mark.parametrize("exception", [CancelledError, MemoryError, OSError])
def test_source_substitution_is_fail_before_later_binding_interruption(monkeypatch: pytest.MonkeyPatch, exception: Any) -> None:
    pins = deepcopy(lookup()["descriptor"]["binding"]["sources"])
    pins["core/certificate.py"] = ZERO
    calls = []
    def cancelled() -> Any:
        calls.append(True)
        raise exception("fixture unavailable after known source pin refutation")
    monkeypatch.setattr(object_facets, "mechanism_digest", cancelled)
    result = lookup(expected_source_bindings=pins)
    assert result["status"] == "FAIL" and result["reason"] == "SOURCE_PIN_DIFFERS"
    assert calls == []


@pytest.mark.parametrize("pins", [{}, {"foreign/file.py": ZERO}])
def test_source_pin_set_contradiction_refuses_before_source_reads(monkeypatch: pytest.MonkeyPatch, pins: dict[str, str]) -> None:
    def prohibited(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("known pin set mismatch must precede source reads")
    monkeypatch.setattr(operations, "_read_package", prohibited)
    result = lookup(expected_source_bindings=pins)
    assert result["status"] == "FAIL" and result["reason"] == "SOURCE_PIN_SET_DIFFERS"


@pytest.mark.parametrize("source", ["core/certificate.py", "standard/CURRENT_NATIVE_OPERATION_CONTRACTS.md",
                                        operations._SCHEMAS[operations.DESCRIPTOR], operations._SCHEMAS[operations.LOOKUP]])
def test_missing_required_package_sources_remain_unavailable(monkeypatch: pytest.MonkeyPatch, source: str) -> None:
    read = operations._read_package
    def missing(name: str, maximum: int=operations.MAX_SOURCE_BYTES) -> bytes:
        if name == source:
            raise FileNotFoundError("fixture omitted one installed support source")
        return read(name, maximum)
    monkeypatch.setattr(operations, "_read_package", missing)
    result = lookup(expected_mechanism_digest=ZERO)
    assert result["status"] == "UNKNOWN" and result["metadata_status"] == "UNAVAILABLE"
    assert result["descriptor"] is None and result["pin_comparison"] == "UNAVAILABLE"


@pytest.mark.parametrize("exception", [OSError, CancelledError, MemoryError])
def test_owner_binding_outage_or_actual_cancellation_is_unknown(monkeypatch: pytest.MonkeyPatch, exception: Any) -> None:
    def interrupted() -> Any:
        raise exception("fixture binding interrupted")
    monkeypatch.setattr(object_facets, "mechanism_digest", interrupted)
    result = lookup()
    assert result["status"] == "UNKNOWN" and result["metadata_status"] == "UNAVAILABLE"
    assert result["native_replay"] == "NOT_RUN"
    validator(operations.LOOKUP).validate(result)


def test_source_memory_error_is_unknown_without_descriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*args: Any, **kwargs: Any) -> Any:
        raise MemoryError("fixture bounded reader cannot allocate")
    monkeypatch.setattr(operations, "_read_package", unavailable)
    result = lookup()
    assert result["status"] == "UNKNOWN" and result["descriptor"] is None
    with pytest.raises(operations.NativeOperationUnavailable):
        operations.export_native_operation_schema(operations.DESCRIPTOR)


@pytest.mark.parametrize('objective', ['VERIFIER-6.1', 'VERIFIER-10.1'])
def test_known_native_selector_with_unavailable_loader_remains_unknown(monkeypatch: pytest.MonkeyPatch, objective: str) -> None:
    def unavailable(**selector: dict[str, str]) -> Any:
        raise operations.routes.CurrentObjectRouteUnavailable("fixture lazy loader missing")
    monkeypatch.setattr(operations.routes, "select_current_object_route", unavailable)
    result = lookup(semantic_version=operations.TEN_TIER, objective=objective)
    assert result["status"] == "UNKNOWN" and result["metadata_status"] == "UNAVAILABLE"


@pytest.mark.parametrize("exception", [operations.routes.CurrentObjectRouteUnavailable, MemoryError, CancelledError])
def test_new_catalog_loader_outage_is_unknown_and_old_catalog_stays_available(monkeypatch: pytest.MonkeyPatch, exception: Any) -> None:
    def unavailable() -> Any:
        raise exception("fixture native catalog loader interrupted")
    monkeypatch.setattr(operations.routes, "current_ten_tier_route_catalog", unavailable)
    result = operations.native_replay_operation_catalog(semantic_version=operations.TEN_TIER)
    assert result["status"] == "UNKNOWN" and result["metadata_status"] == "UNAVAILABLE"
    assert len(operations.native_replay_operation_catalog()["routes"]) == 408


def test_source_reader_uses_small_chunks_and_enforces_actual_bound(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "small.py"
    source.write_bytes(b"small source")
    monkeypatch.setattr(operations, "_package_root", lambda: tmp_path)
    original_open = Path.open
    sizes = []
    class Stream:
        def __init__(self: Any, path: Any) -> Any:
            self.handle = original_open(path, "rb")
        def __enter__(self: Any) -> Any:
            return self
        def __exit__(self: Any, *exc: Any) -> Any:
            self.handle.close()
        def read(self: Any, size: Any) -> Any:
            sizes.append(size)
            return self.handle.read(size)
    monkeypatch.setattr(Path, "open", lambda path, *args, **kwargs: Stream(path))
    assert operations._read_package("small.py") == b"small source"
    assert sizes and max(sizes) <= 8192
    with pytest.raises(operations.NativeOperationUnavailable):
        operations._read_package("small.py", 4)


def test_cooperative_cancellation_never_reads_support_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    def prohibited(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("cancelled lookup entered support reads")
    monkeypatch.setattr(operations, "_read_package", prohibited)
    result = lookup(cancelled=True)
    assert result["status"] == "UNKNOWN" and result["reason"] == "METADATA_LOOKUP_CANCELLED"


@pytest.mark.parametrize("schema_change", ["additionalProperties", "required", "$id"])
def test_malformed_descriptor_schema_cannot_be_exported(monkeypatch: pytest.MonkeyPatch, schema_change: Any) -> None:
    document = schema(operations.DESCRIPTOR)
    document[schema_change] = {"additionalProperties": True, "required": [], "$id": "substituted"}[schema_change]
    read = operations._read_package
    def changed(name: str, maximum: int=operations.MAX_SOURCE_BYTES) -> bytes:
        if name == operations._SCHEMAS[operations.DESCRIPTOR]:
            return canonical_bytes(document)
        return read(name, maximum)
    monkeypatch.setattr(operations, "_read_package", changed)
    with pytest.raises(operations.NativeOperationUnavailable):
        operations.export_native_operation_schema(operations.DESCRIPTOR)
    assert lookup()["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["extra", "native_schema", "full_execution", "native_replay", "wrong_kind"])
def test_descriptor_schema_rejects_unearned_or_unknown_fields(mutation: Any) -> None:
    descriptor = deepcopy(lookup()["descriptor"])
    if mutation == "extra":
        descriptor["unknown_property"] = "present"
    elif mutation == "native_schema":
        descriptor["schemas"]["native_evidence"] = {"digest": ZERO}
    elif mutation == "full_execution":
        descriptor["qualification"]["full_execution"] = "PASS"
    elif mutation == "native_replay":
        descriptor["qualification"]["native_replay"] = "PASS"
    else:
        descriptor["selector"]["represented_kind"] = "NOT-A-KIND"
    assert list(validator(operations.DESCRIPTOR).iter_errors(descriptor))


def test_lookup_result_schema_rejects_carried_pass_without_descriptor() -> None:
    result = lookup()
    result["descriptor"] = None
    assert list(validator(operations.LOOKUP).iter_errors(result))


def test_capture_refuses_foreign_values_without_conversion_or_comparison() -> None:
    class Foreign:
        def __eq__(self: Any, other: Any) -> Any:
            pytest.fail("foreign equality invoked")
        def __str__(self: Any) -> Any:
            pytest.fail("foreign string conversion invoked")
    with pytest.raises(operations.NativeOperationRefusal):
        lookup(objective=Foreign())
    with pytest.raises(operations.NativeOperationRefusal):
        operations._capture({"value": Foreign()})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 1 << 4097, "x" * (operations.MAX_OUTPUT_BYTES + 1)],
                         ids=["nonfinite-nan", "nonfinite-inf", "oversized-integer", "oversized-text"])
def test_capture_bounds_nonfinite_integers_and_text(value: Any) -> None:
    with pytest.raises(operations.NativeOperationRefusal):
        operations._capture(value)


def test_capture_refuses_cycles_and_excess_depth() -> None:
    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(operations.NativeOperationRefusal):
        operations._capture(cyclic)
    deep = None
    for _ in range(50):
        deep = [deep]
    with pytest.raises(operations.NativeOperationRefusal):
        operations._capture(deep)


@pytest.mark.parametrize("changes", [{"expected_descriptor_digest": "sha256:bad"},
                                         {"expected_source_bindings": []}, {"cancelled": 1}])
def test_malformed_external_selection_refuses_before_io(monkeypatch: pytest.MonkeyPatch, changes: Any) -> None:
    def prohibited(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("malformed external pin or flag entered source reads")
    monkeypatch.setattr(operations, "_read_package", prohibited)
    with pytest.raises(operations.NativeOperationRefusal):
        lookup(**changes)


@pytest.mark.parametrize('changes', [{'objective': 'VERIFIER-10.2'}, {'represented_kind': 'MODEL'}])
def test_native10_metadata_schemas_refuse_unregistered_or_wrong_kind_selector(changes: dict[str, str]) -> None:
    result = lookup(semantic_version=operations.TEN_TIER, objective='VERIFIER-10.1')
    descriptor = deepcopy(result['descriptor'])
    descriptor['selector'].update(changes)
    assert list(validator(operations.DESCRIPTOR).iter_errors(descriptor))
    substituted = deepcopy(result)
    substituted['descriptor'] = descriptor
    substituted['selector'].update(changes)
    assert list(validator(operations.LOOKUP).iter_errors(substituted))
