"""Bounded Verifier Standard (VSTD) proposition-transfer regressions.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Unicode Transformation Format, 8-bit (UTF-8). Set members are
dimensionless retained strings, not external facts or authority grants.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

import pytest

from verifier.interoperability.network import (
    CensusEntry, ObjectRecord, SelfDerivationRecord, SiloCommit,
    canonical_bytes, digest_bytes,
)


RULE_PROFILE = {
    "artifact_schema": "VSTD-CANONICAL-FINITE-SET-0.1", "context_policy": "EXACT",
    "facet": "items", "max_evidence_bytes": 4194304, "max_items": 256,
    "max_json_depth": 32, "max_json_nodes": 20000, "max_objects": 34,
    "max_premises": 16, "max_record_bytes": 262144, "max_string_bytes": 256,
    "predicate_id": "canonical_finite_set_subset_v1",
    "rule_id": "canonical_finite_set_union_v1",
    "schema_version": "VSTD-PROPOSITION-TRANSFER-RULE-0.1",
}


def _subject(items: list[str], allowed: list[str]) -> tuple[dict[str, Any], dict[str, bytes]]:
    payload = canonical_bytes({"schema_version": "VSTD-CANONICAL-FINITE-SET-0.1", "items": items})
    path = "items.json"
    commit = SiloCommit(
        publisher_id="publisher:sha256:" + "a" * 64, parents=(),
        census=(CensusEntry(path, ObjectRecord.from_payload(payload, "application/json", "finite-set"), "NECESSARY"),),
        ground_paths=(path,), derivations=(), relations=(), residual_obligations=(),
        exclusions=(), completeness_kind="SILO_CENSUS", coverage_universe=(),
        authority_axiom_agency=(), authority_axiom_agency_version="fixture-only",
        authority_axiom_agency_digest="sha256:" + "b" * 64, authority_model_path=None,
        self_derivation_record=SelfDerivationRecord(
            path, (path,), path, (path,), "DERIVES", False, False, False, False,
            path, path, path, path, (),
        ), created_at="2026-09-09T00:00:00Z",
    )
    commit_bytes = canonical_bytes(commit.to_dict())
    proposition = {
        "commit_digest": digest_bytes(commit_bytes), "artifact_digest": digest_bytes(payload),
        "artifact_path": path, "size_bytes": len(payload),
        "predicate_id": RULE_PROFILE["predicate_id"], "facet": "items",
        "parameters": {"allowed_items": allowed},
        "context": {"semantic_scope": "retained-item-labels", "actor_scope": "declared-observer",
                    "agency_digest": commit.authority_axiom_agency_digest,
                    "authority_model_digest": None, "assumptions": [], "exclusions": []},
    }
    return proposition, {digest_bytes(commit_bytes): commit_bytes, digest_bytes(payload): payload}


def _fixture() -> tuple[dict[str, Any], dict[str, bytes]]:
    first, first_bytes = _subject(["a"], ["a"])
    second, second_bytes = _subject(["b"], ["b"])
    conclusion, conclusion_bytes = _subject(["a", "b"], ["a", "b"])
    return {
        "schema_version": "VSTD-PROPOSITION-TRANSFER-0.1", "rule_id": RULE_PROFILE["rule_id"],
        "rule_profile_digest": digest_bytes(canonical_bytes(RULE_PROFILE)),
        "premises": sorted([first, second], key=lambda value: digest_bytes(canonical_bytes(value))),
        "conclusion": conclusion, "residual_obligations": [],
    }, {**first_bytes, **second_bytes, **conclusion_bytes}


def test_false_premise_survives_missing_commit_and_cannot_support_conclusion() -> None:
    checker = importlib.import_module("verifier.interoperability.proposition_transfer")
    declaration, evidence = _fixture()
    first = declaration["premises"][0]
    first["parameters"]["allowed_items"] = []
    evidence.pop(first["commit_digest"])
    declaration["premises"].sort(key=lambda value: digest_bytes(canonical_bytes(value)))
    result = checker.assess_transfer(canonical_bytes(declaration), evidence)
    affected = next(row for row in result["premises"] if row["proposition_digest"] == digest_bytes(canonical_bytes(first)))
    assert affected["evidence_binding"] == "UNKNOWN"
    assert affected["predicate_result"] == "FAIL"
    assert "PREDICATE_FAIL" in result["reason_codes"]
    assert result["conclusion_support"] == "NOT_ESTABLISHED"


def _checker() -> Any:
    return importlib.import_module("verifier.interoperability.proposition_transfer")


def _wire(declaration: dict[str, Any]) -> bytes:
    declaration["premises"].sort(key=lambda value: digest_bytes(canonical_bytes(value)))
    return canonical_bytes(declaration)


def _row(assessment: dict[str, Any], proposition: dict[str, Any]) -> dict[str, Any]:
    return next(row for row in [*assessment["premises"], assessment["conclusion"]]
                if row["proposition_digest"] == digest_bytes(canonical_bytes(proposition)))


def test_exact_union_has_checked_support_without_authority_or_graph_claims() -> None:
    checker = _checker()
    declaration, evidence = _fixture()
    wire = _wire(declaration)
    assert checker.rule_profile_bytes() == canonical_bytes(RULE_PROFILE)
    assert checker.decode_transfer(wire) == declaration
    result = checker.assess_transfer(wire, evidence)
    assert result["schema_version"] == "VSTD-PROPOSITION-TRANSFER-ASSESSMENT-0.1"
    assert result["reason_codes"] == []
    assert result["conclusion_support"] == "SUPPORTED"
    assert result["authority_admissibility"] == "NOT_ESTABLISHED"
    assert all(result[name] == "PASS" for name in (
        "context_preservation", "artifact_relation", "upper_bound_preservation", "residual_closure"))
    receipt = checker.build_transfer_receipt(wire, evidence)
    assert receipt == checker.build_transfer_receipt(wire, dict(reversed(list(evidence.items()))))
    assert checker.recheck_transfer_receipt(wire, receipt, evidence) == result
    assert set(checker.decode_transfer_receipt(receipt)) == {
        "schema_version", "declaration_digest", "rule_profile_digest", "assessment"}


def test_empty_identity_union_reads_bytes_without_bootstrapping_an_incoming_edge() -> None:
    checker = _checker()
    declaration, _ = _fixture()
    subject, evidence = _subject([], [])
    declaration["premises"], declaration["conclusion"] = [subject], subject
    assert checker.assess_transfer(_wire(declaration), evidence)["conclusion_support"] == "SUPPORTED"
    assert checker.assess_transfer(_wire(declaration), {})["conclusion_support"] == "NOT_ESTABLISHED"


def test_failed_upper_bound_preservation_does_not_negate_actual_conclusion() -> None:
    declaration, evidence = _fixture()
    declaration["premises"][0]["parameters"]["allowed_items"].append("z")
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert result["upper_bound_preservation"] == "FAIL"
    assert result["artifact_relation"] == "PASS"
    assert result["conclusion"]["predicate_result"] == "PASS"
    assert result["reason_codes"] == ["UPPER_BOUND_PRESERVATION_FAIL"]
    assert result["conclusion_support"] == "NOT_ESTABLISHED"


def test_actual_union_relation_is_checked_independently_of_all_subset_predicates() -> None:
    declaration, evidence = _fixture()
    conclusion, extra = _subject(["a"], ["a", "b"])
    declaration["conclusion"] = conclusion
    result = _checker().assess_transfer(_wire(declaration), {**evidence, **extra})
    assert result["artifact_relation"] == "FAIL"
    assert result["upper_bound_preservation"] == "PASS"
    assert all(row["predicate_result"] == "PASS" for row in [*result["premises"], result["conclusion"]])


@pytest.mark.parametrize("field,value", [
    ("semantic_scope", "different-scope"), ("actor_scope", "different-observer"),
    ("agency_digest", "sha256:" + "c" * 64),
    ("authority_model_digest", "sha256:" + "d" * 64),
    ("assumptions", ["new-assumption"]), ("exclusions", ["new-exclusion"]),
])
def test_exact_context_dimensions_are_not_coerced(field: str, value: Any) -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    source["context"][field] = value
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert result["context_preservation"] == "FAIL"
    assert result["artifact_relation"] == "PASS"
    assert _row(result, source)["predicate_result"] == "PASS"
    assert _row(result, source)["evidence_binding"] == ("FAIL" if field in {"agency_digest", "authority_model_digest"} else "PASS")


@pytest.mark.parametrize("change", ["rule", "profile", "predicate", "facet"])
def test_unsupported_inputs_preserve_other_direct_predicate_failures(change: str) -> None:
    declaration, evidence = _fixture()
    bad = declaration["premises"][0]
    bad["parameters"] = {"allowed_items": []}
    if change == "rule":
        declaration["rule_id"] = "never_load_this_plugin"
    elif change == "profile":
        declaration["rule_profile_digest"] = "sha256:" + "c" * 64
    else:
        declaration["conclusion"]["predicate_id" if change == "predicate" else "facet"] = "unsupported"
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, bad)["predicate_result"] == "FAIL"
    assert result["artifact_relation"] == "UNKNOWN"
    assert result["conclusion_support"] == "NOT_ESTABLISHED"


def test_known_context_mismatch_dominates_another_unsupported_predicate() -> None:
    declaration, evidence = _fixture()
    declaration["premises"][0]["predicate_id"] = "unsupported"
    declaration["conclusion"]["context"]["actor_scope"] = "different"
    assert _checker().assess_transfer(_wire(declaration), evidence)["context_preservation"] == "FAIL"


@pytest.mark.parametrize("parameters", [{}, {"allowed_items": ["b", "a"]}, {"allowed_items": ["a", "a"]},
                                         {"allowed_items": [""]}, {"allowed_items": ["x" * 257]},
                                         {"allowed_items": [], "extra": True}, {"allowed_items": 0}])
def test_malformed_supported_parameters_leave_actual_relation_and_identity_available(parameters: dict[str, Any]) -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    source["parameters"] = parameters
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "PASS"
    assert _row(result, source)["predicate_result"] == "INVALID"
    assert result["artifact_relation"] == "PASS"
    assert result["upper_bound_preservation"] == "INVALID"


@pytest.mark.parametrize("which", ["commit_digest", "artifact_digest"])
def test_digest_substitution_is_invalid_even_when_other_evidence_is_missing(which: str) -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    evidence[source[which]] = b"substituted bytes"
    evidence.pop(source["artifact_digest" if which == "commit_digest" else "commit_digest"])
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "INVALID"
    assert result["conclusion_support"] == "NOT_ESTABLISHED"


def test_census_mismatch_and_wrong_actual_size_are_distinct_negative_bindings() -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    source["artifact_path"] = "absent.json"
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "FAIL"
    assert _row(result, source)["predicate_result"] == "PASS"
    source["size_bytes"] += 1
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "INVALID"
    assert _row(result, source)["predicate_result"] == "INVALID"


def test_residual_obligations_prevent_support_without_relabeling_observed_passes() -> None:
    declaration, evidence = _fixture()
    declaration["residual_obligations"] = ["external-proof-not-supplied"]
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert result["residual_closure"] == "UNKNOWN"
    assert result["artifact_relation"] == "PASS"
    assert result["reason_codes"] == ["RESIDUAL_OBLIGATIONS"]


def test_available_evidence_is_copied_once_before_any_later_mapping_mutation() -> None:
    declaration, evidence = _fixture()
    ordered = sorted(evidence)
    mutable = {digest: bytearray(value) for digest, value in evidence.items()}

    class MutatingEvidence(Mapping[str, bytes]):
        def __init__(self) -> None:
            self.reads: list[str] = []

        def __getitem__(self, digest: str) -> Any:
            self.reads.append(digest)
            if len(self.reads) > 1:
                mutable[self.reads[-2]][:] = b"changed after retention"
            return mutable[digest]

        def __iter__(self) -> Any:
            raise AssertionError("unrelated mapping entries must not be enumerated")

        def __len__(self) -> int:
            raise AssertionError("unrelated mapping entries must not be counted")

    changing = MutatingEvidence()
    result = _checker().assess_transfer(_wire(declaration), changing)
    assert result["conclusion_support"] == "SUPPORTED"
    assert changing.reads == ordered


@pytest.mark.parametrize("alter", ["whitespace", "duplicate", "float", "negative_zero", "unknown_field", "bad_path", "bad_digest", "size_boolean", "reversed", "repeated_pair"])
def test_declaration_rejects_noncanonical_or_ambiguous_records(alter: str) -> None:
    checker = _checker()
    declaration, _ = _fixture()
    if alter == "unknown_field":
        declaration["extra"] = True
    elif alter == "bad_path":
        declaration["conclusion"]["artifact_path"] = "../items.json"
    elif alter == "bad_digest":
        declaration["rule_profile_digest"] = declaration["rule_profile_digest"].upper()
    elif alter == "size_boolean":
        declaration["conclusion"]["size_bytes"] = True
    elif alter == "repeated_pair":
        source = deepcopy(declaration["premises"][0])
        source["parameters"] = {"allowed_items": []}
        declaration["premises"] = [declaration["premises"][0], source]
    wire = _wire(declaration)
    if alter == "whitespace":
        wire += b"\n"
    elif alter == "duplicate":
        wire = b'{"rule_id":"duplicate",' + wire[1:]
    elif alter == "float":
        wire = wire.replace(b'"size_bytes":', b'"size_bytes":0.0,"ignored":', 1)
    elif alter == "negative_zero":
        declaration["conclusion"]["parameters"] = {"unknown": 0}
        wire = _wire(declaration).replace(b'"unknown":0', b'"unknown":-0')
    elif alter == "reversed":
        declaration["premises"].reverse()
        wire = canonical_bytes(declaration)
    with pytest.raises(checker.PropositionTransferError):
        checker.decode_transfer(wire)


def test_utf8_item_order_and_exact_byte_lengths_are_not_utf16_order_or_character_counts() -> None:
    declaration, _ = _fixture()
    items = ["\ue000", "\U00010000"]
    source, evidence = _subject(items, items)
    declaration["premises"], declaration["conclusion"] = [source], deepcopy(source)
    assert _checker().assess_transfer(_wire(declaration), evidence)["conclusion_support"] == "SUPPORTED"
    source["parameters"] = {"allowed_items": list(reversed(items))}
    assert _checker().assess_transfer(_wire(declaration), evidence)["upper_bound_preservation"] == "INVALID"
    declaration["rule_id"] = "\U00010000" * 65
    with pytest.raises(_checker().PropositionTransferError, match="256 UTF-8"):
        _checker().decode_transfer(_wire(declaration))


@pytest.mark.parametrize("kind", ["bytes", "depth", "nodes"])
def test_wire_bounds_reject_before_unbounded_canonicalization(kind: str) -> None:
    checker = _checker()
    declaration, _ = _fixture()
    if kind == "bytes":
        wire = b" " * (checker.MAX_RECORD_BYTES + 1)
    elif kind == "depth":
        wire = b'{"deep":' + b"[" * 40 + b"0" + b"]" * 40 + b"}"
    else:
        declaration["conclusion"]["parameters"] = {"nodes": [0] * checker.MAX_JSON_NODES}
        wire = _wire(declaration)
    with pytest.raises(checker.PropositionTransferError):
        checker.decode_transfer(wire)


def test_oversized_evidence_is_unknown_and_does_not_erase_a_different_false_predicate() -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    source["parameters"] = {"allowed_items": []}
    evidence[declaration["conclusion"]["artifact_digest"]] = b"x" * (_checker().MAX_RECORD_BYTES + 1)
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert result["conclusion"]["evidence_binding"] == "UNKNOWN"
    assert _row(result, source)["predicate_result"] == "FAIL"
    assert result["artifact_relation"] == "UNKNOWN"


def test_receipt_replay_distinguishes_binding_invalid_from_changed_availability() -> None:
    checker = _checker()
    declaration, evidence = _fixture()
    wire = _wire(declaration)
    original = checker.build_transfer_receipt(wire, evidence)
    missing = dict(evidence)
    missing.pop(declaration["conclusion"]["artifact_digest"])
    with pytest.raises(checker.PropositionTransferError, match="TRANSFER_NOT_REPRODUCED"):
        checker.recheck_transfer_receipt(wire, original, missing)
    historical = checker.build_transfer_receipt(wire, missing)
    with pytest.raises(checker.PropositionTransferError, match="TRANSFER_NOT_REPRODUCED"):
        checker.recheck_transfer_receipt(wire, historical, evidence)
    for field in ("declaration_digest", "rule_profile_digest"):
        changed = json.loads(original)
        changed[field] = "sha256:" + "0" * 64
        with pytest.raises(checker.PropositionTransferError, match="TRANSFER_RECEIPT_BINDING_INVALID"):
            checker.recheck_transfer_receipt(wire, canonical_bytes(changed), evidence)
    forged = json.loads(original)
    forged["assessment"]["conclusion"]["predicate_result"] = "FAIL"
    with pytest.raises(checker.PropositionTransferError, match="TRANSFER_NOT_REPRODUCED"):
        checker.recheck_transfer_receipt(wire, canonical_bytes(forged), evidence)


@pytest.mark.parametrize("mutation", ["extra", "authority", "result_type", "reason", "duplicate_reason", "version"])
def test_receipt_decoder_rejects_nonportable_record_shapes(mutation: str) -> None:
    checker = _checker()
    declaration, evidence = _fixture()
    receipt = json.loads(checker.build_transfer_receipt(_wire(declaration), evidence))
    if mutation == "extra":
        receipt["execution_assertion"] = True
    elif mutation == "authority":
        receipt["assessment"]["authority_admissibility"] = "ESTABLISHED"
    elif mutation == "result_type":
        receipt["assessment"]["conclusion"]["predicate_result"] = []
    elif mutation == "reason":
        receipt["assessment"]["reason_codes"] = ["UNREGISTERED_CODE"]
    elif mutation == "duplicate_reason":
        receipt["assessment"]["reason_codes"] = ["PREDICATE_FAIL", "PREDICATE_FAIL"]
    else:
        receipt["schema_version"] = "UNKNOWN"
    with pytest.raises(checker.PropositionTransferError):
        checker.decode_transfer_receipt(canonical_bytes(receipt))


def _rebind_artifact(proposition: dict[str, Any], evidence: dict[str, bytes], payload: bytes) -> None:
    commit = json.loads(evidence[proposition["commit_digest"]])
    proposition["artifact_digest"], proposition["size_bytes"] = digest_bytes(payload), len(payload)
    record = next(item["object"] for item in commit["census"] if item["path"] == proposition["artifact_path"])
    record["object_digest"], record["size_bytes"] = digest_bytes(payload), len(payload)
    commit_bytes = canonical_bytes(commit)
    proposition["commit_digest"] = digest_bytes(commit_bytes)
    evidence[proposition["commit_digest"]] = commit_bytes
    evidence[digest_bytes(payload)] = payload


@pytest.mark.parametrize("payload", [
    b"not JSON", b'{"items":[],"schema_version":"VSTD-CANONICAL-FINITE-SET-0.1"}\n',
    b'{"items":["a","a"],"schema_version":"VSTD-CANONICAL-FINITE-SET-0.1"}',
    b'{"items":[],"schema_version":"UNSUPPORTED"}',
    b'{"items":["\\ud800"],"schema_version":"VSTD-CANONICAL-FINITE-SET-0.1"}',
    b'{"items":["e\\u0301"],"schema_version":"VSTD-CANONICAL-FINITE-SET-0.1"}',
])
def test_malformed_actual_artifact_does_not_turn_byte_identity_into_a_semantic_result(payload: bytes) -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    _rebind_artifact(source, evidence, payload)
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "PASS"
    assert _row(result, source)["predicate_result"] == "INVALID"
    assert result["artifact_relation"] == "INVALID"
    assert result["upper_bound_preservation"] == "PASS"


def test_unsupported_predicate_leaves_opaque_non_json_bytes_and_parameters_uninterpreted() -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    _rebind_artifact(source, evidence, b"opaque binary\x00\xff")
    source["predicate_id"] = "unsupported"
    source["parameters"] = {"opaque": ["", "x" * 1000, None, True, 10]}
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "PASS"
    assert _row(result, source)["predicate_result"] == "UNKNOWN"
    assert result["artifact_relation"] == "UNKNOWN"


@pytest.mark.parametrize("malformed", [b"[]", b"{", b'{"schema_version":"VSTD-SILO-COMMIT-0.1"}'])
def test_hash_valid_malformed_commit_is_invalid_without_erasing_direct_predicate(malformed: bytes) -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    source["commit_digest"] = digest_bytes(malformed)
    evidence[source["commit_digest"]] = malformed
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "INVALID"
    assert _row(result, source)["predicate_result"] == "PASS"
    assert result["artifact_relation"] == "PASS"


def test_authority_model_binding_names_exact_census_object_without_assessing_its_model() -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    commit = json.loads(evidence[source["commit_digest"]])
    commit["authority_model_path"] = source["artifact_path"]
    commit_bytes = canonical_bytes(commit)
    source["commit_digest"] = digest_bytes(commit_bytes)
    evidence[source["commit_digest"]] = commit_bytes
    source["context"]["authority_model_digest"] = source["artifact_digest"]
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "PASS"
    assert result["authority_admissibility"] == "NOT_ESTABLISHED"
    source["context"]["authority_model_digest"] = None
    assert _row(_checker().assess_transfer(_wire(declaration), evidence), source)["evidence_binding"] == "FAIL"


def test_invalid_actual_evidence_dominates_missing_in_relation_but_preserves_other_axes() -> None:
    declaration, evidence = _fixture()
    first, second = declaration["premises"]
    _rebind_artifact(first, evidence, b"invalid-set")
    evidence.pop(second["artifact_digest"])
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert result["artifact_relation"] == "INVALID"
    assert _row(result, second)["predicate_result"] == "UNKNOWN"
    assert result["upper_bound_preservation"] == "PASS"


def test_commit_binding_fail_is_not_erased_when_its_artifact_is_unavailable() -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    source["context"]["agency_digest"] = "sha256:" + "0" * 64
    evidence.pop(source["artifact_digest"])
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "FAIL"
    assert _row(result, source)["predicate_result"] == "UNKNOWN"


def test_evidence_aggregate_budget_retains_sorted_distinct_objects_and_skips_without_resetting() -> None:
    checker = _checker()
    # Direct retention-boundary characterization complements public assessment
    # cases. Hash-valid opaque objects exercise the actual four-megabyte budget.
    objects = {digest_bytes(payload): payload for payload in (
        bytes([index]) * checker.MAX_RECORD_BYTES for index in range(20))}
    tiny = b"z"
    objects[digest_bytes(tiny)] = tiny
    ordered = sorted(objects)
    propositions = [{"commit_digest": digest, "artifact_digest": digest} for digest in ordered]
    retained = checker._retain(propositions, objects)
    remaining = checker.MAX_EVIDENCE_BYTES
    for digest in ordered:
        payload = objects[digest]
        if len(payload) <= remaining:
            assert retained[digest] == ("PASS", payload)
            remaining -= len(payload)
        else:
            assert retained[digest] == ("UNKNOWN", None)
    assert any(state == "UNKNOWN" for state, _ in retained.values())
    assert sum(len(data) for _, data in retained.values() if data is not None) <= checker.MAX_EVIDENCE_BYTES


def test_same_digest_is_observed_once_but_conflicting_sizes_are_checked_per_proposition() -> None:
    declaration, evidence = _fixture()
    source = deepcopy(declaration["premises"][0])
    declaration["conclusion"] = source
    source["size_bytes"] += 1
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert result["conclusion"]["evidence_binding"] == "INVALID"
    assert all(row["evidence_binding"] == "PASS" for row in result["premises"])


def test_exact_root_zero_depth_boundary_counts_scalar_values_and_ignores_object_keys() -> None:
    checker = _checker()
    declaration, _ = _fixture()
    # conclusion/parameters consume two levels; the extra field value begins at
    # depth three. Twenty-nine nested arrays put their scalar at depth32.
    value: Any = 0
    for _ in range(29):
        value = [value]
    declaration["conclusion"]["parameters"] = {"opaque": value}
    checker.decode_transfer(_wire(declaration))
    declaration["conclusion"]["parameters"] = {"opaque": [value]}
    with pytest.raises(checker.PropositionTransferError, match="depth|nesting"):
        checker.decode_transfer(_wire(declaration))


def test_evidence_retention_uses_intrinsic_buffer_size_not_subclass_conversion_hooks() -> None:
    checker = _checker()

    class DeceptiveBytes(bytes):
        def __len__(self) -> int:
            raise AssertionError("caller length hook must not be executed")

        def __bytes__(self) -> bytes:
            raise AssertionError("caller conversion hook must not be executed")

    small = b"actual buffer"
    small_digest = digest_bytes(small)
    large = b"x" * (checker.MAX_RECORD_BYTES + 1)
    large_digest = digest_bytes(large)
    propositions = [{"commit_digest": small_digest, "artifact_digest": large_digest}]
    retained = checker._retain(propositions, {small_digest: DeceptiveBytes(small), large_digest: DeceptiveBytes(large)})
    assert retained[small_digest] == ("PASS", small)
    assert retained[large_digest] == ("UNKNOWN", None)


def test_released_memoryview_is_invalid_evidence_without_crashing_other_checks() -> None:
    declaration, evidence = _fixture()
    source = declaration["premises"][0]
    view = memoryview(evidence[source["artifact_digest"]])
    view.release()
    evidence[source["artifact_digest"]] = view  # type: ignore[assignment]
    result = _checker().assess_transfer(_wire(declaration), evidence)
    assert _row(result, source)["evidence_binding"] == "INVALID"
    assert result["conclusion"]["predicate_result"] == "PASS"
