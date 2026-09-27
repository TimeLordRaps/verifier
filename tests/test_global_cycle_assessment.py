"""Adversarial tests for receipt-bound global-cycle assessment.

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256),
Verifier Standard (VSTD), and identifier (ID) are expanded at first use.  These unit fixtures
stand in for the separately tested relation-boundary and source-grounding
recheckers; combined tests must still run against the actual mechanisms.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from verifier.interoperability import global_cycle_assessment as cycle
from verifier.interoperability.global_cycle_assessment import (
    AssessmentState,
    DECLARATION_SCHEMA,
    SEMANTICS_SCHEMA,
    CycleRelationMaterial,
    GlobalCycleDeclaration,
    GlobalCycleError,
    assess_global_cycles,
    build_global_cycle_receipt,
    canonical_bytes,
    digest_bytes,
    recheck_global_cycle_receipt,
)


class FakeRelationBoundaryError(ValueError):
    pass


class FakeRelationBoundary:
    """Minimal exact replay adapter matching the real relation module surface."""

    RelationBoundaryError = FakeRelationBoundaryError

    @staticmethod
    def decode_relation_boundary_receipt(document: bytes) -> Any:
        value = json.loads(document)
        return SimpleNamespace(
            evidence_digest=value["evidence_digest"],
            source_digest=value["source_digest"],
            target_digest=value["target_digest"],
        )

    @staticmethod
    def decode_relation_boundary_declaration(document: bytes) -> Any:
        value = json.loads(document)
        return SimpleNamespace(
            source=SimpleNamespace(
                proposition_id=value["source"]["proposition_id"],
                artifact=SimpleNamespace(digest=value["source"]["digest"]),
            ),
            target=SimpleNamespace(
                proposition_id=value["target"]["proposition_id"],
                artifact=SimpleNamespace(digest=value["target"]["digest"]),
            ),
        )

    @staticmethod
    def recheck_relation_boundary_receipt(
        declaration_bytes: bytes, receipt_bytes: bytes, evidence: dict[str, bytes]
    ) -> Any:
        try:
            declaration = json.loads(declaration_bytes)
            receipt = json.loads(receipt_bytes)
        except (TypeError, ValueError) as error:
            raise FakeRelationBoundaryError("malformed relation bytes") from error
        if receipt["declaration_digest"] != digest_bytes(declaration_bytes):
            raise FakeRelationBoundaryError("relation declaration substitution")
        evidence_digest = receipt["evidence_digest"]
        if evidence_digest not in evidence:
            raise FakeRelationBoundaryError("missing retained relation evidence")
        if digest_bytes(evidence[evidence_digest]) != evidence_digest:
            raise FakeRelationBoundaryError("substituted retained relation evidence")
        if receipt["source_digest"] != declaration["source"]["digest"]:
            raise FakeRelationBoundaryError("source coordinate substitution")
        if receipt["target_digest"] != declaration["target"]["digest"]:
            raise FakeRelationBoundaryError("target coordinate substitution")
        return SimpleNamespace(
            declaration_digest=receipt["declaration_digest"],
            result=SimpleNamespace(value=receipt["result"]),
            source_digest=receipt["source_digest"],
            target_digest=receipt["target_digest"],
        )


class FakeSourceGroundingError(ValueError):
    pass


class FakeSourceGrounding:
    """Minimal exact replay adapter matching the grounding module surface."""

    SourceGroundingError = FakeSourceGroundingError

    @staticmethod
    def canonical_bytes(value: Any) -> bytes:
        return json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")

    @staticmethod
    def decode_source_grounding_receipt(document: bytes) -> Any:
        value = json.loads(document)
        return SimpleNamespace(
            certificate_digest=value["certificate_digest"],
            source_digest=value["source_digest"],
        )

    @staticmethod
    def decode_source_grounding_declaration(document: bytes) -> Any:
        value = json.loads(document)
        proposition = dict(value["ground_proposition"])
        proposition["path"] = tuple(proposition["path"])
        return SimpleNamespace(
            ground_proposition=SimpleNamespace(**proposition),
            source=SimpleNamespace(**value["source"]),
        )

    @staticmethod
    def recheck_source_grounding_receipt(
        declaration_bytes: bytes, receipt_bytes: bytes, evidence: dict[str, bytes]
    ) -> Any:
        declaration = json.loads(declaration_bytes)
        receipt = json.loads(receipt_bytes)
        if receipt["declaration_digest"] != digest_bytes(declaration_bytes):
            raise FakeSourceGroundingError("grounding declaration substitution")
        for field in ("source_digest", "certificate_digest"):
            coordinate = receipt[field]
            if coordinate not in evidence or digest_bytes(evidence[coordinate]) != coordinate:
                raise FakeSourceGroundingError("grounding evidence substitution")
        if receipt["source_digest"] != declaration["source"]["digest"]:
            raise FakeSourceGroundingError("semantic source substitution")
        return SimpleNamespace(
            declaration_digest=receipt["declaration_digest"],
            result=SimpleNamespace(value=receipt["result"]),
            source_digest=receipt["source_digest"],
        )


@pytest.fixture(autouse=True)
def exact_relation_rechecker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cycle, "_relation_boundary_module", lambda: FakeRelationBoundary)
    monkeypatch.setattr(cycle, "_source_grounding_module", lambda: FakeSourceGrounding)


def _artifact_digest(identifier: str) -> str:
    return digest_bytes(identifier.encode("utf-8"))


def _ground_source(
    semantic_source: bytes, *, result: str = "ESTABLISHED"
) -> tuple[bytes, bytes, dict[str, bytes]]:
    semantic_body = json.loads(semantic_source)["cycle_relation_semantics"]
    certificate = FakeSourceGrounding.canonical_bytes({
        "source_digest": digest_bytes(semantic_source),
        "test_observation": "whole semantic object",
    })
    declaration = FakeSourceGrounding.canonical_bytes({
        "ground_proposition": {
            "expected": semantic_body,
            "path": ("cycle_relation_semantics",),
            "predicate": "JSON_POINTER_EQUALS",
        },
        "source": {
            "digest": digest_bytes(semantic_source),
            "size_bytes": len(semantic_source),
        },
    })
    receipt = FakeSourceGrounding.canonical_bytes({
        "certificate_digest": digest_bytes(certificate),
        "declaration_digest": digest_bytes(declaration),
        "result": result,
        "source_digest": digest_bytes(semantic_source),
    })
    return declaration, receipt, {
        digest_bytes(semantic_source): semantic_source,
        digest_bytes(certificate): certificate,
    }


def _material(
    source: str,
    target: str,
    *,
    result: str = "ESTABLISHED",
    source_bytes: bytes | None = None,
    target_bytes: bytes | None = None,
    kind: str = "SUPPORT_DEPENDENCY",
    polarity: str | None = None,
    clock: str | None = None,
    unit: str | None = None,
    offset: int | None = None,
    grounding_result: str = "ESTABLISHED",
) -> CycleRelationMaterial:
    source_artifact = source_bytes or ("artifact:" + source).encode("utf-8")
    target_artifact = target_bytes or ("artifact:" + target).encode("utf-8")
    source_coordinate = digest_bytes(source_artifact)
    target_coordinate = digest_bytes(target_artifact)
    declaration = canonical_bytes({
        "source": {"digest": source_coordinate, "proposition_id": source},
        "target": {"digest": target_coordinate, "proposition_id": target},
    })
    evidence_bytes = canonical_bytes({"observed": [source, target]})
    evidence_digest = digest_bytes(evidence_bytes)
    receipt = canonical_bytes({
        "declaration_digest": digest_bytes(declaration),
        "evidence_digest": evidence_digest,
        "result": result,
        "source_digest": source_coordinate,
        "target_digest": target_coordinate,
    })
    semantic_body: dict[str, Any] = {
        "relation_declaration_digest": digest_bytes(declaration),
        "relation_receipt_digest": digest_bytes(receipt),
        "schema_version": SEMANTICS_SCHEMA,
        "source_endpoint": {
            "artifact_digest": source_coordinate,
            "proposition_id": source,
        },
        "target_endpoint": {
            "artifact_digest": target_coordinate,
            "proposition_id": target,
        },
    }
    if kind == "SUPPORT_DEPENDENCY":
        semantic_body["support"] = {
            "direction": "SOURCE_TO_TARGET",
            "relation": "DEPENDENCY",
        }
    elif kind == "SIMULTANEOUS_CONSTRAINT":
        semantic_body["constraint"] = {"polarity": polarity}
    elif kind == "EXPLICIT_TEMPORAL":
        semantic_body["temporal"] = {
            "clock_id": clock,
            "offset": offset,
            "unit": unit,
        }
    else:
        raise AssertionError("unsupported test fixture kind")
    semantic_source = FakeSourceGrounding.canonical_bytes({
        "cycle_relation_semantics": semantic_body
    })
    grounding_declaration, grounding_receipt, grounding_evidence = _ground_source(
        semantic_source, result=grounding_result
    )
    return CycleRelationMaterial.from_parts(
        declaration,
        receipt,
        {
            evidence_digest: evidence_bytes,
            source_coordinate: source_artifact,
            target_coordinate: target_artifact,
        },
        semantic_source,
        grounding_declaration,
        grounding_receipt,
        grounding_evidence,
    )


def _replace_semantic_source(
    material: CycleRelationMaterial,
    semantic_source: bytes,
    *,
    reground: bool,
) -> CycleRelationMaterial:
    if reground:
        grounding_declaration, grounding_receipt, grounding_evidence = _ground_source(
            semantic_source
        )
    else:
        grounding_declaration = material.grounding_declaration_bytes
        grounding_receipt = material.grounding_receipt_bytes
        grounding_evidence = dict(material.grounding_evidence)
    return CycleRelationMaterial.from_parts(
        material.relation_declaration_bytes,
        material.relation_receipt_bytes,
        dict(material.relation_evidence),
        semantic_source,
        grounding_declaration,
        grounding_receipt,
        grounding_evidence,
    )


def _row(
    identifier: str,
    material: CycleRelationMaterial,
) -> dict[str, Any]:
    return {
        "grounding_declaration_digest": material.grounding_declaration_digest,
        "grounding_receipt_digest": material.grounding_receipt_digest,
        "relation_id": identifier,
        "relation_declaration_digest": material.declaration_digest,
        "receipt_digest": material.receipt_digest,
        "semantic_source_digest": material.semantic_source_digest,
    }


def _declaration(rows: list[dict[str, Any]]) -> bytes:
    return GlobalCycleDeclaration.from_dict({
        "relations": rows,
        "schema_version": DECLARATION_SCHEMA,
    }).canonical_bytes()


def _materials(*values: CycleRelationMaterial) -> dict[str, CycleRelationMaterial]:
    return {value.receipt_digest: value for value in values}


def test_positive_support_cycle_requires_rechecked_relation_receipts() -> None:
    ab = _material("a", "b")
    bc = _material("b", "c")
    ca = _material("c", "a")
    document = _declaration([
        _row("ab", ab),
        _row("bc", bc),
        _row("ca", ca),
    ])
    result = assess_global_cycles(document, _materials(ab, bc, ca)).to_dict()
    assert result["assessment_state"] == "ASSESSED"
    assert result["assessment_complete"] is True
    assert result["support_dependencies"] == {
        "cycle_groups": [["a", "b", "c"]],
        "relation_ids": ["ab", "bc", "ca"],
        "status": "CYCLES_PRESENT",
    }
    assert result["simultaneous_constraints"]["status"] == "NOT_APPLICABLE"
    assert result["temporal_relations"]["status"] == "NOT_APPLICABLE"


def test_label_only_cycle_is_unknown_and_never_reported_as_established() -> None:
    ab = _material("a", "b")
    ba = _material("b", "a")
    document = _declaration([
        _row("ab", ab),
        _row("ba", ba),
    ])
    result = assess_global_cycles(document, {}).to_dict()
    assert result["assessment_state"] == "UNKNOWN"
    assert result["assessment_complete"] is False
    assert result["support_dependencies"]["cycle_groups"] == []
    assert result["reason_codes"] == ["RELATION_MATERIAL_MISSING"]


def test_same_relation_receipt_cannot_be_relabelled_without_new_grounding() -> None:
    support = _material("a", "b")
    semantic = json.loads(support.semantic_source_bytes)["cycle_relation_semantics"]
    semantic.pop("support")
    semantic["temporal"] = {"clock_id": "c", "offset": -1, "unit": "tick"}
    relabelled_source = FakeSourceGrounding.canonical_bytes({
        "cycle_relation_semantics": semantic
    })
    relabelled = _replace_semantic_source(
        support, relabelled_source, reground=False
    )
    result = assess_global_cycles(
        _declaration([_row("r", relabelled)]), _materials(relabelled)
    ).to_dict()
    assert result["assessment_state"] == "INVALID"
    assert result["reason_codes"] == ["SEMANTIC_GROUNDING_COORDINATE_INVALID"]
    assert result["temporal_relations"]["backward_time_relation_ids"] == []

    newly_grounded = _replace_semantic_source(
        support, relabelled_source, reground=True
    )
    accepted = assess_global_cycles(
        _declaration([_row("r", newly_grounded)]), _materials(newly_grounded)
    ).to_dict()
    assert accepted["assessment_state"] == "ASSESSED"
    assert accepted["temporal_relations"]["backward_time_relation_ids"] == ["r"]


def test_semantic_source_substitution_against_bound_global_digest_is_invalid() -> None:
    support = _material("a", "b")
    temporal = _material(
        "a", "b", kind="EXPLICIT_TEMPORAL", clock="c", unit="tick", offset=-1
    )
    result = assess_global_cycles(
        _declaration([_row("r", support)]),
        {support.receipt_digest: temporal},
    ).to_dict()
    assert result["assessment_state"] == "INVALID"
    assert result["reason_codes"] == ["SEMANTIC_SOURCE_SUBSTITUTED"]


def test_grounding_receipt_substitution_is_invalid() -> None:
    relation = _material("a", "b")
    forged_receipt = FakeSourceGrounding.canonical_bytes({
        **json.loads(relation.grounding_receipt_bytes),
        "result": "UNKNOWN",
    })
    forged = CycleRelationMaterial.from_parts(
        relation.relation_declaration_bytes,
        relation.relation_receipt_bytes,
        dict(relation.relation_evidence),
        relation.semantic_source_bytes,
        relation.grounding_declaration_bytes,
        forged_receipt,
        dict(relation.grounding_evidence),
    )
    result = assess_global_cycles(
        _declaration([_row("r", relation)]),
        {relation.receipt_digest: forged},
    ).to_dict()
    assert result["assessment_state"] == "INVALID"
    assert result["reason_codes"] == ["GROUNDING_RECEIPT_SUBSTITUTED"]


def test_circular_semantic_evidence_is_invalid() -> None:
    relation = _material("a", "b")
    circular = CycleRelationMaterial.from_parts(
        relation.relation_declaration_bytes,
        relation.relation_receipt_bytes,
        dict(relation.relation_evidence),
        relation.relation_receipt_bytes,
        relation.grounding_declaration_bytes,
        relation.grounding_receipt_bytes,
        dict(relation.grounding_evidence),
    )
    result = assess_global_cycles(
        _declaration([_row("r", circular)]), _materials(circular)
    ).to_dict()
    assert result["assessment_state"] == "INVALID"
    assert result["reason_codes"] == ["CIRCULAR_OR_ALIASED_SEMANTIC_EVIDENCE"]


def test_ungrounded_semantics_remains_unknown() -> None:
    relation = _material("a", "b")
    ungrounded = CycleRelationMaterial.from_parts(
        relation.relation_declaration_bytes,
        relation.relation_receipt_bytes,
        dict(relation.relation_evidence),
        relation.semantic_source_bytes,
        relation.grounding_declaration_bytes,
        relation.grounding_receipt_bytes,
        {},
    )
    result = assess_global_cycles(
        _declaration([_row("r", ungrounded)]), _materials(ungrounded)
    ).to_dict()
    assert result["assessment_state"] == "UNKNOWN"
    assert result["assessment_complete"] is False
    assert result["reason_codes"] == ["SEMANTIC_GROUNDING_EVIDENCE_INCOMPLETE"]


def test_receipt_substitution_is_invalid_before_graph_analysis() -> None:
    relation = _material("a", "b")
    document = _declaration([_row("ab", relation)])
    substituted = _material("a", "c")
    result = assess_global_cycles(
        document, {relation.receipt_digest: substituted}
    ).to_dict()
    assert result["assessment_state"] == "INVALID"
    assert result["support_dependencies"]["cycle_groups"] == []
    assert result["reason_codes"] == ["RELATION_RECEIPT_SUBSTITUTED"]


def test_retained_evidence_substitution_without_wrongly_bound_bytes_is_unknown() -> None:
    relation = _material("a", "b")
    evidence = dict(relation.relation_evidence)
    evidence[next(iter(evidence))] = b"substituted"
    substituted_digest = digest_bytes(b"substituted")
    forged = CycleRelationMaterial.from_parts(
        relation.relation_declaration_bytes,
        relation.relation_receipt_bytes,
        {substituted_digest: b"substituted"},
        relation.semantic_source_bytes,
        relation.grounding_declaration_bytes,
        relation.grounding_receipt_bytes,
        dict(relation.grounding_evidence),
    )
    document = _declaration([_row("ab", relation)])
    result = assess_global_cycles(document, {relation.receipt_digest: forged}).to_dict()
    assert result["assessment_state"] == "UNKNOWN"
    assert result["reason_codes"] == ["RELATION_EVIDENCE_INCOMPLETE"]


def test_simultaneous_constraint_loop_is_nondirectional_and_can_conflict() -> None:
    ab = _material("a", "b", kind="SIMULTANEOUS_CONSTRAINT", polarity="SAME")
    bc = _material("b", "c", kind="SIMULTANEOUS_CONSTRAINT", polarity="SAME")
    ca = _material("c", "a", kind="SIMULTANEOUS_CONSTRAINT", polarity="INVERTED")
    document = _declaration([
        _row("ab", ab),
        _row("bc", bc),
        _row("ca", ca),
    ])
    result = assess_global_cycles(document, _materials(ab, bc, ca)).to_dict()
    assert result["assessment_state"] == "CONFLICTED"
    assert result["simultaneous_constraints"] == {
        "conflicting_relation_ids": ["ca"],
        "loop_closing_relation_ids": ["ca"],
        "relation_ids": ["ab", "bc", "ca"],
        "status": "CONFLICTED",
    }
    assert result["support_dependencies"]["status"] == "NOT_APPLICABLE"
    assert "no chosen causal direction" in result["semantics"]["simultaneous_constraint"]


def test_consistent_constraint_loop_is_not_misclassified_as_causal() -> None:
    ab = _material("a", "b", kind="SIMULTANEOUS_CONSTRAINT", polarity="INVERTED")
    ba = _material("b", "a", kind="SIMULTANEOUS_CONSTRAINT", polarity="INVERTED")
    result = assess_global_cycles(_declaration([
        _row("ab", ab),
        _row("ba", ba),
    ]), _materials(ab, ba)).to_dict()
    assert result["assessment_state"] == "ASSESSED"
    assert result["simultaneous_constraints"]["status"] == "CONSISTENT"
    assert result["simultaneous_constraints"]["loop_closing_relation_ids"] == ["ba"]
    assert result["support_dependencies"]["cycle_groups"] == []


def test_explicit_backward_time_is_distinct_from_cycle_and_retrocausation() -> None:
    relation = _material(
        "earlier", "later", kind="EXPLICIT_TEMPORAL",
        clock="logical", unit="tick", offset=-1,
    )
    result = assess_global_cycles(_declaration([
        _row("back", relation)
    ]), _materials(relation)).to_dict()
    assert result["assessment_state"] == "ASSESSED"
    assert result["temporal_relations"]["backward_time_relation_ids"] == ["back"]
    assert result["temporal_relations"]["clocks"][0]["status"] == "CONSISTENT"
    assert result["support_dependencies"]["cycle_groups"] == []
    assert "physical retrocausation is not established" in result["semantics"]["backward_time"]


def test_temporal_loop_checks_exact_offset_sum() -> None:
    ab = _material("a", "b", kind="EXPLICIT_TEMPORAL", clock="c", unit="tick", offset=1)
    ba = _material("b", "a", kind="EXPLICIT_TEMPORAL", clock="c", unit="tick", offset=-1)
    consistent = assess_global_cycles(_declaration([
        _row("forward", ab),
        _row("return", ba),
    ]), _materials(ab, ba)).to_dict()
    assert consistent["assessment_state"] == "ASSESSED"
    assert consistent["temporal_relations"]["clocks"][0]["loop_closing_relation_ids"] == ["return"]

    ba_conflict = _material(
        "b", "a", kind="EXPLICIT_TEMPORAL", clock="c", unit="tick", offset=1
    )
    conflicted = assess_global_cycles(_declaration([
        _row("forward", ab),
        _row("return", ba_conflict),
    ]), _materials(ab, ba_conflict)).to_dict()
    assert conflicted["assessment_state"] == "CONFLICTED"
    assert conflicted["temporal_relations"]["clocks"][0]["conflicting_relation_ids"] == ["return"]


def test_separate_clocks_and_units_are_not_compared() -> None:
    first = _material(
        "a", "b", kind="EXPLICIT_TEMPORAL", clock="logical", unit="tick", offset=1
    )
    second = _material(
        "b", "c", kind="EXPLICIT_TEMPORAL", clock="physical",
        unit="nanosecond", offset=-2,
    )
    document = _declaration([
        _row("logical", first),
        _row("physical", second),
    ])
    result = assess_global_cycles(document, _materials(first, second)).to_dict()
    assert result["assessment_state"] == "ASSESSED"
    assert [(item["clock_id"], item["unit"]) for item in result["temporal_relations"]["clocks"]] == [
        ("logical", "tick"), ("physical", "nanosecond")
    ]


def test_one_clock_cannot_mix_temporal_units() -> None:
    first = _material(
        "a", "b", kind="EXPLICIT_TEMPORAL", clock="shared", unit="tick", offset=1
    )
    second = _material(
        "b", "c", kind="EXPLICIT_TEMPORAL", clock="shared",
        unit="nanosecond", offset=1,
    )
    result = assess_global_cycles(_declaration([
        _row("one", first),
        _row("two", second),
    ]), _materials(first, second)).to_dict()
    assert result["assessment_state"] == "INVALID"
    assert result["temporal_relations"]["status"] == "INVALID"
    assert result["reason_codes"] == ["ONE_CLOCK_MIXES_TEMPORAL_UNITS"]


def test_mixed_established_and_unknown_relations_remains_unknown() -> None:
    known = _material("a", "b")
    unknown = _material("b", "a", result="UNKNOWN")
    result = assess_global_cycles(_declaration([
        _row("known", known),
        _row("unknown", unknown),
    ]), _materials(known, unknown)).to_dict()
    assert result["assessment_state"] == "UNKNOWN"
    assert result["assessment_complete"] is False
    assert result["support_dependencies"]["cycle_groups"] == []
    assert result["reason_codes"] == ["RELATION_RESULT_UNKNOWN"]


@pytest.mark.parametrize("boundary_result", ["REFUTED", "INVALID"])
def test_refuted_or_invalid_relation_cannot_enter_the_graph(boundary_result: str) -> None:
    relation = _material("a", "b", result=boundary_result)
    result = assess_global_cycles(
        _declaration([_row("ab", relation)]),
        _materials(relation),
    ).to_dict()
    assert result["assessment_state"] == "INVALID"
    assert result["reason_codes"] == ["RELATION_NOT_ESTABLISHED"]


def test_same_proposition_id_with_different_exact_bytes_is_invalid() -> None:
    first = _material("a", "b")
    second = _material("a", "c", source_bytes=b"different-a")
    result = assess_global_cycles(_declaration([
        _row("first", first),
        _row("second", second),
    ]), _materials(first, second)).to_dict()
    assert result["assessment_state"] == "INVALID"
    assert result["reason_codes"] == ["PROPOSITION_ID_COORDINATE_CONFLICT"]


def test_budget_exhaustion_preserves_unknown_and_discards_partial_facets() -> None:
    relation = _material("a", "a")
    result = assess_global_cycles(
        _declaration([_row("self", relation)]),
        _materials(relation),
        max_work=1,
    ).to_dict()
    assert result["assessment_state"] == "UNKNOWN"
    assert result["assessment_complete"] is False
    assert result["support_dependencies"]["cycle_groups"] == []
    assert result["reason_codes"] == ["CYCLE_ASSESSMENT_WORK_BUDGET_EXHAUSTED"]


@pytest.mark.parametrize("max_work", [True, False, 0, -1, 1.0, "1", cycle.MAX_WORK + 1])
def test_work_budget_is_strictly_typed_and_bounded(max_work: Any) -> None:
    relation = _material("a", "b")
    with pytest.raises(GlobalCycleError, match="max_work"):
        assess_global_cycles(
            _declaration([_row("ab", relation)]),
            _materials(relation),
            max_work=max_work,
        )


@pytest.mark.parametrize("mutation", [
    "unknown-top",
    "unknown-row",
    "unsupported-schema",
    "duplicate-id",
    "duplicate-receipt",
    "bad-digest",
    "caller-kind",
    "caller-polarity",
    "caller-offset",
    "not-array",
])
def test_malformed_declarations_are_rejected_without_coercion(mutation: str) -> None:
    relation = _material("a", "b")
    payload = {
        "relations": [_row("ab", relation)],
        "schema_version": DECLARATION_SCHEMA,
    }
    row = payload["relations"][0]
    if mutation == "unknown-top": payload["extra"] = True
    elif mutation == "unknown-row": row["extra"] = True
    elif mutation == "unsupported-schema": payload["schema_version"] = "future"
    elif mutation == "duplicate-id": payload["relations"].append(copy.deepcopy(row))
    elif mutation == "duplicate-receipt":
        payload["relations"].append({**copy.deepcopy(row), "relation_id": "second"})
    elif mutation == "bad-digest": row["receipt_digest"] = "sha256:" + "A" * 64
    elif mutation == "caller-kind": row["relation_kind"] = "SUPPORT_DEPENDENCY"
    elif mutation == "caller-polarity": row["constraint_polarity"] = "SAME"
    elif mutation == "caller-offset": row["temporal_offset"] = -1
    else: payload["relations"] = tuple(payload["relations"])
    with pytest.raises(GlobalCycleError):
        GlobalCycleDeclaration.from_dict(payload)


@pytest.mark.parametrize("document", [
    b'{"schema_version":"verifier-global-cycle-assessment-1","relations":[],"relations":[]}',
    b"null",
    b"{",
    b" " * (cycle.MAX_DECLARATION_BYTES + 1),
    "not-bytes",
], ids=["duplicate-key", "non-object", "truncated", "over-bytes", "non-bytes"])
def test_malformed_declaration_bytes_are_rejected(document: Any) -> None:
    with pytest.raises(GlobalCycleError):
        GlobalCycleDeclaration.from_bytes(document)


def test_material_constructor_enforces_byte_and_coordinate_bounds() -> None:
    relation = _material("a", "b")
    with pytest.raises(GlobalCycleError):
        CycleRelationMaterial.from_parts(
            relation.relation_declaration_bytes, relation.relation_receipt_bytes,
            {"not-a-digest": b"x"}, relation.semantic_source_bytes,
            relation.grounding_declaration_bytes, relation.grounding_receipt_bytes,
            dict(relation.grounding_evidence),
        )
    with pytest.raises(GlobalCycleError):
        CycleRelationMaterial.from_parts(
            relation.relation_declaration_bytes, relation.relation_receipt_bytes,
            {_artifact_digest("x"): "x"}, relation.semantic_source_bytes,
            relation.grounding_declaration_bytes, relation.grounding_receipt_bytes,
            dict(relation.grounding_evidence),
        )
    with pytest.raises(GlobalCycleError):
        CycleRelationMaterial.from_parts(
            "{}", relation.relation_receipt_bytes, dict(relation.relation_evidence),
            relation.semantic_source_bytes, relation.grounding_declaration_bytes,
            relation.grounding_receipt_bytes, dict(relation.grounding_evidence),
        )
    with pytest.raises(GlobalCycleError, match="does not bind"):
        CycleRelationMaterial.from_parts(
            relation.relation_declaration_bytes, relation.relation_receipt_bytes,
            {_artifact_digest("wrong"): b"other"}, relation.semantic_source_bytes,
            relation.grounding_declaration_bytes, relation.grounding_receipt_bytes,
            dict(relation.grounding_evidence),
        )


def test_aggregate_material_byte_bound_preserves_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relation = _material("a", "b")
    monkeypatch.setattr(cycle, "MAX_TOTAL_MATERIAL_BYTES", 1)
    result = assess_global_cycles(
        _declaration([_row("ab", relation)]),
        _materials(relation),
    ).to_dict()
    assert result["assessment_state"] == "UNKNOWN"
    assert result["reason_codes"] == ["RELATION_MATERIAL_BYTE_BOUND_EXCEEDED"]


def test_records_and_receipts_are_canonical_deterministic_and_recheckable() -> None:
    ab = _material("a", "b")
    ba = _material("b", "a")
    rows = [
        _row("z", ba),
        _row("a", ab),
    ]
    first = _declaration(rows)
    second = _declaration(list(reversed(rows)))
    assert first == second
    assert GlobalCycleDeclaration.from_bytes(first).canonical_digest() == digest_bytes(first)
    receipt = build_global_cycle_receipt(first, _materials(ab, ba))
    parsed = json.loads(receipt)
    assert canonical_bytes(parsed) == receipt
    assert parsed["declaration_digest"] == digest_bytes(first)
    assert recheck_global_cycle_receipt(first, receipt, _materials(ab, ba)).canonical_bytes() == receipt
    changed = bytearray(receipt)
    changed[-2] = ord("1") if changed[-2] != ord("1") else ord("0")
    with pytest.raises(GlobalCycleError, match="NOT_REPRODUCED"):
        recheck_global_cycle_receipt(first, bytes(changed), _materials(ab, ba))


def test_report_never_claims_truth_causation_correctness_or_trust() -> None:
    relation = _material("a", "a")
    report = assess_global_cycles(
        _declaration([_row("self", relation)]),
        _materials(relation),
    ).to_dict()
    assert report["semantics"]["verification_effect"] == "NONE"
    assert set(report["residual_obligations"]) >= {
        "CAUSATION_NOT_ESTABLISHED",
        "PHYSICAL_RETROCAUSATION_NOT_ESTABLISHED",
        "TRUTH_NOT_ESTABLISHED",
    }
    forbidden = {"PASS", "VERIFIED", "CORRECT", "TRUSTED", "RETROCAUSAL"}
    assert not forbidden.intersection(report)
    assert AssessmentState.ASSESSED.value == report["assessment_state"]


def test_consolidated_actual_grounding_and_relation_receipts_interoperate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise actual mechanisms once their concurrently owned files coexist."""

    if (
        importlib.util.find_spec("verifier.interoperability.source_grounding") is None
        or importlib.util.find_spec("verifier.interoperability.relation_boundary") is None
    ):
        # The isolated implementation branch deliberately lacks both concurrent
        # modules.  This same test takes the actual path after consolidation.
        module_dir = Path(cycle.__file__).parent
        assert not (module_dir / "source_grounding.py").exists() or not (
            module_dir / "relation_boundary.py"
        ).exists()
        return

    from verifier.interoperability import relation_boundary as actual_relation
    from verifier.interoperability import source_grounding as actual_grounding

    monkeypatch.setattr(cycle, "_relation_boundary_module", lambda: actual_relation)
    monkeypatch.setattr(cycle, "_source_grounding_module", lambda: actual_grounding)
    vocabulary = "sha256:" + "b" * 64
    source = actual_relation.canonical_bytes({"value": "same"})
    target = actual_relation.canonical_bytes({"value": "same"})

    def endpoint(identifier: str, artifact: bytes) -> dict[str, Any]:
        return {
            "artifact": {
                "digest": actual_relation.digest_bytes(artifact),
                "size_bytes": len(artifact),
            },
            "proposition_id": identifier,
            "semantic_frame": {
                "facets": ["value"],
                "frame_id": "CANONICAL-JSON-OBJECT-0.1",
                "proposition_language": "CANONICAL_JSON_OBJECT",
                "vocabulary_digest": vocabulary,
            },
        }

    relation_record = {
        "assumptions": [],
        "consumed_facets": ["value"],
        "evidence": {"digest": "sha256:" + "0" * 64, "size_bytes": 0},
        "loss_map": [],
        "preservation_map": [{"source_facet": "value", "target_facet": "value"}],
        "schema_version": actual_relation.DECLARATION_SCHEMA,
        "source": endpoint("a", source),
        "target": endpoint("b", target),
        "translation": {
            "checker_coordinate": actual_relation.current_checker_coordinate().to_dict(),
            "mechanism_id": actual_relation.MECHANISM_ID,
            "mechanism_profile_digest": actual_relation.relation_boundary_mechanism_profile_digest(),
        },
    }
    provisional = actual_relation.decode_relation_boundary_declaration(
        actual_relation.canonical_bytes(relation_record)
    )
    relation_evidence_bytes = actual_relation.expected_relation_boundary_evidence(
        provisional, source, target, "combined-test-relation@0.1"
    )
    relation_record["evidence"] = {
        "digest": actual_relation.digest_bytes(relation_evidence_bytes),
        "size_bytes": len(relation_evidence_bytes),
    }
    relation_declaration = actual_relation.canonical_bytes(relation_record)
    relation_evidence = {
        actual_relation.digest_bytes(source): source,
        actual_relation.digest_bytes(target): target,
        actual_relation.digest_bytes(relation_evidence_bytes): relation_evidence_bytes,
    }
    relation_receipt = actual_relation.build_relation_boundary_receipt(
        relation_declaration, relation_evidence
    )
    semantic_body = {
        "relation_declaration_digest": actual_relation.digest_bytes(relation_declaration),
        "relation_receipt_digest": actual_relation.digest_bytes(relation_receipt),
        "schema_version": SEMANTICS_SCHEMA,
        "source_endpoint": {
            "artifact_digest": actual_relation.digest_bytes(source),
            "proposition_id": "a",
        },
        "support": {"direction": "SOURCE_TO_TARGET", "relation": "DEPENDENCY"},
        "target_endpoint": {
            "artifact_digest": actual_relation.digest_bytes(target),
            "proposition_id": "b",
        },
    }
    semantic_source = actual_grounding.canonical_bytes({
        "cycle_relation_semantics": semantic_body
    })
    grounding_record = {
        "assumptions": [],
        "certificate": {
            "certificate_kind": "DERIVATION",
            "digest": "sha256:" + "0" * 64,
            "size_bytes": 0,
        },
        "declarer_coordinate": "combined-test-semantics@0.1",
        "ground_proposition": {
            "expected": semantic_body,
            "path": ["cycle_relation_semantics"],
            "predicate": "JSON_POINTER_EQUALS",
            "proposition_id": "whole-cycle-relation-semantics",
        },
        "interpretation": {
            "checker_coordinate": actual_grounding.current_checker_coordinate().to_dict(),
            "mechanism_id": actual_grounding.MECHANISM_ID,
            "mechanism_profile_digest": actual_grounding.source_grounding_mechanism_profile_digest(),
            "profile_id": actual_grounding.INTERPRETATION_PROFILE,
        },
        "schema_version": actual_grounding.DECLARATION_SCHEMA,
        "semantic_frame": {
            "facets": ["cycle_relation_semantics"],
            "frame_id": "CANONICAL-JSON-OBJECT-0.1",
            "proposition_language": "CANONICAL_JSON_OBJECT",
            "vocabulary_digest": vocabulary,
        },
        "source": {
            "digest": actual_grounding.digest_bytes(semantic_source),
            "size_bytes": len(semantic_source),
        },
    }
    provisional_grounding = actual_grounding.decode_source_grounding_declaration(
        actual_grounding.canonical_bytes(grounding_record)
    )
    certificate = actual_grounding.expected_source_grounding_certificate(
        provisional_grounding, semantic_source, "combined-test-grounding@0.1"
    )
    grounding_record["certificate"] = {
        "certificate_kind": "DERIVATION",
        "digest": actual_grounding.digest_bytes(certificate),
        "size_bytes": len(certificate),
    }
    grounding_declaration = actual_grounding.canonical_bytes(grounding_record)
    grounding_evidence = {
        actual_grounding.digest_bytes(semantic_source): semantic_source,
        actual_grounding.digest_bytes(certificate): certificate,
    }
    grounding_receipt = actual_grounding.build_source_grounding_receipt(
        grounding_declaration, grounding_evidence
    )
    material = CycleRelationMaterial.from_parts(
        relation_declaration,
        relation_receipt,
        relation_evidence,
        semantic_source,
        grounding_declaration,
        grounding_receipt,
        grounding_evidence,
    )
    result = assess_global_cycles(
        _declaration([_row("ab", material)]), _materials(material)
    ).to_dict()
    assert result["assessment_state"] == "ASSESSED"
    assert result["relation_results"][0]["relation_kind"] == "SUPPORT_DEPENDENCY"
