"""Adversarial Verifier Standard (VSTD) relation-boundary replay tests.

JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
identities bind exact proposition frames but do not imply general equivalence.
A serialized identifier (ID) names a mechanism or proposition.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from verifier.interoperability import relation_boundary as relation
from verifier.interoperability import source_grounding as grounding


VOCABULARY = "sha256:" + "b" * 64
PRODUCER = "test:relation-boundary-producer@0.1"


def _endpoint(proposition_id: str, artifact: bytes, facets: list[str], vocabulary: str = VOCABULARY) -> dict:
    return {
        "artifact": {"digest": relation.digest_bytes(artifact), "size_bytes": len(artifact)},
        "proposition_id": proposition_id,
        "semantic_frame": {
            "facets": facets,
            "frame_id": "CANONICAL-JSON-OBJECT-0.1",
            "proposition_language": "CANONICAL_JSON_OBJECT",
            "vocabulary_digest": vocabulary,
        },
    }


def _fixture(*, with_loss: bool = False) -> tuple[bytes, bytes, bytes, bytes, dict[str, bytes]]:
    source_record = {"claim": "ready"}
    target_record = {"claim_out": "ready"}
    consumed = ["claim"]
    loss_map: list[str] = []
    if with_loss:
        source_record["private"] = "withheld"
        consumed.append("private")
        loss_map.append("private")
    source = relation.canonical_bytes(source_record)
    target = relation.canonical_bytes(target_record)
    base = {
        "assumptions": ["facet values use the declared vocabulary"],
        "consumed_facets": consumed,
        "evidence": {"digest": "sha256:" + "0" * 64, "size_bytes": 0},
        "loss_map": loss_map,
        "preservation_map": [{"source_facet": "claim", "target_facet": "claim_out"}],
        "schema_version": relation.DECLARATION_SCHEMA,
        "source": _endpoint("source-claim", source, consumed),
        "target": _endpoint("target-claim", target, ["claim_out"]),
        "translation": {
            "checker_coordinate": relation.current_checker_coordinate().to_dict(),
            "mechanism_id": relation.MECHANISM_ID,
            "mechanism_profile_digest": relation.relation_boundary_mechanism_profile_digest(),
        },
    }
    provisional = relation.decode_relation_boundary_declaration(relation.canonical_bytes(base))
    execution = relation.expected_relation_boundary_evidence(
        provisional, source, target, PRODUCER
    )
    base["evidence"] = {
        "digest": relation.digest_bytes(execution),
        "size_bytes": len(execution),
    }
    declaration = relation.canonical_bytes(base)
    return declaration, source, target, execution, {
        relation.digest_bytes(source): source,
        relation.digest_bytes(target): target,
        relation.digest_bytes(execution): execution,
    }


def test_exact_facet_translation_is_established_by_replay() -> None:
    declaration, _source, _target, _execution, evidence = _fixture()

    receipt = relation.qualify_relation_boundary(declaration, evidence)

    assert receipt.result is relation.RelationResult.ESTABLISHED
    assert receipt.information_loss == "NONE"
    assert dict(receipt.checks)["evidence_recheck"] == "REPRODUCED"
    assert dict(receipt.checks)["relation_evaluation"] == "ESTABLISHED"
    assert "GENERAL_TRANSLATION_NOT_ESTABLISHED" in receipt.residual_obligations
    receipt_bytes = relation.build_relation_boundary_receipt(declaration, evidence)
    assert relation.recheck_relation_boundary_receipt(declaration, receipt_bytes, evidence) == receipt


def test_information_loss_is_explicit_not_silently_equated() -> None:
    declaration, _source, _target, _execution, evidence = _fixture(with_loss=True)

    receipt = relation.qualify_relation_boundary(declaration, evidence)

    assert receipt.result is relation.RelationResult.ESTABLISHED
    assert receipt.information_loss == "PRESENT"
    assert receipt.loss_map == ("private",)
    assert {item.source_facet for item in receipt.preservation_map} == {"claim"}


def test_mismatched_preserved_value_is_refuted_after_exact_execution() -> None:
    declaration, source, _target, _execution, _evidence = _fixture()
    changed_target = relation.canonical_bytes({"claim_out": "not-ready"})
    record = json.loads(declaration)
    record["target"] = _endpoint("target-claim", changed_target, ["claim_out"])
    provisional = relation.decode_relation_boundary_declaration(relation.canonical_bytes(record))
    execution = relation.expected_relation_boundary_evidence(
        provisional, source, changed_target, PRODUCER
    )
    record["evidence"] = {
        "digest": relation.digest_bytes(execution),
        "size_bytes": len(execution),
    }
    rebound = relation.canonical_bytes(record)

    receipt = relation.qualify_relation_boundary(
        rebound,
        {
            relation.digest_bytes(source): source,
            relation.digest_bytes(changed_target): changed_target,
            relation.digest_bytes(execution): execution,
        },
    )

    assert receipt.result is relation.RelationResult.REFUTED
    assert dict(receipt.checks)["relation_evaluation"] == "REFUTED"


def test_relation_json_boolean_does_not_equal_integer_one() -> None:
    declaration, source, target, _execution, _evidence = _fixture()
    source = relation.canonical_bytes({"claim": True})
    target = relation.canonical_bytes({"claim_out": 1})
    record = json.loads(declaration)
    record["source"] = _endpoint("source-claim", source, ["claim"])
    record["target"] = _endpoint("target-claim", target, ["claim_out"])
    provisional = relation.decode_relation_boundary_declaration(relation.canonical_bytes(record))
    execution = relation.expected_relation_boundary_evidence(provisional, source, target, PRODUCER)
    record["evidence"] = {
        "digest": relation.digest_bytes(execution),
        "size_bytes": len(execution),
    }

    receipt = relation.qualify_relation_boundary(
        relation.canonical_bytes(record),
        {
            relation.digest_bytes(source): source,
            relation.digest_bytes(target): target,
            relation.digest_bytes(execution): execution,
        },
    )

    assert receipt.result is relation.RelationResult.REFUTED


def test_false_refutation_is_invalid_not_accepted() -> None:
    declaration, source, target, execution, _evidence = _fixture()
    forged = json.loads(execution)
    forged["result"] = "REFUTED"
    forged_bytes = relation.canonical_bytes(forged)
    record = json.loads(declaration)
    record["evidence"] = {
        "digest": relation.digest_bytes(forged_bytes),
        "size_bytes": len(forged_bytes),
    }

    receipt = relation.qualify_relation_boundary(
        relation.canonical_bytes(record),
        {
            relation.digest_bytes(source): source,
            relation.digest_bytes(target): target,
            relation.digest_bytes(forged_bytes): forged_bytes,
        },
    )

    assert receipt.result is relation.RelationResult.INVALID
    assert "EXECUTION_EVIDENCE_RECHECK_INVALID" in receipt.reason_codes


@pytest.mark.parametrize("which", ["source", "target"])
def test_source_or_target_substitution_is_invalid(which: str) -> None:
    declaration, source, target, _execution, evidence = _fixture()
    digest = relation.digest_bytes(source if which == "source" else target)
    evidence[digest] = (source if which == "source" else target) + b" "

    receipt = relation.qualify_relation_boundary(declaration, evidence)

    assert receipt.result is relation.RelationResult.INVALID
    assert f"{which.upper()}_INVALID" in receipt.reason_codes


@pytest.mark.parametrize("case", ["unsupported-mechanism", "incompatible-frames"])
def test_unsupported_mechanism_or_incompatible_frames_remain_unknown(case: str) -> None:
    declaration, source, target, _execution, _evidence = _fixture()
    record = json.loads(declaration)
    if case == "unsupported-mechanism":
        record["translation"]["mechanism_id"] = "unregistered"
    else:
        record["target"]["semantic_frame"]["vocabulary_digest"] = "sha256:" + "c" * 64
    evidence_digest = record["evidence"]["digest"]
    evidence = {
        relation.digest_bytes(source): source,
        relation.digest_bytes(target): target,
    }

    receipt = relation.qualify_relation_boundary(relation.canonical_bytes(record), evidence)

    assert receipt.result is relation.RelationResult.UNKNOWN
    assert "EXECUTION_EVIDENCE_UNKNOWN" in receipt.reason_codes
    assert evidence_digest not in evidence
    expected_reason = (
        "MECHANISM_OR_PROFILE_UNSUPPORTED"
        if case == "unsupported-mechanism"
        else "SEMANTIC_FRAMES_INCOMPATIBLE"
    )
    assert expected_reason in receipt.reason_codes


def test_unaccounted_source_facet_is_invalid_topology() -> None:
    declaration, _source, _target, _execution, evidence = _fixture(with_loss=True)
    record = json.loads(declaration)
    record["loss_map"] = []

    receipt = relation.qualify_relation_boundary(relation.canonical_bytes(record), evidence)

    assert receipt.result is relation.RelationResult.INVALID
    assert "PRESERVATION_AND_LOSS_NOT_A_PARTITION" in receipt.reason_codes


@pytest.mark.parametrize("mutation", ["unknown-field", "unsorted", "noncanonical", "oversized"])
def test_relation_declaration_rejects_unknown_fields_bounds_and_canonical_order(
    mutation: str,
) -> None:
    declaration, _source, _target, _execution, _evidence = _fixture(with_loss=True)
    record = json.loads(declaration)
    if mutation == "unknown-field":
        record["equivalent"] = True
        payload = relation.canonical_bytes(record)
    elif mutation == "unsorted":
        record["consumed_facets"] = ["private", "claim"]
        payload = relation.canonical_bytes(record)
    elif mutation == "noncanonical":
        payload = json.dumps(record, indent=2, sort_keys=True).encode("utf-8")
    else:
        payload = b"{" + b" " * grounding.MAX_RECORD_BYTES + b"}"

    with pytest.raises((relation.RelationBoundaryError, grounding.SourceGroundingError)):
        relation.decode_relation_boundary_declaration(payload)


def test_recheck_rejects_receipt_from_changed_evidence() -> None:
    declaration, _source, _target, _execution, evidence = _fixture()
    receipt = relation.build_relation_boundary_receipt(declaration, evidence)
    evidence.pop(json.loads(declaration)["evidence"]["digest"])

    with pytest.raises(relation.RelationBoundaryError, match="NOT_REPRODUCED"):
        relation.recheck_relation_boundary_receipt(declaration, receipt, evidence)


def test_public_receipt_functions_have_single_definitions() -> None:
    tree = ast.parse(Path(relation.__file__).read_text(encoding="utf-8"))
    names = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    assert names.count("build_relation_boundary_receipt") == 1
    assert names.count("recheck_relation_boundary_receipt") == 1
