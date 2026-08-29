"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).

Published JavaScript Object Notation (JSON) Schema coverage for the numbered-profile release.

JSON Schema checks document shape. The separately implemented kernel remains authoritative
for grounding, tier, count, binding, and proof semantics.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from verifier.core.certificate import (
    ClaimBinding,
    ClaimCoordinate,
    ClauseGrounding,
    EncodingRule,
    GroundedFact,
    Grounding,
    ResourceBounds,
    VariableGrounding,
    canonical_digest,
)
from verifier.core.kernel import check, reference_descriptor
from verifier.core.refutation import build_horn_certificate
from verifier.data.models import (
    ArtifactNode,
    ArtifactStatus,
    ArtifactType,
    ConflictRecord,
    ProvenanceHypergraph,
)


SCHEMA_DIR = Path(__file__).resolve().parents[1] / "receipts" / "schema"
PUBLISHED_SCHEMAS = (
    "vstd1_receipt.json",
    "vstd1_generic_run_receipt.json",
    "vstd2_receipt.json",
    "vstd3_receipt.json",
    "vstd4_receipt.json",
    "vstd5_receipt.json",
    "vstd4_certificate.json",
    "vstd_graph_receipt.json",
    "vstd3_accelerator_profile.json",
)
HEX = "a" * 64


def _load(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def _certificate():
    formula = ((1,),)
    rule = EncodingRule("RULE:ASSERT", ("claim",), ((1, "claim"),))
    grounding = Grounding(
        variables=(
            VariableGrounding(
                1,
                GroundedFact("artifact:sha256:" + HEX, "declared", "ASSERTED"),
            ),
        ),
        clauses=(
            ClauseGrounding(
                0,
                rule.rule_id,
                {"claim": 1},
                {"claim": "artifact:sha256:" + HEX},
            ),
        ),
        rules=(rule,),
    )
    binding = ClaimBinding(
        claim="the declared artifact exists",
        coordinate=ClaimCoordinate(
            "artifact:sha256:" + HEX, "declared", {"scope": "fixture"}
        ),
        policy_root=canonical_digest([list(clause) for clause in formula]),
        evidence_root=HEX,
        verifier=reference_descriptor(),
        bounds=ResourceBounds(100, 100, 10000),
        prior_commitment=HEX,
    )
    certificate = build_horn_certificate(formula, grounding, binding)
    assert check(certificate, binding=binding).accepted
    return certificate, binding


def _registry() -> Registry:
    certificate_schema = _load("vstd4_certificate.json")
    return Registry().with_resource(
        certificate_schema["$id"], Resource.from_contents(certificate_schema)
    )


def test_every_published_schema_is_valid_draft_2020_12() -> None:
    for name in PUBLISHED_SCHEMAS:
        Draft202012Validator.check_schema(_load(name))


def test_graph_schema_and_runtime_share_status_and_conflict_shapes() -> None:
    schema = _load("vstd_graph_receipt.json")["properties"]["hypergraph"]
    graph = ProvenanceHypergraph()
    graph.add_artifact(
        ArtifactNode("artifact:a", "a", ArtifactType.CORPUS, "a" * 64, status=ArtifactStatus.VALID)
    )
    graph.add_conflict(
        ConflictRecord(
            "conflict:a",
            "artifact:a",
            "content_digest",
            ("sha256:a", "sha256:b"),
            ("receipt:a", "receipt:b"),
        )
    )
    payload = graph.to_dict()
    Draft202012Validator(schema).validate(payload)
    assert ProvenanceHypergraph.from_dict(payload).to_dict() == payload


def test_graph_schema_keeps_legacy_candidate_blocks_additively_valid() -> None:
    candidate_schema = _load("vstd_graph_receipt.json")["properties"][
        "computed_graph_level"
    ]
    legacy = {
        "collection_id": "collection:legacy",
        "level": 2,
        "max_level": 5,
        "blocking_obligations": [],
        "witness_digest": HEX,
        "refutation_digest": HEX,
    }
    Draft202012Validator(candidate_schema).validate(legacy)
    assert "rating_basis" not in candidate_schema["required"]
    assert "conformance_status" not in candidate_schema["required"]


def test_independence_schema_rejects_actorless_independence_claim() -> None:
    basis_schema = _load("vstd1_receipt.json")["properties"]["independent_audit"][
        "properties"
    ]["independence_basis"]
    basis = {
        "independently_verified": True,
        "actor_independence": "NOT_DEMONSTRATED",
        "implementation_separation": "EVIDENCED",
        "runtime_separation": "EVIDENCED",
        "evidence": ["receipt:checker"],
    }
    assert list(Draft202012Validator(basis_schema).iter_errors(basis))


def test_vstd4_gdc_certificate_matches_its_published_schema() -> None:
    certificate, _binding = _certificate()
    Draft202012Validator(_load("vstd4_certificate.json")).validate(
        certificate.to_dict()
    )


def test_vstd4_candidate_receipt_is_explicit_and_keeps_legacy_shape_valid() -> None:
    certificate, binding = _certificate()
    schema = _load("vstd4_receipt.json")
    validator = Draft202012Validator(schema, registry=_registry())
    receipt = {
        "schema_version": "VSTD-4",
        "receipt_id": "VFY-4-SCHEMA-TEST",
        "claim_id": "claim:schema-test",
        "binding": binding.to_dict(),
        "vstd4_depth": 13,
        "conformance_status": "NOT_ESTABLISHED",
        "rung_evidence": {f"4.{index}": f"sha256:{HEX}" for index in range(1, 14)},
        "witness": certificate.to_dict(),
        "ceiling_refutation": certificate.to_dict(),
        "blocking_rungs": ["4.14"],
        "status": "VALID",
    }
    validator.validate(receipt)
    assert "does not establish VSTD-4 conformance" in schema["properties"]["status"]["description"]

    legacy = dict(receipt)
    del legacy["conformance_status"]
    validator.validate(legacy)

    receipt["conformance_status"] = "ESTABLISHED"
    assert list(validator.iter_errors(receipt))
    receipt["conformance_status"] = "NOT_ESTABLISHED"

    receipt["ceiling_refutation"] = None
    errors = list(validator.iter_errors(receipt))
    assert errors
    assert any("not of type 'object'" in error.message for error in errors)


def test_vstd5_schema_requires_replayable_evidence_bound_inputs() -> None:
    schema = _load("vstd5_receipt.json")
    assert schema["properties"]["schema_version"]["const"] == "VSTD-5"
    assert "must recheck" in schema["description"]
    legacy_draft = {
        "schema_version": "VSTD-5-DRAFT",
        "status": "DRAFT",
        "receipt_id": "VFY-5-SCHEMA-TEST",
    }
    assert list(Draft202012Validator(schema).iter_errors(legacy_draft))

    dimension = schema["$defs"]["dimension"]
    assert dimension["required"] == ["state", "binding"]
    assert {"type": "null"} in dimension["properties"]["binding"]["anyOf"]


def test_current_wire_identifiers_and_profile_discriminators() -> None:
    claim = _load("vstd1_receipt.json")["properties"]
    generic = _load("vstd1_generic_run_receipt.json")["properties"]
    assert claim["schema_version"]["enum"] == ["VSTD-1"]
    assert claim["receipt_kind"]["const"] == "claim_mechanics"
    assert generic["schema_version"]["const"] == "VSTD-1"
    assert generic["receipt_kind"]["const"] == "generic_computational_run"
    assert _load("vstd2_receipt.json")["properties"]["schema_version"]["const"] == "VSTD-2"
    assert _load("vstd_graph_receipt.json")["properties"]["schema_version"][
        "enum"
    ] == ["VSTD-DATA-0.1"]
