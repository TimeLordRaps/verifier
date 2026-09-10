"""Evidence-bound silo-composition declaration and receipt tests.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD). These tests establish only the exact
runtime recomputation and canonical bindings they exercise.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from verifier.interoperability.network import (
    ArtifactRelation,
    CensusEntry,
    ContentAddressedStore,
    DerivationEdge,
    NetworkError,
    SiloCommit,
    SiloComposition,
    SiloCompositionAssessmentReceipt,
    build_silo_composition_assessment_receipt,
    canonical_bytes,
    digest_bytes,
    recheck_silo_composition_assessment_receipt,
    silo_composition_mechanism_bytes,
)

from test_artifact_network import _boundary, _complete_silo


def _members(tmp_path: Path) -> tuple[
    tuple[SiloCommit, ContentAddressedStore],
    tuple[SiloCommit, ContentAddressedStore],
    tuple[SiloCommit, ContentAddressedStore],
]:
    first_store, first = _complete_silo(tmp_path / "first")
    second_store, second = _complete_silo(tmp_path / "second")
    second = replace(second, created_at="2026-09-08T00:00:01Z")
    second = replace(second, coverage_universe=_boundary(second, second_store))
    substitute_store, substitute = _complete_silo(tmp_path / "substitute")
    substitute = replace(substitute, created_at="2026-09-08T00:00:02Z")
    substitute = replace(substitute, coverage_universe=_boundary(substitute, substitute_store))
    return (first, first_store), (second, second_store), (substitute, substitute_store)


def _valid_composite(
    tmp_path: Path,
    first: SiloCommit,
    second: SiloCommit,
) -> tuple[SiloCommit, ContentAddressedStore]:
    store, base = _complete_silo(tmp_path / "composite")
    extras = (
        ("members/first.json", canonical_bytes(first.to_dict()), "member-commit"),
        ("members/second.json", canonical_bytes(second.to_dict()), "member-commit"),
        ("adapter.bin", b"adapter", "composition-adapter"),
        ("policy.json", b"additive policy", "composition-policy"),
        ("bridge.json", b"bridge relation", "composition-relation"),
    )
    entries = tuple(
        CensusEntry(path, store.add_object(content, "application/json", kind), "NECESSARY")
        for path, content, kind in extras
    )
    derivations = (*base.derivations, *(DerivationEdge(entry.path, ("ground.txt",), "mechanism.bin") for entry in entries))
    relations = (ArtifactRelation("CHECKS", "members/first.json", "members/second.json", "adapter.bin", "member-compatibility"),)
    composite = replace(base, census=(*base.census, *entries), derivations=derivations, relations=relations)
    composite = replace(composite, coverage_universe=_boundary(composite, store))
    return composite, store


def test_composition_declaration_canonical_roundtrip_and_digest(tmp_path: Path) -> None:
    first, second, _ = _members(tmp_path)
    declaration = SiloComposition((second[0].canonical_digest(), first[0].canonical_digest()))
    assert declaration.member_commit_digests == tuple(sorted(declaration.member_commit_digests))
    assert SiloComposition.from_dict(declaration.to_dict()) == declaration
    assert declaration.canonical_digest() == digest_bytes(canonical_bytes(declaration.to_dict()))

    receipt = build_silo_composition_assessment_receipt(declaration, (second, first))
    assert SiloCompositionAssessmentReceipt.from_dict(receipt.to_dict()) == receipt
    assert receipt.canonical_digest() == digest_bytes(canonical_bytes(receipt.to_dict()))
    assert receipt.composition_mechanism_digest == digest_bytes(silo_composition_mechanism_bytes())


def test_composition_declaration_refuses_noncanonical_or_ambiguous_wire(tmp_path: Path) -> None:
    first, second, _ = _members(tmp_path)
    canonical = SiloComposition((first[0].canonical_digest(), second[0].canonical_digest())).to_dict()
    unsorted = {**canonical, "member_commit_digests": list(reversed(canonical["member_commit_digests"]))}
    duplicate = {**canonical, "member_commit_digests": [canonical["member_commit_digests"][0]] * 2}
    extra = {**canonical, "unexpected": True}
    with pytest.raises(NetworkError, match="canonical member order"):
        SiloComposition.from_dict(unsorted)
    with pytest.raises(NetworkError, match="duplicates"):
        SiloComposition.from_dict(duplicate)
    with pytest.raises(NetworkError, match="exactly its defined fields"):
        SiloComposition.from_dict(extra)
    missing = dict(canonical)
    del missing["composite_commit_digest"]
    with pytest.raises(NetworkError, match="exactly its defined fields"):
        SiloComposition.from_dict(missing)


def test_resolved_members_must_match_declaration_exactly(tmp_path: Path) -> None:
    first, second, substitute = _members(tmp_path)
    declaration = SiloComposition((first[0].canonical_digest(), second[0].canonical_digest()))
    with pytest.raises(NetworkError, match="exactly match"):
        build_silo_composition_assessment_receipt(declaration, (first,))
    with pytest.raises(NetworkError, match="exactly match"):
        build_silo_composition_assessment_receipt(declaration, (first, second, substitute))
    with pytest.raises(NetworkError, match="exactly match"):
        build_silo_composition_assessment_receipt(declaration, (first, substitute))


def test_recheck_rejects_result_receipt_and_mechanism_substitution(tmp_path: Path) -> None:
    first, second, _ = _members(tmp_path)
    declaration = SiloComposition((first[0].canonical_digest(), second[0].canonical_digest()))
    receipt = build_silo_composition_assessment_receipt(declaration, (first, second))
    recheck_silo_composition_assessment_receipt(declaration, receipt, (second, first))

    forged_result = replace(receipt.assessment, result="ADMISSIBLE")
    with pytest.raises(NetworkError, match="independent recomputation"):
        recheck_silo_composition_assessment_receipt(declaration, replace(receipt, assessment=forged_result), (first, second))
    forged_member = replace(receipt.member_assessment_receipts[0], mechanism_digest="sha256:" + "0" * 64)
    with pytest.raises(NetworkError, match="independent recomputation"):
        recheck_silo_composition_assessment_receipt(
            declaration,
            replace(receipt, member_assessment_receipts=(forged_member, *receipt.member_assessment_receipts[1:])),
            (first, second),
        )
    with pytest.raises(NetworkError, match="independent recomputation"):
        recheck_silo_composition_assessment_receipt(
            declaration,
            replace(receipt, composition_mechanism_digest="sha256:" + "0" * 64),
            (first, second),
        )
    with pytest.raises(NetworkError, match="independent recomputation"):
        recheck_silo_composition_assessment_receipt(
            declaration,
            replace(receipt, declaration_digest="sha256:" + "0" * 64),
            (first, second),
        )
    substituted_declaration = SiloComposition((first[0].canonical_digest(),))
    with pytest.raises(NetworkError, match="exactly match"):
        recheck_silo_composition_assessment_receipt(substituted_declaration, receipt, (first, second))


def test_receipt_structure_cross_binds_nested_assessments(tmp_path: Path) -> None:
    first, second, _ = _members(tmp_path)
    declaration = SiloComposition((first[0].canonical_digest(), second[0].canonical_digest()))
    receipt = build_silo_composition_assessment_receipt(declaration, (first, second))
    with pytest.raises(NetworkError, match="equal length"):
        replace(receipt, member_assessment_receipts=receipt.member_assessment_receipts[:1])
    forged_nested = replace(receipt.member_assessment_receipts[0].assessment, completeness="INCOMPLETE")
    with pytest.raises(NetworkError, match="exactly bind"):
        replace(
            receipt,
            member_assessment_receipts=(
                replace(receipt.member_assessment_receipts[0], assessment=forged_nested),
                *receipt.member_assessment_receipts[1:],
            ),
        )
    with pytest.raises(NetworkError, match="presence"):
        replace(receipt, assessment=replace(receipt.assessment, composite_silo=receipt.assessment.silos[0]))
    serialized = receipt.to_dict()
    with pytest.raises(NetworkError, match="canonical unique commit order"):
        SiloCompositionAssessmentReceipt.from_dict({
            **serialized,
            "member_assessment_receipts": list(reversed(serialized["member_assessment_receipts"])),
        })
    with pytest.raises(NetworkError, match="exactly its defined fields"):
        SiloCompositionAssessmentReceipt.from_dict({**serialized, "unexpected": True})


def test_receipt_is_deterministic_and_member_only_fails_closed(tmp_path: Path) -> None:
    first, second, _ = _members(tmp_path)
    declaration = SiloComposition((first[0].canonical_digest(), second[0].canonical_digest()))
    forward = build_silo_composition_assessment_receipt(declaration, (first, second))
    reverse = build_silo_composition_assessment_receipt(declaration, (second, first))
    assert canonical_bytes(forward.to_dict()) == canonical_bytes(reverse.to_dict())
    assert tuple(item.commit_digest for item in forward.member_assessment_receipts) == declaration.member_commit_digests
    assert forward.assessment.result == "NOT_ADMISSIBLE"
    assert forward.assessment.composition_completeness == "UNKNOWN"
    assert forward.assessment.composition_member_binding == "UNKNOWN"
    assert forward.assessment.local_authority_addition_preservation == "UNKNOWN"
    assert forward.assessment.authority_axiom_agency == "UNKNOWN"
    assert forward.composite_assessment_receipt is None


def test_exact_valid_composite_path_is_admissible_and_recheckable(tmp_path: Path) -> None:
    first, second, _ = _members(tmp_path)
    composite = _valid_composite(tmp_path, first[0], second[0])
    declaration = SiloComposition(
        (first[0].canonical_digest(), second[0].canonical_digest()),
        composite[0].canonical_digest(),
    )
    receipt = build_silo_composition_assessment_receipt(declaration, (second, first), composite)
    assert receipt.assessment.result == "ADMISSIBLE"
    assert receipt.assessment.composition_member_binding == "COMPLETE"
    assert receipt.assessment.local_authority_addition_preservation == "COMPLETE"
    assert receipt.composite_assessment_receipt is not None
    recheck_silo_composition_assessment_receipt(declaration, json.loads(canonical_bytes(receipt.to_dict())), (first, second), composite)

    with pytest.raises(NetworkError, match="resolved composite commit"):
        build_silo_composition_assessment_receipt(replace(declaration, composite_commit_digest=None), (first, second), composite)
    with pytest.raises(NetworkError, match="resolved composite commit"):
        recheck_silo_composition_assessment_receipt(declaration, receipt, (first, second), first)
    assert receipt.composite_assessment_receipt is not None
    forged_composite = replace(receipt.composite_assessment_receipt.assessment, completeness="INCOMPLETE")
    with pytest.raises(NetworkError, match="composite receipt must exactly bind"):
        replace(
            receipt,
            composite_assessment_receipt=replace(
                receipt.composite_assessment_receipt,
                assessment=forged_composite,
            ),
        )


def test_published_composition_schemas_validate_runtime_records(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    first, second, _ = _members(tmp_path)
    declaration = SiloComposition((first[0].canonical_digest(), second[0].canonical_digest()))
    receipt = build_silo_composition_assessment_receipt(declaration, (first, second))
    schema_dir = Path("standard/schemas")
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in (
            schema_dir / "vstd-silo-assessment-0.1.schema.json",
            schema_dir / "vstd-silo-assessment-receipt-0.1.schema.json",
            schema_dir / "vstd-silo-composition-0.1.schema.json",
            schema_dir / "vstd-silo-composition-assessment-0.1.schema.json",
            schema_dir / "vstd-silo-composition-assessment-receipt-0.1.schema.json",
        )
    }
    registry = referencing.Registry().with_resources(
        (schema["$id"], referencing.Resource.from_contents(schema))
        for schema in schemas.values()
    )
    jsonschema.Draft202012Validator(
        schemas["vstd-silo-composition-0.1.schema.json"],
        registry=registry,
    ).validate(declaration.to_dict())
    jsonschema.Draft202012Validator(
        schemas["vstd-silo-composition-assessment-receipt-0.1.schema.json"],
        registry=registry,
    ).validate(receipt.to_dict())
