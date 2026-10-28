from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import jsonschema
import pytest
import referencing

from verifier.runtime.namespace_contracts import namespace_registry, registry_document
from verifier.runtime.namespace_manifest import (
    COMPACT_SCHEMA,
    MAX_COMPACT_EXPANDED_EVIDENCE_REFERENCES,
    MAX_COMPACT_SELECTORS,
    MAX_COMPACT_SELECTORS_PER_OBJECT,
    MAX_COMPACT_EVIDENCE_REFERENCES_PER_OBJECT,
    SCHEMA,
    compact_manifest,
    normalize_manifest,
    validate_manifest,
)
from verifier.runtime.tier_zero_manifest import (
    MAX_PACKAGE_MANIFEST_BYTES,
    MAX_PACKAGE_MANIFEST_NODES,
)
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "src" / "verifier" / "schemas"


def _reference(path: str, digit: str) -> dict[str, str]:
    return {"path": path, "sha256": "sha256:" + digit * 64}


def _v2_manifest() -> dict[str, object]:
    registry = namespace_registry()
    evidence = [_reference("src/subject.py", "a"), _reference("tests/test_subject.py", "b")]
    return {
        "schema_version": SCHEMA,
        "registry_digest": registry_document(registry)["digest"],
        "extensions": [],
        "objects": [{
            "object_id": "subject",
            "kind": "OBJECT",
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": ["subject.route"],
            "reason": "The subject is the bounded object under repository admission.",
            "classification": {
                "OBJECT": {
                    "status": "APPLIES",
                    "reason": "The declared subject is an object.",
                    "evidence": deepcopy(evidence),
                }
            },
            "obligations": {
                "OBJECT-0.1-subject-boundary": {
                    "reason": "The object boundary must remain inspectable.",
                    "declaration": {"contract": "subject.route"},
                    "evidence": deepcopy(evidence),
                }
            },
        }],
    }


def _compact_manifest() -> dict[str, object]:
    return compact_manifest(_v2_manifest())


def _only_digest(document: dict[str, object]) -> str:
    return next(iter(document["objects"][0]["evidence_sets"]))


def _replace_digest(document: dict[str, object], old: str, new: str) -> None:
    row = document["objects"][0]
    for decision in row["classification"].values():
        if decision.get("evidence_set_digest") == old:
            decision["evidence_set_digest"] = new
    for binding in row["obligations"].values():
        if binding.get("evidence_set_digest") == old:
            binding["evidence_set_digest"] = new


def _assert_rejected(document: dict[str, object], code: str) -> None:
    with pytest.raises(ValueError, match=f"^{code}$"):
        validate_manifest(document)


def _replace_evidence_set(
    document: dict[str, object], evidence: list[dict[str, str]],
) -> str:
    row = document["objects"][0]
    old = next(iter(row["evidence_sets"]))
    digest = value_digest(evidence)
    row["evidence_sets"] = {digest: evidence}
    _replace_digest(document, old, digest)
    return digest


def _reuse_selector(
    document: dict[str, object], digest: str, *, obligation_count: int,
) -> None:
    row = document["objects"][0]
    row["obligations"] = {
        "OBJECT-0.amplified-" + str(index): {
            "reason": "The selected evidence remains exact.",
            "declaration": {},
            "evidence_set_digest": digest,
        }
        for index in range(obligation_count)
    }


def test_compact_round_trip_preserves_exact_v2_shape_and_order() -> None:
    inline = _v2_manifest()
    compact = _compact_manifest()

    validate_manifest(inline)
    validate_manifest(compact)
    expanded = normalize_manifest(compact)

    assert expanded == inline
    assert expanded is not inline
    assert expanded["objects"][0]["classification"]["OBJECT"]["evidence"] == [
        _reference("src/subject.py", "a"),
        _reference("tests/test_subject.py", "b"),
    ]
    expanded["objects"][0]["classification"]["OBJECT"]["evidence"][0]["path"] = "changed"
    assert normalize_manifest(compact) == inline


def test_production_encoder_is_deterministic_exact_and_has_no_unused_sets() -> None:
    inline = _v2_manifest()
    before = deepcopy(inline)

    first = compact_manifest(inline)
    second = compact_manifest(deepcopy(inline))
    normalized = normalize_manifest(first)
    row = first["objects"][0]
    digest = _only_digest(first)

    assert inline == before
    assert first == second
    assert canonical_bytes(first) == canonical_bytes(second)
    assert normalized == inline
    assert canonical_bytes(normalized) == canonical_bytes(inline)
    assert first["schema_version"] == COMPACT_SCHEMA
    assert len(row["evidence_sets"]) == 1
    assert set(row["evidence_sets"]) == {digest}
    assert row["classification"]["OBJECT"] == {
        "status": "APPLIES",
        "reason": "The declared subject is an object.",
        "evidence_set_digest": digest,
    }
    assert row["obligations"]["OBJECT-0.1-subject-boundary"][
        "evidence_set_digest"
    ] == digest
    assert "evidence" not in row["classification"]["OBJECT"]
    validate_manifest(first)


def test_encoder_preserves_order_distinct_evidence_arrays() -> None:
    inline = _v2_manifest()
    reversed_evidence = list(reversed(
        inline["objects"][0]["classification"]["OBJECT"]["evidence"]
    ))
    inline["objects"][0]["obligations"][
        "OBJECT-0.1-subject-boundary"
    ]["evidence"] = reversed_evidence

    compact = compact_manifest(inline)

    assert len(compact["objects"][0]["evidence_sets"]) == 2
    assert normalize_manifest(compact) == inline


def test_compact_capacity_constants_retain_the_package_envelope() -> None:
    assert MAX_PACKAGE_MANIFEST_BYTES == 32 * 1024 * 1024
    assert MAX_PACKAGE_MANIFEST_NODES == 1_000_000
    assert MAX_COMPACT_EVIDENCE_REFERENCES_PER_OBJECT == 65_536
    assert MAX_COMPACT_SELECTORS_PER_OBJECT == 65_536
    assert MAX_COMPACT_SELECTORS == MAX_PACKAGE_MANIFEST_NODES
    assert MAX_COMPACT_EXPANDED_EVIDENCE_REFERENCES == MAX_PACKAGE_MANIFEST_NODES


def test_v2_acceptance_and_normalization_remain_unchanged() -> None:
    inline = _v2_manifest()
    legacy_evidence = [
        {"path": "same.py", "sha256": "legacy-free-form"},
        {"path": "same.py", "sha256": "legacy-free-form"},
    ]
    inline["objects"][0]["classification"]["OBJECT"]["evidence"] = deepcopy(legacy_evidence)
    inline["objects"][0]["obligations"]["OBJECT-0.1-subject-boundary"]["evidence"] = deepcopy(legacy_evidence)

    validate_manifest(inline)
    normalized = normalize_manifest(inline)

    assert normalized == inline
    assert normalized is not inline


def test_compact_schema_is_distinct_and_accepts_the_valid_transport() -> None:
    compact_schema = json.loads(
        (SCHEMA_ROOT / "verifier-namespace-manifest-3.schema.json").read_text(encoding="utf-8")
    )
    inline_schema = json.loads(
        (SCHEMA_ROOT / "verifier-objects-manifest-2.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(compact_schema)
    registry = referencing.Registry().with_resource(
        inline_schema["$id"], referencing.Resource.from_contents(inline_schema)
    )
    validator = jsonschema.Draft202012Validator(compact_schema, registry=registry)

    validator.validate(_compact_manifest())
    assert compact_schema["$id"].endswith("/verifier-namespace-manifest-3.schema.json")
    assert compact_schema["properties"]["schema_version"]["const"] == COMPACT_SCHEMA


def test_missing_evidence_set_reference_is_rejected() -> None:
    compact = _compact_manifest()
    compact["objects"][0]["evidence_sets"].clear()
    _assert_rejected(compact, "NAMESPACE_COMPACT_EVIDENCE_SET_REFERENCE_MISSING")


def test_forged_digest_format_is_rejected() -> None:
    compact = _compact_manifest()
    digest = _only_digest(compact)
    compact["objects"][0]["classification"]["OBJECT"]["evidence_set_digest"] = digest.upper()
    _assert_rejected(compact, "NAMESPACE_COMPACT_BINDING_DIGEST_INVALID")


def test_evidence_set_digest_must_recompute_from_exact_content() -> None:
    compact = _compact_manifest()
    digest = _only_digest(compact)
    evidence = compact["objects"][0]["evidence_sets"].pop(digest)
    mismatched = "sha256:" + "f" * 64
    compact["objects"][0]["evidence_sets"][mismatched] = evidence
    _replace_digest(compact, digest, mismatched)
    _assert_rejected(compact, "NAMESPACE_COMPACT_EVIDENCE_SET_DIGEST_DIFFERS")


def test_unused_evidence_set_is_rejected() -> None:
    compact = _compact_manifest()
    unused = [_reference("unused.py", "c")]
    compact["objects"][0]["evidence_sets"][value_digest(unused)] = unused
    _assert_rejected(compact, "NAMESPACE_COMPACT_EVIDENCE_SET_UNUSED")


def test_duplicate_paths_within_one_evidence_set_are_rejected() -> None:
    compact = _compact_manifest()
    digest = _only_digest(compact)
    duplicated = [_reference("same.py", "a"), _reference("same.py", "b")]
    replacement = value_digest(duplicated)
    del compact["objects"][0]["evidence_sets"][digest]
    compact["objects"][0]["evidence_sets"][replacement] = duplicated
    _replace_digest(compact, digest, replacement)
    _assert_rejected(compact, "NAMESPACE_COMPACT_EVIDENCE_PATH_DUPLICATED")


def test_mixed_inline_and_digest_binding_is_rejected_by_runtime_and_schema() -> None:
    compact = _compact_manifest()
    decision = compact["objects"][0]["classification"]["OBJECT"]
    decision["evidence"] = [_reference("mixed.py", "d")]
    _assert_rejected(compact, "NAMESPACE_COMPACT_BINDING_SELECTOR")

    compact_schema = json.loads(
        (SCHEMA_ROOT / "verifier-namespace-manifest-3.schema.json").read_text(encoding="utf-8")
    )
    inline_schema = json.loads(
        (SCHEMA_ROOT / "verifier-objects-manifest-2.schema.json").read_text(encoding="utf-8")
    )
    registry = referencing.Registry().with_resource(
        inline_schema["$id"], referencing.Resource.from_contents(inline_schema)
    )
    validator = jsonschema.Draft202012Validator(compact_schema, registry=registry)
    assert not validator.is_valid(compact)


def test_evidence_array_order_is_digest_significant() -> None:
    compact = _compact_manifest()
    digest = _only_digest(compact)
    compact["objects"][0]["evidence_sets"][digest].reverse()
    _assert_rejected(compact, "NAMESPACE_COMPACT_EVIDENCE_SET_DIGEST_DIFFERS")


def test_compact_inline_binding_remains_lossless_without_a_table_entry() -> None:
    compact = _compact_manifest()
    row = compact["objects"][0]
    digest = _only_digest(compact)
    evidence = row["evidence_sets"][digest]
    for decision in row["classification"].values():
        del decision["evidence_set_digest"]
        decision["evidence"] = deepcopy(evidence)
    for binding in row["obligations"].values():
        del binding["evidence_set_digest"]
        binding["evidence"] = deepcopy(evidence)
    row["evidence_sets"].clear()

    validate_manifest(compact)
    assert normalize_manifest(compact) == _v2_manifest()


def test_reused_large_set_hits_expanded_reference_bound_before_deepcopy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import namespace_manifest

    compact = _compact_manifest()
    evidence = [
        _reference("src/evidence-" + str(index) + ".py", "c")
        for index in range(128)
    ]
    digest = _replace_evidence_set(compact, evidence)
    _reuse_selector(compact, digest, obligation_count=512)

    def no_copy(value: object) -> object:
        raise AssertionError("selector amplification was materialized")

    monkeypatch.setattr(namespace_manifest, "deepcopy", no_copy)
    _assert_rejected(
        compact, "NAMESPACE_COMPACT_EXPANDED_EVIDENCE_CAPACITY",
    )


def test_selector_multiplicity_is_bounded_before_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import namespace_manifest

    compact = _compact_manifest()
    digest = _replace_evidence_set(compact, [])
    _reuse_selector(compact, digest, obligation_count=9)
    monkeypatch.setattr(namespace_manifest, "MAX_COMPACT_SELECTORS_PER_OBJECT", 8)

    def no_copy(value: object) -> object:
        raise AssertionError("selector amplification was materialized")

    monkeypatch.setattr(namespace_manifest, "deepcopy", no_copy)
    _assert_rejected(compact, "NAMESPACE_COMPACT_SELECTOR_CAPACITY")


def test_expanded_structural_nodes_are_globally_bounded_before_deepcopy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import namespace_manifest

    compact = _compact_manifest()
    evidence = [
        _reference("src/evidence-" + str(index) + ".py", "d")
        for index in range(128)
    ]
    digest = _replace_evidence_set(compact, evidence)
    _reuse_selector(compact, digest, obligation_count=499)
    template = compact["objects"][0]
    compact["objects"] = []
    for index in range(6):
        row = deepcopy(template)
        row["object_id"] = "subject-" + str(index)
        compact["objects"].append(row)

    def no_copy(value: object) -> object:
        raise AssertionError("selector amplification was materialized")

    # Isolate the independent structural ceiling: with the production byte
    # ceiling this particular shape is rejected even earlier by its exact
    # projected canonical byte size.
    monkeypatch.setattr(
        namespace_manifest, "MAX_PACKAGE_MANIFEST_BYTES", 128 * 1024 * 1024,
    )
    monkeypatch.setattr(namespace_manifest, "deepcopy", no_copy)
    _assert_rejected(
        compact, "NAMESPACE_COMPACT_EXPANDED_STRUCTURE_CAPACITY",
    )


def test_expanded_canonical_bytes_are_bounded_before_deepcopy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import namespace_manifest

    compact = _compact_manifest()
    evidence = [_reference("p" * 4000, "e")]
    digest = _replace_evidence_set(compact, evidence)
    _reuse_selector(compact, digest, obligation_count=9_000)

    def no_copy(value: object) -> object:
        raise AssertionError("selector amplification was materialized")

    monkeypatch.setattr(namespace_manifest, "deepcopy", no_copy)
    _assert_rejected(compact, "NAMESPACE_COMPACT_EXPANDED_BYTE_CAPACITY")
