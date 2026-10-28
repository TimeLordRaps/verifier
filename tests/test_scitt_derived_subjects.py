"""Terminology: Concise Binary Object Representation (CBOR);
JavaScript Object Notation (JSON).

Known-answer, negative, and claim-binding tests for the pinned Derived Subjects draft."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from verifier.interoperability.scitt.adapter import VstdCoordinates
from verifier.interoperability.scitt.derived_subjects import (
    DRAFT_REVISION,
    DerivedSubjectComparison,
    DerivedSubjectError,
    DerivedSubjectResourceLimit,
    DerivedSubjectValue,
    ScopedIdentifier,
    binding_bytes,
    compare_subject,
    compare_vstd_binding,
    derive_vstd_subject_binding,
    parse_subject_text,
    parse_value_cbor,
    parse_value_json,
    subject_digest,
    subject_preimage,
    subject_text,
    value_to_json_bytes,
    value_to_cbor_bytes,
    vstd_value,
)


def _coordinates(**changes: object) -> VstdCoordinates:
    values: dict[str, object] = {
        "receipt_id": "receipt-1",
        "schema_version": "VSTD4-GDC-1",
        "claim_id": "claim-1",
        "subject": "artifact:sha256:" + "11" * 32,
        "predicate": "content_digest_matches",
        "parameters": {"algorithm": "sha-256", "mode": "exact"},
        "native_result": "PASS",
        "native_canonical_digest": "22" * 32,
        "evidence_bounds": {"max_nodes": 100, "max_seconds": 2},
        "artifact_digests": {"primary": "11" * 32},
        "provenance_references": ("urn:example:source",),
    }
    values.update(changes)
    return VstdCoordinates(**values)  # type: ignore[arg-type]


def test_appendix_a1_empty_value_vector() -> None:
    value = DerivedSubjectValue(b"", b"")
    assert binding_bytes(value).hex() == "00" * 24
    assert subject_preimage(value).hex() == (
        "000000000000001873636974742d646572697665642d7375626a6563742f7631"
        + "00" * 24
    )
    assert subject_digest(value).hex() == (
        "0d06c23223da76324e4675f6dfed69e88146cdc6fa6ced2b965b98c68c14dd14"
    )
    assert subject_text(value) == (
        "scitt-derived-subject-v1."
        "DQbCMiPadjJORnX23-1p6IFGzcb6bO0rlluYxowU3RQ"
    )
    assert parse_value_json(b'{"identifiers":[],"content":"","context":""}') == value
    pytest.importorskip(
        "cbor2",
        reason="OPTIONAL_DEPENDENCY_ABSENT: deterministic CBOR vectors require the scitt extra",
    )
    cbor = bytes.fromhex(
        "a367636f6e74656e744067636f6e74657874406b6964656e7469666965727380"
    )
    assert parse_value_cbor(cbor) == value
    assert value_to_cbor_bytes(value) == cbor


def test_appendix_a2_empty_pair_is_not_empty_set() -> None:
    empty = DerivedSubjectValue(b"", b"")
    one_empty_pair = DerivedSubjectValue(b"", b"", (ScopedIdentifier(b"", b""),))
    assert binding_bytes(one_empty_pair).hex() == "00" * 23 + "01" + "00" * 16
    assert subject_text(one_empty_pair) == (
        "scitt-derived-subject-v1."
        "aFuDQ4EGtUuQbSLL65f6zB6IvhpdaKM2DB5J1Wm-cIo"
    )
    assert subject_text(empty) != subject_text(one_empty_pair)


def test_appendix_a3_pair_framing_distinguishes_boundaries() -> None:
    context = bytes.fromhex("73636f7065642d6672616d696e672f7631")
    content = bytes.fromhex("6c6f63616c")
    left = DerivedSubjectValue(context, content, (ScopedIdentifier(b"ab", b"c"),))
    right = DerivedSubjectValue(context, content, (ScopedIdentifier(b"a", b"bc"),))
    assert subject_text(left) == (
        "scitt-derived-subject-v1."
        "Sry_1GPju02wO5KezhHlMk8HNB2vTPUkzRw7uGisV1o"
    )
    assert subject_text(right) == (
        "scitt-derived-subject-v1."
        "sLXvSqBxUgde22sAaY_IPqYqS5nuVHRAQChw2LSv9_Q"
    )
    assert subject_text(left) != subject_text(right)


def test_appendix_a4_non_utf8_octet_order_vector() -> None:
    q0 = ScopedIdentifier(bytes.fromhex("00667574757265ff"), b"\x02")
    q1 = ScopedIdentifier(b"ecosystem-A", b"\x01")
    value = DerivedSubjectValue(b"c", b"v", (q1, q0))
    assert [item.encoded().hex() for item in value.identifiers] == [
        "000000000000000800667574757265ff000000000000000102",
        "000000000000000b65636f73797374656d2d41000000000000000101",
    ]
    assert binding_bytes(value).hex() == (
        "0000000000000001630000000000000001760000000000000002"
        "000000000000000800667574757265ff000000000000000102"
        "000000000000000b65636f73797374656d2d41000000000000000101"
    )
    assert subject_digest(value).hex() == (
        "35c3b0568e89a1b740e86f18049d29b7a25e11cb8d609f1242db02cc5f07738b"
    )
    assert subject_text(value) == (
        "scitt-derived-subject-v1."
        "NcOwVo6JobdA6G8YBJ0pt6JeEcuNYJ8SQtsCzF8Hc4s"
    )
    published_json = (
        b'{"context":"Yw","content":"dg","identifiers":['
        b'"AAAAAAAAAAgAZnV0dXJl_wAAAAAAAAABAg",'
        b'"AAAAAAAAAAtlY29zeXN0ZW0tQQAAAAAAAAABAQ"]}'
    )
    assert parse_value_json(published_json) == value
    pytest.importorskip(
        "cbor2",
        reason="OPTIONAL_DEPENDENCY_ABSENT: deterministic CBOR vectors require the scitt extra",
    )
    published_cbor = bytes.fromhex(
        "a367636f6e74656e74417667636f6e7465787441636b6964656e746966696572"
        "73825819000000000000000800667574757265ff000000000000000102581c0000"
        "00000000000b65636f73797374656d2d41000000000000000101"
    )
    assert parse_value_cbor(published_cbor) == value
    assert value_to_cbor_bytes(value) == published_cbor


def test_appendix_a5_duplicate_identifier_is_rejected() -> None:
    vector = (
        b'{"context":"","content":"","identifiers":['
        b'"AAAAAAAAAAFhAAAAAAAAAAEx","AAAAAAAAAAFhAAAAAAAAAAEx"]}'
    )
    with pytest.raises(DerivedSubjectError, match="duplicates"):
        parse_value_json(vector)
    pytest.importorskip(
        "cbor2",
        reason="OPTIONAL_DEPENDENCY_ABSENT: deterministic CBOR vectors require the scitt extra",
    )
    cbor = bytes.fromhex(
        "a367636f6e74656e744067636f6e74657874406b6964656e74696669657273"
        "82520000000000000001610000000000000001315200000000000000016100"
        "0000000000000131"
    )
    with pytest.raises(DerivedSubjectError, match="duplicates"):
        parse_value_cbor(cbor)


def test_appendix_a6_noncanonical_identifier_order_is_rejected() -> None:
    vector = (
        b'{"context":"","content":"","identifiers":['
        b'"AAAAAAAAAAJhYQAAAAAAAAABMQ","AAAAAAAAAAF6AAAAAAAAAAEx"]}'
    )
    with pytest.raises(DerivedSubjectError, match="canonical octet order"):
        parse_value_json(vector)
    pytest.importorskip(
        "cbor2",
        reason="OPTIONAL_DEPENDENCY_ABSENT: deterministic CBOR vectors require the scitt extra",
    )
    cbor = bytes.fromhex(
        "a367636f6e74656e744067636f6e74657874406b6964656e74696669657273"
        "8253000000000000000261610000000000000001315200000000000000017a"
        "000000000000000131"
    )
    with pytest.raises(DerivedSubjectError, match="canonical octet order"):
        parse_value_cbor(cbor)


def test_appendix_a7_complete_encoding_octet_order_is_enforced() -> None:
    accepted = (
        b'{"context":"","content":"","identifiers":['
        b'"AAAAAAAAAAAAAAAAAAAAAQw","AAAAAAAAAAAAAAAAAAAAAQ0"]}'
    )
    parsed = parse_value_json(accepted)
    assert value_to_json_bytes(parsed) == (
        b'{"content":"","context":"","identifiers":['
        b'"AAAAAAAAAAAAAAAAAAAAAQw","AAAAAAAAAAAAAAAAAAAAAQ0"]}'
    )
    rejected = accepted.replace(
        b'"AAAAAAAAAAAAAAAAAAAAAQw","AAAAAAAAAAAAAAAAAAAAAQ0"',
        b'"AAAAAAAAAAAAAAAAAAAAAQ0","AAAAAAAAAAAAAAAAAAAAAQw"',
    )
    with pytest.raises(DerivedSubjectError, match="canonical octet order"):
        parse_value_json(rejected)


def test_identifier_set_order_does_not_change_subject() -> None:
    first = ScopedIdentifier(b"z", b"1")
    second = ScopedIdentifier(b"aa", b"1")
    assert subject_text(DerivedSubjectValue(b"c", b"v", (first, second))) == subject_text(
        DerivedSubjectValue(b"c", b"v", (second, first))
    )


def test_duplicate_json_member_and_noncanonical_base64_are_rejected() -> None:
    with pytest.raises(DerivedSubjectError, match="duplicate JSON member"):
        parse_value_json(
            b'{"context":"","context":"","content":"","identifiers":[]}'
        )
    with pytest.raises(DerivedSubjectError, match="unpadded base64url"):
        parse_value_json(b'{"context":"YQ==","content":"","identifiers":[]}')


def test_malformed_profile_subject_is_error_but_other_profile_is_not_established() -> None:
    candidate = DerivedSubjectValue(b"", b"")
    with pytest.raises(DerivedSubjectError, match="32 bytes"):
        compare_subject(
            "scitt-derived-subject-v1.AA",
            candidate,
            semantics_established=True,
        )
    assert (
        compare_subject("urn:other:subject", candidate, semantics_established=True)
        is DerivedSubjectComparison.NOT_ESTABLISHED
    )


def test_profile_revision_and_semantics_must_be_established() -> None:
    value = DerivedSubjectValue(b"", b"")
    observed = subject_text(value)
    assert (
        compare_subject(observed, value, semantics_established=False)
        is DerivedSubjectComparison.NOT_ESTABLISHED
    )
    assert (
        compare_subject(
            observed,
            value,
            semantics_established=True,
            draft_revision="draft-le-scitt-derived-subjects-01",
        )
        is DerivedSubjectComparison.NOT_ESTABLISHED
    )
    assert (
        compare_subject(
            observed,
            value,
            semantics_established=True,
            draft_revision=DRAFT_REVISION,
        )
        is DerivedSubjectComparison.MATCH
    )


def test_vstd_same_subject_and_artifacts_is_deterministic() -> None:
    left = _coordinates(parameters={"mode": "exact", "algorithm": "sha-256"})
    right = _coordinates(parameters={"algorithm": "sha-256", "mode": "exact"})
    assert subject_text(vstd_value(left)) == subject_text(vstd_value(right))
    assert derive_vstd_subject_binding(left) == derive_vstd_subject_binding(right)


def test_vstd_artifact_change_changes_derived_subject() -> None:
    original = _coordinates()
    mutated = _coordinates(
        subject="artifact:sha256:" + "33" * 32,
        artifact_digests={"primary": "33" * 32},
    )
    assert subject_text(vstd_value(original)) != subject_text(vstd_value(mutated))
    assert (
        compare_vstd_binding(original, derive_vstd_subject_binding(mutated).to_dict())
        is DerivedSubjectComparison.NO_MATCH
    )


def test_parameter_change_does_not_redefine_subject_but_full_binding_fails() -> None:
    original = _coordinates()
    changed = _coordinates(parameters={"algorithm": "sha-256", "mode": "prefix"})
    original_binding = derive_vstd_subject_binding(original)
    changed_binding = derive_vstd_subject_binding(changed)
    assert original_binding.subject == changed_binding.subject
    assert original_binding.claim_coordinate_sha256 != changed_binding.claim_coordinate_sha256
    assert (
        compare_vstd_binding(original, changed_binding.to_dict())
        is DerivedSubjectComparison.NO_MATCH
    )


def test_bound_change_is_not_silently_equivalent() -> None:
    original = _coordinates()
    changed = _coordinates(evidence_bounds={"max_nodes": 101, "max_seconds": 2})
    original_binding = derive_vstd_subject_binding(original)
    changed_binding = derive_vstd_subject_binding(changed)
    assert original_binding.subject == changed_binding.subject
    assert original_binding.evidence_bounds_sha256 != changed_binding.evidence_bounds_sha256
    assert (
        compare_vstd_binding(original, changed_binding.to_dict())
        is DerivedSubjectComparison.NO_MATCH
    )


def test_missing_or_unknown_vstd_mapping_is_not_established() -> None:
    coordinates = _coordinates()
    assert compare_vstd_binding(coordinates, None) is DerivedSubjectComparison.NOT_ESTABLISHED
    observed = derive_vstd_subject_binding(coordinates).to_dict()
    observed["mapping_version"] = "unknown-map/9"
    assert (
        compare_vstd_binding(coordinates, observed)
        is DerivedSubjectComparison.NOT_ESTABLISHED
    )


def test_vstd_artifact_identity_cannot_be_replaced_while_binding_stays_strong() -> None:
    coordinates = _coordinates()
    serialized = derive_vstd_subject_binding(coordinates).to_dict()
    attempted_replacement = _coordinates(artifact_digests={"primary": "44" * 32})
    assert (
        compare_vstd_binding(attempted_replacement, serialized)
        is DerivedSubjectComparison.NO_MATCH
    )


def test_local_resource_limits_are_explicit_not_unknown() -> None:
    data = json.dumps({"context": "", "content": "", "identifiers": []}).encode()
    with pytest.raises(DerivedSubjectResourceLimit, match="max_input_bytes"):
        parse_value_json(data, max_input_bytes=len(data) - 1)
    with pytest.raises(DerivedSubjectResourceLimit, match="max_identifiers"):
        parse_value_json(
            b'{"context":"","content":"","identifiers":['
            b'"AAAAAAAAAAAAAAAAAAAAAQw"]}',
            max_identifiers=0,
        )


def test_subject_parser_rejects_padding_and_noncanonical_digest() -> None:
    valid = subject_text(DerivedSubjectValue(b"", b""))
    assert len(parse_subject_text(valid)) == 32
    with pytest.raises(DerivedSubjectError, match="unpadded"):
        parse_subject_text(valid + "=")


def test_dataclass_replace_remains_loss_sensitive() -> None:
    coordinates = _coordinates()
    changed = replace(coordinates, claim_id="claim-2")
    assert derive_vstd_subject_binding(coordinates).subject == derive_vstd_subject_binding(
        changed
    ).subject
    assert derive_vstd_subject_binding(
        coordinates
    ).claim_coordinate_sha256 != derive_vstd_subject_binding(changed).claim_coordinate_sha256
