"""Unit tests for verifiable.core.translation -- the translation-boundary
assurance module.

These tests use synthetic, dependency-free "translators" (plain Python
functions), not outlines_core, so they exercise the module's classification
and fail-closed logic in isolation. See
tests/test_outlines_translation_boundary.py for the real, non-toy
application against outlines_core.json_schema.build_regex_from_schema.
"""

from __future__ import annotations

import pytest

from verifiable.core.translation import (
    AMBIGUOUS,
    FAIL_CLOSED_UNSUPPORTED_SEMANTICS,
    DOWNGRADED_PARTIAL_COVERAGE,
    FULL_COVERAGE,
    IGNORED,
    TRANSLATED,
    UNSUPPORTED,
    TranslationRecord,
    TranslationUnit,
    canonical_json_digest,
    differential_probe,
    validate_translation_record,
)


def test_translation_unit_rejects_invalid_status():
    with pytest.raises(ValueError):
        TranslationUnit(construct="x", location="$.x", status="NOT_A_REAL_STATUS")


def test_full_coverage_when_all_units_translated():
    record = TranslationRecord(
        translator_name="toy",
        translator_version="1.0",
        translator_digest="abc123",
        translator_digest_basis="sha256 of toy_translator.py",
        source_digest=canonical_json_digest({"a": 1}),
        units=[
            TranslationUnit(construct="a", location="$.a", status=TRANSLATED, formal_constraint="a==1"),
            TranslationUnit(construct="title", location="$.title", status=IGNORED, trivial=True, note="cosmetic-only field, carries no constraint"),
        ],
    )
    assert record.overall_status() == FULL_COVERAGE
    assert record.coverage_ratio() == 1.0
    assert validate_translation_record(record) == []


def test_unsupported_meaningful_construct_forces_fail_closed():
    record = TranslationRecord(
        translator_name="toy",
        translator_version="1.0",
        translator_digest="abc123",
        translator_digest_basis="sha256 of toy_translator.py",
        source_digest=canonical_json_digest({"a": 1, "b": 2}),
        units=[
            TranslationUnit(construct="a", location="$.a", status=TRANSLATED, formal_constraint="a==1"),
            TranslationUnit(construct="b", location="$.b", status=UNSUPPORTED, note="silently dropped"),
        ],
    )
    assert record.overall_status() == FAIL_CLOSED_UNSUPPORTED_SEMANTICS
    assert record.coverage_ratio() == 0.5
    assert len(record.unsupported_or_ambiguous_meaningful_units()) == 1
    assert validate_translation_record(record) == []


def test_ambiguous_only_without_unsupported_downgrades_but_does_not_fail_closed():
    record = TranslationRecord(
        translator_name="toy",
        translator_version="1.0",
        translator_digest="abc123",
        translator_digest_basis="sha256 of toy_translator.py",
        source_digest=canonical_json_digest({"a": 1}),
        units=[
            TranslationUnit(construct="a", location="$.a", status=AMBIGUOUS, note="translator raised on one variant"),
        ],
    )
    assert record.overall_status() == DOWNGRADED_PARTIAL_COVERAGE


def test_trivial_units_are_exempt_from_fail_closed():
    record = TranslationRecord(
        translator_name="toy",
        translator_version="1.0",
        translator_digest="abc123",
        translator_digest_basis="sha256 of toy_translator.py",
        source_digest=canonical_json_digest({"title": "hello"}),
        units=[
            TranslationUnit(construct="title", location="$.title", status=UNSUPPORTED, trivial=True, note="cosmetic only"),
        ],
    )
    assert record.overall_status() == FULL_COVERAGE
    assert record.coverage_ratio() is None  # zero non-trivial units


def test_validate_catches_translated_without_formal_constraint():
    record = TranslationRecord(
        translator_name="toy",
        translator_version="1.0",
        translator_digest="abc123",
        translator_digest_basis="sha256 of toy_translator.py",
        source_digest=canonical_json_digest({"a": 1}),
        units=[TranslationUnit(construct="a", location="$.a", status=TRANSLATED, formal_constraint=None)],
    )
    errors = validate_translation_record(record)
    assert any("no formal_constraint" in e for e in errors)


def test_validate_requires_digest_or_explicit_unavailable_reason():
    record = TranslationRecord(
        translator_name="opaque",
        translator_version="1.0",
        translator_digest=None,
        translator_digest_basis="",  # no explanation -- should be flagged
        source_digest=canonical_json_digest({"a": 1}),
        units=[],
    )
    errors = validate_translation_record(record)
    assert any("translator_digest" in e for e in errors)

    record_honest = TranslationRecord(
        translator_name="opaque",
        translator_version="1.0",
        translator_digest=None,
        translator_digest_basis="UNAVAILABLE: compiled Rust extension, no readable source artifact to hash",
        source_digest=canonical_json_digest({"a": 1}),
        units=[],
    )
    assert validate_translation_record(record_honest) == []


def test_validate_catches_inconsistent_overall_status_claim():
    # Manually construct a record whose to_dict/overall_status is internally
    # consistent (overall_status is a method, not stored data), so instead
    # verify from_dict round-trips a record whose stored blocking units
    # can't be papered over.
    record = TranslationRecord(
        translator_name="toy",
        translator_version="1.0",
        translator_digest="abc123",
        translator_digest_basis="sha256 of toy_translator.py",
        source_digest=canonical_json_digest({"a": 1}),
        units=[TranslationUnit(construct="a", location="$.a", status=UNSUPPORTED)],
    )
    d = record.to_dict()
    assert d["overall_status"] == FAIL_CLOSED_UNSUPPORTED_SEMANTICS
    restored = TranslationRecord.from_dict(d)
    assert restored.overall_status() == FAIL_CLOSED_UNSUPPORTED_SEMANTICS
    assert restored.units[0].status == UNSUPPORTED


def test_differential_probe_detects_effect():
    def compile_fn(has_feature: bool) -> str:
        return "X+feature" if has_feature else "X"

    unit = differential_probe("feature", "$.feature", compile_fn, True, False)
    assert unit.status == TRANSLATED
    assert unit.formal_constraint == "X+feature"


def test_differential_probe_detects_silent_drop():
    def compile_fn(_ignored: bool) -> str:
        return "X"  # never changes regardless of input -- construct is dropped

    unit = differential_probe("dropped_feature", "$.dropped_feature", compile_fn, True, False)
    assert unit.status == UNSUPPORTED
    assert "identical" in unit.note.lower()


def test_differential_probe_ambiguous_on_translator_exception():
    def compile_fn(x: bool) -> str:
        if x:
            raise RuntimeError("translator chokes on this variant")
        return "X"

    unit = differential_probe("flaky", "$.flaky", compile_fn, True, False)
    assert unit.status == AMBIGUOUS
    assert "raised" in unit.note.lower()


def test_canonical_json_digest_is_deterministic_and_order_independent():
    d1 = canonical_json_digest({"a": 1, "b": 2})
    d2 = canonical_json_digest({"b": 2, "a": 1})
    assert d1 == d2
    assert d1 != canonical_json_digest({"a": 1, "b": 3})


def test_record_canonical_digest_changes_when_units_change():
    base = TranslationRecord(
        translator_name="toy",
        translator_version="1.0",
        translator_digest="abc123",
        translator_digest_basis="sha256 of toy_translator.py",
        source_digest=canonical_json_digest({"a": 1}),
        units=[TranslationUnit(construct="a", location="$.a", status=TRANSLATED, formal_constraint="a==1")],
    )
    d1 = base.canonical_digest()
    base.units.append(TranslationUnit(construct="b", location="$.b", status=UNSUPPORTED))
    d2 = base.canonical_digest()
    assert d1 != d2
