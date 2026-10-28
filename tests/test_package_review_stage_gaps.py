"""A review stage may run past a stale specialization label, but never drop it."""

from __future__ import annotations

from copy import deepcopy

import pytest

from verifier.runtime import package_review_stage_gaps as gaps


def _rows() -> dict[str, dict]:
    return {
        "vstd-example": {
            "object_id": "vstd-example",
            "kind": "LEDGER",
            "specializations": ["POLICY", "PROTOCOL", "TRANSACTION"],
            "classification": {
                "PROTOCOL": {
                    "status": "APPLIES",
                    "reason": "A stored reviewed reason.",
                    "evidence": [{"path": "src/a.py", "sha256": "sha256:" + "a" * 64}],
                },
                "POLICY": {"status": "APPLIES", "reason": "policy", "evidence": []},
            },
            "obligations": {
                "PROTOCOL-0.1-participants": {
                    "reason": "",
                    "evidence": [],
                    "declaration": {"participants": ""},
                },
                "POLICY-0.1-scope": {
                    "reason": "",
                    "evidence": [],
                    "declaration": {"scope": ""},
                },
            },
        }
    }


def _stage_refusing(kind: str, seen: list):
    """A stage that refuses a label it does not support, as the real ones do."""

    def stage(rows):
        seen.append(deepcopy(rows))
        row = rows["vstd-example"]
        if kind in row["specializations"]:
            raise ValueError("PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:vstd-example:" + kind)
        result = deepcopy(rows)
        result["vstd-example"]["classification"]["STAGE"] = {"status": "UNRESOLVED"}
        return result

    return stage


def test_strict_mode_passes_the_refusal_through_untouched():
    rows = _rows()
    with pytest.raises(ValueError, match="LABEL_CONFLICT:vstd-example:PROTOCOL"):
        gaps.run_stage(_stage_refusing("PROTOCOL", []), rows, name="records")
    assert rows == _rows()


def test_record_mode_hides_the_label_from_the_stage_then_restores_all_of_it():
    rows = _rows()
    seen: list = []
    report: list = []
    result = gaps.run_stage(
        _stage_refusing("PROTOCOL", seen),
        rows,
        name="records",
        record_gaps=True,
        report=report,
    )

    row = result["vstd-example"]
    original = _rows()["vstd-example"]
    assert row["specializations"] == original["specializations"]
    assert row["classification"]["PROTOCOL"] == original["classification"]["PROTOCOL"]
    assert row["obligations"] == original["obligations"]
    assert row["classification"]["STAGE"] == {"status": "UNRESOLVED"}
    # The stage that succeeded never saw the label, its cell or its obligations.
    final = seen[-1]["vstd-example"]
    assert "PROTOCOL" not in final["specializations"]
    assert final["classification"]["PROTOCOL"]["status"] == "UNRESOLVED"
    assert final["classification"]["PROTOCOL"]["evidence"] == []
    assert not [name for name in final["obligations"] if name.startswith("PROTOCOL")]
    assert rows == _rows()
    assert report == [
        {
            "stage": "records",
            "object_id": "vstd-example",
            "kind": "PROTOCOL",
            "gap": "STALE_SPECIALIZATION_LABEL",
        }
    ]


def test_record_mode_copies_only_the_row_with_a_hidden_label() -> None:
    rows = _rows()
    rows["vstd-unrelated"] = {"object_id": "vstd-unrelated", "payload": {"large": [1, 2, 3]}}
    observed_identities: list[tuple[bool, bool]] = []

    def stage(current):
        if "PROTOCOL" in current["vstd-example"]["specializations"]:
            raise ValueError(
                "PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:vstd-example:PROTOCOL"
            )
        observed_identities.append(
            (
                current["vstd-example"] is rows["vstd-example"],
                current["vstd-unrelated"] is rows["vstd-unrelated"],
            )
        )
        return deepcopy(dict(current))

    result = gaps.run_stage(
        stage,
        rows,
        name="records",
        record_gaps=True,
    )

    assert observed_identities == [(False, True)]
    assert result["vstd-unrelated"] == rows["vstd-unrelated"]
    assert rows["vstd-example"] == _rows()["vstd-example"]


def test_record_mode_never_hides_the_primary_label():
    def stage(rows):
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:vstd-example:LEDGER")

    with pytest.raises(ValueError, match="LABEL_CONFLICT:vstd-example:LEDGER"):
        gaps.run_stage(stage, _rows(), name="records", record_gaps=True)


def test_record_mode_passes_every_other_refusal_through():
    def stage(rows):
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_DECISION_CONFLICT:vstd-example:PROTOCOL")

    with pytest.raises(ValueError, match="DECISION_CONFLICT"):
        gaps.run_stage(stage, _rows(), name="records", record_gaps=True)


def test_record_mode_cannot_loop_on_a_label_that_stays_refused():
    calls = 0

    def stage(rows):
        nonlocal calls
        calls += 1
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:vstd-example:PROTOCOL")

    with pytest.raises(ValueError, match="LABEL_CONFLICT:vstd-example:PROTOCOL"):
        gaps.run_stage(stage, _rows(), name="records", record_gaps=True)
    assert calls == 2


def test_record_mode_ignores_a_label_the_object_does_not_hold():
    def stage(rows):
        raise ValueError("PACKAGE_SEMANTIC_REVIEW_LABEL_CONFLICT:vstd-example:ASSET")

    with pytest.raises(ValueError, match="LABEL_CONFLICT:vstd-example:ASSET"):
        gaps.run_stage(stage, _rows(), name="records", record_gaps=True)


def _owning_rows() -> dict[str, dict]:
    rows = _rows()
    row = rows["vstd-example"]
    row["surfaces"] = [
        "file:src/a.py",
        "python:src/a.py:run",
        "file:tests/test_a.py",
        "python:tests/test_a.py:test_it",
    ]
    row["classification"]["ASSET"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Refuted over the reviewed source set.",
        "evidence": [{"path": "src/a.py", "sha256": "sha256:" + "a" * 64}],
    }
    return rows


def _surface_recording_stage(seen: list):
    def stage(rows):
        seen.append(list(rows["vstd-example"]["surfaces"]))
        return deepcopy(dict(rows))

    return stage


def test_record_mode_hides_unreviewed_owned_files_then_restores_them_and_reopens_refutations():
    rows = _owning_rows()
    seen: list = []
    report: list = []
    result = gaps.run_stage(
        _surface_recording_stage(seen),
        rows,
        name="package_object",
        record_gaps=True,
        report=report,
        reviewed={"vstd-example": ("src/a.py",)},
    )

    assert seen == [["file:src/a.py", "python:src/a.py:run"]]
    row = result["vstd-example"]
    assert row["surfaces"] == _owning_rows()["vstd-example"]["surfaces"]
    assert row["classification"]["ASSET"]["status"] == "UNRESOLVED"
    assert row["classification"]["ASSET"]["evidence"] == []
    # An APPLIES finding cites reviewed bytes, so extra files cannot weaken it.
    assert row["classification"]["POLICY"]["status"] == "APPLIES"
    assert rows == _owning_rows()
    assert report == [
        {
            "stage": "package_object",
            "object_id": "vstd-example",
            "gap": "UNREVIEWED_OWNED_PATHS",
            "paths": ["tests/test_a.py"],
        }
    ]


def test_record_mode_does_nothing_when_every_owned_file_was_reviewed():
    rows = _owning_rows()
    seen: list = []
    report: list = []
    result = gaps.run_stage(
        _surface_recording_stage(seen),
        rows,
        name="package_object",
        record_gaps=True,
        report=report,
        reviewed={"vstd-example": ("src/a.py", "tests/test_a.py")},
    )
    assert seen == [rows["vstd-example"]["surfaces"]]
    assert result["vstd-example"]["classification"]["ASSET"]["status"] == "DOES_NOT_APPLY"
    assert report == []


def test_record_mode_never_hides_files_when_a_reviewed_file_is_missing():
    rows = _owning_rows()
    seen: list = []
    gaps.run_stage(
        _surface_recording_stage(seen),
        rows,
        name="package_object",
        record_gaps=True,
        reviewed={"vstd-example": ("src/a.py", "src/gone.py")},
    )
    assert seen == [rows["vstd-example"]["surfaces"]]


def test_strict_mode_ignores_the_reviewed_paths():
    rows = _owning_rows()
    seen: list = []
    gaps.run_stage(
        _surface_recording_stage(seen),
        rows,
        name="package_object",
        reviewed={"vstd-example": ("src/a.py",)},
    )
    assert seen == [rows["vstd-example"]["surfaces"]]
