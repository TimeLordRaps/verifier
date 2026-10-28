"""A reviewed answer whose source meaning changed is reopened, never inherited."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from verifier.runtime import package_manifest_migration as migration

_DIGEST = "sha256:" + "a" * 64


def _write(root: Path, path: str, text: str) -> None:
    (root / path).parent.mkdir(parents=True, exist_ok=True)
    (root / path).write_text(text, encoding="utf-8")


def _row(object_id: str, kind: str, paths: list[str]) -> dict:
    return {
        "object_id": object_id,
        "kind": kind,
        "specializations": [],
        "payload": {},
        "operands": {},
        "surfaces": ["file:" + path for path in paths],
        "reason": "Synthetic owner.",
        "classification": {
            "POLICY": {
                "status": "APPLIES",
                "reason": "Reviewed policy role.",
                "evidence": [{"path": path, "sha256": _DIGEST} for path in paths],
            },
            "ASSET": {
                "status": "DOES_NOT_APPLY",
                "reason": "Reviewed refutation.",
                "evidence": [{"path": paths[0], "sha256": _DIGEST}],
            },
            "MARKET": {"status": "UNRESOLVED", "reason": "Open.", "evidence": []},
        },
        "obligations": {
            "POLICY-0.1-scope": {
                "reason": "Reviewed scope.",
                "evidence": [{"path": paths[0], "sha256": _DIGEST}],
                "declaration": {"scope": "Authored scope text."},
            },
            "POLICY-0.2-other": {
                "reason": "",
                "evidence": [],
                "declaration": {"other": ""},
            },
        },
    }


def _document(root: Path) -> dict:
    _write(root, "a.py", "def a():\n    return 1\n")
    _write(root, "b.py", "def b():\n    return 2\n")
    rows = {
        "vstd-owner-a": _row("vstd-owner-a", "VERIFIER", ["a.py"]),
        "vstd-owner-b": _row("vstd-owner-b", "VERIFIER", ["b.py"]),
        "vstd-package-graph": {
            "object_id": "vstd-package-graph",
            "kind": "GRAPH",
            "specializations": [],
            "payload": {},
            "operands": {},
            "surfaces": [],
            "reason": "Graph.",
            "classification": {},
            "obligations": {},
        },
    }
    rows["vstd-package-graph"]["payload"]["source_semantic_profile"] = (
        migration.source_semantic_profile(root, rows)
    )
    return {"namespace": {"objects": list(rows.values())}}


def _deltas(root: Path, document: dict) -> list[dict]:
    from verifier.runtime import package_manifest_refresh as refresh

    profile = next(
        row["payload"]["source_semantic_profile"]
        for row in document["namespace"]["objects"]
        if row["object_id"] == "vstd-package-graph"
    )
    return refresh._source_semantic_deltas(root, profile)


def _by_id(document: dict) -> dict:
    return {row["object_id"]: row for row in document["namespace"]["objects"]}


def test_unchanged_sources_reopen_nothing(tmp_path):
    document = _document(tmp_path)
    reopened, gaps = migration.reopen_changed_source_answers(tmp_path, document, [])
    assert reopened == document
    assert gaps == []


def test_changed_source_reopens_only_the_answers_bound_to_it(tmp_path):
    document = _document(tmp_path)
    original = deepcopy(document)
    _write(tmp_path, "a.py", "def a():\n    return 99\n")

    deltas = _deltas(tmp_path, document)
    reopened, gaps = migration.reopen_changed_source_answers(
        tmp_path, document, deltas
    )

    assert document == original
    rows = _by_id(reopened)
    a, b = rows["vstd-owner-a"], rows["vstd-owner-b"]
    assert b == _by_id(original)["vstd-owner-b"]
    assert a["classification"]["POLICY"]["status"] == "UNRESOLVED"
    assert a["classification"]["POLICY"]["evidence"] == []
    assert "a.py" in a["classification"]["POLICY"]["reason"]
    assert a["classification"]["ASSET"]["status"] == "UNRESOLVED"
    # An open question stays exactly as it was.
    assert a["classification"]["MARKET"] == original_row(original, "vstd-owner-a")[
        "classification"
    ]["MARKET"]
    scope = a["obligations"]["POLICY-0.1-scope"]
    assert scope == {"reason": "", "evidence": [], "declaration": {"scope": ""}}
    assert a["obligations"]["POLICY-0.2-other"] == original_row(
        original, "vstd-owner-a"
    )["obligations"]["POLICY-0.2-other"]
    assert gaps == [
        {
            "stage": "source_semantics",
            "gap": "SOURCE_SEMANTICS_CHANGED",
            "path": "a.py",
            "object_id": "vstd-owner-a",
            "classifications": ["ASSET", "POLICY"],
            "obligations": ["POLICY-0.1-scope"],
        }
    ]


def original_row(document: dict, object_id: str) -> dict:
    return _by_id(document)[object_id]


def test_the_profile_is_regenerated_over_the_remaining_answers(tmp_path):
    document = _document(tmp_path)
    _write(tmp_path, "a.py", "def a():\n    return 99\n")
    deltas = _deltas(tmp_path, document)
    reopened, _ = migration.reopen_changed_source_answers(tmp_path, document, deltas)

    profile = _by_id(reopened)["vstd-package-graph"]["payload"][
        "source_semantic_profile"
    ]
    assert [record.split("\t")[0] for record in profile["records"]] == ["b.py"]
    # The reopened document now passes the strict refusal it would otherwise hit.
    migration._validate_source_semantic_refresh(tmp_path, reopened)
    with pytest.raises(ValueError, match="SOURCE_SEMANTICS_CHANGED:a.py"):
        migration._validate_source_semantic_refresh(tmp_path, document)


def test_a_deleted_source_reopens_its_answers_too(tmp_path):
    document = _document(tmp_path)
    (tmp_path / "b.py").unlink()
    deltas = _deltas(tmp_path, document)
    assert {delta["reason"] for delta in deltas} == {"SOURCE_UNAVAILABLE"}

    reopened, gaps = migration.reopen_changed_source_answers(
        tmp_path, document, deltas
    )
    assert _by_id(reopened)["vstd-owner-b"]["classification"]["POLICY"][
        "status"
    ] == "UNRESOLVED"
    assert [gap["path"] for gap in gaps] == ["b.py"]


def test_a_comment_only_edit_changes_no_semantics_and_reopens_nothing(tmp_path):
    document = _document(tmp_path)
    _write(tmp_path, "a.py", "# a note\ndef a():\n    return 1\n")
    assert _deltas(tmp_path, document) == []


def test_an_answer_the_review_just_rederived_against_the_new_bytes_is_not_reopened(
    tmp_path,
):
    document = _document(tmp_path)
    previous = _by_id(deepcopy(document))
    _write(tmp_path, "a.py", "def a():\n    return 99\n")
    deltas = _deltas(tmp_path, document)
    rows = _by_id(deepcopy(document))
    owner = rows["vstd-owner-a"]
    fresh = [{"path": "a.py", "sha256": "sha256:" + "b" * 64}]
    # The reviewed catalog re-evaluated the policy role and its scope on the new bytes.
    owner["classification"]["POLICY"] = {
        "status": "APPLIES", "reason": "Reviewed policy role.", "evidence": fresh,
    }
    owner["obligations"]["POLICY-0.1-scope"] = {
        "reason": "Reviewed scope.",
        "evidence": fresh,
        "declaration": {"scope": "Authored scope text."},
    }

    gaps = migration._reopen_rows(rows, deltas, previous)

    assert owner["classification"]["POLICY"]["evidence"] == fresh
    assert owner["obligations"]["POLICY-0.1-scope"]["declaration"] == {
        "scope": "Authored scope text."
    }
    # The refutation nothing re-derived is still the inherited answer, so it reopens.
    assert owner["classification"]["ASSET"]["status"] == "UNRESOLVED"
    assert gaps == [
        {
            "stage": "source_semantics",
            "gap": "SOURCE_SEMANTICS_CHANGED",
            "path": "a.py",
            "object_id": "vstd-owner-a",
            "classifications": ["ASSET"],
            "obligations": [],
            "readopted_classifications": ["POLICY"],
            "readopted_obligations": ["POLICY-0.1-scope"],
        }
    ]


def test_an_inherited_answer_is_reopened_even_when_previous_rows_are_supplied(tmp_path):
    document = _document(tmp_path)
    previous = _by_id(deepcopy(document))
    _write(tmp_path, "a.py", "def a():\n    return 99\n")
    deltas = _deltas(tmp_path, document)
    rows = _by_id(deepcopy(document))

    gaps = migration._reopen_rows(rows, deltas, previous)

    owner = rows["vstd-owner-a"]
    assert owner["classification"]["POLICY"]["status"] == "UNRESOLVED"
    assert owner["obligations"]["POLICY-0.1-scope"]["evidence"] == []
    assert gaps[0]["classifications"] == ["ASSET", "POLICY"]
    assert gaps[0]["obligations"] == ["POLICY-0.1-scope"]
    assert "readopted_classifications" not in gaps[0]
    assert "readopted_obligations" not in gaps[0]
