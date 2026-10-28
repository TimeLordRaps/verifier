"""Fail-closed preview of retained-root semantic-ownership consolidation.

Terminology: JavaScript Object Notation (JSON).
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from verifier.runtime.package_manifest_migration import (
    preview_retained_root_takeovers,
    retained_root_takeover_blockers,
)


ROOT = Path(__file__).resolve().parents[1]


def _document() -> dict:
    return json.loads((ROOT / "objects.vstd").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def preview() -> dict:
    return preview_retained_root_takeovers(ROOT, _document())


def _row(preview: dict, object_id: str) -> dict:
    return next(
        row for row in preview["candidates"] if row["object_id"] == object_id
    )


def _codes(blockers: tuple[dict, ...] | list[dict]) -> set[str]:
    return {row["code"] for row in blockers}


def _validate(candidate: dict, document: dict | None = None) -> set[str]:
    return _codes(retained_root_takeover_blockers(
        ROOT, _document() if document is None else document, candidate
    ))


def test_preview_is_deterministic_and_does_not_mutate_the_manifest() -> None:
    document = _document()
    before = json.dumps(document, sort_keys=True, separators=(",", ":"))

    first = preview_retained_root_takeovers(ROOT, document)
    second = preview_retained_root_takeovers(ROOT, document)

    assert first == second
    assert first["digest"] == second["digest"]
    assert json.dumps(document, sort_keys=True, separators=(",", ":")) == before


def test_validator_accepts_the_planner_candidate_shape(preview: dict) -> None:
    data = _row(preview, "vstd-data")

    assert retained_root_takeover_blockers(
        ROOT, _document(), data["proposed"]
    ) == tuple(data["blockers"])


def test_live_preview_blocks_four_roots_on_real_role_and_obligation_differences(
    preview: dict,
) -> None:
    assert preview["status"] == "BLOCKED"
    for object_id in (
        "verifier-core-self", "vstd-data", "vstd-hardware", "vstd-training"
    ):
        row = _row(preview, object_id)
        codes = _codes(row["blockers"])
        assert row["status"] == "BLOCKED"
        assert "RETAINED_ROOT_SEMANTIC_ROLES_DIFFER" in codes
        assert "RETAINED_ROOT_OBLIGATION_SET_DIFFERS" in codes
        assert "RETAINED_ROOT_OPERAND_TARGET_MISSING" not in codes
        assert "CHILD_OPERAND_INHERITANCE_FORBIDDEN" not in codes
        assert "RETAINED_ROOT_PATHS_DIFFER" not in codes
        assert "RETAINED_ROOT_PATH_DIGEST_DIFFERS" not in codes
        assert "RETAINED_ROOT_SOURCE_DRIFT" not in codes
        assert "RETAINED_ROOT_SOURCE_FRAGMENT_KIND_DIFFERS" not in codes
    assert _row(preview, "vstd-training")["proposed"]["operands"] == {
        "arch": ["vstd-architecture"],
        "bench": ["vstd-benchmark"],
        "data": ["vstd-data"],
        "events": ["vstd-event"],
    }


def test_generic_object_fallback_is_explicit_unknown(preview: dict) -> None:
    row = _row(preview, "vstd-package-object")
    codes = _codes(row["blockers"])

    assert row["status"] == "UNKNOWN"
    assert "GENERIC_OBJECT_FALLBACK_ONLY" in codes
    assert "RETAINED_ROOT_PATHS_DIFFER" in codes
    assert "RETAINED_ROOT_SOURCE_DRIFT" in codes
    assert "RETAINED_ROOT_SOURCE_FRAGMENT_KIND_DIFFERS" in codes


def test_same_kind_child_cannot_substitute_for_root(preview: dict) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    candidate["object_id"] = "vstd-data-native-checks"

    assert "RETAINED_ROOT_SAME_ID_REQUIRED" in _validate(candidate)


def test_caller_cannot_supply_a_convenient_same_kind_catalog(preview: dict) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    blockers = retained_root_takeover_blockers(
        ROOT, _document(), candidate, semantic_specs=()
    )

    assert "RETAINED_ROOT_SEMANTIC_CATALOG_DIFFERS" in _codes(blockers)


def test_non_json_candidate_value_returns_typed_blocker(preview: dict) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    candidate["primary_kind"] = {"DATA"}

    assert retained_root_takeover_blockers(ROOT, _document(), candidate) == ({
        "code": "RETAINED_ROOT_CANDIDATE_NOT_CANONICAL_JSON",
        "reason": "A takeover candidate must contain only canonical JSON values.",
    },)


def test_unavailable_repository_root_returns_typed_blocker(
    preview: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    original = Path.resolve

    def fail_selected_root(path: Path, *args: object, **kwargs: object) -> Path:
        if path == ROOT:
            raise OSError("bounded unavailable root")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_selected_root)
    blockers = retained_root_takeover_blockers(ROOT, _document(), candidate)

    assert "RETAINED_ROOT_SOURCE_ROOT_UNAVAILABLE" in _codes(blockers)


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    (
        ("primary_kind", "HARDWARE", "RETAINED_ROOT_ORIGINAL_KIND_DIFFERS"),
        (
            "representation_role",
            "same-kind-convenient-substitute",
            "RETAINED_ROOT_REPRESENTATION_ROLE_DIFFERS",
        ),
        ("operands", {"data": ["vstd-training"]}, "RETAINED_ROOT_OPERANDS_DIFFER"),
    ),
)
def test_kind_role_and_full_operands_are_exact(
    preview: dict, field: str, replacement: object, code: str
) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    candidate[field] = replacement

    assert code in _validate(candidate)


def test_candidate_paths_digest_and_source_denominator_are_all_exact(
    preview: dict,
) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    candidate["owned_paths"].pop()
    candidate["owned_path_set_digest"] = "sha256:" + "0" * 64
    candidate["source_sha256"].pop(next(iter(candidate["source_sha256"])))
    codes = _validate(candidate)

    assert "RETAINED_ROOT_PATHS_DIFFER" in codes
    assert "RETAINED_ROOT_PATH_DIGEST_DIFFERS" in codes
    assert "RETAINED_ROOT_SOURCE_DENOMINATOR_DIFFERS" in codes


def test_duplicate_manifest_graph_and_path_ownership_are_refused(
    preview: dict,
) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    document = _document()
    rows = document["namespace"]["objects"]
    data = next(row for row in rows if row["object_id"] == "vstd-data")
    graph = next(row for row in rows if row["kind"] == "GRAPH")
    other = next(row for row in rows if row["object_id"] == "vstd-human")
    rows.append(deepcopy(data))
    graph["operands"]["members"].append("vstd-data")
    other["surfaces"].append("file:src/verifier/domains/data.py")
    codes = _validate(candidate, document)

    assert "RETAINED_ROOT_MANIFEST_ROW_COUNT_DIFFERS" in codes
    assert "RETAINED_ROOT_GRAPH_MEMBERSHIP_COUNT_DIFFERS" in codes
    assert "RETAINED_ROOT_PATH_OWNER_DUPLICATED" in codes


@pytest.mark.parametrize(
    ("container", "field", "code"),
    (
        ("classification", "reason", "RETAINED_ROOT_CLASSIFICATION_REASON_DIFFERS"),
        ("classification", "evidence", "RETAINED_ROOT_CLASSIFICATION_EVIDENCE_DIFFERS"),
        ("obligations", "reason", "RETAINED_ROOT_OBLIGATION_BINDING_REASON_DIFFERS"),
        ("obligations", "declaration", "RETAINED_ROOT_OBLIGATION_BINDING_DECLARATION_DIFFERS"),
        ("obligations", "evidence", "RETAINED_ROOT_OBLIGATION_BINDING_EVIDENCE_DIFFERS"),
    ),
)
def test_reviewed_binding_reason_declaration_and_evidence_cannot_be_lost(
    preview: dict, container: str, field: str, code: str
) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    binding = candidate[container][next(iter(candidate[container]))]
    binding[field] = [] if field == "evidence" else "forged"

    assert code in _validate(candidate)


def test_object_reason_and_obligation_denominator_cannot_be_lost(
    preview: dict,
) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    candidate["reason"] = "shorter convenient reason"
    candidate["obligations"].pop(next(iter(candidate["obligations"])))
    codes = _validate(candidate)

    assert "RETAINED_ROOT_OBJECT_REASON_DIFFERS" in codes
    assert "RETAINED_ROOT_OBLIGATION_BINDING_SET_DIFFERS" in codes


def test_child_operand_inheritance_is_forbidden(preview: dict) -> None:
    candidate = deepcopy(_row(preview, "vstd-training")["proposed"])
    candidate["source_fragments"][0]["operands"] = deepcopy(candidate["operands"])
    codes = _validate(candidate)

    assert "CHILD_OPERAND_INHERITANCE_FORBIDDEN" in codes
    assert "RETAINED_ROOT_SOURCE_FRAGMENTS_DIFFER" in codes


def test_source_fragment_identity_and_role_decisions_are_exact(preview: dict) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    candidate["source_fragments"][0]["object_id"] = "same-kind-substitute"
    candidate["source_fragments"][0]["root_role_decisions"][0]["status"] = "APPLIES"

    assert "RETAINED_ROOT_SOURCE_FRAGMENTS_DIFFER" in _validate(candidate)


def test_proposed_operand_cycle_is_refused(preview: dict) -> None:
    candidate = deepcopy(_row(preview, "vstd-data")["proposed"])
    # vstd-training already points to vstd-data, so this closes a two-node cycle.
    candidate["operands"] = {"training": ["vstd-training"]}
    codes = _validate(candidate)

    assert "RETAINED_ROOT_OPERANDS_DIFFER" in codes
    assert "RETAINED_ROOT_OPERAND_CYCLE" in codes
