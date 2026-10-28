"""Reject foreign selections before retained model-lineage child replay.

MODEL means model reproducibility, TRAIN means training-run specification,
and DATA means dataset integrity and lineage. These probes exercise selection
admission and implementation binding; they do not establish historical training.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from verifier.domains.contracts import model_data_lineage as lineage
from verifier.runtime import polish
from test_current_model_data_lineage import selected


class Foreign:
    """Caller-controlled operations must never run during request admission."""

    def __eq__(self, other: object) -> bool:
        raise AssertionError("foreign equality executed")

    def __ne__(self, other: object) -> bool:
        raise AssertionError("foreign inequality executed")

    def __lt__(self, other: object) -> bool:
        raise AssertionError("foreign ordering executed")

    def __le__(self, other: object) -> bool:
        raise AssertionError("foreign ordering executed")

    def __str__(self) -> str:
        raise AssertionError("foreign coercion executed")


FIELDS = (
    "schema_version", "semantic_version", "coordinate", "proposition_digest",
    "object_kind", "subject_id", "object_digest", "collection_digest",
    "evidence_ref", "policy_digest", "limits", "train_subject_id",
    "train_object_digest", "model_data_subject_id", "model_data_object_digest",
    "batch_view_subject_id", "batch_view_object_digest",
    "model_data_certificate_digest", "model_data_request", "model_data_policy",
    "bridge_certificate_digest", "bridge_request", "bridge_policy",
)


@pytest.mark.parametrize("field", FIELDS)
def test_foreign_selection_refuses_before_callbacks_and_replay(
    field: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, request, policy, evidence = selected()
    request[field] = Foreign()
    monkeypatch.setattr(
        lineage.model_data_citation, "recheck_model_data_certificate",
        lambda *a, **kw: pytest.fail("MODEL child dispatched before admission"),
    )
    monkeypatch.setattr(
        lineage.train_data_bridge, "recheck_train_data_bridge_certificate",
        lambda *a, **kw: pytest.fail("TRAIN child dispatched before admission"),
    )
    with pytest.raises(lineage.ModelDataLineageError):
        lineage.build_model_data_lineage_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("field", [
    "model_data_request", "model_data_policy", "bridge_request", "bridge_policy",
])
def test_nested_foreign_selection_refuses_before_replay(
    field: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, request, policy, evidence = selected()
    request[field]["foreign"] = Foreign()
    monkeypatch.setattr(
        lineage.model_data_citation, "recheck_model_data_certificate",
        lambda *a, **kw: pytest.fail("MODEL child dispatched before admission"),
    )
    monkeypatch.setattr(
        lineage.train_data_bridge, "recheck_train_data_bridge_certificate",
        lambda *a, **kw: pytest.fail("TRAIN child dispatched before admission"),
    )
    with pytest.raises(lineage.ModelDataLineageError):
        lineage.build_model_data_lineage_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/model_data_lineage.py", "standard/CURRENT_MODEL_DATA_LINEAGE.md",
])
def test_changed_dependency_invalidates_polish(
    relative: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()

    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before
