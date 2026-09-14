"""Adversarial tests for bounded merge-group policy aggregation."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HEAD = "c" * 40
BASE = "b" * 40


def _module():
    path = ROOT / "scripts" / "check_merge_group_policy.py"
    spec = importlib.util.spec_from_file_location("check_merge_group_policy", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _event(
    *, terminal: int = 31, head: str = HEAD, base: str = BASE, ref_base: str | None = None
) -> dict:
    ref_base = base if ref_base is None else ref_base
    return {
        "action": "checks_requested",
        "merge_group": {
            "head_sha": head,
            "base_sha": base,
            "head_ref": f"refs/heads/gh-readonly-queue/main/pr-{terminal}-{ref_base}",
            "base_ref": "refs/heads/main",
        },
    }


def _queue(numbers: tuple[int, ...] = (30, 31), *, has_next: bool = False) -> dict:
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "mergeQueue": {
                        "entries": {
                            "nodes": [
                                {"position": position, "pullRequest": {"number": number}}
                                for position, number in enumerate(numbers, 1)
                            ],
                            "pageInfo": {"hasNextPage": has_next},
                            "totalCount": len(numbers),
                        }
                    }
                }
            }
        }
    }


def _receipt(number: int) -> dict:
    return {
        "result": "PASS",
        "pull_request_number": number,
        "head_sha": "a" * 40,
        "base_sha": BASE,
        "promotion_record_sha256": "d" * 64,
        "pull_request_body_sha256": "e" * 64,
    }


def test_manifest_conservatively_includes_every_entry_through_terminal() -> None:
    manifest = _module().build_manifest(_event(), _queue())
    assert manifest["required_pull_requests"] == [30, 31]
    assert manifest["terminal_pull_request"] == 31


@pytest.mark.parametrize(
    ("event", "queue", "message"),
    (
        (_event(base="a" * 40, ref_base=BASE), _queue(), "bind its base"),
        (_event(terminal=32), _queue(), "absent"),
        (_event(), _queue(has_next=True), "bounded"),
    ),
)
def test_manifest_fails_closed_on_unbound_or_incomplete_membership(
    event: dict, queue: dict, message: str
) -> None:
    module = _module()
    with pytest.raises(module.MergeGroupPolicyError, match=message):
        module.build_manifest(event, queue)


def test_confirmation_requires_every_exact_receipt(tmp_path: Path) -> None:
    module = _module()
    manifest = module.build_manifest(_event(), _queue())
    (tmp_path / "30.json").write_text(json.dumps(_receipt(30)), encoding="utf-8")
    with pytest.raises(module.MergeGroupPolicyError, match="PR 31"):
        module.confirm(
            manifest=manifest,
            current_event=_event(),
            current_queue=_queue(),
            receipts_dir=tmp_path,
        )


def test_confirmation_rejects_queue_mutation_after_receipts(tmp_path: Path) -> None:
    module = _module()
    manifest = module.build_manifest(_event(), _queue())
    for number in (30, 31):
        (tmp_path / f"{number}.json").write_text(
            json.dumps(_receipt(number)), encoding="utf-8"
        )
    with pytest.raises(module.MergeGroupPolicyError, match="changed"):
        module.confirm(
            manifest=manifest,
            current_event=_event(),
            current_queue=_queue((29, 30, 31)),
            receipts_dir=tmp_path,
        )


def test_confirmation_accepts_complete_unchanged_receipts(tmp_path: Path) -> None:
    module = _module()
    manifest = module.build_manifest(_event(), _queue())
    for number in (30, 31):
        (tmp_path / f"{number}.json").write_text(
            json.dumps(_receipt(number)), encoding="utf-8"
        )
    result = module.confirm(
        manifest=manifest,
        current_event=_event(),
        current_queue=_queue(),
        receipts_dir=tmp_path,
    )
    assert result["result"] == "PASS"
    assert [item["pull_request_number"] for item in result["constituent_receipts"]] == [30, 31]


def test_later_queue_entry_does_not_stale_an_earlier_group(tmp_path: Path) -> None:
    module = _module()
    manifest = module.build_manifest(_event(), _queue())
    for number in (30, 31):
        (tmp_path / f"{number}.json").write_text(
            json.dumps(_receipt(number)), encoding="utf-8"
        )
    result = module.confirm(
        manifest=manifest,
        current_event=_event(),
        current_queue=_queue((30, 31, 32)),
        receipts_dir=tmp_path,
    )
    assert result["result"] == "PASS"
