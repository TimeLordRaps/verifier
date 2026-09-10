"""Terminology: continuous integration (CI); identifier (ID).

Tests for distinct source and executed CI coordinates.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40


def _module():
    path = ROOT / "scripts" / "record_ci_coordinate.py"
    spec = importlib.util.spec_from_file_location("record_ci_coordinate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pull_request_coordinate_keeps_head_base_and_executed_commit_distinct() -> None:
    result = _module().coordinate(
        {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_SHA": MERGE,
            "PULL_REQUEST_HEAD_SHA": HEAD,
            "PULL_REQUEST_BASE_SHA": BASE,
            "GITHUB_REF": "refs/pull/34/merge",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
        }
    )
    assert result["executed_commit"] == MERGE
    assert result["pull_request_head_commit"] == HEAD
    assert result["pull_request_base_commit"] == BASE
    assert result["executed_coordinate_kind"] == "pull_request_integration"
    assert result["run_id"] == "123"


def test_merge_group_requires_executed_head_identity() -> None:
    module = _module()
    environment = {
        "GITHUB_EVENT_NAME": "merge_group",
        "GITHUB_SHA": MERGE,
        "MERGE_GROUP_HEAD_SHA": HEAD,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    with pytest.raises(ValueError, match="differs"):
        module.coordinate(environment)


def test_pull_request_rejects_missing_source_coordinate() -> None:
    module = _module()
    with pytest.raises(ValueError, match="pull-request head"):
        module.coordinate(
            {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_SHA": MERGE,
                "GITHUB_RUN_ID": "123",
                "GITHUB_RUN_ATTEMPT": "1",
            }
        )


def test_coordinate_rejects_unbound_repository_run() -> None:
    module = _module()
    with pytest.raises(ValueError, match="run ID"):
        module.coordinate({"GITHUB_EVENT_NAME": "push", "GITHUB_SHA": HEAD})
