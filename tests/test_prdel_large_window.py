"""Exact bounded large-file source regions; no semantic or binary waiver."""
from __future__ import annotations

from typing import Any

import pytest
from verifier.runtime import prdel


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
@pytest.mark.parametrize("change", ["replace", "insert", "delete"])
def test_large_equal_edges_preserve_exact_small_change(ending, change, monkeypatch):
    lines = [("café-" + str(index) + ending) for index in range(2000)]
    after = list(lines)
    if change == "replace": after[1200] = "changed" + ending
    elif change == "insert": after.insert(1200, "inserted" + ending)
    else: after.pop(1200)
    matcher = prdel.difflib.SequenceMatcher
    products = []
    def bounded(*args, **kwargs):
        products.append(len(args[1]) * len(args[2]))
        assert products[-1] <= 2_000_000
        return matcher(*args, **kwargs)
    monkeypatch.setattr(prdel.difflib, "SequenceMatcher", bounded)
    before_raw, after_raw = "".join(lines).encode(), "".join(after).encode()
    row, = prdel._changes({"source.txt": before_raw}, {"source.txt": after_raw})
    assert products and row["analysis_boundary"] is None
    a,b = row["old_range"]; c,d = row["new_range"]
    assert row["before_text"] == "".join(lines[a-1:b])
    assert row["after_text"] == "".join(after[c-1:d])
    assert lines[:a-1] == after[:c-1] and lines[b:] == after[d:]
    assert lines[:a-1] + after[c-1:d] + lines[b:] == after
    assert row["before_sha256"] == prdel.digest(before_raw)
    assert row["after_sha256"] == prdel.digest(after_raw)


def test_large_changed_window_still_requires_subdivision(monkeypatch):
    monkeypatch.setattr(prdel.difflib, "SequenceMatcher", lambda *args, **kwargs: pytest.fail("unbounded diff"))
    row, = prdel._changes({"large.txt": b"before\n" * 2000}, {"large.txt": b"after\n" * 2000})
    assert row["analysis_boundary"] == "LARGE_REGION_REQUIRES_SUBDIVISION"


def test_binary_change_is_not_supported_by_equal_edge_trimming():
    row, = prdel._changes({"binary": b"\x00before"}, {"binary": b"\x00after"})
    assert row["analysis_boundary"] == "BINARY_CHANGE"


def test_large_mode_only_change_retains_explicit_mode_obligation():
    class Snapshot(dict): pass
    raw = b"same\n" * 2000
    before, after = Snapshot({"script":raw}), Snapshot({"script":raw})
    before.modes = {"script":"100644"}; after.modes = {"script":"100755"}
    row, = prdel._changes(before,after)
    assert row["before_mode"] == "100644" and row["after_mode"] == "100755"
    assert row["before_text"] == row["after_text"] == ""
    assert row["analysis_boundary"] is None



def _reconstruct_regions(before: list[str], after: list[str], rows: list[dict[str, Any]]) -> None:
    old_cursor = new_cursor = 0
    reconstructed = []
    for row in rows:
        a, b = row["old_range"]; c, d = row["new_range"]
        assert a - 1 >= old_cursor and c - 1 >= new_cursor
        assert before[old_cursor:a-1] == after[new_cursor:c-1]
        assert row["before_text"] == "".join(before[a-1:b])
        assert row["after_text"] == "".join(after[c-1:d])
        reconstructed.extend(before[old_cursor:a-1])
        reconstructed.extend(after[c-1:d])
        old_cursor, new_cursor = b, d
    assert before[old_cursor:] == after[new_cursor:]
    reconstructed.extend(before[old_cursor:])
    assert reconstructed == after


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
@pytest.mark.parametrize("mutation", ["scattered", "reordered", "insertion", "deletion"])
def test_internal_anchors_reconstruct_all_changed_bytes(
    ending: str, mutation: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = ["café-" + str(i) + ending for i in range(2200)]
    after = list(before)
    after[0], after[-1] = "changed-first" + ending, "changed-last" + ending
    if mutation == "scattered":
        for i in range(50, 2150, 50): after[i] = "changed-" + str(i) + ending
    elif mutation == "reordered": after[1000:1002] = list(reversed(after[1000:1002]))
    elif mutation == "insertion": after.insert(1000, "inserted" + ending)
    else: after.pop(1000)
    matcher, products = prdel.difflib.SequenceMatcher, []

    def bounded(*args: Any, **kwargs: Any) -> Any:
        products.append(len(args[1]) * len(args[2]))
        assert sum(products) <= 2_000_000
        return matcher(*args, **kwargs)

    monkeypatch.setattr(prdel.difflib, "SequenceMatcher", bounded)
    rows = prdel._changes({"source.txt": "".join(before).encode()}, {"source.txt": "".join(after).encode()})
    assert products and all(row["analysis_boundary"] is None for row in rows)
    _reconstruct_regions(before, after, rows)
    assert sum(len(row["before_text"].splitlines()) for row in rows) < 100


def test_anchor_windows_preflight_the_aggregate_budget_before_any_diff(monkeypatch: pytest.MonkeyPatch) -> None:
    before = b"before-a\n" * 1100 + b"anchor\n" + b"before-b\n" * 1100
    after = b"after-a\n" * 1100 + b"anchor\n" + b"after-b\n" * 1100
    monkeypatch.setattr(prdel.difflib, "SequenceMatcher", lambda *a, **k: pytest.fail("aggregate bound bypass"))
    row, = prdel._changes({"source.txt": before}, {"source.txt": after})
    assert row["analysis_boundary"] == "LARGE_REGION_REQUIRES_SUBDIVISION"


def test_anchor_window_count_bound_refuses_without_partial_diff(monkeypatch: pytest.MonkeyPatch) -> None:
    before, after = ["before\n"] * 1501, ["after\n"] * 1501
    for i in (400, 800, 1200): before[i] = after[i] = "anchor-" + str(i) + "\n"
    monkeypatch.setattr(prdel, "MAX_REGIONS", 2)
    monkeypatch.setattr(prdel.difflib, "SequenceMatcher", lambda *a, **k: pytest.fail("window count bypass"))
    row, = prdel._changes({"source.txt": "".join(before).encode()}, {"source.txt": "".join(after).encode()})
    assert row["analysis_boundary"] == "LARGE_REGION_REQUIRES_SUBDIVISION"
