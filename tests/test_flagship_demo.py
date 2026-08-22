"""Conformance tests for the public, adversarial VSTD flagship demo."""

from __future__ import annotations

import json
from pathlib import Path

from verifiable.runtime.demo import demo_index, demo_report, emit_specimens, run_demo


EXPECTED_OBSERVATIONS = {
    "wrong-artifact": "REJECTED",
    "honest-unknown": "ACCEPTED/UNKNOWN",
    "inflated-tier": "REJECTED",
    "poisoned-ancestor": "GRAPH-LEVEL-0; REVOKED",
}


def test_all_flagship_scenarios_close_the_intended_failure() -> None:
    results = run_demo()
    assert tuple(item.scenario for item in results) == tuple(EXPECTED_OBSERVATIONS)
    assert all(item.ok for item in results)
    for item in results:
        assert item.observed == EXPECTED_OBSERVATIONS[item.scenario]


def test_demo_report_and_emitted_specimens_are_deterministic(tmp_path: Path) -> None:
    first = run_demo()
    second = run_demo()
    assert demo_report(first) == demo_report(second)

    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_paths = emit_specimens(first, first_dir)
    second_paths = emit_specimens(second, second_dir)
    assert [path.name for path in first_paths] == [path.name for path in second_paths]
    for first_path, second_path in zip(first_paths, second_paths):
        assert first_path.read_bytes() == second_path.read_bytes()
        json.loads(first_path.read_text(encoding="utf-8"))


def test_emit_refuses_to_overwrite_different_content(tmp_path: Path) -> None:
    conflicting = tmp_path / "wrong-artifact.json"
    conflicting.write_text("do not replace\n", encoding="utf-8")
    try:
        emit_specimens(run_demo("wrong-artifact"), tmp_path)
    except FileExistsError as exc:
        assert str(conflicting) in str(exc)
    else:
        raise AssertionError("different existing content was overwritten")
    assert conflicting.read_text(encoding="utf-8") == "do not replace\n"


def test_checked_in_specimens_match_the_demo_producer() -> None:
    root = Path(__file__).resolve().parents[1]
    checked = root / "examples" / "flagship_demo" / "specimens"
    for result in run_demo():
        expected = json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"
        assert (checked / f"{result.scenario}.json").read_text(encoding="utf-8") == expected
    expected_index = json.dumps(demo_index(run_demo()), indent=2, sort_keys=True) + "\n"
    assert (checked / "index.json").read_text(encoding="utf-8") == expected_index
