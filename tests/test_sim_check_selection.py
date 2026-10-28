"""Generative simulation specification (SIM) checker selection boundaries.

The synthetic counter's state and action count steps; causal time counts steps.
These tests establish finite checker behavior, not a complete object profile.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from verifier.domains import sim
from verifier.domains.catalog import CHECKS
from verifier.domains.common import Budget, Refuted, Unavailable, digest


CHECK_NAMES = ("replay", "invariants", "refinement", "channels", "shards")


def specimen() -> tuple[dict, dict]:
    """One analytic x -> x + action transition, with all five check contracts."""
    states = [{"x": 0.0}, {"x": 1.0}]
    inputs = {
        "states": states, "entropy": [1.0], "times": [0.0, 1.0],
        "observations": [{"position": 0.0}, {"position": 1.0}],
        "actions": [{"action": 1.0}], "macro_states": deepcopy(states),
        "shards": {name: [{"time": float(i), "state": dict(state), "signature": None}
                          for i, state in enumerate(states)] for name in ("left", "right")},
    }
    artifact = {
        "transition": {"x": {"op": "add", "args": [{"var": "x"}, {"var": "entropy"}]}},
        "initial_state": states[0], "trajectory_digest": digest(states),
        "entropy_digest": digest(inputs["entropy"]), "times_digest": digest(inputs["times"]),
        "invariants": [{"op": "le", "args": [{"var": "x"}, 1.0]}],
        "observation": {"position": {"var": "x"}},
        "action_bounds": {"action": {"minimum": 0.0, "maximum": 1.0}},
        "projection": {"x": {"var": "x"}}, "macro_digest": digest(inputs["macro_states"]),
        "tolerance": 0.0,
        "shards": {"ids": ["left", "right"], "require_signatures": False,
                   "relations": [{"op": "eq", "args": [{"var": "root.x"}, {"var": "left.x"}]},
                                 {"op": "eq", "args": [{"var": "left.x"}, {"var": "right.x"}]}]},
    }
    return artifact, inputs


def test_selected_sim_checks_match_legacy_catalog() -> None:
    assert set(CHECK_NAMES) == {row[0] for row in CHECKS["SIM"]}


@pytest.mark.parametrize("check", CHECK_NAMES)
def test_each_admitted_sim_check_replays_positive_control(check: str) -> None:
    artifact, inputs = specimen()
    assert sim.evaluate(check, artifact, inputs, Budget(10000), witness_keys={}) == {
        "states": 2, "transitions": 1,
    }


@pytest.mark.parametrize("check", ["invariant", "", "INVARIANTS", " invariants", None, True, ["invariants"]])
def test_unknown_sim_check_cannot_return_success(check: Any) -> None:
    artifact, inputs = specimen()
    with pytest.raises(Unavailable, match="unsupported simulation check"):
        sim.evaluate(check, artifact, inputs, Budget(10000), witness_keys={})


def test_text_subclass_cannot_forge_check_selection() -> None:
    class ForgedCheck(str):
        def __eq__(self, other: object) -> bool:
            return True

    artifact, inputs = specimen()
    with pytest.raises(Unavailable, match="unsupported simulation check"):
        sim.evaluate(ForgedCheck("not-a-check"), artifact, inputs, Budget(10000), witness_keys={})


def test_unsupported_check_refuses_before_evidence_or_budget_use() -> None:
    class UnreadableEvidence(dict):
        def __contains__(self, key: object) -> bool:
            raise AssertionError("unsupported selection read evidence")

    budget = Budget(0)
    with pytest.raises(Unavailable, match="unsupported simulation check"):
        sim.evaluate("invariant", UnreadableEvidence(), {}, budget, witness_keys={})
    assert budget.used == 0


@pytest.mark.parametrize("check", CHECK_NAMES)
def test_admitted_checks_still_refute_false_transition(check: str) -> None:
    artifact, inputs = specimen()
    inputs["states"][1]["x"] = 2.0
    artifact["trajectory_digest"] = digest(inputs["states"])
    with pytest.raises(Refuted, match="transition replay differs"):
        sim.evaluate(check, artifact, inputs, Budget(10000), witness_keys={})


@pytest.mark.parametrize("check", CHECK_NAMES)
def test_admitted_checks_preserve_unavailable_resource_result(check: str) -> None:
    artifact, inputs = specimen()
    with pytest.raises(Unavailable, match="operation bound exhausted"):
        sim.evaluate(check, artifact, inputs, Budget(0), witness_keys={})
