"""Terminology: Verifier Standard (VSTD).

The VSTD-NAMESPACE is closed, and this is what closes it.

`scripts/check_namespace_closure.py` is the gate; these tests keep the gate
honest.  A gate that passes but cannot fail would have admitted all 59 invented
heads just as silently as no gate at all, so the rejection path is asserted here
rather than checked once by hand.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check_namespace_closure.py"


def _gate():
    spec = importlib.util.spec_from_file_location("check_namespace_closure", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repository_holds_no_name_outside_the_namespace() -> None:
    """Every VSTD- identifier on disk names something the namespace contains."""

    found = _gate().offenders()
    assert not found, "names outside the closed VSTD-NAMESPACE:\n" + "\n".join(
        f"  {relative}:{number}: {token}" for relative, number, token in found
    )


def test_the_namespace_is_the_base_abstract_and_sixteen_objects() -> None:
    gate = _gate()
    assert len(gate.OBJECTS) == 16
    assert len(set(gate.OBJECTS)) == 16
    assert set(gate.OBJECTS) == {
        "GRAPH", "ENV", "DATA", "BENCH", "HYPER", "MODEL", "SIM", "HARNESS",
        "AGENT", "BOT", "ACTOR", "ROLE", "COLLECTIVE", "IDENTITY", "HUMAN", "OWNER",
    }


@pytest.mark.parametrize(
    "token",
    [
        "VSTD",
        "VSTD-1", "VSTD-5", "VSTD-3.2",
        "VSTD-DATA", "VSTD-DATA-1", "VSTD-OWNER-6", "VSTD-GRAPH-2.3",
        "VSTD-BENCH-5.m", "VSTD-ENV-N", "VSTD-SIM-1..5",
        "VSTD-conformant-lowercase-prose",
    ],
)
def test_admits_the_legal_forms(token: str) -> None:
    assert _gate().admissible(token)


@pytest.mark.parametrize(
    "token",
    [
        # the heads that actually squatted the namespace before the gate existed
        "VSTD-SILO-TRANSFER-1", "VSTD-OBJECT-1", "VSTD-PUBLISHER-1",
        "VSTD-PROPOSITION-TRANSFER-RULE-1", "VSTD-RUNTIME-AUTHORITY-1",
        "VSTD-UNTRAVERSABLE-1", "VSTD-ARTIFACT-1", "VSTD-ZK-1",
        # a plausible future invention
        "VSTD-REGISTRY-1",
    ],
)
def test_rejects_a_head_the_namespace_never_admitted(token: str) -> None:
    """The fail path is the whole point: assert it, do not assume it."""

    assert not _gate().admissible(token)


def test_the_zero_tier_is_not_admissible() -> None:
    """A zero tier is inadmissible on its own, independently of the head.

    The two defects arrived together -- a name that was never an object reached
    for the one tier the grid does not have -- so fixing the head must not leave
    a route back to the zero.
    """

    gate = _gate()
    # Split the way scripts/check_presentation.py splits its own RETIRED_SURFACES
    # entries, and for the same reason: that gate forbids the bare literal
    # everywhere, and a test asserting the literal is rejected would otherwise
    # trip it.  Joining these back up turns the suite red -- the assertion is
    # identical at runtime, so there is nothing to gain by it.
    zero = "VSTD-" + "0.1"
    for token in (zero, "VSTD-DATA-" + "0.1", "VSTD-GRAPH-0.3", "VSTD-SIM-" + "0.1"):
        assert not gate.admissible(token), token


def test_every_exception_and_pending_head_carries_its_reason() -> None:
    """A name is admitted by an argument, never by an empty slot."""

    gate = _gate()
    for table in (gate.EXCEPTIONS, gate.PENDING):
        for name, reason in table.items():
            assert reason.strip(), f"{name} was admitted without a reason"
            assert len(reason) > 20, f"{name} carries no real reason: {reason!r}"


def test_the_gate_runs_as_a_script() -> None:
    finished = subprocess.run(
        [sys.executable, str(GATE)], capture_output=True, text=True
    )
    assert finished.returncode == 0, finished.stdout + finished.stderr
    assert "PASS" in finished.stdout
