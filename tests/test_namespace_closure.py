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


def named(tail: str) -> str:
    """Build a VSTD- token without spelling one.

    This file is scanned by the very gate it tests, and by scripts/
    check_presentation.py besides.  A reject-path fixture written as a plain
    literal would be found by both -- correctly, since finding exactly those
    strings is their job -- so the fixtures name only the tail and the prefix is
    joined on at runtime.  The scanner's token regex requires an alphanumeric
    after the hyphen, so `VSTD-{tail}` in this source matches nothing.

    The assertion is identical at runtime.  Inlining these back into literals
    turns the suite red and gains nothing.
    """

    return f"VSTD-{tail}"


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
    "tail",
    [
        "1", "5", "3.2",
        "DATA", "DATA-1", "OWNER-6", "GRAPH-2.3",
        "BENCH-5.m", "ENV-N", "SIM-1..5",
        "conformant-lowercase-prose",
    ],
)
def test_admits_the_legal_forms(tail: str) -> None:
    assert _gate().admissible(named(tail))


def test_admits_the_base_abstract_bare() -> None:
    assert _gate().admissible("VSTD")


@pytest.mark.parametrize(
    "tail",
    [
        # the heads that actually squatted the namespace before the gate existed
        "SILO-TRANSFER-1", "OBJECT-1", "PUBLISHER-1",
        "PROPOSITION-TRANSFER-RULE-1", "RUNTIME-AUTHORITY-1",
        "UNTRAVERSABLE-1", "ARTIFACT-1", "ZK-1",
        # a plausible future invention
        "REGISTRY-1",
    ],
)
def test_rejects_a_head_the_namespace_never_admitted(tail: str) -> None:
    """The fail path is the whole point: assert it, do not assume it."""

    assert not _gate().admissible(named(tail))


def test_no_zero_is_admissible_in_either_position() -> None:
    """The namespace is 1-indexed in both positions of `<tier>.<module>`.

    The zero tier and the squatting were one defect -- a name that was never an
    object had no real tier available to it -- so repairing the head must not
    leave a route back to the zero, in either position.
    """

    gate = _gate()
    for tail in (
        "0.1", "DATA-0.1", "GRAPH-0.3", "SIM-0.1",     # no zero tier
        "3.0", "DATA-1.0", "SIM-2.0", "GRAPH-4.0",     # no zero module
    ):
        assert not gate.admissible(named(tail)), tail


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
