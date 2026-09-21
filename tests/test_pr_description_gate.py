"""Terminology: continuous integration (CI); pull request (PR); Secure Hash Algorithm 256-bit (SHA-256).

Qualify the pull-request description gate.

Every test here asserts the gate *fails* on a description that stopped matching the
tree. A currency check that cannot fail is decoration, so passing on the real
description is the least interesting property it has; these tests discriminate on the
mismatches it exists to catch.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "check_pr_description", ROOT / "scripts" / "check_pr_description.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


GATE = _load_gate()


def _body(head: str, *, domains: str = "six", checks: str = "28", files: str = "620",
          ranges: str = "DATA.1–DATA.5 ENV.1–ENV.4 BENCH.1–BENCH.4 "
                        "HYPER.1–HYPER.5 MODEL.1–MODEL.5 SIM.1–SIM.5") -> str:
    """Build a minimal description carrying exactly the claims the gate reads."""
    return (
        f"This candidate adds {domains} grounded domain adapters with {checks} "
        f"computational checks.\n\n{ranges}\n\n"
        f"Current signed head: `{head}`. The tracked inventory is {files} files.\n"
    )


@pytest.fixture()
def head() -> str:
    return GATE.head_commit()


@pytest.fixture()
def tracked() -> str:
    return str(GATE.tracked_file_count())


def test_a_current_description_passes(head: str, tracked: str) -> None:
    """The gate must not fire on a description that still matches the tree."""
    findings: list[str] = []
    body = _body(head, files=tracked)
    GATE.check_domains_are_described(body, findings)
    GATE.check_counts_are_described(body, findings)
    GATE.check_head_is_bound(body, findings)
    GATE.check_inventory_is_bound(body, findings)
    assert findings == []


def test_an_undescribed_new_domain_fails(head: str, tracked: str, monkeypatch) -> None:
    """Adding an adapter without describing it is the failure this gate exists for.

    This is the load-bearing case: it simulates exactly what happens when HARNESS or
    AGENT lands in the catalogue and the description is left alone.
    """
    inventory = dict(GATE.domain_inventory())
    inventory["HARNESS"] = 5
    monkeypatch.setattr(GATE, "domain_inventory", lambda: inventory)
    monkeypatch.setattr(GATE, "adapter_modules", lambda: set(inventory))

    findings: list[str] = []
    GATE.check_domains_are_described(_body(head, files=tracked), findings)
    assert any("HARNESS" in finding and "never names it" in finding for finding in findings)


def test_a_stale_domain_count_fails(head: str, tracked: str, monkeypatch) -> None:
    """The prose count must follow the catalogue, not the other way round."""
    inventory = dict(GATE.domain_inventory())
    inventory["HARNESS"] = 5
    monkeypatch.setattr(GATE, "domain_inventory", lambda: inventory)

    findings: list[str] = []
    GATE.check_counts_are_described(_body(head, domains="six", files=tracked), findings)
    assert any("seven" in finding for finding in findings)


def test_a_stale_check_total_fails(head: str, tracked: str) -> None:
    findings: list[str] = []
    GATE.check_counts_are_described(_body(head, checks="27", files=tracked), findings)
    assert any("total of 28" in finding for finding in findings)


def test_a_changed_coordinate_range_fails(head: str, tracked: str) -> None:
    """Adding a sixth SIM check without widening the stated range must fail."""
    body = _body(head, files=tracked).replace("SIM.1–SIM.5", "SIM.1–SIM.4")
    findings: list[str] = []
    GATE.check_domains_are_described(body, findings)
    assert any("SIM.1-SIM.5" in finding for finding in findings)


def test_a_stale_head_fails(tracked: str) -> None:
    """A description binds one head; a new push does not inherit its evidence."""
    findings: list[str] = []
    GATE.check_head_is_bound(_body("0" * 40, files=tracked), findings)
    assert any("does not carry forward" in finding for finding in findings)


def test_a_missing_head_fails(tracked: str) -> None:
    findings: list[str] = []
    GATE.check_head_is_bound("no coordinate here", findings)
    assert findings and "no `Current signed head:`" in findings[0]


def test_a_stale_file_inventory_fails(head: str) -> None:
    findings: list[str] = []
    GATE.check_inventory_is_bound(_body(head, files="1"), findings)
    assert any("working tree tracks" in finding for finding in findings)


def test_an_undeclared_module_fails(head: str, tracked: str, monkeypatch) -> None:
    """A module on disk that the catalogue never declares is reported, not ignored."""
    monkeypatch.setattr(GATE, "adapter_modules", lambda: set(GATE.domain_inventory()) | {"AGENT"})
    findings: list[str] = []
    GATE.check_domains_are_described(_body(head, files=tracked), findings)
    assert any("catalogue does not declare" in finding for finding in findings)


def test_the_catalogue_and_the_adapter_modules_agree() -> None:
    """Guard against the gate itself going stale as support modules are added."""
    assert GATE.adapter_modules() == set(GATE.domain_inventory())


def test_the_real_description_is_current() -> None:
    """The committed description must describe the committed tree.

    Skipped rather than failed when the description cannot be read, because absence of
    a description is not evidence that it disagrees.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["gh", "pr", "view", "--json", "body", "--jq", ".body"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:  # pragma: no cover
        pytest.skip(f"OPTIONAL_DEPENDENCY_ABSENT: gh unavailable ({error})")
    if result.returncode != 0:  # pragma: no cover
        pytest.skip("EXTERNAL_SERVICE_BOUNDARY: no readable pull request for this branch")

    findings: list[str] = []
    GATE.check_domains_are_described(result.stdout, findings)
    GATE.check_counts_are_described(result.stdout, findings)
    assert findings == [], findings


def test_an_unparseable_run_field_fails() -> None:
    """Prose appended to a machine-read field must fail here, not silently in the
    continuous integration (CI) checks.

    This is a regression test for a real failure: explanatory text was appended to
    the run line, the promotion workflow's digits-only extraction returned nothing,
    and the step exited with no stated reason.
    """
    findings: list[str] = []
    GATE.check_machine_read_fields_are_parseable(
        "- Repository-check run: 123 — stale; see below\n", findings
    )
    assert any("not parseable" in finding for finding in findings)


def test_a_bare_run_field_passes() -> None:
    findings: list[str] = []
    GATE.check_machine_read_fields_are_parseable("- Repository-check run: 35559556082\n", findings)
    assert findings == []


def test_a_missing_run_field_fails() -> None:
    findings: list[str] = []
    GATE.check_machine_read_fields_are_parseable("no record here", findings)
    assert findings and "no `Repository-check run:`" in findings[0]
