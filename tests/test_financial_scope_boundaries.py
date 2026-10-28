"""Cross-object regressions for bounded financial execution claims.

Passing a local or retained mechanism is evidence only for its declared model.
It must not be reusable as evidence of real authority, custody, backing,
settlement, finality, market access, or manipulation absence.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from verifier.runtime import local_ledger_execution
from verifier.runtime.local_ledger_worker import observe
from verifier.runtime.tier_zero_profile import value_digest


@pytest.fixture(scope="module")
def ledger_observations(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return observe(Path(tmp_path_factory.mktemp("financial-scope-ledger")))


@pytest.mark.parametrize(
    "coordinate,path",
    [
        ("LEDGER-1.1", ("records", "first")),
        ("LEDGER-2.1", ("records", "first")),
        ("LEDGER-3.1", ("faults", "after", "recovery", "commit")),
        ("LEDGER-1.2", ("controls", "provisioning", "commit")),
        ("LEDGER-2.2", ("controls", "retention", "count", "accepted")),
        ("LEDGER-3.2", ("controls", "integrity", "commit")),
        ("TRANSACTION-1.1", ("controls", "authorization", "boundary")),
        ("TRANSACTION-2.1", ("faults", "after", "recovery", "commit")),
        ("TRANSACTION-3.1", ("epochs", "prior")),
    ],
)
def test_local_receipt_scope_cannot_be_relabelled_as_real_financial_evidence(
    ledger_observations: dict, coordinate: str, path: tuple[str, ...]
) -> None:
    """A self-consistent row count cannot hide an inflated financial claim."""
    assert local_ledger_execution.check_observations(coordinate, ledger_observations)
    changed = deepcopy(ledger_observations)
    receipt = changed
    for part in path:
        receipt = receipt[part]
    receipt["public_consumption_authentication"] = "ESTABLISHED"
    assert not local_ledger_execution.check_observations(coordinate, changed)


def test_local_receipt_field_injection_cannot_extend_the_closed_claim_scope(
    ledger_observations: dict,
) -> None:
    changed = deepcopy(ledger_observations)
    changed["records"]["first"]["real_settlement"] = "PASS"
    assert not local_ledger_execution.check_observations("LEDGER-1.1", changed)


def test_count_preserving_ledger_identity_substitution_is_refused_even_when_rehashed(
    ledger_observations: dict,
) -> None:
    changed = deepcopy(ledger_observations)
    receipt = changed["records"]["first"]
    receipt["ledger_id"] = "substituted-market-ledger"
    receipt["receipt_digest"] = value_digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    assert not local_ledger_execution.check_observations("LEDGER-1.1", changed)
