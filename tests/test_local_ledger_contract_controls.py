"""Actual local LEDGER/TRANSACTION controls for Verifier Standard (VSTD).

Only the fixed worker runs, using its own temporary databases. No operator state,
money, authority channel or repository-supplied command participates.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from verifier.runtime import local_ledger_execution as execution


ADDITIONS = {
    "LEDGER-1.2-local-provisioning-continuity",
    "LEDGER-2.2-local-retention-boundaries",
    "LEDGER-3.2-local-record-integrity",
    "TRANSACTION-1.2-local-resource-selection",
    "TRANSACTION-2.2-local-cancellation-boundary",
    "TRANSACTION-3.2-local-epoch-transition-guards",
}


@pytest.fixture(scope="module")
def observations() -> dict[str, Any]:
    request = {"schema_version": "verifier-local-ledger-execution-request-1", "nonce": "contract-control-regression",
        "object_id": "local-test", "object_digest": "sha256:" + "1" * 64,
        "collection_digest": "sha256:" + "2" * 64}
    result = subprocess.run([sys.executable, "-I", "-S", "-B",
        str(Path(execution.__file__).with_name("local_ledger_worker.py"))],
        input=json.dumps(request).encode(), capture_output=True, timeout=60, check=True)
    report = json.loads(result.stdout)
    assert report["request"] == request
    return report["observations"]


def test_all_additional_controls_have_exact_reasoned_catalog_routes() -> None:
    routes = {row["obligation_id"]: row for row in execution.catalog()}
    assert ADDITIONS <= routes.keys()
    assert all(routes[name]["reason"] and routes[name]["exact_claim"] for name in ADDITIONS)


def test_fixed_worker_observes_the_missing_contract_boundaries(observations: dict[str, Any]) -> None:
    assert "controls" in observations, "The package worker does not yet exercise these contract boundaries."
    assert set(observations["controls"]) == {"provisioning", "retention", "integrity", "resources", "cancellation", "epoch_guards"} | FIELD_EVIDENCE


@pytest.mark.parametrize("coordinate", sorted(name.rsplit("-local-", 1)[0] for name in ADDITIONS))
def test_actual_control_has_a_refutable_state_oracle(observations: dict[str, Any], coordinate: str) -> None:
    assert any(row["coordinate"] == coordinate for row in execution.catalog()), "Required mechanism is absent."
    assert execution.check_observations(coordinate, observations)
    # Labels cannot make missing state evidence pass, even with intact old checks.
    altered = deepcopy(observations)
    section = {"LEDGER-1.2": "provisioning", "LEDGER-2.2": "retention", "LEDGER-3.2": "integrity",
        "TRANSACTION-1.2": "resources", "TRANSACTION-2.2": "cancellation", "TRANSACTION-3.2": "epoch_guards"}[coordinate]
    altered["controls"][section] = {"status": "PASS"}
    try:
        refused = not execution.check_observations(coordinate, altered)
    except (ValueError, KeyError, TypeError):
        refused = True
    assert refused, "Missing state may be refused or malformed, but must never pass."


@pytest.mark.parametrize("coordinate,path,replacement", [
    ("LEDGER-1.2", ("provisioning", "same", "entries"), []),
    ("LEDGER-1.2", ("provisioning", "refused", 0, "outcome"), "RETURNED"),
    ("LEDGER-1.2", ("provisioning", "refused", 1, "state", "metadata"), []),
    ("LEDGER-1.2", ("provisioning", "same", "entries", 0, 0), True),
    ("LEDGER-2.2", ("retention", "count", "before", "count"), 4094),
    ("LEDGER-2.2", ("retention", "bytes", "at_limit", "retained_bytes"), 67108863),
    ("LEDGER-2.2", ("retention", "bytes", "after_exhaustion", "count"), 18),
    ("LEDGER-2.2", ("retention", "count", "duplicate", "status"), "UNKNOWN"),
    ("LEDGER-2.2", ("retention", "count", "after_duplicate", "content_digest"), "changed"),
    ("LEDGER-3.2", ("integrity", "cases", "proposal", "recovery", "status"), "PASS"),
    ("LEDGER-3.2", ("integrity", "cases", "commit_time", "after", "entries"), []),
    ("LEDGER-3.2", ("integrity", "cases", "policy_epoch", "restored", "metadata"), []),
    ("LEDGER-3.2", ("integrity", "cases", "mechanism_digest", "restored_replay", "status"), "FAIL"),
    ("LEDGER-3.2", ("integrity", "cases", "commit_time", "corrupted", "entries", 0, 5), -2),
    ("TRANSACTION-1.2", ("resources", "missing", 0, "after_exists"), True),
    ("TRANSACTION-1.2", ("resources", "missing", 1, "result", "status"), "PASS"),
    ("TRANSACTION-1.2", ("resources", "invalid", 0, "commit", "status"), "PASS"),
    ("TRANSACTION-1.2", ("resources", "invalid", 3, "state", "entries"), []),
    ("TRANSACTION-2.2", ("cancellation", "CancelledError-before", "before_recovery", "sequence"), [["issuance", 1]]),
    ("TRANSACTION-2.2", ("cancellation", "CancelledError-after", "after_recovery", "entries"), []),
    ("TRANSACTION-2.2", ("cancellation", "KeyboardInterrupt-before", "recovery", "status"), "PASS"),
    ("TRANSACTION-2.2", ("cancellation", "KeyboardInterrupt-after", "commit", "status"), "PASS"),
    ("TRANSACTION-3.2", ("epoch_guards", "refused", 3, "value"), 1),
    ("TRANSACTION-3.2", ("epoch_guards", "refused", 0, "outcome"), "RETURNED"),
    ("TRANSACTION-3.2", ("epoch_guards", "advanced", "entries"), []),
    ("TRANSACTION-3.2", ("epoch_guards", "after_stale", "metadata"), [[1, "epoch-guards", "local-check", 4]]),
    ("TRANSACTION-3.2", ("epoch_guards", "duplicate", "status"), "PASS"),
    ("TRANSACTION-3.2", ("epoch_guards", "final", "entries", 1, 2), 1),
    ("TRANSACTION-3.2", ("epoch_guards", "original", "metadata", 0, 3), True),
])
def test_each_control_refutes_wrong_persisted_effects(observations: dict[str, Any], coordinate: str,
        path: tuple[Any, ...], replacement: Any) -> None:
    altered = deepcopy(observations)
    target = altered["controls"]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement
    assert not execution.check_observations(coordinate, altered)


def test_current_six_proposition_commitments_are_explicitly_pinned() -> None:
    # LEDGER-2.1 changed deliberately when its executable claim was strengthened
    # from retained row counting to explicit unit/source/sink/rounding semantics.
    # Pin the new proposition instead of pretending that semantic change did not
    # occur; all other route propositions remain at their prior coordinates.
    expected = {
        "LEDGER-1.1": "sha256:8f8a763e95dc318a14b84b8883576708979ef7963eec8f02a2fb0b7eeba4bf56",
        "LEDGER-2.1": "sha256:d747e792e4f7e8f729b44fbad480ff394d8c2a65f79d0b5e1c588ef02c796a3b",
        "LEDGER-3.1": "sha256:42106e70630115463c9592dda77ce8942eaabe28a4174c1b3ebedc856d01355e",
        "TRANSACTION-1.1": "sha256:0db34cb1e6b3423e9cf8b84782d38e9ab8928b82cbae459c0199f4e8665c27b3",
        "TRANSACTION-2.1": "sha256:f34af6a88de443c0ff741ed6510c20ba2f9d5c08123ef810277215fe2f8a7613",
        "TRANSACTION-3.1": "sha256:e0ffd5087091167c88282960c4cfb50606343fa22d2448b5bd4bd9730913622a",
    }
    current = {row["coordinate"]: row["proposition_digest"] for row in execution.catalog()}
    assert {coordinate: current[coordinate] for coordinate in expected} == expected


FIELD_EVIDENCE = {"ordering", "corrections", "retry", "authorization", "accounting"}


def test_field_evidence_sections_are_observed_before_any_predicate_trusts_them(observations: dict[str, Any]) -> None:
    """RED until the fixed worker observes ordering, corrections, retry, authorization and balance."""
    assert FIELD_EVIDENCE <= set(observations["controls"])


@pytest.mark.parametrize("coordinate,path,replacement", [
    # LEDGER-0.1 ordering is carried by LEDGER-2.1 sequence accounting.
    ("LEDGER-2.1", ("controls", "ordering", "second", "commit_sequence"), 3),
    ("LEDGER-2.1", ("controls", "ordering", "last", "commit_sequence"), 2**63),
    ("LEDGER-2.1", ("controls", "ordering", "last", "commit_sequence"), True),
    ("LEDGER-2.1", ("controls", "ordering", "rows", 1, 0), 3),
    ("LEDGER-2.1", ("controls", "ordering", "rows", 2, 1), "a"),
    ("LEDGER-2.1", ("controls", "ordering", "rows"), []),
    ("LEDGER-2.1", ("controls", "ordering", "sequence"), [["issuance", 5]]),
    ("LEDGER-2.1", ("controls", "ordering", "duplicate", "status"), "PASS"),
    ("LEDGER-2.1", ("controls", "ordering", "uncertain_before", "status"), "PASS"),
    ("LEDGER-2.1", ("controls", "ordering", "uncertain_after", "reason"), "LEDGER_COMMIT_CANCELLED_OR_UNCERTAIN"),
    # LEDGER-0.2 sources and sinks are a balance over every persisted step.
    ("LEDGER-2.1", ("controls", "accounting", "steps", 0, "after", "entries"), []),
    ("LEDGER-2.1", ("controls", "accounting", "steps", 1, "outcome", "status"), "PASS"),
    ("LEDGER-2.1", ("controls", "accounting", "steps", 2, "after", "metadata"), [[1, "accounting", "local-check", 2]]),
    ("LEDGER-2.1", ("controls", "accounting", "steps", 3, "after", "entries", 0, 6), "tampered"),
    ("LEDGER-2.1", ("controls", "accounting", "steps", 5, "after", "entries", 2, 6), "x"),
    ("LEDGER-2.1", ("controls", "accounting", "final", "entries", 0, 1), "z"),
    # LEDGER-0.3 corrections are refused during replay and recovery without mutation.
    ("LEDGER-3.1", ("controls", "corrections", "commit", "status"), "PASS"),
    ("LEDGER-3.1", ("controls", "corrections", "replay", "status"), "PASS"),
    ("LEDGER-3.1", ("controls", "corrections", "recover", "status"), "PASS"),
    ("LEDGER-3.1", ("controls", "corrections", "after", "entries"), []),
    ("LEDGER-3.1", ("controls", "corrections", "epoch", "metadata"), [[1, "corrections", "local-check", 1]]),
    # TRANSACTION-0.3 maps to both local Tier-3 routes; each must bind one
    # backend attempt per selected operation and the finite busy bound.
    *[
        (coordinate, path, replacement)
        for coordinate in ("TRANSACTION-3.1", "TRANSACTION-3.2")
        for path, replacement in (
            (("controls", "retry", "commit_precommit", "attempts"), 2),
            (("controls", "retry", "commit_precommit", "attempts"), True),
            (("controls", "retry", "recover_after_postcommit", "attempts"), 0),
            (("controls", "retry", "commit_postcommit", "outcome", "status"), "PASS"),
            (("controls", "retry", "busy_seconds"), 6.0),
            (("controls", "retry", "busy_seconds"), 0.0),
        )
    ],
    # TRANSACTION-0.1 authority inputs are refused when malformed; authenticity remains boundary-only.
    ("TRANSACTION-1.1", ("controls", "authorization", "refused", "bytes", "status"), "PASS"),
    ("TRANSACTION-1.1", ("controls", "authorization", "refused", "padded", "reason"), "LEDGER_COMMIT_UNAVAILABLE_OR_UNCERTAIN"),
    ("TRANSACTION-1.1", ("controls", "authorization", "boundary", "public_consumption_authentication"), "ESTABLISHED"),
    ("TRANSACTION-1.1", ("controls", "authorization", "after_refusals", "entries"), [["x"]]),
    ("TRANSACTION-1.1", ("controls", "authorization", "final", "entries"), []),
])
def test_new_field_evidence_refutes_wrong_persisted_effects(observations: dict[str, Any], coordinate: str,
        path: tuple[Any, ...], replacement: Any) -> None:
    altered = deepcopy(observations)
    target: Any = altered
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement
    assert not execution.check_observations(coordinate, altered)


@pytest.mark.parametrize("coordinate,section", [
    ("LEDGER-2.1", "ordering"), ("LEDGER-2.1", "accounting"), ("LEDGER-3.1", "corrections"),
    ("TRANSACTION-1.1", "authorization"),
    ("TRANSACTION-3.1", "retry"), ("TRANSACTION-3.2", "retry"),
])
def test_missing_field_evidence_never_passes(observations: dict[str, Any], coordinate: str, section: str) -> None:
    altered = deepcopy(observations)
    del altered["controls"][section]
    try:
        passed = execution.check_observations(coordinate, altered)
    except (KeyError, ValueError, TypeError):
        passed = False
    assert not passed
