"""Adversarial checks for the in-memory two-resource transaction declaration model.

Terminology: JavaScript Object Notation (JSON).

These propositions cover only the transaction coordinator in
``verifier.runtime.transaction_execution``. A local ledger PASS is not used as
evidence here, and no test reads ledger state.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import pytest

from verifier.runtime import local_ledger_execution, package_execution
from verifier.runtime import transaction_execution as tx
from verifier.runtime.transaction_execution import Coordinator, LocalResource, SimulatedCrash

KEY = b"transaction-test-authorizer-key-0001"


def pre(resource: str, key: str, expected: Any) -> dict[str, Any]:
    return {"resource": resource, "key": key, "expected": expected}


def eff(resource: str, key: str, new_value: Any) -> dict[str, Any]:
    return {"resource": resource, "key": key, "new_value": new_value}


def body(op: str = "op-1", *, authorizer: str = "auth-1", limit: int = 0,
         preconditions: list | None = None, effects: list | None = None) -> dict[str, Any]:
    return {
        "schema": tx.SCHEMA_REQUEST, "operation_id": op, "authorizer": authorizer, "retry_limit": limit,
        "preconditions": preconditions if preconditions is not None
        else [pre("resource_a", "slot", "a0"), pre("resource_b", "slot", "b0")],
        "effects": effects if effects is not None
        else [eff("resource_a", "slot", "a1"), eff("resource_b", "slot", "b1")],
    }


def signed(request_body: dict[str, Any], key: bytes = KEY) -> dict[str, Any]:
    return {**request_body, "authorization_tag": tx.authorization_tag(key, request_body)}


def make(a_values: dict | None = None, b_values: dict | None = None) -> tuple[Coordinator, LocalResource, LocalResource]:
    a = LocalResource("resource_a", a_values if a_values is not None else {"slot": "a0"})
    b = LocalResource("resource_b", b_values if b_values is not None else {"slot": "b0"})
    return Coordinator({"auth-1": KEY}, a, b), a, b


def values_of(a: LocalResource, b: LocalResource) -> tuple[dict, dict]:
    return dict(a.values), dict(b.values)


def fails(receipt: dict[str, Any], reason: str) -> None:
    assert receipt["status"] == "FAIL", receipt["reasons"]
    assert reason in receipt["reasons"], receipt["reasons"]


def test_module_is_stdlib_only_and_does_not_read_ledger_routes() -> None:
    source = Path(tx.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    assert roots <= set(sys.stdlib_module_names), roots
    assert "local_ledger" not in source and "package_execution" not in source


def test_happy_path_commits_both_resources_and_reports_only_local_finality() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body()))
    assert prepared["status"] == "PASS" and prepared["state"] == "PREPARED"
    assert prepared["dispositions"]["authorization"] == "PASS"
    committed = coord.commit("op-1", prepared)
    assert committed["status"] == "PASS" and committed["state"] == "COMMITTED"
    assert committed["finality"] == "FINAL_LOCAL_RECORD"
    assert committed["external_settlement"] == "NOT_ESTABLISHED"
    assert committed["dispositions"]["atomicity"] == "ALL_EFFECTS_APPLIED"
    assert a.values["slot"] == "a1" and b.values["slot"] == "b1"
    assert a.write_count == 1 and b.write_count == 1


def test_identity_authentication_is_not_established_even_when_tag_verifies() -> None:
    coord, _, _ = make()
    receipt = coord.prepare(signed(body()))
    assert receipt["dispositions"]["authorization"] == "PASS"
    assert receipt["authorization"]["identity_authentication"] == "NOT_ESTABLISHED"
    assert receipt["authorization"]["authorizer"] == "auth-1"


FORGERIES: dict[str, Callable[[], dict[str, Any]]] = {
    "wrong_key": lambda: signed(body(), key=b"w" * 32),
    "tag_for_other_effects": lambda: {
        **body(effects=[eff("resource_a", "slot", "a9"), eff("resource_b", "slot", "b1")]),
        "authorization_tag": tx.authorization_tag(KEY, body())},
    "tag_for_other_operation": lambda: {**body("op-1"), "authorization_tag": tx.authorization_tag(KEY, body("op-2"))},
    "unknown_authorizer": lambda: signed(body(authorizer="auth-9")),
    "uppercase_tag": lambda: {**signed(body()), "authorization_tag": tx.authorization_tag(KEY, body()).upper()},
    "missing_tag": lambda: {k: v for k, v in signed(body()).items() if k != "authorization_tag"},
}


@pytest.mark.parametrize("name", sorted(FORGERIES))
def test_forged_authority_is_refused_before_any_record_or_mutation(name: str) -> None:
    coord, a, b = make()
    before = values_of(a, b)
    receipt = coord.prepare(FORGERIES[name]())
    assert receipt["status"] == "FAIL" and receipt["state"] == "REFUSED"
    assert coord.journal == [] and values_of(a, b) == before
    assert a.write_count == b.write_count == 0
    # A refused forgery consumes no operation identifier, so the genuine request still prepares.
    assert coord.prepare(signed(body()))["status"] == "PASS"


def _mutate(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    request_body = body()
    change(request_body)
    return signed(request_body)


MALFORMED: dict[str, Callable[[dict[str, Any]], None]] = {
    "extra_top_field": lambda r: r.__setitem__("extra", 1),
    "extra_precondition_field": lambda r: r["preconditions"][0].__setitem__("note", "x"),
    "extra_effect_field": lambda r: r["effects"][0].__setitem__("expected", "a0"),
    "float_value": lambda r: r["effects"][0].__setitem__("new_value", 1.5),
    "tuple_preconditions": lambda r: r.__setitem__("preconditions", tuple(r["preconditions"])),
    "string_retry_limit": lambda r: r.__setitem__("retry_limit", "1"),
    "bool_retry_limit": lambda r: r.__setitem__("retry_limit", True),
    "retry_limit_over_bound": lambda r: r.__setitem__("retry_limit", tx.MAX_RETRY_LIMIT + 1),
    "duplicate_effect_target": lambda r: r["effects"].append(eff("resource_a", "slot", "a2")),
    "effect_without_precondition": lambda r: r["preconditions"].pop(1),
    "noop_effect": lambda r: r["effects"][0].__setitem__("new_value", "a0"),
    "single_resource": lambda r: r.__setitem__("effects", [eff("resource_a", "slot", "a1")]),
    "wrong_schema": lambda r: r.__setitem__("schema", "other"),
    "uppercase_operation_id": lambda r: r.__setitem__("operation_id", "Op 1"),
    "empty_effects": lambda r: r.__setitem__("effects", []),
    "unknown_resource": lambda r: r["effects"][0].__setitem__("resource", "resource_c"),
    "uppercase_key": lambda r: r["effects"][0].__setitem__("key", "Slot"),
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_closed_request_forms_refuse_without_mutation(name: str) -> None:
    coord, a, b = make()
    before = values_of(a, b)
    receipt = coord.prepare(_mutate(MALFORMED[name]))
    assert receipt["status"] == "FAIL" and receipt["state"] == "REFUSED"
    assert coord.journal == [] and values_of(a, b) == before
    assert a.write_count == b.write_count == 0


def test_undeclared_key_is_refused_at_prepare_without_record() -> None:
    coord, a, b = make()
    ghost = body(preconditions=[pre("resource_a", "ghost", "a0"), pre("resource_b", "slot", "b0")],
                 effects=[eff("resource_a", "ghost", "a1"), eff("resource_b", "slot", "b1")])
    fails(coord.prepare(signed(ghost)), "PRECONDITION_KEY_UNDECLARED")
    assert coord.journal == [] and values_of(a, b) == ({"slot": "a0"}, {"slot": "b0"})


def test_bool_and_int_remain_distinct_in_preconditions_and_effects() -> None:
    coord, a, _ = make({"slot": 1}, {"slot": "b0"})
    refused = coord.prepare(signed(body(preconditions=[pre("resource_a", "slot", True), pre("resource_b", "slot", "b0")])))
    fails(refused, "PRECONDITION_MISMATCH")
    assert type(a.values["slot"]) is int and a.write_count == 0
    prepared = coord.prepare(signed(body(
        preconditions=[pre("resource_a", "slot", 1), pre("resource_b", "slot", "b0")],
        effects=[eff("resource_a", "slot", True), eff("resource_b", "slot", "b1")])))
    assert prepared["status"] == "PASS"
    assert coord.commit("op-1", prepared)["status"] == "PASS"
    assert a.values["slot"] is True


def test_stale_precondition_refuses_prepare_and_snapshot_change_refuses_commit() -> None:
    coord, a, b = make()
    stale = coord.prepare(signed(body(preconditions=[pre("resource_a", "slot", "zz"), pre("resource_b", "slot", "b0")])))
    fails(stale, "PRECONDITION_MISMATCH")
    assert coord.journal == []
    prepared = coord.prepare(signed(body()))
    a.write("slot", "elsewhere")  # Out-of-band drift, not a declared effect.
    refused = coord.commit("op-1", prepared)
    fails(refused, "PRECONDITION_CHANGED_BEFORE_COMMIT")
    assert refused["dispositions"]["preconditions"] == "STALE_AT_COMMIT"
    assert "PRECONDITION_DRIFT" in refused["reasons"]
    assert a.values["slot"] == "elsewhere" and b.values["slot"] == "b0" and b.write_count == 0
    aborted = coord.abort("op-1")
    assert aborted["status"] == "PASS" and aborted["state"] == "ABORTED"


def test_duplicate_operation_id_replays_without_second_application_and_refuses_reuse() -> None:
    coord, a, b = make()
    first = coord.prepare(signed(body()))
    entries = len(coord.journal)
    replay = coord.prepare(signed(body()))
    assert replay["status"] == "PASS" and "OPERATION_ID_REPLAYED" in replay["reasons"]
    assert replay["dispositions"]["operation_identity"] == "REPLAYED"
    reused = coord.prepare(signed(body(effects=[eff("resource_a", "slot", "a9"), eff("resource_b", "slot", "b1")])))
    fails(reused, "OPERATION_ID_REUSED_WITH_DIFFERENT_REQUEST")
    assert len(coord.journal) == entries
    committed = coord.commit("op-1", first)
    assert committed["status"] == "PASS"
    again = coord.commit("op-1", first)
    assert again["status"] == "PASS" and "OPERATION_REPLAYED" in again["reasons"]
    assert a.write_count == 1 and b.write_count == 1 and a.values["slot"] == "a1"
    fails(coord.abort("op-1"), "OPERATION_TERMINAL")


def test_cross_transaction_and_forged_evidence_are_refused_without_mutation() -> None:
    coord, a, b = make()
    first = coord.prepare(signed(body("op-1")))
    second = coord.prepare(signed(body("op-2", effects=[eff("resource_a", "slot", "a2"), eff("resource_b", "slot", "b2")])))
    fails(coord.commit("op-1", second), "EVIDENCE_MISMATCH")
    fails(coord.commit("op-2", first), "EVIDENCE_MISMATCH")
    forged = dict(first, status="PASS", finality="FINAL_LOCAL_RECORD")
    fails(coord.commit("op-1", forged), "EVIDENCE_MISMATCH")
    recomputed = dict(first, state="COMMITTED")
    recomputed["receipt_digest"] = tx._digest({k: v for k, v in recomputed.items() if k != "receipt_digest"})
    assert tx.verify_receipt(recomputed) is True  # Digest is integrity of bytes, not authentication.
    fails(coord.commit("op-1", recomputed), "EVIDENCE_MISMATCH")
    assert values_of(a, b) == ({"slot": "a0"}, {"slot": "b0"}) and a.write_count == 0 and b.write_count == 0


def test_returned_receipt_mutation_cannot_forge_stored_evidence() -> None:
    coord, a, _ = make()
    issued = coord.prepare(signed(body()))
    original = dict(issued)
    issued["state"] = "FORGED"
    issued["status"] = "PASS"
    fails(coord.commit("op-1", issued), "EVIDENCE_MISMATCH")
    assert coord.commit("op-1", original)["status"] == "PASS" and a.values["slot"] == "a1"


def test_refused_prepare_does_not_consume_operation_identifier() -> None:
    coord, _, _ = make()
    fails(coord.prepare(signed(body(preconditions=[pre("resource_a", "slot", "zz"), pre("resource_b", "slot", "b0")]))),
          "PRECONDITION_MISMATCH")
    assert coord.prepare(signed(body()))["status"] == "PASS"


def test_aliasing_and_post_submission_mutation_cannot_change_intended_effects() -> None:
    coord, a, b = make()
    request_body = body()
    request = signed(request_body)
    prepared = coord.prepare(request)
    request_body["effects"][0]["new_value"] = "evil"
    request["effects"][0]["new_value"] = "evil"
    request["preconditions"].clear()
    assert coord.commit("op-1", prepared)["status"] == "PASS"
    assert a.values["slot"] == "a1" and b.values["slot"] == "b1"


def test_injected_partial_commit_is_unknown_and_needs_compensation_not_pass() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body()))
    partial = coord.commit("op-1", prepared, inject={"effect": 1, "mode": "before_write"})
    assert partial["status"] == "UNKNOWN" and partial["state"] == "NEEDS_COMPENSATION"
    assert partial["applied_effects"] == [0] and partial["finality"] == "NOT_FINAL"
    assert partial["dispositions"]["partial_failure"] == "NEEDS_COMPENSATION"
    assert "COMMIT_INTERRUPTED_BY_RESOURCE_FAULT" in partial["reasons"]
    assert values_of(a, b) == ({"slot": "a1"}, {"slot": "b0"})
    fails(coord.commit("op-1", prepared), "PARTIAL_EFFECTS_REQUIRE_COMPENSATION")
    assert a.write_count == 1 and b.write_count == 0
    assert coord.reconcile("op-1")["status"] == "UNKNOWN"
    compensated = coord.compensate("op-1")
    assert compensated["status"] == "PASS" and compensated["state"] == "COMPENSATED"
    assert compensated["finality"] == "FINAL_LOCAL_RECORD" and compensated["external_settlement"] == "NOT_ESTABLISHED"
    assert values_of(a, b) == ({"slot": "a0"}, {"slot": "b0"})
    length = len(coord.journal)
    again = coord.compensate("op-1")
    assert again["status"] == "PASS" and "COMPENSATION_ALREADY_RECORDED" in again["reasons"]
    assert len(coord.journal) == length and a.write_count == 2 and b.write_count == 0


def test_failure_after_write_is_observed_not_trusted_and_before_write_allows_bounded_retry() -> None:
    coord, a, _ = make()
    prepared = coord.prepare(signed(body()))
    raised = coord.commit("op-1", prepared, inject={"effect": 0, "mode": "after_write"})
    assert raised["status"] == "UNKNOWN" and raised["applied_effects"] == [0]
    assert raised["state"] == "NEEDS_COMPENSATION"
    coord_b, a_b, _ = make()
    prepared_b = coord_b.prepare(signed(body(limit=1)))
    first = coord_b.commit("op-1", prepared_b, inject={"effect": 0, "mode": "before_write"})
    assert first["status"] == "UNKNOWN" and first["state"] == "PREPARED"
    assert first["dispositions"]["partial_failure"] == "COMMIT_FAILED_NO_EFFECT"
    assert first["attempts"] == {"used": 1, "allowed": 2}
    second = coord_b.commit("op-1", prepared_b)
    assert second["status"] == "PASS" and second["attempts"] == {"used": 2, "allowed": 2}
    assert a_b.values["slot"] == "a1" and a_b.write_count == 1


def test_retry_budget_overflow_is_refused_without_mutation() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body(limit=1)))
    for _ in range(2):
        assert coord.commit("op-1", prepared, inject={"effect": 0, "mode": "before_write"})["status"] == "UNKNOWN"
    overflow = coord.commit("op-1", prepared)
    fails(overflow, "RETRY_LIMIT_EXCEEDED")
    assert overflow["attempts"] == {"used": 2, "allowed": 2}
    assert values_of(a, b) == ({"slot": "a0"}, {"slot": "b0"}) and a.write_count == 0 and b.write_count == 0


def test_abort_is_refused_once_effects_are_recorded_and_replays_after_abort() -> None:
    coord, _, _ = make()
    prepared = coord.prepare(signed(body()))
    coord.commit("op-1", prepared, inject={"effect": 1, "mode": "before_write"})
    fails(coord.abort("op-1"), "EFFECTS_RECORDED_USE_COMPENSATE")
    coord2, _, _ = make()
    prepared2 = coord2.prepare(signed(body()))
    aborted = coord2.abort("op-1")
    assert aborted["status"] == "PASS" and aborted["state"] == "ABORTED"
    replay = coord2.abort("op-1")
    assert replay["status"] == "PASS" and "OPERATION_REPLAYED" in replay["reasons"]
    fails(coord2.commit("op-1", prepared2), "OPERATION_TERMINAL")


@pytest.mark.parametrize("crash_at", ["after_prepare"])
def test_crash_after_prepare_is_reconciled_as_prepared_and_then_aborted(crash_at: str) -> None:
    coord, a, b = make()
    with pytest.raises(SimulatedCrash):
        coord.prepare(signed(body()), crash_at=crash_at)
    pending = coord.reconcile("op-1")
    assert pending["status"] == "UNKNOWN" and pending["state"] == "PREPARED"
    assert values_of(a, b) == ({"slot": "a0"}, {"slot": "b0"})
    assert coord.abort("op-1")["state"] == "ABORTED"
    assert a.write_count == 0 and b.write_count == 0


def test_crash_after_attempt_recorded_consumes_the_retry_budget_before_any_write() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body(limit=0)))
    with pytest.raises(SimulatedCrash):
        coord.commit("op-1", prepared, crash_at="attempt")
    report = coord.reconcile("op-1")
    assert report["state"] == "PREPARED" and report["status"] == "UNKNOWN"
    assert report["attempts"] == {"used": 1, "allowed": 1}
    assert values_of(a, b) == ({"slot": "a0"}, {"slot": "b0"})
    fails(coord.commit("op-1", prepared), "RETRY_LIMIT_EXCEEDED")
    assert coord.abort("op-1")["state"] == "ABORTED"
    assert a.write_count == 0 and b.write_count == 0


def test_crash_after_first_effect_is_reconciled_then_compensated_without_double_write() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body()))
    with pytest.raises(SimulatedCrash):
        coord.commit("op-1", prepared, crash_at="effect:0")
    report = coord.reconcile("op-1")
    assert report["state"] == "NEEDS_COMPENSATION" and report["status"] == "UNKNOWN"
    assert report["applied_effects"] == [0]
    assert [row["disposition"] for row in report["effects"]] == ["APPLIED", "NOT_APPLIED"]
    compensated = coord.compensate("op-1")
    assert compensated["state"] == "COMPENSATED" and compensated["status"] == "PASS"
    assert values_of(a, b) == ({"slot": "a0"}, {"slot": "b0"})
    assert a.write_count == 2 and b.write_count == 0


def test_crash_after_all_effects_completes_from_observed_effects_without_rewriting() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body()))
    with pytest.raises(SimulatedCrash):
        coord.commit("op-1", prepared, crash_at="all_effects")
    report = coord.reconcile("op-1")
    assert report["state"] == "APPLIED_UNRECORDED" and report["status"] == "UNKNOWN"
    assert report["finality"] == "NOT_FINAL"
    completed = coord.commit("op-1", prepared)
    assert completed["status"] == "PASS" and completed["state"] == "COMMITTED"
    assert "COMMIT_RECORDED_FROM_OBSERVED_EFFECTS" in completed["reasons"]
    assert a.write_count == 1 and b.write_count == 1


def test_crash_during_compensation_leaves_missing_compensation_visible() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body()))
    with pytest.raises(SimulatedCrash):
        coord.commit("op-1", prepared, crash_at="all_effects")
    with pytest.raises(SimulatedCrash):
        coord.compensate("op-1", crash_at="compensate:1")
    missing = coord.reconcile("op-1")
    assert missing["state"] == "NEEDS_COMPENSATION" and missing["status"] == "UNKNOWN"
    assert missing["compensated_effects"] == [1]
    assert values_of(a, b) == ({"slot": "a1"}, {"slot": "b0"})
    done = coord.compensate("op-1")
    assert done["status"] == "PASS" and done["state"] == "COMPENSATED"
    assert values_of(a, b) == ({"slot": "a0"}, {"slot": "b0"})
    assert a.write_count == 2 and b.write_count == 2


def test_compensation_refusals_for_unapplied_and_committed_operations() -> None:
    coord, _, _ = make()
    coord.prepare(signed(body()))
    fails(coord.compensate("op-1"), "NOTHING_TO_COMPENSATE")
    coord2, _, _ = make()
    coord2.commit("op-1", coord2.prepare(signed(body())))
    fails(coord2.compensate("op-1"), "OPERATION_NOT_COMPENSABLE")


def test_compensation_record_contradicted_by_later_state_is_unknown_and_not_final() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body()))
    coord.commit("op-1", prepared, inject={"effect": 1, "mode": "before_write"})
    coord.compensate("op-1")
    a.write("slot", "a1")  # External write restores the declared new value after compensation.
    report = coord.reconcile("op-1")
    assert report["status"] == "UNKNOWN" and report["state"] == "CONFLICT_REQUIRES_REVIEW"
    assert "COMPENSATION_NOT_REVERSED" in report["reasons"]
    assert report["finality"] == "NOT_FINAL"


def test_external_revert_after_commit_is_never_reported_as_final() -> None:
    coord, a, _ = make()
    coord.commit("op-1", coord.prepare(signed(body())))
    a.write("slot", "a0")
    report = coord.reconcile("op-1")
    assert report["status"] == "UNKNOWN" and report["state"] == "CONFLICT_REQUIRES_REVIEW"
    assert report["finality"] == "NOT_FINAL"
    assert "RECORDED_EFFECTS_DO_NOT_MATCH_OBSERVATION" in report["reasons"]
    assert report["dispositions"]["recorded_effects"] == "DIVERGED"


@pytest.mark.parametrize("scenario", ["partial", "conflict", "reverted_after_commit"])
def test_finality_is_never_claimed_for_partial_conflicted_or_reverted_records(scenario: str) -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body()))
    if scenario == "partial":
        coord.commit("op-1", prepared, inject={"effect": 1, "mode": "before_write"})
    elif scenario == "conflict":
        coord.commit("op-1", prepared, inject={"effect": 1, "mode": "before_write"})
        a.write("slot", "zz")
    else:
        coord.commit("op-1", prepared)
        b.write("slot", "b0")
    report = coord.reconcile("op-1")
    assert report["finality"] == "NOT_FINAL" and report["status"] != "PASS"
    assert report["external_settlement"] == "NOT_ESTABLISHED"


def test_journal_entry_tamper_breaks_chain_and_blocks_commit() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body()))
    coord.journal[0]["note"] = "rewritten"
    report = coord.commit("op-1", prepared)
    fails(report, "JOURNAL_CHAIN_BROKEN")
    assert a.write_count == 0 and b.write_count == 0


def test_reordered_effect_records_are_caught_even_when_the_chain_is_resealed() -> None:
    coord, _, _ = make()
    prepared = coord.prepare(signed(body()))
    with pytest.raises(SimulatedCrash):
        coord.commit("op-1", prepared, crash_at="all_effects")
    entries = list(coord.journal)
    applied = [index for index, entry in enumerate(entries) if entry["event"] == "EFFECT_APPLIED"]
    entries[applied[0]], entries[applied[1]] = entries[applied[1]], entries[applied[0]]
    coord.journal[:] = tx.chain_entries(entries)
    report = coord.reconcile("op-1")
    assert report["status"] == "FAIL" and "EFFECT_ORDER_VIOLATION" in report["reasons"]
    assert report["state"] == "INTEGRITY_VIOLATION"


def test_reordered_compensation_records_are_caught_even_when_the_chain_is_resealed() -> None:
    coord, _, _ = make()
    prepared = coord.prepare(signed(body()))
    with pytest.raises(SimulatedCrash):
        coord.commit("op-1", prepared, crash_at="all_effects")
    coord.compensate("op-1")
    entries = list(coord.journal)
    compensations = [index for index, entry in enumerate(entries) if entry["event"] == "COMPENSATED_EFFECT"]
    entries[compensations[0]], entries[compensations[1]] = entries[compensations[1]], entries[compensations[0]]
    coord.journal[:] = tx.chain_entries(entries)
    report = coord.reconcile("op-1")
    assert report["status"] == "FAIL" and "COMPENSATION_ORDER_VIOLATION" in report["reasons"]


def test_reconciliation_reports_intended_versus_applied_per_effect() -> None:
    coord, _, _ = make()
    prepared = coord.prepare(signed(body()))
    coord.commit("op-1", prepared, inject={"effect": 1, "mode": "before_write"})
    report = coord.reconcile("op-1")
    rows = report["effects"]
    assert [row["index"] for row in rows] == [0, 1]
    assert rows[0] == {"index": 0, "resource": "resource_a", "key": "slot", "before": "a0",
                       "intended_after": "a1", "observed": "a1", "disposition": "APPLIED",
                       "applied_by_journal": True, "compensated_by_journal": False}
    assert rows[1]["disposition"] == "NOT_APPLIED" and rows[1]["observed"] == "b0"
    assert report["dispositions"]["atomicity"] == "PARTIAL_EFFECTS_APPLIED"


def test_receipts_are_closed_bound_to_current_source_and_forgery_evident() -> None:
    coord, _, _ = make()
    receipt = coord.commit("op-1", coord.prepare(signed(body())))
    assert set(receipt) == tx.RECEIPT_FIELDS
    assert receipt["source"]["sha256"] == hashlib.sha256(Path(tx.__file__).read_bytes()).hexdigest()
    assert receipt["source"]["path"] == tx.SOURCE_PATH
    assert set(receipt["dispositions"]) == {
        "preconditions", "authorization", "operation_identity", "atomicity", "retry", "partial_failure",
        "compensation", "recorded_effects", "finality"}
    assert tx.verify_receipt(receipt) is True
    assert tx.verify_receipt(dict(receipt, status="FAIL")) is False
    assert tx.verify_receipt(dict(receipt, extra=1)) is False
    assert "LEDGER" not in str(receipt)


def test_stored_journal_state_is_consistent_after_a_refused_crash_sequence() -> None:
    coord, a, b = make()
    prepared = coord.prepare(signed(body()))
    with pytest.raises(SimulatedCrash):
        coord.commit("op-1", prepared, crash_at="effect:0")
    fails(coord.commit("op-1", prepared), "PARTIAL_EFFECTS_REQUIRE_COMPENSATION")
    assert [entry["event"] for entry in coord.journal] == ["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED"]
    assert tx.chain_entries(list(coord.journal)) == list(coord.journal)


# Route surface: mechanism-side propositions, one fresh observation, and a fail-closed oracle.
EXISTING_TRANSACTION_COORDINATES = frozenset({
    "TRANSACTION-1.1", "TRANSACTION-1.2", "TRANSACTION-1.3", "TRANSACTION-1.4",
    "TRANSACTION-2.1", "TRANSACTION-2.2", "TRANSACTION-2.3", "TRANSACTION-2.4",
    "TRANSACTION-3.1", "TRANSACTION-3.2", "TRANSACTION-3.3", "TRANSACTION-3.4",
})
ROUTES = ("TRANSACTION-1.1", "TRANSACTION-2.1", "TRANSACTION-3.1")


def _receipts(observed: dict[str, Any]) -> list[dict[str, Any]]:
    return [row["receipt"] for name in tx._SECTION_NAMES for steps in observed[name].values()
            for row in steps if row["receipt"] is not None]


def _resign(receipt: dict[str, Any]) -> None:
    """Recompute only the digest, so a forged receipt is digest-valid yet semantically wrong."""
    receipt["receipt_digest"] = tx._digest({key: value for key, value in receipt.items() if key != "receipt_digest"})


def test_route_set_is_exact_and_each_row_binds_its_claim() -> None:
    rows = tx.catalog()
    assert [row["route_coordinate"] for row in rows] == list(ROUTES)
    assert set(ROUTES) <= EXISTING_TRANSACTION_COORDINATES  # Routes reuse existing coordinates, never invent one.
    for row in rows:
        assert row["object_kind"] == "TRANSACTION" and row["adapter"] == tx.ADAPTER
        assert row["semantic_version"] == tx.SEMANTIC_VERSION and row["checking_mechanism"].endswith("check_observations")
        assert row["in_model_claim_digest"] == tx._digest(
            {"route_coordinate": row["route_coordinate"], "claim": row["in_model_claim"], "boundary": tx.BOUNDARY})
        assert row["route_proposition_digest"] == OWNER_PINS[row["route_coordinate"]]
        assert "NOT_ESTABLISHED" in row["in_model_claim"]
        assert "status" not in row and "state" not in row  # A row is a proposition, not an outcome.
    assert tx.IMPLEMENTATION == tx.SOURCE_PATH


def test_fresh_observation_satisfies_each_route_and_is_deterministic() -> None:
    observed = tx.observe()
    assert tx.observe() == observed
    for coordinate in ROUTES:
        assert tx.check_observations(coordinate, observed) is True


def test_catalog_row_and_status_words_are_not_evidence() -> None:
    for row in tx.catalog():
        assert tx.check_observations(row["route_coordinate"], row) is False
    observed = tx.observe()
    assert tx.check_observations("TRANSACTION-1.1", {**observed, "status": "PASS"}) is False
    assert tx.check_observations("TRANSACTION-1.1", {"status": "PASS", "state": "COMMITTED",
                                                     "finality": "FINAL_LOCAL_RECORD"}) is False


def test_proposition_drift_refuses_observations_taken_under_the_old_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    before = tx.observe()
    changed = tuple((coordinate, slug, tier, reason, claim + " Extended." if coordinate == "TRANSACTION-1.1" else claim)
                    for coordinate, slug, tier, reason, claim in tx._ROUTES)
    monkeypatch.setattr(tx, "_ROUTES", changed)
    row = next(row for row in tx.catalog() if row["route_coordinate"] == "TRANSACTION-1.1")
    assert row["in_model_claim_digest"] != before["propositions"]["TRANSACTION-1.1"]["in_model_claim_digest"]
    assert tx.check_observations("TRANSACTION-1.1", before) is False
    assert tx.check_observations("TRANSACTION-1.1", tx.observe()) is True  # A fresh execution rebinds the new digest.


def test_source_drift_of_the_module_refuses_old_observations(monkeypatch: pytest.MonkeyPatch) -> None:
    before = tx.observe()
    monkeypatch.setattr(tx, "_SOURCE_SHA256", "0" * 64)
    assert all(tx.check_observations(coordinate, before) is False for coordinate in ROUTES)


def test_receipt_claiming_another_source_is_refused_even_with_a_valid_digest() -> None:
    observed = tx.observe()
    for receipt in _receipts(observed):
        receipt["source"] = {"path": tx.SOURCE_PATH, "sha256": "1" * 64}
        _resign(receipt)
        assert tx.verify_receipt(receipt) is True
    assert all(tx.check_observations(coordinate, observed) is False for coordinate in ROUTES)


def test_missing_duplicate_and_unknown_routes_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    observed = tx.observe()
    for coordinate in ("TRANSACTION-1.2", "TRANSACTION-2.3", "TRANSACTION-9.9"):
        with pytest.raises(ValueError, match="TRANSACTION_COORDINATE_UNREGISTERED"):
            tx.check_observations(coordinate, observed)
    missing_section = {key: value for key, value in observed.items() if key != "replay_and_retry"}
    assert tx.check_observations("TRANSACTION-3.1", missing_section) is False
    missing_case = copy.deepcopy(observed)
    del missing_case["replay_and_retry"]["retry_budget"]
    assert tx.check_observations("TRANSACTION-3.1", missing_case) is False
    missing_step = copy.deepcopy(observed)
    missing_step["commit_boundary"]["committed"].pop()
    assert tx.check_observations("TRANSACTION-2.1", missing_step) is False
    monkeypatch.setattr(tx, "_ROUTES", tx._ROUTES + (tx._ROUTES[0],))
    with pytest.raises(ValueError, match="TRANSACTION_ROUTE_DUPLICATED"):
        tx.catalog()


def test_forged_pass_words_cannot_replace_recomputed_steps() -> None:
    observed = tx.observe()
    refused = copy.deepcopy(observed)
    refused["input_refusals"]["forgery:wrong_key"][0]["status"] = "PASS"
    assert tx.check_observations("TRANSACTION-1.1", refused) is False
    state_only = copy.deepcopy(observed)
    state_only["commit_boundary"]["before_second_write"][1]["state"] = "COMMITTED"
    assert tx.check_observations("TRANSACTION-2.1", state_only) is False
    forged = copy.deepcopy(observed)
    step = forged["commit_boundary"]["before_second_write"][1]
    step["status"] = "PASS"
    step["receipt"]["status"] = "PASS"
    _resign(step["receipt"])
    assert tx.verify_receipt(step["receipt"]) is True
    assert tx.check_observations("TRANSACTION-2.1", forged) is False
    unsigned = copy.deepcopy(observed)
    unsigned["replay_and_retry"]["commit_replay"][2]["receipt"]["reasons"] = []
    assert tx.check_observations("TRANSACTION-3.1", unsigned) is False  # The digest no longer matches the receipt.


def test_alias_reorder_and_type_confusion_fail_closed() -> None:
    observed = tx.observe()
    aliased = copy.deepcopy(observed)
    aliased["input_refusals"]["forgery:wrong_key"] = aliased["input_refusals"]["stale_precondition"]
    assert tx.check_observations("TRANSACTION-1.1", aliased) is False
    reordered_events = copy.deepcopy(observed)
    reordered_events["commit_boundary"]["before_second_write"][1]["events"].reverse()
    assert tx.check_observations("TRANSACTION-2.1", reordered_events) is False
    reordered_steps = copy.deepcopy(observed)
    steps = reordered_steps["commit_boundary"]["crash_before_committed_record"]
    steps[2], steps[3] = steps[3], steps[2]
    assert tx.check_observations("TRANSACTION-2.1", reordered_steps) is False
    as_tuple = copy.deepcopy(observed)
    as_tuple["replay_and_retry"]["retry_budget"][3]["reasons"] = tuple(as_tuple["replay_and_retry"]["retry_budget"][3]["reasons"])
    assert tx.check_observations("TRANSACTION-3.1", as_tuple) is False
    as_float = copy.deepcopy(observed)
    as_float["commit_boundary"]["committed"][1]["writes"] = [1.0, 1]
    assert tx.check_observations("TRANSACTION-2.1", as_float) is False
    key_order = dict(reversed(list(copy.deepcopy(observed).items())))
    assert tx.check_observations("TRANSACTION-1.1", key_order) is True  # JSON object order is not evidence.


def test_extra_or_unbound_fields_fail_closed() -> None:
    observed = tx.observe()
    assert tx.check_observations("TRANSACTION-1.1", {**observed, "extra": 1}) is False
    extra_case = copy.deepcopy(observed)
    extra_case["input_refusals"]["extra_case"] = copy.deepcopy(observed["input_refusals"]["undeclared_key"])
    assert tx.check_observations("TRANSACTION-1.1", extra_case) is False
    extra_field = copy.deepcopy(observed)
    extra_field["commit_boundary"]["committed"][0]["note"] = "x"
    assert tx.check_observations("TRANSACTION-2.1", extra_field) is False
    assert tx.check_observations("TRANSACTION-1.1", extra_field) is True  # Route 1.1 checks its own section only.


@pytest.mark.parametrize("observed", [None, "PASS", [], {}])
def test_non_observation_inputs_are_refused(observed: Any) -> None:
    assert all(tx.check_observations(coordinate, observed) is False for coordinate in ROUTES)


def test_every_receipt_keeps_external_settlement_and_identity_not_established() -> None:
    receipts = _receipts(tx.observe())
    assert receipts
    assert all(receipt["external_settlement"] == "NOT_ESTABLISHED"
               and receipt["authorization"]["identity_authentication"] == "NOT_ESTABLISHED"
               and receipt["boundary"] == tx.BOUNDARY for receipt in receipts)


def test_mutation_that_skips_authority_fails_route_1_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tx.Coordinator, "_authorize", lambda *_: None)
    assert tx.check_observations("TRANSACTION-1.1", tx.observe()) is False


def test_mutation_that_ignores_injected_faults_fails_route_2_1(monkeypatch: pytest.MonkeyPatch) -> None:
    original_apply = tx.Coordinator._apply
    monkeypatch.setattr(tx.Coordinator, "_apply", lambda self, operation, record, injection, crash_at, context:
                        original_apply(self, operation, record, None, crash_at, context))
    observed = tx.observe()
    assert tx.check_observations("TRANSACTION-2.1", observed) is False
    assert tx.check_observations("TRANSACTION-1.1", observed) is True


def test_mutation_that_rewrites_on_replayed_commit_fails_route_3_1(monkeypatch: pytest.MonkeyPatch) -> None:
    original_commit = tx.Coordinator.commit

    def replaying_commit(self: Any, operation_id: Any, evidence: Any, *, inject: Any = None, crash_at: Any = None) -> Any:
        operation = tx._safe_id(operation_id)
        if operation in self._ops and self._derive(operation)["state"] == "COMMITTED":
            for effect in self._ops[operation]["effects"]:
                self._resources[effect["resource"]].write(effect["key"], effect["new_value"])
        return original_commit(self, operation_id, evidence, inject=inject, crash_at=crash_at)

    monkeypatch.setattr(tx.Coordinator, "commit", replaying_commit)
    observed = tx.observe()
    assert tx.check_observations("TRANSACTION-3.1", observed) is False
    assert tx.check_observations("TRANSACTION-2.1", observed) is True


# Auxiliary correspondence to existing owner coordinates. The owner pins below are a literal copy of
# the historical commitments in test_local_ledger_contract_controls, so they are not read from the module.
OWNER_ADAPTER = "verifier-local-invocation-ledger-1"
OWNER_PINS = {
    "TRANSACTION-1.1": "sha256:0db34cb1e6b3423e9cf8b84782d38e9ab8928b82cbae459c0199f4e8665c27b3",
    "TRANSACTION-2.1": "sha256:f34af6a88de443c0ff741ed6510c20ba2f9d5c08123ef810277215fe2f8a7613",
    "TRANSACTION-3.1": "sha256:7d1bb429c0ac6cf9c2f62535f85fbadb3fec47040783f58bde01b280e106590f",
}


def _owner_rows() -> list[dict[str, Any]]:
    return [row for row in local_ledger_execution.catalog() if row["coordinate"] in ROUTES]


def _single_owner(rows: list[dict[str, Any]]) -> None:
    """Oracle: each live coordinate appears exactly once. A route row is keyed by route_coordinate."""
    counts = Counter(row.get("coordinate", row.get("route_coordinate")) for row in rows)
    duplicated = sorted((str(coordinate) for coordinate, count in counts.items() if count != 1))
    assert duplicated == [], duplicated


def test_module_is_not_a_registered_package_execution_mechanism() -> None:
    registered = package_execution.mechanisms()
    assert tx.ADAPTER not in registered
    assert all(module is not tx for module in registered.values())
    assert not {"evaluate", "worker", "WORKER", "_execute"} & set(tx.__dict__)


def test_every_live_package_execution_coordinate_has_exactly_one_owner_adapter() -> None:
    rows = package_execution.catalog()
    _single_owner(rows)
    owners = {row["coordinate"]: row["adapter"] for row in rows if row["coordinate"] in ROUTES}
    assert owners == {coordinate: OWNER_ADAPTER for coordinate in ROUTES}


def test_hostile_registration_of_this_module_duplicates_transaction_coordinates_and_is_rejected(
        monkeypatch: pytest.MonkeyPatch) -> None:
    registered = dict(package_execution.mechanisms())
    registered[tx.ADAPTER] = tx
    monkeypatch.setattr(package_execution, "mechanisms", lambda: registered)
    hostile = package_execution.catalog()
    assert [row["route_coordinate"] for row in hostile if row["adapter"] == tx.ADAPTER] == list(ROUTES)
    with pytest.raises(AssertionError, match="TRANSACTION-1.1"):
        _single_owner(hostile)


def test_catalog_rows_are_auxiliary_and_bound_to_the_pinned_owner_adapter_and_digests() -> None:
    rows = tx.catalog()
    assert [row["route_coordinate"] for row in rows] == list(ROUTES)
    assert tx.OWNER_ADAPTER == OWNER_ADAPTER and tx.OWNER_PROPOSITION_DIGESTS == OWNER_PINS
    for row in rows:
        assert "coordinate" not in row and "proposition_digest" not in row
        assert row["route_owner_adapter"] == OWNER_ADAPTER
        assert row["route_proposition_digest"] == OWNER_PINS[row["route_coordinate"]]
        assert row["carried_by_route"] is False
        assert row["route_status"] == "NOT_ESTABLISHED"
        assert row["conformance_status"] == "NOT_ESTABLISHED"


def test_pinned_owner_digests_equal_live_owner_rows_and_historical_commitments() -> None:
    owner = _owner_rows()
    assert {row["coordinate"]: row["proposition_digest"] for row in owner} == OWNER_PINS
    assert {row["adapter"] for row in owner} == {OWNER_ADAPTER}


def test_route_drift_fails_on_owner_claim_change_and_on_pin_or_shape_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    owner = _owner_rows()
    assert tx.route_drift(owner) == []
    assert tx.route_drift(owner[1:]) == ["MISSING:TRANSACTION-1.1"]
    assert tx.route_drift(owner + [owner[0]]) == ["DUPLICATED:TRANSACTION-1.1"]
    assert tx.route_drift([{**owner[0], "proposition_digest": "sha256:" + "0" * 64}, *owner[1:]]) == [
        "PROPOSITION_DRIFT:TRANSACTION-1.1"]
    assert tx.route_drift([{**owner[0], "tier": 2}, *owner[1:]]) == ["TIER_DRIFT:TRANSACTION-1.1"]
    assert tx.route_drift([{**owner[0], "adapter": "other"}, *owner[1:]]) == ["ADAPTER_DRIFT:TRANSACTION-1.1"]
    assert tx.route_drift(["not a row", *owner[1:]]) == ["ROW_SHAPE_DIFFERS", "MISSING:TRANSACTION-1.1"]
    changed = tuple(
        (coordinate, slug, kind, tier, reason, claim + " Extended." if coordinate == "TRANSACTION-1.1" else claim)
        for coordinate, slug, kind, tier, reason, claim in local_ledger_execution._CONTRACTS)
    monkeypatch.setattr(local_ledger_execution, "_CONTRACTS", changed)
    assert tx.route_drift(_owner_rows()) == ["PROPOSITION_DRIFT:TRANSACTION-1.1"]


def test_all_three_rows_remain_not_established_even_when_in_model_reproduction_holds() -> None:
    observed = tx.observe()
    assert all(tx.check_observations(coordinate, observed) is True for coordinate in ROUTES)
    rows = tx.catalog()
    assert {row["route_status"] for row in rows} == {"NOT_ESTABLISHED"}
    assert {row["conformance_status"] for row in rows} == {"NOT_ESTABLISHED"}
    assert {row["carried_by_route"] for row in rows} == {False}
    assert observed["propositions"] == {
        coordinate: {"route_proposition_digest": OWNER_PINS[coordinate],
                     "in_model_claim_digest": row["in_model_claim_digest"]}
        for coordinate, row in zip(ROUTES, rows)}
