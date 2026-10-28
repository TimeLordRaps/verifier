"""Source-bound fresh local ledger checks for Verifier Standard (VSTD).

These finite propositions test the selected local invocation implementation, not
monetary backing, authority authenticity, power-loss durability or all executions.
Unselected/unsupported variants stay UNKNOWN. Historical local receipts and the
26-kind native wire registry retain their meanings.
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

import subprocess
from typing import Any

from verifier.core.namespace import NamespaceObject
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


ADAPTER = "verifier-local-invocation-ledger-1"
SEMANTIC_VERSION = "verifier-local-invocation-obligations-1"
IMPLEMENTATION = "src/verifier/runtime/polish_invocation_ledger.py"
WORKER = "local_ledger_worker.py"
REQUEST_SCHEMA = "verifier-local-ledger-execution-request-1"
OBSERVATION_SCHEMA = "verifier-local-ledger-execution-observations-1"
BOUNDARY = ("Fresh bounded executions of the exact owned local invocation implementation in isolated temporary SQLite databases. "
            "Not production-history replay, monetary accounting, authority authentication, power-loss durability, complete kind conformance or package polish.")
_LOCAL_RECEIPT_SCHEMA = "verifier-polish-local-invocation-commit-1"
_LOCAL_RECEIPT_BOUNDARY = ("Same exact committed proposal in one configured local ledger only; "
                           "not polish, public historical execution or worldwide uniqueness.")
_LOCAL_RECEIPT_FIELDS = {
    "schema_version", "status", "polished", "invocation_consumption", "ledger_id",
    "policy_domain", "policy_epoch", "invocation_id", "commit_sequence",
    "proposal_digest", "authority_status_digest", "commit_time", "mechanism_digest",
    "public_consumption_authentication", "claim_boundary", "receipt_digest",
}
_CONTRACTS = (
    ("LEDGER-1.1", "local-record-identity", "LEDGER", 1,
     "A ledger must bind its recorded proposal and selected identity; a receipt for a different ledger is not its evidence.",
     "A fresh exact proposal is retained and replayed, while different ledger/domain selections are rejected."),
    ("LEDGER-2.1", "local-invocation-accounting", "LEDGER", 2,
     "The accounting unit, balance rule, rounding boundary and sources/sinks must be executable properties of the selected ledger, not prose attached to row counts.",
     "The unit is one exact canonical proposal per consumed invocation: two distinct successful commits are the only sources, replay is no source, no sink occurs, integer sequence accounting is unrounded, and every receipt binds the exact persisted unit."),
    ("LEDGER-3.1", "local-readonly-recovery", "LEDGER", 3,
     "Uncertain commit acknowledgement does not determine whether a ledger entry exists, and recovery must not consume again.",
     "Read-only recovery distinguishes an absent precommit record from an actually committed record after acknowledgement loss."),
    ("TRANSACTION-1.1", "local-input-preconditions", "TRANSACTION", 1,
     "Known invalid proposal, selection or digest inputs must be refused before they change the configured resources.",
     "Wrong proposal digest, invalid status digest, stale epoch and noncanonical proposal each fail without an inserted row."),
    ("TRANSACTION-2.1", "local-commit-boundary", "TRANSACTION", 2,
     "A failure before commit and a failure after commit have different effects even when both calls report uncertainty.",
     "Injected precommit failure rolls back; injected postcommit acknowledgement loss preserves one row; both calls return UNKNOWN."),
    ("TRANSACTION-3.1", "local-replay-and-epoch", "TRANSACTION", 3,
     "Concurrency and authority-epoch changes must not permit duplicate application or reuse of a consumed invocation.",
     "Four concurrent attempts consume once; epoch advance rejects stale selection and does not reenable consumed identifiers; each selected commit, recovery and recheck operation opens one backend connection under the finite five-second busy bound."),
    ("LEDGER-1.2", "local-provisioning-continuity", "LEDGER", 1,
     "Provisioning must not erase consumed identities or substitute ledger/domain/epoch metadata for an existing ledger.",
     "Repeated matching provisioning preserves all stored fields; changed ledger, domain and epoch each refuse without mutation."),
    ("LEDGER-2.2", "local-retention-boundaries", "LEDGER", 2,
     "Retention limits must state their units and exact integer boundary, bound real consumption without rounding, and neither delete history nor disguise a known replay as resource uncertainty.",
     "Fixture-seeded states accept the final record at the exact 4096-record and 67108864-byte caps without rounding; another distinct invocation is UNKNOWN without a source or sink mutation, while a duplicate remains FAIL."),
    ("LEDGER-3.2", "local-record-integrity", "LEDGER", 3,
     "Read-only replay and recovery must reject contradictory stored fields instead of laundering them into a valid receipt.",
     "Five isolated stored-field corruptions are refused without mutation; restoring each field restores exact receipt replay."),
    ("TRANSACTION-1.2", "local-resource-selection", "TRANSACTION", 1,
     "Ordinary consumption and recovery must not implicitly provision missing resources or accept a different selection boundary.",
     "Commit, replay and recovery leave a missing database absent and return UNKNOWN; wrong ledger/domain/epoch/native selection type each FAIL without changing existing records."),
    ("TRANSACTION-2.2", "local-cancellation-boundary", "TRANSACTION", 2,
     "Cancellation can arrive before or after commit and cannot establish non-consumption or authorize blind retry.",
     "Injected asynchronous cancellation and keyboard interruption before/after COMMIT return UNKNOWN; rollback versus retained consumption is distinguished by read-only recovery."),
    ("TRANSACTION-3.2", "local-epoch-transition-guards", "TRANSACTION", 3,
     "An invalid or stale epoch transition must not rewrite policy state or renew already consumed invocation identities.",
     "Equal, zero, negative, boolean and overflowing epochs refuse without mutation; a valid advance changes metadata only, rejects a stale advance, retains consumed identifiers and permits a fresh invocation; selected commit, recovery and recheck operations each open one backend connection under the finite five-second busy bound."),
)


def catalog() -> list[dict[str, Any]]:
    """The proposition itself names finite coverage; it is never full-kind proof."""
    return [{"coordinate": coordinate, "obligation_id": coordinate + "-" + slug,
             "obligation_name": slug.replace("-", " ").capitalize(), "object_kind": kind,
             "tier": tier, "reason": reason, "exact_claim": claim,
             "semantic_version": SEMANTIC_VERSION,
             "proposition_digest": value_digest({"coordinate": coordinate, "claim": claim, "boundary": BOUNDARY}),
             "checking_mechanism": "verifier.runtime.local_ledger_execution.evaluate",
             "scope": "fresh_local_invocation_ledger_" + slug.replace("-", "_"), "adapter": ADAPTER}
            for coordinate, slug, kind, tier, reason, claim in _CONTRACTS]


def validate_bindings(bindings: Any, rows: list[dict[str, Any]]) -> None:
    """Compatibility entry point; the closed registry now owns selection shape."""
    from verifier.runtime.package_execution import validate_bindings as validate
    validate(bindings, rows)


def _record(identifier: str, sequence: int, epoch: int = 1) -> dict[str, Any]:
    return {"sequence": sequence, "invocation": identifier, "epoch": epoch,
            "proposal": canonical_bytes({"value": identifier}).decode("utf-8")}


def _receipt_matches_record(receipt: Any, record: dict[str, Any], *, ledger_id: str = "records") -> bool:
    """Bind the public accounting receipt to the independently read SQLite unit."""
    if not _closed_local_receipt(receipt):
        return False
    proposal = record["proposal"].encode("utf-8")
    return (
        receipt.get("status") == "PASS"
        and receipt.get("invocation_consumption") == "CONSUMED_EXACT_LOCAL_LEDGER"
        and receipt.get("ledger_id") == ledger_id
        and receipt.get("policy_domain") == "local-check"
        and type(receipt.get("policy_epoch")) is int
        and receipt["policy_epoch"] == record["epoch"]
        and receipt.get("invocation_id") == record["invocation"]
        and type(receipt.get("commit_sequence")) is int
        and receipt["commit_sequence"] == record["sequence"]
        and receipt.get("proposal_digest")
        == value_digest({"value": record["invocation"]})
        and proposal == canonical_bytes({"value": record["invocation"]})
    )


def _closed_local_receipt(receipt: Any) -> bool:
    """Accept only the exact self-bound local receipt and its non-financial scope.

    The digest detects count-preserving or field-preserving substitution inside the
    worker response. It authenticates no external authority; that exclusion is an
    exact required field rather than prose a caller can replace or extend.
    """
    if type(receipt) is not dict or set(receipt) != _LOCAL_RECEIPT_FIELDS:
        return False
    body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    return (
        receipt["schema_version"] == _LOCAL_RECEIPT_SCHEMA
        and receipt["status"] == "PASS"
        and receipt["polished"] is False
        and receipt["invocation_consumption"] == "CONSUMED_EXACT_LOCAL_LEDGER"
        and receipt["public_consumption_authentication"] == "NOT_ESTABLISHED"
        and receipt["claim_boundary"] == _LOCAL_RECEIPT_BOUNDARY
        and receipt["receipt_digest"] == value_digest(body)
    )


def _same(first: Any, *others: Any) -> bool:
    """Canonical equality keeps integer, boolean and string types distinct."""
    expected = canonical_bytes(first)
    return all(canonical_bytes(value) == expected for value in others)


def _outcome(row: dict[str, Any], status: str, reason: str | None = None,
             *, ledger_id: str | None = None) -> bool:
    markers = {"commit_sequence", "claim_boundary", "public_consumption_authentication"}
    scoped = not markers.intersection(row) or _closed_local_receipt(row)
    selected = ledger_id is None or row.get("ledger_id") == ledger_id
    return scoped and selected and row["status"] == status and (reason is None or row["reason"] == reason)


def _retained(state: dict[str, Any]) -> int:
    return sum(len(row[6].encode("utf-8")) for row in state["entries"])


# Expected persisted-row delta per _accounting step; a sink would be a negative or unexplained change.
_ACCOUNTING_STEPS = (("commit-a", "PASS", 1), ("duplicate-a", "FAIL", 0), ("precommit-c", "UNKNOWN", 0),
                     ("postcommit-d", "UNKNOWN", 1), ("recover-d", "PASS", 0), ("commit-e", "PASS", 1))


def _ordering_ok(value: dict[str, Any]) -> bool:
    """LEDGER-0.1: gap-free persisted sequence in commit order; rollback consumes no sequence."""
    return (_outcome(value["first"], "PASS", ledger_id="ordering") and _same(value["first"]["commit_sequence"], 1)
            and _outcome(value["duplicate"], "FAIL", "KNOWN_INVOCATION_REPLAY")
            and _outcome(value["uncertain_before"], "UNKNOWN", "LEDGER_COMMIT_UNAVAILABLE_OR_UNCERTAIN")
            and _outcome(value["second"], "PASS", ledger_id="ordering") and _same(value["second"]["commit_sequence"], 2)
            and _outcome(value["uncertain_after"], "UNKNOWN", "LEDGER_COMMIT_UNAVAILABLE_OR_UNCERTAIN")
            and _outcome(value["last"], "PASS", ledger_id="ordering") and _same(value["last"]["commit_sequence"], 4)
            and _same([[row[0], row[1]] for row in value["rows"]], [[1, "a"], [2, "b"], [3, "d"], [4, "e"]])
            and _same(value["sequence"], [["issuance", 4]]))


def _accounting_ok(value: dict[str, Any]) -> bool:
    """LEDGER-0.2: every step is a balance; prior rows persist exactly and sinks are zero."""
    steps = value["steps"]
    if [row["name"] for row in steps] != [name for name, _, _ in _ACCOUNTING_STEPS]:
        return False
    if steps[0]["before"]["entries"] != [] or not _same(steps[0]["before"]["metadata"], value["final"]["metadata"]):
        return False
    for index, (row, (_, status, delta)) in enumerate(zip(steps, _ACCOUNTING_STEPS)):
        before, after = row["before"], row["after"]
        expected_ledger = "accounting" if "commit_sequence" in row["outcome"] else None
        if not _outcome(row["outcome"], status, ledger_id=expected_ledger):
            return False
        if index and not _same(before, steps[index - 1]["after"]):
            return False
        if not _same(before["entries"], after["entries"][:len(before["entries"])]):
            return False  # A sink, reorder or mutation of an earlier persisted row.
        added = after["entries"][len(before["entries"]):]
        if len(added) != delta or type(len(added)) is not int or not _same(before["metadata"], after["metadata"]):
            return False
        if _retained(after) - _retained(before) != sum(len(row_[6].encode("utf-8")) for row_ in added):
            return False
    return (_same(value["final"], steps[-1]["after"]) and _same([row[1] for row in value["final"]["entries"]], ["a", "d", "e"])
            and _same([row[0] for row in value["final"]["entries"]], [1, 2, 3])
            and _same(_retained(value["final"]), sum(len(canonical_bytes({"value": name})) for name in ("a", "d", "e"))))


def _corrections_ok(value: dict[str, Any]) -> bool:
    """LEDGER-0.3: consumed proposals cannot be corrected by commit, replay or recovery; epoch is metadata only."""
    return (_outcome(value["receipt"], "PASS", ledger_id="corrections")
            and _outcome(value["commit"], "FAIL", "KNOWN_INVOCATION_REPLAY")
            and _outcome(value["replay"], "FAIL", "LEDGER_SELECTION_OR_RECEIPT_REFUSED")
            and _outcome(value["recover"], "FAIL", "ANOTHER_PROPOSAL_CONSUMED_INVOCATION")
            and _same(value["original"]["entries"], value["after"]["entries"], value["epoch"]["entries"])
            and _same(value["after"]["sequence"], value["original"]["sequence"], value["epoch"]["sequence"])
            and _same(value["epoch"]["metadata"], [[1, "corrections", "local-check", 2]]))


def _retry_ok(value: dict[str, Any]) -> bool:
    """TRANSACTION-0.3: one backend attempt per public operation; the busy wait is finite and declared."""
    attempts = all(_same(value[name]["attempts"], 1) for name in (
        "commit_precommit", "recover_after_precommit", "commit_postcommit", "recover_after_postcommit",
        "recheck", "duplicate"))
    busy = value["busy_seconds"]
    return (attempts and type(busy) is float and 0.0 < busy <= 5.0
            and _outcome(value["commit_precommit"]["outcome"], "UNKNOWN", "LEDGER_COMMIT_UNAVAILABLE_OR_UNCERTAIN")
            and _outcome(value["recover_after_precommit"]["outcome"], "UNKNOWN", "EXACT_COMMITTED_INVOCATION_UNAVAILABLE")
            and _outcome(value["commit_postcommit"]["outcome"], "UNKNOWN", "LEDGER_COMMIT_UNAVAILABLE_OR_UNCERTAIN")
            and _outcome(value["recover_after_postcommit"]["outcome"], "PASS")
            and _closed_local_receipt(value["recover_after_postcommit"]["outcome"]["commit"])
            and value["recover_after_postcommit"]["outcome"]["commit"]["ledger_id"] == "retry"
            and _outcome(value["recheck"]["outcome"], "PASS")
            and _outcome(value["duplicate"]["outcome"], "FAIL", "KNOWN_INVOCATION_REPLAY"))


def _authorization_ok(value: dict[str, Any]) -> bool:
    """TRANSACTION-0.1 supported part: malformed authority digests are refused with no row; authenticity stays boundary."""
    labels = {"absent", "empty", "uppercase", "short", "wrong_algorithm", "bytes", "padded"}
    refused = value["refused"]
    return (set(refused) == labels and all(_outcome(row, "FAIL", "LEDGER_SELECTION_OR_PROPOSAL_REFUSED") for row in refused.values())
            and _same(value["before"], value["after_refusals"]) and value["after_refusals"]["entries"] == []
            and _outcome(value["boundary"], "PASS", ledger_id="authorization")
            and _same(value["boundary"]["public_consumption_authentication"], "NOT_ESTABLISHED")
            and _same([row[1] for row in value["final"]["entries"]], ["b"])
            and _same(value["final"]["entries"][0][4], "sha256:" + "a" * 64))


def check_observations(coordinate: str, observed: dict[str, Any]) -> bool:
    """Independent state oracle: status words cannot replace persisted effects."""
    if coordinate in {"LEDGER-1.2", "LEDGER-2.2", "LEDGER-3.2", "TRANSACTION-1.2", "TRANSACTION-2.2", "TRANSACTION-3.2"}:
        from verifier.runtime.local_ledger_control_checks import check_control
        checked = check_control(coordinate, observed["controls"])
        if coordinate == "TRANSACTION-3.2":
            checked = checked and _retry_ok(observed["controls"]["retry"])
        return checked
    first, second = _record("a", 1), _record("b", 2)
    records, faults, epochs = observed["records"], observed["faults"], observed["epochs"]
    before, after = faults["before"], faults["after"]
    controls = observed["controls"]
    if coordinate == "LEDGER-1.1":
        return (records["initial"] == [] and _receipt_matches_record(records["first"], first)
                and records["first_rows"] == [first] and records["replay"]["status"] == "PASS"
                and len(records["wrong_selection"]) == 2
                and all(row["status"] == "FAIL" for row in records["wrong_selection"]))
    if coordinate == "LEDGER-2.1":
        return (records["duplicate"]["status"] == "FAIL" and records["duplicate"]["reason"] == "KNOWN_INVOCATION_REPLAY"
                and records["first_rows"] == records["duplicate_rows"] == [first]
                and _receipt_matches_record(records["first"], first)
                and _receipt_matches_record(records["second"], second)
                and records["final_rows"] == [first, second]
                and _ordering_ok(controls["ordering"]) and _accounting_ok(controls["accounting"]))
    if coordinate == "LEDGER-3.1":
        return (before["before_recovery"] == before["after_recovery"] == []
                and after["before_recovery"] == after["after_recovery"] == [first]
                and before["recovery"]["status"] == "UNKNOWN" and after["recovery"]["status"] == "PASS"
                and after["recovery"]["commit"]["invocation_id"] == "a"
                and _receipt_matches_record(after["recovery"]["commit"], first, ledger_id="after")
                and after["retry"]["status"] == "FAIL" and after["final_rows"] == [first]
                and _corrections_ok(controls["corrections"]))
    if coordinate == "TRANSACTION-1.1":
        inputs = observed["preconditions"]
        return (len(inputs["results"]) == 4 and all(row["status"] == "FAIL" for row in inputs["results"]) and inputs["rows"] == []
                and _authorization_ok(controls["authorization"]))
    if coordinate == "TRANSACTION-2.1":
        return (all(row["commit"]["status"] == "UNKNOWN" and row["commit"]["reason"] == "LEDGER_COMMIT_UNAVAILABLE_OR_UNCERTAIN"
                    for row in (before, after)) and before["before_recovery"] == [] and after["before_recovery"] == [first]
                and _outcome(before["retry"], "PASS") and before["final_rows"] == [first]
                and _receipt_matches_record(after["recovery"]["commit"], first, ledger_id="after")
                and _retry_ok(controls["retry"]))
    if coordinate == "TRANSACTION-3.1":
        attempts = observed["concurrency"]["results"]
        return (_receipt_matches_record(epochs["prior"], first, ledger_id="epochs")
                and _receipt_matches_record(epochs["fresh"], _record("b", 2, 2), ledger_id="epochs")
                and all(epochs[name]["status"] == "FAIL" for name in ("stale", "repeated", "old_replay"))
                and epochs["rows"] == [first, _record("b", 2, 2)] and len(attempts) == 4
                and sum(row["status"] == "PASS" for row in attempts) == 1
                and sum(row["status"] == "FAIL" and row["reason"] == "KNOWN_INVOCATION_REPLAY" for row in attempts) == 3
                and observed["concurrency"]["rows"] == [first]
                and _retry_ok(controls["retry"]))
    raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")


def _execute(snapshot: Any, item: NamespaceObject, selection: dict[str, Any]) -> dict[str, Any]:
    """Only a closed installed worker executes; caller code and paths never do."""
    from verifier.runtime.package_execution import execute_bound
    return execute_bound(snapshot, item, selection)


def evaluate(snapshot: Any, item: NamespaceObject, route: dict[str, Any]) -> dict[str, Any] | None:
    # All five adapters use the same parent-capture gate. A duplicated evaluator
    # here would let the oldest adapter bypass a later provenance requirement.
    from verifier.runtime.package_execution import evaluate_selected
    return evaluate_selected(snapshot, item, route)
