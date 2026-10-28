"""Independent finite ledger control predicates for Verifier Standard (VSTD).

These predicates do not call the subject or its experiment helpers. They compare
raw persisted effects against explicit contract expectations. Secure Hash
Algorithm 256-bit (SHA-256); no digest here authenticates operator authority.
"""
from __future__ import annotations

import hashlib
from typing import Any

from verifier.runtime.tier_zero_profile import canonical_bytes


_LOCAL_RECEIPT_SCHEMA = "verifier-polish-local-invocation-commit-1"
_LOCAL_RECEIPT_BOUNDARY = ("Same exact committed proposal in one configured local ledger only; "
                           "not polish, public historical execution or worldwide uniqueness.")
_LOCAL_RECEIPT_FIELDS = {
    "schema_version", "status", "polished", "invocation_consumption", "ledger_id",
    "policy_domain", "policy_epoch", "invocation_id", "commit_sequence",
    "proposal_digest", "authority_status_digest", "commit_time", "mechanism_digest",
    "public_consumption_authentication", "claim_boundary", "receipt_digest",
}


def _closed_local_receipt(value: Any) -> bool:
    """Validate the exact local-only PASS boundary without trusting its status word."""
    if type(value) is not dict or set(value) != _LOCAL_RECEIPT_FIELDS:
        return False
    body = {key: field for key, field in value.items() if key != "receipt_digest"}
    return (
        value["schema_version"] == _LOCAL_RECEIPT_SCHEMA
        and value["status"] == "PASS"
        and value["polished"] is False
        and value["invocation_consumption"] == "CONSUMED_EXACT_LOCAL_LEDGER"
        and value["public_consumption_authentication"] == "NOT_ESTABLISHED"
        and value["claim_boundary"] == _LOCAL_RECEIPT_BOUNDARY
        and value["receipt_digest"]
        == "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()
    )


def _entry(identifier: str, sequence: int, epoch: int, source: str) -> list[Any]:
    raw = canonical_bytes({"value": identifier})
    return [sequence, identifier, epoch, "sha256:" + hashlib.sha256(raw).hexdigest(),
            "sha256:" + "a" * 64, 100, raw.decode(), source]


def _first_state(name: str, receipt: dict[str, Any]) -> dict[str, Any]:
    return {"metadata": [[1, name, "local-check", 1]],
            "entries": [_entry("a", 1, 1, receipt["mechanism_digest"])], "sequence": [["issuance", 1]]}


def _result(value: dict[str, Any], status: str, reason: str | None = None,
            *, ledger_id: str | None = None) -> bool:
    markers = {"commit_sequence", "claim_boundary", "public_consumption_authentication"}
    scoped = not markers.intersection(value) or _closed_local_receipt(value)
    selected = ledger_id is None or value.get("ledger_id") == ledger_id
    return scoped and selected and value["status"] == status and (reason is None or value["reason"] == reason)


def _same(first: Any, *others: Any) -> bool:
    """Canonical equality retains plain integer versus boolean distinctions."""
    expected = canonical_bytes(first)
    return all(canonical_bytes(value) == expected for value in others)


def _integrity(value: dict[str, Any]) -> bool:
    expected = _first_state("integrity", value["commit"])
    mutations = {"proposal": (6, canonical_bytes({"value": "other"}).decode()),
        "proposal_digest": (3, "sha256:" + "0" * 64), "policy_epoch": (2, 2),
        "commit_time": (5, -1), "mechanism_digest": (7, "sha256:" + "0" * 64)}
    if (not _result(value["commit"], "PASS", ledger_id="integrity")
            or not _same(value["original"], expected) or set(value["cases"]) != set(mutations)):
        return False
    for column, (index, replacement) in mutations.items():
        entry = list(expected["entries"][0])
        entry[index] = replacement
        corrupted = {**expected, "entries": [entry]}
        row = value["cases"][column]
        if not (_same(corrupted, row["corrupted"], row["after"]) and _same(row["restored"], expected)
                and _result(row["replay"], "FAIL") and _result(row["recovery"], "FAIL")
                and _result(row["restored_replay"], "PASS")):
            return False
    return True


def check_control(coordinate: str, controls: dict[str, Any]) -> bool:
    if coordinate == "LEDGER-1.2":
        value = controls["provisioning"]
        expected = _first_state("provisioning", value["commit"])
        return (_result(value["commit"], "PASS", ledger_id="provisioning") and _same(value["before"], value["same"], expected)
                and value["same_outcome"] == "RETURNED" and len(value["refused"]) == 3
                and all(row["outcome"] == "ValueError" and _same(row["state"], expected) for row in value["refused"]))
    if coordinate == "LEDGER-2.2":
        value = controls["retention"]
        checks = []
        for name, count, size in (("count", 4095, 4095 * len(canonical_bytes({"padding": ""}))),
                                  ("bytes", 16, 64 * 1024**2 - len(canonical_bytes({"value": "a"})))):
            row = value[name]
            before, full = row["before"], row["at_limit"]
            checks.append(_same(before["count"], count) and _same(before["retained_bytes"], size)
                and _result(row["accepted"], "PASS", ledger_id="retention-" + name)
                and _same(row["accepted"]["commit_sequence"], count + 1)
                and _same(full["count"], count + 1) and _same(full["retained_bytes"], size + len(canonical_bytes({"value": "a"})))
                and full["content_digest"] != before["content_digest"]
                and _result(row["exhausted"], "UNKNOWN", "LEDGER_RESOURCE_BOUND_EXHAUSTED")
                and _result(row["duplicate"], "FAIL", "KNOWN_INVOCATION_REPLAY")
                and _same(full, row["after_exhaustion"], row["after_duplicate"]))
        return all(checks)
    if coordinate == "LEDGER-3.2":
        return _integrity(controls["integrity"])
    if coordinate == "TRANSACTION-1.2":
        value = controls["resources"]
        expected = _first_state("resources", value["commit"])
        return (_result(value["commit"], "PASS", ledger_id="resources") and _same(value["original"], value["final"], expected)
                and len(value["missing"]) == 3 and len(value["invalid"]) == 4
                and all(row["before_exists"] is False and row["after_exists"] is False
                    and _result(row["result"], "UNKNOWN", reason) for row, reason in zip(value["missing"],
                        ("LEDGER_COMMIT_UNAVAILABLE_OR_UNCERTAIN", "LEDGER_REPLAY_UNAVAILABLE", "LEDGER_RECOVERY_UNAVAILABLE")))
                and all(_same(row["state"], expected) and all(_result(row[name], "FAIL") for name in ("commit", "replay", "recovery"))
                    for row in value["invalid"]))
    if coordinate == "TRANSACTION-2.2":
        value = controls["cancellation"]
        names = {exception + "-" + phase for exception in ("CancelledError", "KeyboardInterrupt") for phase in ("before", "after")}
        if set(value) != names:
            return False
        for name, row in value.items():
            empty = {"metadata": [[1, name, "local-check", 1]], "entries": [], "sequence": []}
            if (not _same(row["initial"], empty) or not _same(row["before_recovery"], row["after_recovery"])
                    or not _result(row["commit"], "UNKNOWN", "LEDGER_COMMIT_CANCELLED_OR_UNCERTAIN")):
                return False
            if name.endswith("-before"):
                if not _same(row["before_recovery"], empty) or not _result(row["recovery"], "UNKNOWN", "EXACT_COMMITTED_INVOCATION_UNAVAILABLE"):
                    return False
            elif (not _result(row["recovery"], "PASS") or row["recovery"]["commit"]["invocation_id"] != "a"
                    or not _closed_local_receipt(row["recovery"]["commit"])
                    or row["recovery"]["commit"]["ledger_id"] != name
                    or not _same(row["before_recovery"], _first_state(name, row["recovery"]["commit"]))):
                return False
        return True
    if coordinate == "TRANSACTION-3.2":
        value = controls["epoch_guards"]
        expected = _first_state("epoch-guards", value["commit"])
        advanced = {**expected, "metadata": [[1, "epoch-guards", "local-check", 3]]}
        final = {**advanced, "entries": [*expected["entries"], _entry("b", 2, 3, value["commit"]["mechanism_digest"])],
                 "sequence": [["issuance", 2]]}
        # bool and int compare equal in Python; preserve the tested input types.
        inputs = canonical_bytes([row["value"] for row in value["refused"]])
        return (_result(value["commit"], "PASS", ledger_id="epoch-guards") and _same(value["original"], expected)
                and inputs == canonical_bytes([1, 0, -1, True, 2**63])
                and all(row["outcome"] == "ValueError" and _same(row["state"], expected) for row in value["refused"])
                and _same(value["advanced"], value["after_stale"], advanced) and value["stale"] == "ValueError"
                and _result(value["duplicate"], "FAIL", "KNOWN_INVOCATION_REPLAY")
                and _result(value["fresh"], "PASS", ledger_id="epoch-guards")
                and _same(value["final"], final))
    raise ValueError("PACKAGE_EXECUTION_COORDINATE_UNREGISTERED")
