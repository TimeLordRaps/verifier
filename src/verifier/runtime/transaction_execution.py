"""Deterministic in-memory two-resource transaction coordinator for TRANSACTION declarations.

This module models, inside its in-memory boundary only, the Verifier Standard (VSTD) TRANSACTION
declaration fields that the local ledger mechanism does not establish: preconditions, authorization, operation identity
and replay, atomicity boundaries, retry limits, partial failure, compensation, finality and
reconciliation with recorded effects. The model has two in-memory resources,
``resource_a`` and ``resource_b``. A request declares preconditions, a bounded retry limit,
one effect per target, and a hash-based message authentication code (HMAC) tag from a named
authorizer. Phases are prepare, commit, abort and compensate. Each transition appends to a
Secure Hash Algorithm 256-bit (SHA-256) hash-chained journal. Every receipt derives its state
fresh from that journal and from the observed resource values, so no state word is stored and
trusted.

Established only inside this model: precondition snapshot binding; authorization by a keyed
tag over the canonical JavaScript Object Notation (JSON) request body; operation identity and
replay; no partial mutation on a refused form; the commit boundary; bounded retries; partial
failure and idempotent compensation; a local finality record; and reconciliation of intended
against applied effects.

NOT_ESTABLISHED: real authorizer identity (the key registry is in-process), durability of any
store, concurrent writers outside the coordinator, external settlement, and any relation to a
local ledger PASS. This module never reads ledger state.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SCHEMA_REQUEST = "verifier-transaction-request-1"
SCHEMA_RECEIPT = "verifier-transaction-receipt-1"
SOURCE_PATH = "src/verifier/runtime/transaction_execution.py"
RESOURCE_NAMES = ("resource_a", "resource_b")
MAX_EFFECTS = 4
MAX_RETRY_LIMIT = 3
GENESIS = "sha256:" + "0" * 64
BOUNDARY = (
    "In-memory two-resource model only: closed requests, HMAC-SHA256 tags from an in-process key registry, "
    "a SHA-256 hash-chained journal and reconciliation against observed values. Real authorizer identity, "
    "durable storage, concurrent writers, external settlement and any relation to a local ledger PASS are NOT_ESTABLISHED."
)
RECEIPT_FIELDS = frozenset({
    "schema", "operation", "operation_id", "request_digest", "snapshot_digest", "status", "state", "finality",
    "external_settlement", "reasons", "dispositions", "effects", "applied_effects", "compensated_effects",
    "attempts", "journal", "authorization", "source", "boundary", "receipt_digest",
})
TERMINAL_STATES = frozenset({"COMMITTED", "ABORTED", "COMPENSATED"})
_AUTHORIZATION_REASONS = frozenset({"AUTHORIZER_UNKNOWN", "AUTHORIZATION_TAG_REFUSED"})
_REQUEST_FIELDS = frozenset({
    "schema", "operation_id", "authorizer", "authorization_tag", "retry_limit", "preconditions", "effects",
})
_PRECONDITION_FIELDS = frozenset({"resource", "key", "expected"})
_EFFECT_FIELDS = frozenset({"resource", "key", "new_value"})
_NAME = re.compile(r"[a-z][a-z0-9._-]{0,63}")
_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}")
_TAG = re.compile(r"hmac-sha256:[0-9a-f]{64}")
_SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


class SimulatedCrash(BaseException):
    """A process stop between journal writes; BaseException keeps ``except Exception`` from absorbing it."""


class _Injected(Exception):
    """An injected resource fault. Its effect is classified by observation, never trusted from the exception."""


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _same(first: Any, second: Any) -> bool:
    """Canonical equality keeps bool, int, string and null values distinct."""
    return _canonical(first) == _canonical(second)


def _scalar(value: Any) -> Any:
    if type(value) is str or type(value) is bool or type(value) is int or value is None:
        return value
    raise _Refused("VALUE_TYPE_REFUSED")


def _text(value: Any, pattern: re.Pattern[str], reason: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise _Refused(reason)
    return value


def _safe_id(value: Any) -> str | None:
    return value if type(value) is str and _NAME.fullmatch(value) is not None else None


def _closed(value: Any, fields: frozenset[str], reason: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise _Refused(reason)
    return value


def _retry(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= MAX_RETRY_LIMIT:
        raise _Refused("RETRY_LIMIT_REFUSED")
    return value


def _rows(value: Any, fields: frozenset[str], reason: str, limit: int, field: str) -> list[dict[str, Any]]:
    if type(value) is not list or not 1 <= len(value) <= limit:
        raise _Refused(reason + "_LIST_REFUSED")
    rows = []
    for item in value:
        item = _closed(item, fields, reason + "_FIELDS_REFUSED")
        if type(item["resource"]) is not str or item["resource"] not in RESOURCE_NAMES:
            raise _Refused("RESOURCE_REFUSED")
        rows.append({"resource": item["resource"], "key": _text(item["key"], _KEY, reason + "_KEY_REFUSED"),
                     field: _scalar(item[field])})
    return rows


def _semantic(body: dict[str, Any]) -> None:
    """Reject ambiguous targets before any authority or resource is consulted."""
    expected: dict[tuple[str, str], Any] = {}
    for row in body["preconditions"]:
        target = (row["resource"], row["key"])
        if target in expected:
            raise _Refused("DUPLICATE_PRECONDITION")
        expected[target] = row["expected"]
    targets: set[tuple[str, str]] = set()
    for row in body["effects"]:
        target = (row["resource"], row["key"])
        if target in targets:
            raise _Refused("DUPLICATE_EFFECT_TARGET")
        targets.add(target)
        if target not in expected:
            raise _Refused("EFFECT_WITHOUT_PRECONDITION")
        if _same(expected[target], row["new_value"]):
            raise _Refused("NOOP_EFFECT_REFUSED")  # A no-op cannot be told apart from a non-application.
    if {row["resource"] for row in body["effects"]} != set(RESOURCE_NAMES):
        raise _Refused("SINGLE_RESOURCE_REFUSED")


def _parse(request: Any) -> tuple[dict[str, Any], Any]:
    """Return a freshly built canonical body and the presented tag; caller objects are never retained."""
    form = _closed(request, _REQUEST_FIELDS, "REQUEST_FIELDS_REFUSED")
    if type(form["schema"]) is not str or form["schema"] != SCHEMA_REQUEST:
        raise _Refused("REQUEST_SCHEMA_REFUSED")
    body = {
        "schema": SCHEMA_REQUEST,
        "operation_id": _text(form["operation_id"], _NAME, "OPERATION_ID_REFUSED"),
        "authorizer": _text(form["authorizer"], _NAME, "AUTHORIZER_REFUSED"),
        "retry_limit": _retry(form["retry_limit"]),
        "preconditions": _rows(form["preconditions"], _PRECONDITION_FIELDS, "PRECONDITION", 2 * MAX_EFFECTS, "expected"),
        "effects": _rows(form["effects"], _EFFECT_FIELDS, "EFFECT", MAX_EFFECTS, "new_value"),
    }
    _semantic(body)
    return body, form["authorization_tag"]


def _injection(value: Any, count: int) -> dict[str, Any] | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != {"effect", "mode"}:
        raise _Refused("INJECTION_FORM_REFUSED")
    index, mode = value["effect"], value["mode"]
    if type(index) is not int or not 0 <= index < count or mode not in ("before_write", "after_write"):
        raise _Refused("INJECTION_FORM_REFUSED")
    return {"effect": index, "mode": mode}


def _link(previous: str, body: dict[str, Any]) -> dict[str, Any]:
    return {**body, "chain": _digest({"previous": previous, "entry": body})}


def chain_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Seal entries in order. Tests use it to model an attacker who rewrites the chain itself."""
    sealed: list[dict[str, Any]] = []
    previous = GENESIS
    for index, entry in enumerate(entries):
        body = {"sequence": index, "operation_id": entry["operation_id"], "event": entry["event"],
                "effect": entry["effect"], "note": entry["note"]}
        sealed.append(_link(previous, body))
        previous = sealed[-1]["chain"]
    return sealed


def _chain_intact(entries: list[dict[str, Any]]) -> bool:
    try:
        return _same(entries, chain_entries(entries))
    except (KeyError, TypeError):
        return False


def authorization_tag(key: bytes, body: Mapping[str, Any]) -> str:
    """An authorizer's HMAC-SHA256 tag over the canonical request body, excluding the tag itself."""
    return "hmac-sha256:" + hmac.new(key, _canonical(dict(body)), hashlib.sha256).hexdigest()


def verify_receipt(receipt: Any) -> bool:
    """Integrity of receipt bytes only. The digest is not a signature and proves no authorship."""
    if type(receipt) is not dict or set(receipt) != RECEIPT_FIELDS:
        return False
    body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    return receipt["schema"] == SCHEMA_RECEIPT and receipt["receipt_digest"] == _digest(body)


def _checkpoint(crash_at: str | None, point: str) -> None:
    if crash_at == point:
        raise SimulatedCrash(point)


def _context(preconditions: str = "NOT_EVALUATED", authorization: str = "NOT_EVALUATED",
             identity: str = "NOT_EVALUATED") -> dict[str, str]:
    return {"preconditions": preconditions, "authorization": authorization, "operation_identity": identity}


class LocalResource:
    """An in-memory store with declared keys. ``write_count`` counts every mutation, including compensation."""

    def __init__(self, name: str, values: Mapping[str, Any]) -> None:
        if name not in RESOURCE_NAMES:
            raise ValueError("RESOURCE_NAME_REFUSED")
        self.name = name
        self.values: dict[str, Any] = {}
        for key, value in values.items():
            self.values[_text(key, _KEY, "KEY_REFUSED")] = _scalar(value)
        self.write_count = 0

    def write(self, key: str, value: Any) -> None:
        if key not in self.values:
            raise KeyError(key)
        self.values[key] = _scalar(value)
        self.write_count += 1


class Coordinator:
    """Prepare, commit, abort, compensate and reconcile over two in-memory resources."""

    def __init__(self, authorizer_keys: Mapping[str, bytes], resource_a: LocalResource, resource_b: LocalResource) -> None:
        for name, key in authorizer_keys.items():
            if type(name) is not str or _NAME.fullmatch(name) is None or type(key) is not bytes or len(key) < 16:
                raise ValueError("AUTHORIZER_KEY_REFUSED")
        self._keys = dict(authorizer_keys)
        self._resources = {resource.name: resource for resource in (resource_a, resource_b)}
        if tuple(sorted(self._resources)) != RESOURCE_NAMES:
            raise ValueError("RESOURCE_PAIR_REFUSED")
        self._ops: dict[str, dict[str, Any]] = {}
        self.journal: list[dict[str, Any]] = []

    def prepare(self, request: Any, *, crash_at: str | None = None) -> dict[str, Any]:
        peeked = _safe_id(request.get("operation_id")) if type(request) is dict else None
        try:
            body, tag = _parse(request)
            self._authorize(body, tag)
        except _Refused as refusal:
            auth = "FAIL" if refusal.reason in _AUTHORIZATION_REASONS else "NOT_EVALUATED"
            return self._receipt("prepare", peeked, "FAIL", [refusal.reason], _context(authorization=auth))
        operation = body["operation_id"]
        digest = _digest(body)
        existing = self._ops.get(operation)
        if existing is not None:
            if existing["request_digest"] != digest:
                return self._receipt("prepare", operation, "FAIL", ["OPERATION_ID_REUSED_WITH_DIFFERENT_REQUEST"],
                                     _context(authorization="PASS", identity="REUSED_REFUSED"))
            return self._receipt("prepare", operation, "PASS", ["OPERATION_ID_REPLAYED"],
                                 _context(authorization="PASS", identity="REPLAYED"))
        expected = {(row["resource"], row["key"]): row["expected"] for row in body["preconditions"]}
        for row in body["preconditions"]:
            values = self._resources[row["resource"]].values
            if row["key"] not in values:
                return self._receipt("prepare", operation, "FAIL", ["PRECONDITION_KEY_UNDECLARED"],
                                     _context("FAIL", "PASS", "NOT_CONSUMED"))
            if not _same(values[row["key"]], row["expected"]):
                return self._receipt("prepare", operation, "FAIL", ["PRECONDITION_MISMATCH"],
                                     _context("FAIL", "PASS", "NOT_CONSUMED"))
        self._ops[operation] = {
            "authorizer": body["authorizer"], "authorization_tag": tag, "retry_limit": body["retry_limit"],
            "request_digest": digest, "preconditions": body["preconditions"],
            "snapshot_digest": self._snapshot(body["preconditions"]),
            "effects": [{"resource": row["resource"], "key": row["key"],
                         "before": expected[(row["resource"], row["key"])], "new_value": row["new_value"]}
                        for row in body["effects"]],
        }
        record = self._ops[operation]
        self._append(operation, "PREPARED", note=digest)
        receipt = self._receipt("prepare", operation, "PASS", [], _context("PASS", "PASS", "NEW"))
        record["prepare_receipt"] = json.loads(_canonical(receipt))  # A copy: caller mutation cannot forge evidence.
        _checkpoint(crash_at, "after_prepare")
        return receipt

    def commit(self, operation_id: Any, evidence: Any, *, inject: Any = None, crash_at: str | None = None) -> dict[str, Any]:
        operation = _safe_id(operation_id)
        record = self._ops.get(operation)
        if record is None:
            return self._receipt("commit", operation, "FAIL", ["OPERATION_UNKNOWN"], _context())
        if not _same(evidence, record["prepare_receipt"]):
            return self._receipt("commit", operation, "FAIL", ["EVIDENCE_MISMATCH"], _context())
        context = _context(identity="EVIDENCE_BOUND")
        try:
            injection = _injection(inject, len(record["effects"]))
        except _Refused as refusal:
            return self._receipt("commit", operation, "FAIL", [refusal.reason], context)
        derived = self._derive(operation)
        if derived["integrity"] or derived["unexplained"]:
            return self._receipt("commit", operation, None, [], context)
        state = derived["state"]
        if state == "COMMITTED":
            return self._receipt("commit", operation, "PASS", ["OPERATION_REPLAYED"], context)
        if state == "APPLIED_UNRECORDED":
            self._append(operation, "COMMITTED", note="RECORDED_FROM_OBSERVED_EFFECTS")
            return self._receipt("commit", operation, "PASS", ["COMMIT_RECORDED_FROM_OBSERVED_EFFECTS"], context)
        if state == "NEEDS_COMPENSATION":
            return self._receipt("commit", operation, "FAIL", ["PARTIAL_EFFECTS_REQUIRE_COMPENSATION"], context)
        if state != "PREPARED":
            return self._receipt("commit", operation, "FAIL", ["OPERATION_TERMINAL"], context)
        if self._snapshot(record["preconditions"]) != record["snapshot_digest"]:
            return self._receipt("commit", operation, "FAIL", ["PRECONDITION_CHANGED_BEFORE_COMMIT"],
                                 _context("STALE_AT_COMMIT", identity="EVIDENCE_BOUND"))
        if derived["attempts"] >= 1 + record["retry_limit"]:
            return self._receipt("commit", operation, "FAIL", ["RETRY_LIMIT_EXCEEDED"], context)
        self._append(operation, "COMMIT_ATTEMPT", note=f"attempt {derived['attempts'] + 1}")
        return self._apply(operation, record, injection, crash_at, context)

    def abort(self, operation_id: Any) -> dict[str, Any]:
        operation = _safe_id(operation_id)
        if operation not in self._ops:
            return self._receipt("abort", operation, "FAIL", ["OPERATION_UNKNOWN"], _context())
        derived = self._derive(operation)
        if derived["integrity"] or derived["unexplained"]:
            return self._receipt("abort", operation, None, [], _context())
        state = derived["state"]
        if state == "ABORTED":
            return self._receipt("abort", operation, "PASS", ["OPERATION_REPLAYED"], _context())
        if state == "PREPARED":
            self._append(operation, "ABORTED", note="NO_EFFECTS_RECORDED")
            return self._receipt("abort", operation, "PASS", [], _context())
        reason = "EFFECTS_RECORDED_USE_COMPENSATE" if state in ("NEEDS_COMPENSATION", "APPLIED_UNRECORDED") else "OPERATION_TERMINAL"
        return self._receipt("abort", operation, "FAIL", [reason], _context())

    def compensate(self, operation_id: Any, *, crash_at: str | None = None) -> dict[str, Any]:
        operation = _safe_id(operation_id)
        if operation not in self._ops:
            return self._receipt("compensate", operation, "FAIL", ["OPERATION_UNKNOWN"], _context())
        derived = self._derive(operation)
        if derived["integrity"] or derived["unexplained"]:
            return self._receipt("compensate", operation, None, [], _context())
        state = derived["state"]
        if state == "COMPENSATED":
            return self._receipt("compensate", operation, "PASS", ["COMPENSATION_ALREADY_RECORDED"], _context())
        if state not in ("NEEDS_COMPENSATION", "APPLIED_UNRECORDED"):
            reason = "NOTHING_TO_COMPENSATE" if state == "PREPARED" else "OPERATION_NOT_COMPENSABLE"
            return self._receipt("compensate", operation, "FAIL", [reason], _context())
        record = self._ops[operation]
        for index in reversed(derived["applied"]):
            if index in derived["compensated"]:
                continue
            effect = record["effects"][index]
            resource = self._resources[effect["resource"]]
            note = None
            try:
                resource.write(effect["key"], effect["before"])
            except Exception as error:
                if not _same(resource.values[effect["key"]], effect["before"]):
                    return self._receipt("compensate", operation, "UNKNOWN",
                                         ["COMPENSATION_INTERRUPTED_BY_RESOURCE_FAULT"], _context())
                note = "RAISED_AFTER_WRITE:" + type(error).__name__
            self._append(operation, "COMPENSATED_EFFECT", effect=index, note=note)
            _checkpoint(crash_at, f"compensate:{index}")
        return self._receipt("compensate", operation, None, [], _context())

    def reconcile(self, operation_id: Any) -> dict[str, Any]:
        """Read-only: the journal and observed values are compared, and nothing is written."""
        operation = _safe_id(operation_id)
        if operation not in self._ops:
            return self._receipt("reconcile", operation, "FAIL", ["OPERATION_UNKNOWN"], _context())
        return self._receipt("reconcile", operation, None, [], _context())

    def _authorize(self, body: dict[str, Any], tag: Any) -> None:
        key = self._keys.get(body["authorizer"])
        if key is None:
            raise _Refused("AUTHORIZER_UNKNOWN")
        if type(tag) is not str or _TAG.fullmatch(tag) is None or not hmac.compare_digest(tag, authorization_tag(key, body)):
            raise _Refused("AUTHORIZATION_TAG_REFUSED")

    def _snapshot(self, preconditions: list[dict[str, Any]]) -> str:
        return _digest([[row["resource"], row["key"], self._resources[row["resource"]].values[row["key"]]]
                        for row in preconditions])

    def _append(self, operation_id: str, event: str, effect: int | None = None, note: str | None = None) -> None:
        previous = self.journal[-1]["chain"] if self.journal else GENESIS
        body = {"sequence": len(self.journal), "operation_id": operation_id, "event": event, "effect": effect, "note": note}
        self.journal.append(_link(previous, body))

    def _apply(self, operation: str, record: dict[str, Any], injection: dict[str, Any] | None,
               crash_at: str | None, context: dict[str, str]) -> dict[str, Any]:
        _checkpoint(crash_at, "attempt")  # The attempt is journaled, so its retry budget is consumed even if no write follows.
        for index, effect in enumerate(record["effects"]):
            resource = self._resources[effect["resource"]]
            targeted = injection is not None and injection["effect"] == index
            try:
                if targeted and injection["mode"] == "before_write":
                    raise _Injected("before_write")
                resource.write(effect["key"], effect["new_value"])
                if targeted and injection["mode"] == "after_write":
                    raise _Injected("after_write")
            except Exception as error:
                if _same(resource.values[effect["key"]], effect["new_value"]):
                    self._append(operation, "EFFECT_APPLIED", effect=index, note="RAISED_AFTER_WRITE:" + type(error).__name__)
                else:
                    self._append(operation, "EFFECT_FAILED", effect=index, note=type(error).__name__)
                return self._receipt("commit", operation, "UNKNOWN", ["COMMIT_INTERRUPTED_BY_RESOURCE_FAULT"], context)
            self._append(operation, "EFFECT_APPLIED", effect=index)
            _checkpoint(crash_at, f"effect:{index}")
        _checkpoint(crash_at, "all_effects")
        self._append(operation, "COMMITTED", note="ALL_EFFECTS_APPLIED")
        return self._receipt("commit", operation, "PASS", [], context)

    def _derive(self, operation_id: str) -> dict[str, Any]:
        """Reconcile the journal with observed values; the state is computed here and never stored."""
        record = self._ops[operation_id]
        entries = [entry for entry in self.journal if entry["operation_id"] == operation_id]
        events = [entry["event"] for entry in entries]
        applied = [entry["effect"] for entry in entries if entry["event"] == "EFFECT_APPLIED"]
        compensated = [entry["effect"] for entry in entries if entry["event"] == "COMPENSATED_EFFECT"]
        rows = []
        for index, effect in enumerate(record["effects"]):
            observed = self._resources[effect["resource"]].values[effect["key"]]
            if _same(observed, effect["new_value"]):
                disposition = "APPLIED"
            elif _same(observed, effect["before"]):
                disposition = "NOT_APPLIED"
            else:
                disposition = "CONFLICT"
            rows.append({"index": index, "resource": effect["resource"], "key": effect["key"],
                         "before": effect["before"], "intended_after": effect["new_value"], "observed": observed,
                         "disposition": disposition, "applied_by_journal": index in applied,
                         "compensated_by_journal": index in compensated})
        integrity: list[str] = []
        unexplained: list[str] = []
        drift: list[str] = []
        if not _chain_intact(self.journal):
            integrity.append("JOURNAL_CHAIN_BROKEN")
        valid = all(type(index) is int and 0 <= index < len(rows) for index in applied + compensated)
        if not valid:
            integrity.append("EFFECT_INDEX_OUT_OF_RANGE")
        else:
            if applied != list(range(len(applied))):
                integrity.append("EFFECT_ORDER_VIOLATION")
            if compensated != list(reversed(applied))[:len(compensated)]:
                integrity.append("COMPENSATION_ORDER_VIOLATION")
            contradicts = ("COMMITTED" in events and ("ABORTED" in events or compensated or len(applied) != len(rows))
                           or "ABORTED" in events and (applied or compensated))
            if contradicts:
                integrity.append("TERMINAL_RECORD_CONTRADICTS_EFFECTS")
            written = {row["index"] for row in rows if row["disposition"] == "APPLIED"}
            if set(applied) != written | set(compensated):
                unexplained.append("RECORDED_EFFECTS_DO_NOT_MATCH_OBSERVATION")
            if any(rows[index]["disposition"] != "NOT_APPLIED" for index in compensated):
                unexplained.append("COMPENSATION_NOT_REVERSED")
            if any(row["disposition"] == "CONFLICT" for row in rows):
                # With no applied effects, a drifted target only blocks commit; it is not an unexplained effect.
                if applied:
                    unexplained.append("EFFECT_TARGET_CONFLICT")
                else:
                    drift.append("PRECONDITION_DRIFT")
        if "ABORTED" in events:
            state = "ABORTED"
        elif "COMMITTED" in events:
            state = "COMMITTED"
        elif not applied:
            state = "PREPARED"
        elif len(compensated) == len(applied):
            state = "COMPENSATED"
        elif not compensated and len(applied) == len(rows):
            state = "APPLIED_UNRECORDED"
        else:
            state = "NEEDS_COMPENSATION"
        if integrity:
            state = "INTEGRITY_VIOLATION"
        elif unexplained:
            state = "CONFLICT_REQUIRES_REVIEW"
        return {"state": state, "finality": "FINAL_LOCAL_RECORD" if state in TERMINAL_STATES else "NOT_FINAL",
                "rows": rows, "applied": applied, "compensated": compensated, "attempts": events.count("COMMIT_ATTEMPT"),
                "events": events, "integrity": integrity, "unexplained": unexplained, "drift": drift}

    def _dispositions(self, derived: dict[str, Any], context: Mapping[str, str], record: dict[str, Any] | None) -> dict[str, str]:
        state, applied, total = derived["state"], derived["applied"], len(derived["rows"])
        violated = bool(derived["integrity"] or derived["unexplained"])
        if violated:
            atomicity = "UNRESOLVED"
        elif not applied:
            atomicity = "NO_PARTIAL_MUTATION"
        elif len(applied) == total:
            atomicity = "ALL_EFFECTS_APPLIED"
        else:
            atomicity = "PARTIAL_EFFECTS_APPLIED"
        if violated:
            partial = "UNRESOLVED"
        elif state == "NEEDS_COMPENSATION":
            partial = "NEEDS_COMPENSATION"
        elif state == "APPLIED_UNRECORDED":
            partial = "COMMIT_UNRECORDED"
        elif state == "PREPARED" and "EFFECT_FAILED" in derived["events"]:
            partial = "COMMIT_FAILED_NO_EFFECT"
        else:
            partial = "NONE"
        if violated:
            compensation = "UNRESOLVED"
        elif state in ("NEEDS_COMPENSATION", "APPLIED_UNRECORDED"):
            compensation = "PENDING"
        elif state == "COMPENSATED":
            compensation = "COMPLETE"
        else:
            compensation = "NOT_REQUIRED"
        attempts = derived["attempts"]
        if record is None or attempts == 0:
            retry = "NOT_APPLICABLE"
        else:
            retry = "WITHIN_LIMIT" if attempts <= 1 + record["retry_limit"] else "LIMIT_EXCEEDED"
        recorded = "INTEGRITY_VIOLATION" if derived["integrity"] else "DIVERGED" if derived["unexplained"] else "EXACT"
        return {"preconditions": context["preconditions"], "authorization": context["authorization"],
                "operation_identity": context["operation_identity"], "atomicity": atomicity, "retry": retry,
                "partial_failure": partial, "compensation": compensation, "recorded_effects": recorded,
                "finality": derived["finality"]}

    def _receipt(self, operation: str, operation_id: str | None, status: str | None,
                 reasons: list[str], context: Mapping[str, str]) -> dict[str, Any]:
        record = self._ops.get(operation_id) if operation_id is not None else None
        if record is None:
            derived = {"state": "REFUSED", "finality": "NOT_FINAL", "rows": [], "applied": [], "compensated": [],
                       "attempts": 0, "events": [], "integrity": [], "unexplained": [], "drift": []}
        else:
            derived = self._derive(operation_id)
        if derived["integrity"]:
            status = "FAIL"
        elif derived["unexplained"]:
            status = "UNKNOWN"
        elif status is None:
            status = "PASS" if derived["state"] in TERMINAL_STATES else "UNKNOWN"
        body = {
            "schema": SCHEMA_RECEIPT, "operation": operation, "operation_id": operation_id,
            "request_digest": record["request_digest"] if record else None,
            "snapshot_digest": record["snapshot_digest"] if record else None,
            "status": status, "state": derived["state"], "finality": derived["finality"],
            "external_settlement": "NOT_ESTABLISHED",
            "reasons": list(dict.fromkeys(reasons + derived["integrity"] + derived["unexplained"] + derived["drift"])),
            "dispositions": self._dispositions(derived, context, record),
            "effects": derived["rows"], "applied_effects": derived["applied"],
            "compensated_effects": derived["compensated"],
            "attempts": {"used": derived["attempts"], "allowed": 1 + record["retry_limit"] if record else None},
            "journal": {"entries": len(self.journal),
                        "chain_head": self.journal[-1]["chain"] if self.journal else GENESIS},
            "authorization": {"authorizer": record["authorizer"] if record else None,
                              "tag_digest": _digest(record["authorization_tag"]) if record else None,
                              "identity_authentication": "NOT_ESTABLISHED"},
            "source": {"path": SOURCE_PATH, "sha256": _SOURCE_SHA256},
            "boundary": BOUNDARY,
        }
        return {**body, "receipt_digest": _digest(body)}


# Auxiliary correspondence to existing TRANSACTION owner coordinates, mechanism side only. The owner
# is the local invocation ledger: this module names its adapter and pins its proposition digests but
# never imports or reads it. Each row reproduces one in-model claim against its owner coordinate. It is
# not a carried route, a route PASS or conformance, and this module is not a package execution mechanism.
ADAPTER = "verifier-transaction-coordinator-1"
OWNER_ADAPTER = "verifier-local-invocation-ledger-1"
OWNER_PROPOSITION_DIGESTS = {
    "TRANSACTION-1.1": "sha256:0db34cb1e6b3423e9cf8b84782d38e9ab8928b82cbae459c0199f4e8665c27b3",
    "TRANSACTION-2.1": "sha256:f34af6a88de443c0ff741ed6510c20ba2f9d5c08123ef810277215fe2f8a7613",
    "TRANSACTION-3.1": "sha256:7d1bb429c0ac6cf9c2f62535f85fbadb3fec47040783f58bde01b280e106590f",
}
ROUTE_COORDINATES = ("TRANSACTION-1.1", "TRANSACTION-2.1", "TRANSACTION-3.1")
ROUTE_TIERS = {"TRANSACTION-1.1": 1, "TRANSACTION-2.1": 2, "TRANSACTION-3.1": 3}
SEMANTIC_VERSION = "verifier-transaction-coordinator-obligations-1"
IMPLEMENTATION = SOURCE_PATH
OBSERVATION_SCHEMA = "verifier-transaction-coordinator-observations-1"
_ROUTES = (
    ("TRANSACTION-1.1", "coordinator-input-preconditions", 1,
     "Invalid authority, closed-form, undeclared-key and stale-precondition inputs must be refused before any journal record or resource write.",
     "In the in-memory two-resource model, every forged or unknown authority form, closed-form violation, undeclared key and stale precondition in the fixture set returns FAIL with state REFUSED, no journal record, no resource write and no consumed operation identifier, and a genuine request then prepares. Authorizer identity and identity authentication are NOT_ESTABLISHED."),
    ("TRANSACTION-2.1", "coordinator-commit-boundary", 2,
     "A failure before a resource write and a failure after it must leave different recorded effects, and neither may be reported as a completed commit.",
     "In the in-memory model, a failure before the second write leaves one applied effect that needs compensation; a failure before the first write applies nothing and is retryable within its limit; a failure after the first write is recorded as applied; a crash after all writes but before the COMMITTED record is reconciled from observed values and completed without rewriting. Finality is local only and external settlement is NOT_ESTABLISHED."),
    ("TRANSACTION-3.1", "coordinator-replay-and-retry", 3,
     "Replay, identifier reuse, repeated compensation and retries must not apply the same effect a second time or exceed the declared retry bound.",
     "In the single-threaded in-memory model, repeated prepare or commit of one operation identifier, repeated compensation, and a commit after the declared retry budget is consumed never add a resource write, and reuse of an identifier with a different request is refused. Concurrent writers and authority-epoch transitions are NOT_ESTABLISHED."),
)
_SECTIONS = {"TRANSACTION-1.1": "input_refusals", "TRANSACTION-2.1": "commit_boundary", "TRANSACTION-3.1": "replay_and_retry"}
_SECTION_NAMES = ("input_refusals", "commit_boundary", "replay_and_retry")
_OBSERVATION_KEY = b"transaction-coordinator-observation-key-0001"
_STEP_FIELDS = ("status", "state", "reasons", "applied_effects", "compensated_effects", "finality",
                "external_settlement", "values", "writes", "events")
_MALFORMED = {
    "extra_top_field": lambda r: r.__setitem__("extra", 1),
    "extra_precondition_field": lambda r: r["preconditions"][0].__setitem__("note", "x"),
    "extra_effect_field": lambda r: r["effects"][0].__setitem__("expected", "a0"),
    "float_value": lambda r: r["effects"][0].__setitem__("new_value", 1.5),
    "tuple_preconditions": lambda r: r.__setitem__("preconditions", tuple(r["preconditions"])),
    "string_retry_limit": lambda r: r.__setitem__("retry_limit", "1"),
    "bool_retry_limit": lambda r: r.__setitem__("retry_limit", True),
    "retry_limit_over_bound": lambda r: r.__setitem__("retry_limit", MAX_RETRY_LIMIT + 1),
    "duplicate_effect_target": lambda r: r["effects"].append({"resource": "resource_a", "key": "slot", "new_value": "a2"}),
    "effect_without_precondition": lambda r: r["preconditions"].pop(1),
    "noop_effect": lambda r: r["effects"][0].__setitem__("new_value", "a0"),
    "single_resource": lambda r: r.__setitem__("effects", [{"resource": "resource_a", "key": "slot", "new_value": "a1"}]),
    "wrong_schema": lambda r: r.__setitem__("schema", "other"),
    "uppercase_operation_id": lambda r: r.__setitem__("operation_id", "Op 1"),
    "empty_effects": lambda r: r.__setitem__("effects", []),
    "unknown_resource": lambda r: r["effects"][0].__setitem__("resource", "resource_c"),
    "uppercase_key": lambda r: r["effects"][0].__setitem__("key", "Slot"),
}
# Each expected refusal reason is the one _parse or prepare actually emits for that form.
_REFUSAL_REASONS = {
    "forgery:wrong_key": "AUTHORIZATION_TAG_REFUSED",
    "forgery:tag_for_other_effects": "AUTHORIZATION_TAG_REFUSED",
    "forgery:tag_for_other_operation": "AUTHORIZATION_TAG_REFUSED",
    "forgery:unknown_authorizer": "AUTHORIZER_UNKNOWN",
    "forgery:uppercase_tag": "AUTHORIZATION_TAG_REFUSED",
    "forgery:missing_tag": "REQUEST_FIELDS_REFUSED",
    "malformed:extra_top_field": "REQUEST_FIELDS_REFUSED",
    "malformed:extra_precondition_field": "PRECONDITION_FIELDS_REFUSED",
    "malformed:extra_effect_field": "EFFECT_FIELDS_REFUSED",
    "malformed:float_value": "VALUE_TYPE_REFUSED",
    "malformed:tuple_preconditions": "PRECONDITION_LIST_REFUSED",
    "malformed:string_retry_limit": "RETRY_LIMIT_REFUSED",
    "malformed:bool_retry_limit": "RETRY_LIMIT_REFUSED",
    "malformed:retry_limit_over_bound": "RETRY_LIMIT_REFUSED",
    "malformed:duplicate_effect_target": "DUPLICATE_EFFECT_TARGET",
    "malformed:effect_without_precondition": "EFFECT_WITHOUT_PRECONDITION",
    "malformed:noop_effect": "NOOP_EFFECT_REFUSED",
    "malformed:single_resource": "SINGLE_RESOURCE_REFUSED",
    "malformed:wrong_schema": "REQUEST_SCHEMA_REFUSED",
    "malformed:uppercase_operation_id": "OPERATION_ID_REFUSED",
    "malformed:empty_effects": "EFFECT_LIST_REFUSED",
    "malformed:unknown_resource": "RESOURCE_REFUSED",
    "malformed:uppercase_key": "EFFECT_KEY_REFUSED",
    "undeclared_key": "PRECONDITION_KEY_UNDECLARED",
    "stale_precondition": "PRECONDITION_MISMATCH",
}


def catalog() -> list[dict[str, Any]]:
    """Auxiliary correspondence rows. The owner digest is pinned; the in-model claim digest binds this model."""
    rows = [{"route_coordinate": coordinate, "obligation_id": coordinate + "-" + slug,
             "obligation_name": slug.replace("-", " ").capitalize(), "object_kind": "TRANSACTION", "tier": tier,
             "reason": reason, "in_model_claim": claim,
             "in_model_claim_digest": _digest({"route_coordinate": coordinate, "claim": claim, "boundary": BOUNDARY}),
             "route_proposition_digest": OWNER_PROPOSITION_DIGESTS.get(coordinate),
             "route_owner_adapter": OWNER_ADAPTER, "semantic_version": SEMANTIC_VERSION,
             "checking_mechanism": "verifier.runtime.transaction_execution.check_observations",
             "scope": "fresh_transaction_coordinator_" + slug.replace("-", "_"), "adapter": ADAPTER,
             "coverage": "AUXILIARY_CORRESPONDENCE", "carried_by_route": False,
             "route_status": "NOT_ESTABLISHED", "conformance_status": "NOT_ESTABLISHED"}
            for coordinate, slug, tier, reason, claim in _ROUTES]
    if len({row["route_coordinate"] for row in rows}) != len(rows):
        raise ValueError("TRANSACTION_ROUTE_DUPLICATED")
    if any(row["route_coordinate"] not in OWNER_PROPOSITION_DIGESTS for row in rows):
        raise ValueError("TRANSACTION_ROUTE_UNPINNED")
    return rows


def _propositions() -> dict[str, dict[str, str]]:
    """Header binding for observations: the pinned owner digest and the in-model claim digest per coordinate."""
    return {row["route_coordinate"]: {"route_proposition_digest": row["route_proposition_digest"],
                                      "in_model_claim_digest": row["in_model_claim_digest"]}
            for row in catalog()}


def route_drift(rows: Sequence[Any]) -> list[str]:
    """Compare caller-supplied owner route rows with the pinned correspondence. An empty list means exact agreement.

    Rows use the owner's own shape (coordinate, tier, proposition_digest, adapter). The module never reads
    the owner, so a changed owner claim surfaces here only when a caller supplies its live rows.
    """
    diagnostics: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if type(row) is not dict:
            diagnostics.append("ROW_SHAPE_DIFFERS")
            continue
        coordinate = row.get("coordinate")
        if coordinate not in ROUTE_COORDINATES:
            diagnostics.append(f"UNKNOWN:{coordinate!r}")
            continue
        if coordinate in seen:
            diagnostics.append(f"DUPLICATED:{coordinate}")
            continue
        seen.add(coordinate)
        if row.get("tier") != ROUTE_TIERS[coordinate]:
            diagnostics.append(f"TIER_DRIFT:{coordinate}")
        if row.get("proposition_digest") != OWNER_PROPOSITION_DIGESTS[coordinate]:
            diagnostics.append(f"PROPOSITION_DRIFT:{coordinate}")
        if row.get("adapter") != OWNER_ADAPTER:
            diagnostics.append(f"ADAPTER_DRIFT:{coordinate}")
    for coordinate in ROUTE_COORDINATES:
        if coordinate not in seen:
            diagnostics.append(f"MISSING:{coordinate}")
    return diagnostics


def _canonical_copy(value: Any) -> Any:
    """A detached JSON copy, so no observation shares a mutable object with coordinator state."""
    return json.loads(_canonical(value))


def _strict_json(value: Any) -> bool:
    """Exact JSON types only: a tuple, a float or a non-string key is a form change, not equal evidence."""
    if type(value) is dict:
        return all(type(key) is str and _strict_json(item) for key, item in value.items())
    if type(value) is list:
        return all(_strict_json(item) for item in value)
    return type(value) in (str, int, bool) or value is None


def _unaliased(value: Any) -> bool:
    """Each container appears once; a shared object would let one step stand in for another."""
    seen: set[int] = set()
    stack = [value]
    while stack:
        item = stack.pop()
        if type(item) in (dict, list):
            if id(item) in seen:
                return False
            seen.add(id(item))
            stack.extend(item.values() if type(item) is dict else item)
    return True


def _effects(a_value: Any, b_value: Any) -> list[dict[str, Any]]:
    return [{"resource": "resource_a", "key": "slot", "new_value": a_value},
            {"resource": "resource_b", "key": "slot", "new_value": b_value}]


def _body(op: str = "op-1", *, authorizer: str = "auth-1", limit: int = 0, effects: list | None = None,
          preconditions: list | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA_REQUEST, "operation_id": op, "authorizer": authorizer, "retry_limit": limit,
        "preconditions": preconditions if preconditions is not None else [
            {"resource": "resource_a", "key": "slot", "expected": "a0"},
            {"resource": "resource_b", "key": "slot", "expected": "b0"}],
        "effects": effects if effects is not None else _effects("a1", "b1"),
    }


def _signed(body: dict[str, Any], key: bytes = _OBSERVATION_KEY) -> dict[str, Any]:
    return {**body, "authorization_tag": authorization_tag(key, body)}


def _fixture() -> tuple[Coordinator, LocalResource, LocalResource]:
    a = LocalResource("resource_a", {"slot": "a0"})
    b = LocalResource("resource_b", {"slot": "b0"})
    return Coordinator({"auth-1": _OBSERVATION_KEY}, a, b), a, b


def _values(a: LocalResource, b: LocalResource) -> list[dict[str, Any]]:
    return [dict(a.values), dict(b.values)]


def _step(coord: Coordinator, a: LocalResource, b: LocalResource, receipt: dict[str, Any]) -> dict[str, Any]:
    return {"status": receipt["status"], "state": receipt["state"], "reasons": receipt["reasons"],
            "applied_effects": receipt["applied_effects"], "compensated_effects": receipt["compensated_effects"],
            "finality": receipt["finality"], "external_settlement": receipt["external_settlement"],
            "values": _values(a, b), "writes": [a.write_count, b.write_count],
            "events": [entry["event"] for entry in coord.journal], "receipt": receipt}


def _attempt(call: Callable[[], dict[str, Any]], coord: Coordinator, a: LocalResource, b: LocalResource) -> dict[str, Any]:
    """A call stopped by a simulated crash is observed as the state it left, with no receipt."""
    try:
        return _step(coord, a, b, call())
    except SimulatedCrash:
        return {"status": "SIMULATED_CRASH", "state": None, "reasons": [], "applied_effects": [],
                "compensated_effects": [], "finality": "NOT_FINAL", "external_settlement": "NOT_ESTABLISHED",
                "values": _values(a, b), "writes": [a.write_count, b.write_count],
                "events": [entry["event"] for entry in coord.journal], "receipt": None}


def _input_refusals() -> dict[str, list[dict[str, Any]]]:
    coord, a, b = _fixture()
    forged = {
        "wrong_key": _signed(_body(), key=b"w" * 32),
        "tag_for_other_effects": {**_body(effects=_effects("a9", "b1")),
                                  "authorization_tag": authorization_tag(_OBSERVATION_KEY, _body())},
        "tag_for_other_operation": {**_body("op-1"),
                                    "authorization_tag": authorization_tag(_OBSERVATION_KEY, _body("op-2"))},
        "unknown_authorizer": _signed(_body(authorizer="auth-9")),
        "uppercase_tag": {**_signed(_body()),
                          "authorization_tag": authorization_tag(_OBSERVATION_KEY, _body()).upper()},
        "missing_tag": _body(),
    }
    cases: dict[str, list[dict[str, Any]]] = {}
    for name, request in forged.items():
        cases["forgery:" + name] = [_attempt(lambda request=request: coord.prepare(request), coord, a, b)]
    for name, change in _MALFORMED.items():
        body = _body()
        change(body)
        cases["malformed:" + name] = [_attempt(lambda body=body: coord.prepare(_signed(body)), coord, a, b)]
    undeclared = _body(preconditions=[{"resource": "resource_a", "key": "ghost", "expected": "a0"},
                                      {"resource": "resource_b", "key": "slot", "expected": "b0"}],
                       effects=[{"resource": "resource_a", "key": "ghost", "new_value": "a1"},
                                {"resource": "resource_b", "key": "slot", "new_value": "b1"}])
    cases["undeclared_key"] = [_attempt(lambda: coord.prepare(_signed(undeclared)), coord, a, b)]
    stale = _body(preconditions=[{"resource": "resource_a", "key": "slot", "expected": "zz"},
                                 {"resource": "resource_b", "key": "slot", "expected": "b0"}])
    cases["stale_precondition"] = [_attempt(lambda: coord.prepare(_signed(stale)), coord, a, b)]
    cases["genuine_after_refusals"] = [_attempt(lambda: coord.prepare(_signed(_body())), coord, a, b)]
    return cases


def _commit_boundary() -> dict[str, list[dict[str, Any]]]:
    cases: dict[str, list[dict[str, Any]]] = {}
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body()))
    cases["before_second_write"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.commit("op-1", prepared, inject={"effect": 1, "mode": "before_write"}), coord, a, b),
        _attempt(lambda: coord.reconcile("op-1"), coord, a, b)]
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body()))
    cases["after_first_write"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.commit("op-1", prepared, inject={"effect": 0, "mode": "after_write"}), coord, a, b),
        _attempt(lambda: coord.abort("op-1"), coord, a, b)]
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body(limit=1)))
    cases["before_first_write_retryable"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.commit("op-1", prepared, inject={"effect": 0, "mode": "before_write"}), coord, a, b),
        _attempt(lambda: coord.commit("op-1", prepared), coord, a, b)]
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body()))
    cases["crash_before_committed_record"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.commit("op-1", prepared, crash_at="all_effects"), coord, a, b),
        _attempt(lambda: coord.reconcile("op-1"), coord, a, b),
        _attempt(lambda: coord.commit("op-1", prepared), coord, a, b)]
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body()))
    cases["committed"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.commit("op-1", prepared), coord, a, b)]
    return cases


def _replay_and_retry() -> dict[str, list[dict[str, Any]]]:
    cases: dict[str, list[dict[str, Any]]] = {}
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body()))
    cases["duplicate_prepare"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.prepare(_signed(_body())), coord, a, b)]
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body()))
    cases["reused_identifier"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.prepare(_signed(_body(effects=_effects("a9", "b1")))), coord, a, b)]
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body()))
    cases["commit_replay"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.commit("op-1", prepared), coord, a, b),
        _attempt(lambda: coord.commit("op-1", prepared), coord, a, b)]
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body()))
    cases["compensate_replay"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.commit("op-1", prepared, inject={"effect": 0, "mode": "after_write"}), coord, a, b),
        _attempt(lambda: coord.compensate("op-1"), coord, a, b),
        _attempt(lambda: coord.compensate("op-1"), coord, a, b)]
    coord, a, b = _fixture()
    prepared = coord.prepare(_signed(_body(limit=1)))
    cases["retry_budget"] = [
        _step(coord, a, b, prepared),
        _attempt(lambda: coord.commit("op-1", prepared, inject={"effect": 0, "mode": "before_write"}), coord, a, b),
        _attempt(lambda: coord.commit("op-1", prepared, inject={"effect": 0, "mode": "before_write"}), coord, a, b),
        _attempt(lambda: coord.commit("op-1", prepared), coord, a, b)]
    return cases


def observe() -> dict[str, Any]:
    """One fresh, deterministic execution of the in-memory model. Repeated calls return identical bytes."""
    return _canonical_copy({
        "source": {"path": SOURCE_PATH, "sha256": _SOURCE_SHA256},
        "mechanism_version": SEMANTIC_VERSION,
        "propositions": _propositions(),
        "boundary": BOUNDARY,
        "input_refusals": _input_refusals(),
        "commit_boundary": _commit_boundary(),
        "replay_and_retry": _replay_and_retry(),
    })


def _exp(status: str, state: str | None, reasons: Any = (), *, applied: Any = (), compensated: Any = (),
         values: tuple[str, str] = ("a0", "b0"), writes: tuple[int, int] = (0, 0), events: Any = (),
         finality: str = "NOT_FINAL") -> dict[str, Any]:
    """Exact expected step. Lists are copied so no expectation can alias another."""
    return {"status": status, "state": state, "reasons": list(reasons), "applied_effects": list(applied),
            "compensated_effects": list(compensated), "finality": finality, "external_settlement": "NOT_ESTABLISHED",
            "values": [{"slot": values[0]}, {"slot": values[1]}], "writes": list(writes), "events": list(events)}


_INTERRUPTED = ["COMMIT_INTERRUPTED_BY_RESOURCE_FAULT"]
_PREPARE = ["PREPARED"]
_EXPECTED_SECTIONS: dict[str, dict[str, list[dict[str, Any]]]] = {
    "input_refusals": {
        **{name: [_exp("FAIL", "REFUSED", [reason])] for name, reason in _REFUSAL_REASONS.items()},
        "genuine_after_refusals": [_exp("PASS", "PREPARED", events=_PREPARE)],
    },
    "commit_boundary": {
        "before_second_write": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("UNKNOWN", "NEEDS_COMPENSATION", _INTERRUPTED, applied=[0], values=("a1", "b0"), writes=(1, 0),
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "EFFECT_FAILED"]),
            _exp("UNKNOWN", "NEEDS_COMPENSATION", applied=[0], values=("a1", "b0"), writes=(1, 0),
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "EFFECT_FAILED"]),
        ],
        "after_first_write": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("UNKNOWN", "NEEDS_COMPENSATION", _INTERRUPTED, applied=[0], values=("a1", "b0"), writes=(1, 0),
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED"]),
            _exp("FAIL", "NEEDS_COMPENSATION", ["EFFECTS_RECORDED_USE_COMPENSATE"], applied=[0],
                 values=("a1", "b0"), writes=(1, 0), events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED"]),
        ],
        "before_first_write_retryable": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("UNKNOWN", "PREPARED", _INTERRUPTED, events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_FAILED"]),
            _exp("PASS", "COMMITTED", applied=[0, 1], values=("a1", "b1"), writes=(1, 1), finality="FINAL_LOCAL_RECORD",
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_FAILED", "COMMIT_ATTEMPT", "EFFECT_APPLIED",
                         "EFFECT_APPLIED", "COMMITTED"]),
        ],
        "crash_before_committed_record": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("SIMULATED_CRASH", None, values=("a1", "b1"), writes=(1, 1),
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "EFFECT_APPLIED"]),
            _exp("UNKNOWN", "APPLIED_UNRECORDED", applied=[0, 1], values=("a1", "b1"), writes=(1, 1),
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "EFFECT_APPLIED"]),
            _exp("PASS", "COMMITTED", ["COMMIT_RECORDED_FROM_OBSERVED_EFFECTS"], applied=[0, 1], values=("a1", "b1"),
                 writes=(1, 1), finality="FINAL_LOCAL_RECORD",
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "EFFECT_APPLIED", "COMMITTED"]),
        ],
        "committed": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("PASS", "COMMITTED", applied=[0, 1], values=("a1", "b1"), writes=(1, 1), finality="FINAL_LOCAL_RECORD",
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "EFFECT_APPLIED", "COMMITTED"]),
        ],
    },
    "replay_and_retry": {
        "duplicate_prepare": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("PASS", "PREPARED", ["OPERATION_ID_REPLAYED"], events=_PREPARE),
        ],
        "reused_identifier": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("FAIL", "PREPARED", ["OPERATION_ID_REUSED_WITH_DIFFERENT_REQUEST"], events=_PREPARE),
        ],
        "commit_replay": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("PASS", "COMMITTED", applied=[0, 1], values=("a1", "b1"), writes=(1, 1), finality="FINAL_LOCAL_RECORD",
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "EFFECT_APPLIED", "COMMITTED"]),
            _exp("PASS", "COMMITTED", ["OPERATION_REPLAYED"], applied=[0, 1], values=("a1", "b1"), writes=(1, 1),
                 finality="FINAL_LOCAL_RECORD",
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "EFFECT_APPLIED", "COMMITTED"]),
        ],
        "compensate_replay": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("UNKNOWN", "NEEDS_COMPENSATION", _INTERRUPTED, applied=[0], values=("a1", "b0"), writes=(1, 0),
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED"]),
            _exp("PASS", "COMPENSATED", applied=[0], compensated=[0], writes=(2, 0), finality="FINAL_LOCAL_RECORD",
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "COMPENSATED_EFFECT"]),
            _exp("PASS", "COMPENSATED", ["COMPENSATION_ALREADY_RECORDED"], applied=[0], compensated=[0], writes=(2, 0),
                 finality="FINAL_LOCAL_RECORD",
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_APPLIED", "COMPENSATED_EFFECT"]),
        ],
        "retry_budget": [
            _exp("PASS", "PREPARED", events=_PREPARE),
            _exp("UNKNOWN", "PREPARED", _INTERRUPTED, events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_FAILED"]),
            _exp("UNKNOWN", "PREPARED", _INTERRUPTED,
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_FAILED", "COMMIT_ATTEMPT", "EFFECT_FAILED"]),
            _exp("FAIL", "PREPARED", ["RETRY_LIMIT_EXCEEDED"],
                 events=["PREPARED", "COMMIT_ATTEMPT", "EFFECT_FAILED", "COMMIT_ATTEMPT", "EFFECT_FAILED"]),
        ],
    },
}


def _step_matches(row: Any, expected: dict[str, Any]) -> bool:
    """A step is evidence only if its receipt is digest-valid, bound to this source, and agrees with the row."""
    if type(row) is not dict or set(row) != {*_STEP_FIELDS, "receipt"}:
        return False
    receipt = row["receipt"]
    if row["status"] == "SIMULATED_CRASH":
        bound = receipt is None
    else:
        bound = (verify_receipt(receipt) and receipt["status"] == row["status"] and receipt["state"] == row["state"]
                 and receipt["reasons"] == row["reasons"]
                 and receipt["source"] == {"path": SOURCE_PATH, "sha256": _SOURCE_SHA256}
                 and receipt["boundary"] == BOUNDARY
                 and receipt["authorization"]["identity_authentication"] == "NOT_ESTABLISHED")
    return bound and _canonical({key: row[key] for key in _STEP_FIELDS}) == _canonical(expected)


def _section_matches(section: Any, expected: dict[str, list[dict[str, Any]]]) -> bool:
    return type(section) is dict and set(section) == set(expected) and all(
        type(section[name]) is list and len(section[name]) == len(steps)
        and all(_step_matches(row, exp) for row, exp in zip(section[name], steps))
        for name, steps in expected.items())


def _header_matches(observed: dict[str, Any]) -> bool:
    """Source, version, boundary and every proposition digest must be the current ones."""
    return (set(observed) == {"source", "mechanism_version", "propositions", "boundary", *_SECTION_NAMES}
            and observed["source"] == {"path": SOURCE_PATH, "sha256": _SOURCE_SHA256}
            and observed["mechanism_version"] == SEMANTIC_VERSION and observed["boundary"] == BOUNDARY
            and observed["propositions"] == _propositions())


def check_observations(coordinate: str, observed: dict[str, Any]) -> bool:
    """Fail-closed oracle over one fresh observation; a catalog row or status word never substitutes for it."""
    if coordinate not in _SECTIONS:
        raise ValueError("TRANSACTION_COORDINATE_UNREGISTERED")
    name = _SECTIONS[coordinate]
    try:
        return (type(observed) is dict and _strict_json(observed) and _unaliased(observed)
                and _header_matches(observed) and _section_matches(observed[name], _EXPECTED_SECTIONS[name]))
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        return False
