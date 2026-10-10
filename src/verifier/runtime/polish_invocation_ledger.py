"""JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

Bounded local consume-and-record prerequisite for a new polish issuer.

Experimental bounded local consumption prerequisite. JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256); Structured Query Language (SQL); Uniform Naming Convention
(UNC). This explicit local state operation does not assess complete
polish, public historical execution, worldwide uniqueness, human authority, or
publication. An authenticated host provisions the ledger; candidates cannot choose
its path or policy epoch. Integer timestamps are host observations, not time truth.
"""
from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import sqlite3
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import certificate_dag as codec

MAX_PROPOSAL_BYTES = 4 * 1024**2
MAX_RECEIPT_BYTES = 64 * 1024
MAX_INVOCATIONS = 4096
MAX_RETAINED_BYTES = 64 * 1024**2
MAX_BUSY_SECONDS = 5.0
RECEIPT = "verifier-polish-local-invocation-commit-1"
REPLAY = "verifier-polish-local-invocation-replay-1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CLAIM_BOUNDARY = ("Same exact committed proposal in one configured local ledger only; "
                   "not polish, public historical execution or worldwide uniqueness.")


@dataclass(frozen=True)
class IssuerLedgerSelection:
    """Host-provisioned local trust boundary; never decoded from candidate JSON."""

    path: str
    ledger_id: str
    policy_domain: str
    policy_epoch: int


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def mechanism_digest() -> str:
    root = Path(__file__).parents[1]
    files = ("runtime/polish_invocation_ledger.py", "domains/contracts/certificate_dag.py",
             "core/certificate.py", "core/receipt.py", "standard/POLISH_INVOCATION_LEDGER.md")
    return _digest(canonical_bytes({"sources": {p: _digest((root / p).read_bytes()) for p in files},
                                   "sqlite_version": sqlite3.sqlite_version}))


def _time(value: Any) -> int:
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError("plain bounded ledger time/epoch required")
    return value


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError("exact proposal/status byte digest required")
    return value


def _selection(value: IssuerLedgerSelection) -> tuple[IssuerLedgerSelection, Path]:
    if type(value) is not IssuerLedgerSelection:
        raise ValueError("authenticated host ledger selection required")
    if type(value.path) is not str or not value.path or len(value.path) > 4096:
        raise ValueError("bounded local configured ledger path required")
    path = Path(value.path)
    if not path.is_absolute() or path.anchor.startswith("\\\\"):
        raise ValueError("absolute non-UNC configured ledger path required")
    codec._text(value.ledger_id)
    codec._text(value.policy_domain)
    if _time(value.policy_epoch) < 1:
        raise ValueError("positive configured policy epoch required")
    return IssuerLedgerSelection(value.path, value.ledger_id, value.policy_domain, value.policy_epoch), path


def _connect(path: Path, *, writable: bool) -> sqlite3.Connection:
    # Commit/recheck never creates a missing database. Only explicit provisioning
    # may create it. A host must place this database on storage it controls.
    connection = sqlite3.connect(path.as_uri() + ("?mode=rw" if writable else "?mode=ro"),
                                 uri=True, timeout=MAX_BUSY_SECONDS, isolation_level=None)
    if writable:
        connection.execute("PRAGMA synchronous=FULL")
    return connection


def _meta(connection: sqlite3.Connection, selection: IssuerLedgerSelection) -> None:
    rows = connection.execute("SELECT ledger_id, policy_domain, policy_epoch FROM ledger_meta LIMIT 2").fetchall()
    if rows != [(selection.ledger_id, selection.policy_domain, selection.policy_epoch)]:
        raise ValueError("configured ledger identity or current policy epoch differs")


def provision_issuance_ledger(selection: IssuerLedgerSelection) -> None:
    """Explicit operator initialization; no artifact assessment or candidate setup."""
    selected, path = _selection(selection)
    with closing(sqlite3.connect(path, timeout=MAX_BUSY_SECONDS, isolation_level=None)) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("CREATE TABLE IF NOT EXISTS ledger_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), ledger_id TEXT NOT NULL, policy_domain TEXT NOT NULL, policy_epoch INTEGER NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS issuance (sequence INTEGER PRIMARY KEY AUTOINCREMENT, invocation_id TEXT UNIQUE NOT NULL, policy_epoch INTEGER NOT NULL, proposal_digest TEXT NOT NULL, authority_status_digest TEXT NOT NULL, commit_time INTEGER NOT NULL, proposal BLOB NOT NULL, mechanism_digest TEXT NOT NULL)")
            if not connection.execute("SELECT singleton FROM ledger_meta").fetchall():
                connection.execute("INSERT INTO ledger_meta VALUES (1, ?, ?, ?)",
                                   (selected.ledger_id, selected.policy_domain, selected.policy_epoch))
            _meta(connection, selected)
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise


def advance_policy_epoch(selection: IssuerLedgerSelection, *, new_epoch: int) -> None:
    """Operator invalidation fence; source/root/status changes must advance it.

    This update alone neither authenticates new roots nor makes an earlier issuance
    acceptable under a changed policy. Provisioning/revocation responsibilities are
    explicit external host obligations.
    """
    selected, path = _selection(selection)
    if _time(new_epoch) <= selected.policy_epoch:
        raise ValueError("ledger policy epoch must strictly advance")
    with closing(_connect(path, writable=True)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _meta(connection, selected)
            connection.execute("UPDATE ledger_meta SET policy_epoch=? WHERE singleton=1", (new_epoch,))
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise


def _proposal(raw: bytes, expected_digest: str) -> None:
    if type(raw) is not bytes or len(raw) > MAX_PROPOSAL_BYTES:
        raise ValueError("bounded immutable issuance proposal required")
    if _hash(expected_digest) != _digest(raw):
        raise ValueError("exact externally selected issuance proposal differs")
    codec._parse(raw)  # Canonical finite plain object, not a polish verdict.


def _receipt(selected: IssuerLedgerSelection, invocation: str, row: tuple[Any, ...]) -> dict[str, Any]:
    sequence, epoch, digest, status_digest, instant, raw, source = row
    if (type(sequence) is not int or not 1 <= sequence < 2**63 or _time(epoch) != selected.policy_epoch
            or type(raw) is not bytes or len(raw) > MAX_PROPOSAL_BYTES or _digest(raw) != digest
            or source != mechanism_digest()):
        raise ValueError("committed proposal/epoch/mechanism differs")
    _time(instant)
    _hash(status_digest)
    result = {"schema_version": RECEIPT, "status": "PASS", "polished": False,
        "invocation_consumption": "CONSUMED_EXACT_LOCAL_LEDGER", "ledger_id": selected.ledger_id,
        "policy_domain": selected.policy_domain, "policy_epoch": epoch, "invocation_id": invocation,
        "commit_sequence": sequence, "proposal_digest": digest, "authority_status_digest": status_digest,
        "commit_time": instant, "mechanism_digest": source,
        "public_consumption_authentication": "NOT_ESTABLISHED",
        "claim_boundary": _CLAIM_BOUNDARY}
    result["receipt_digest"] = _digest(canonical_bytes(result))
    return result


def _read_row(connection: sqlite3.Connection, invocation: str) -> tuple[Any, ...] | None:
    size = connection.execute("SELECT length(proposal) FROM issuance WHERE invocation_id=?", (invocation,)).fetchone()
    if size is None:
        return None
    if type(size[0]) is not int or not 0 <= size[0] <= MAX_PROPOSAL_BYTES:
        raise ValueError("stored proposal exceeds the admitted fixed bound")
    return connection.execute("SELECT sequence, policy_epoch, proposal_digest, authority_status_digest, commit_time, proposal, mechanism_digest FROM issuance WHERE invocation_id=?", (invocation,)).fetchone()


def commit_issuance(proposal_bytes: bytes, *, expected_proposal_digest: str,
        invocation_id: str, authority_status_digest: str, commit_time: int,
        selection: IssuerLedgerSelection) -> dict[str, Any]:
    """Atomically consume one invocation and retain its exact bounded proposal.

    The full issuer calls this only after real completeness/native/public/authority
    checks. The host serializes revocation/configuration changes through policy_epoch;
    this primitive cannot obtain or authenticate an external authority channel.
    """
    result = {"schema_version": RECEIPT, "status": "UNKNOWN", "polished": False,
              "invocation_consumption": "NOT_ESTABLISHED"}
    try:
        selected, path = _selection(selection)
        _proposal(proposal_bytes, expected_proposal_digest)
        invocation = codec._text(invocation_id)
        _hash(authority_status_digest)
        _time(commit_time)
        source = mechanism_digest()
        with closing(_connect(path, writable=True)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                _meta(connection, selected)
                if connection.execute("SELECT 1 FROM issuance WHERE invocation_id=?", (invocation,)).fetchone():
                    connection.execute("ROLLBACK")
                    return {**result, "status": "FAIL", "reason": "KNOWN_INVOCATION_REPLAY"}
                count, retained = connection.execute("SELECT COUNT(*), COALESCE(SUM(length(proposal)), 0) FROM issuance").fetchone()
                if count >= MAX_INVOCATIONS or retained + len(proposal_bytes) > MAX_RETAINED_BYTES:
                    raise codec._Exhausted("configured local ledger retained capacity")
                cursor = connection.execute("INSERT INTO issuance (invocation_id, policy_epoch, proposal_digest, authority_status_digest, commit_time, proposal, mechanism_digest) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (invocation, selected.policy_epoch, expected_proposal_digest, authority_status_digest,
                     commit_time, proposal_bytes, source))
                # Construct bounded receipt before COMMIT; any capacity/source failure
                # rolls the transaction back. Uncertain COMMIT never returns PASS.
                receipt = _receipt(selected, invocation, (cursor.lastrowid, selected.policy_epoch,
                    expected_proposal_digest, authority_status_digest, commit_time, proposal_bytes, source))
                if len(canonical_bytes(receipt)) > MAX_RECEIPT_BYTES:
                    raise codec._Exhausted("ledger receipt capacity")
                connection.execute("COMMIT")
                return receipt
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
    except (codec._Exhausted, RecursionError, OverflowError):
        result["reason"] = "LEDGER_RESOURCE_BOUND_EXHAUSTED"
    except (asyncio.CancelledError, KeyboardInterrupt):
        result["reason"] = "LEDGER_COMMIT_CANCELLED_OR_UNCERTAIN"
    except (OSError, sqlite3.Error, ImportError):
        result["reason"] = "LEDGER_COMMIT_UNAVAILABLE_OR_UNCERTAIN"
    except (ValueError, TypeError, KeyError, UnicodeError):
        result.update(status="FAIL", reason="LEDGER_SELECTION_OR_PROPOSAL_REFUSED")
    return result


def recheck_issuance_commit(receipt_bytes: bytes, *, proposal_bytes: bytes,
        expected_proposal_digest: str, selection: IssuerLedgerSelection) -> dict[str, Any]:
    """Read the SAME committed entry; never retry consumption or issue again."""
    result = {"schema_version": REPLAY, "status": "FAIL", "replay_status": "REJECTED", "polished": False}
    try:
        selected, path = _selection(selection)
        _proposal(proposal_bytes, expected_proposal_digest)
        if type(receipt_bytes) is not bytes or len(receipt_bytes) > MAX_RECEIPT_BYTES:
            raise ValueError("bounded immutable ledger receipt required")
        stored = codec._parse(receipt_bytes)
        codec._record(stored, {"schema_version", "status", "polished", "invocation_consumption",
            "ledger_id", "policy_domain", "policy_epoch", "invocation_id", "commit_sequence",
            "proposal_digest", "authority_status_digest", "commit_time", "mechanism_digest",
            "public_consumption_authentication", "claim_boundary", "receipt_digest"})
        # A hash is not authentication. These are locally decidable contradictions
        # checked before storage/source availability can turn reproduction UNKNOWN.
        if (stored["schema_version"] != RECEIPT or stored["status"] != "PASS"
                or stored["polished"] is not False
                or stored["invocation_consumption"] != "CONSUMED_EXACT_LOCAL_LEDGER"
                or stored["public_consumption_authentication"] != "NOT_ESTABLISHED"
                or stored["claim_boundary"] != _CLAIM_BOUNDARY
                or stored["proposal_digest"] != expected_proposal_digest
                or stored["ledger_id"] != selected.ledger_id
                or stored["policy_domain"] != selected.policy_domain
                or _time(stored["policy_epoch"]) != selected.policy_epoch
                or _hash(stored["receipt_digest"]) != _digest(canonical_bytes(
                    {k:v for k,v in stored.items() if k != "receipt_digest"}))):
            raise ValueError("retained receipt/proposal/selection commitment differs")
        if _time(stored["commit_sequence"]) < 1:
            raise ValueError("positive plain committed sequence required")
        _time(stored["commit_time"])
        _hash(stored["authority_status_digest"])
        _hash(stored["mechanism_digest"])
        invocation = codec._text(stored["invocation_id"])
        with closing(_connect(path, writable=False)) as connection:
            connection.execute("BEGIN")
            _meta(connection, selected)
            row = _read_row(connection, invocation)
            connection.execute("COMMIT")
        if row is None:
            return {**result, "status": "UNKNOWN", "reason": "EXACT_COMMITTED_INVOCATION_UNAVAILABLE"}
        if row[5] != proposal_bytes:
            raise ValueError("another proposal consumed this invocation")
        actual = _receipt(selected, invocation, row)
        if canonical_bytes(actual) != canonical_bytes(stored):
            raise ValueError("exact ledger receipt differs")
        return {**result, "status": "PASS", "replay_status": "REPRODUCED",
                "receipt_digest": actual["receipt_digest"], "proposal_digest": expected_proposal_digest}
    except (codec._Exhausted, RecursionError, OverflowError):
        return {**result, "status": "UNKNOWN", "reason": "LEDGER_RESOURCE_BOUND_EXHAUSTED"}
    except (asyncio.CancelledError, KeyboardInterrupt):
        return {**result, "status": "UNKNOWN", "reason": "LEDGER_REPLAY_CANCELLED"}
    except (OSError, sqlite3.Error, ImportError):
        return {**result, "status": "UNKNOWN", "reason": "LEDGER_REPLAY_UNAVAILABLE"}
    except (ValueError, TypeError, KeyError, UnicodeError):
        return {**result, "reason": "LEDGER_SELECTION_OR_RECEIPT_REFUSED"}


def recover_issuance_commit(proposal_bytes: bytes, *, expected_proposal_digest: str,
        invocation_id: str, selection: IssuerLedgerSelection) -> dict[str, Any]:
    """Read-only recovery after uncertain commit; never consumes or retries issuance."""
    result = {"schema_version": REPLAY, "status": "UNKNOWN", "replay_status": "UNAVAILABLE", "polished": False}
    try:
        selected, path = _selection(selection)
        _proposal(proposal_bytes, expected_proposal_digest)
        invocation = codec._text(invocation_id)
        with closing(_connect(path, writable=False)) as connection:
            connection.execute("BEGIN")
            _meta(connection, selected)
            row = _read_row(connection, invocation)
            connection.execute("COMMIT")
        if row is None:
            return {**result, "reason": "EXACT_COMMITTED_INVOCATION_UNAVAILABLE"}
        if row[5] != proposal_bytes:
            return {**result, "status": "FAIL", "replay_status": "REJECTED", "reason": "ANOTHER_PROPOSAL_CONSUMED_INVOCATION"}
        return {**result, "status": "PASS", "replay_status": "REPRODUCED", "commit": _receipt(selected, invocation, row)}
    except (codec._Exhausted, RecursionError, OverflowError):
        return {**result, "reason": "LEDGER_RESOURCE_BOUND_EXHAUSTED"}
    except (asyncio.CancelledError, KeyboardInterrupt):
        return {**result, "reason": "LEDGER_RECOVERY_CANCELLED"}
    except (OSError, sqlite3.Error, ImportError):
        return {**result, "reason": "LEDGER_RECOVERY_UNAVAILABLE"}
    except (ValueError, TypeError, KeyError, UnicodeError):
        return {**result, "status": "FAIL", "replay_status": "REJECTED", "reason": "LEDGER_SELECTION_OR_PROPOSAL_REFUSED"}
