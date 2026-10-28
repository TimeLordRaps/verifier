"""Fixed local ledger control experiments for Verifier Standard (VSTD).

Structured Query Language (SQL); Secure Hash Algorithm 256-bit (SHA-256).
Only the worker's private databases are changed. Direct fixture inserts establish
capacity boundary states, not historical issuance evidence. Backend interruption
is injected in-process; no operator process, authority or storage is controlled.
"""
from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import shutil
import sqlite3
from typing import Any, Callable

from verifier.core.certificate import canonical_bytes
from verifier.runtime import polish_invocation_ledger as ledger


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _proposal(identifier: str = "a") -> bytes:
    return canonical_bytes({"value": identifier})


def _state(selected: ledger.IssuerLedgerSelection) -> dict[str, Any]:
    """Read all persisted fields independently of the production receipt builder."""
    with closing(sqlite3.connect(Path(selected.path).as_uri() + "?mode=ro", uri=True)) as connection:
        metadata = connection.execute("SELECT * FROM ledger_meta ORDER BY singleton").fetchall()
        entries = connection.execute("SELECT * FROM issuance ORDER BY sequence").fetchall()
        sequence = connection.execute("SELECT * FROM sqlite_sequence ORDER BY name").fetchall()
    return {"metadata": [list(row) for row in metadata],
            "entries": [[value.decode() if type(value) is bytes else value for value in row] for row in entries],
            "sequence": [list(row) for row in sequence]}


def _usage(selected: ledger.IssuerLedgerSelection) -> dict[str, Any]:
    """Bounded output even when the fixture contains the full retained-byte cap."""
    count, retained, commitment = 0, 0, hashlib.sha256()
    with closing(sqlite3.connect(Path(selected.path).as_uri() + "?mode=ro", uri=True)) as connection:
        for row in connection.execute("SELECT * FROM issuance ORDER BY sequence"):
            count += 1
            retained += len(row[6])
            commitment.update(canonical_bytes([_digest(value) if type(value) is bytes else value for value in row]))
    return {"count": count, "retained_bytes": retained, "content_digest": "sha256:" + commitment.hexdigest()}


def _refusal(action: Callable[[], None]) -> str:
    try:
        action()
    except ValueError:
        return "ValueError"
    return "RETURNED"


@dataclass(frozen=True)
class _Experiment:
    directory: Path

    def provision(self, name: str) -> ledger.IssuerLedgerSelection:
        selected = ledger.IssuerLedgerSelection(str(self.directory / (name + ".sqlite")), name, "local-check", 1)
        ledger.provision_issuance_ledger(selected)
        return selected

    def commit(self, selected: Any, identifier: str = "a") -> dict[str, Any]:
        raw = _proposal(identifier)
        return ledger.commit_issuance(raw, expected_proposal_digest=_digest(raw), invocation_id=identifier,
            authority_status_digest="sha256:" + "a" * 64, commit_time=100, selection=selected)

    def replay(self, selected: Any, receipt: dict[str, Any]) -> dict[str, Any]:
        return ledger.recheck_issuance_commit(canonical_bytes(receipt), proposal_bytes=_proposal(),
            expected_proposal_digest=_digest(_proposal()), selection=selected)

    def recover(self, selected: Any) -> dict[str, Any]:
        return ledger.recover_issuance_commit(_proposal(), expected_proposal_digest=_digest(_proposal()),
            invocation_id="a", selection=selected)


def _provisioning(probe: _Experiment) -> dict[str, Any]:
    selected = probe.provision("provisioning")
    committed = probe.commit(selected)
    before = _state(selected)
    repeated = _refusal(lambda: ledger.provision_issuance_ledger(selected))
    same = _state(selected)
    refused = []
    for variant in (replace(selected, ledger_id="different"), replace(selected, policy_domain="different"),
                    replace(selected, policy_epoch=2)):
        outcome = _refusal(lambda: ledger.provision_issuance_ledger(variant))
        refused.append({"outcome": outcome, "state": _state(selected)})
    return {"commit": committed, "before": before, "same_outcome": repeated, "same": same, "refused": refused}


def _seed(selected: ledger.IssuerLedgerSelection, sizes: list[int]) -> None:
    """Seed valid canonical proposals; actual boundary commits use the public path."""
    overhead = len(canonical_bytes({"padding": ""}))
    source = ledger.mechanism_digest()
    with closing(sqlite3.connect(selected.path)) as connection:
        with connection:
            for index, size in enumerate(sizes):
                if not overhead <= size <= 4 * 1024**2:
                    raise ValueError("fixed seed size outside proposal boundary")
                raw = canonical_bytes({"padding": "x" * (size - overhead)})
                connection.execute("INSERT INTO issuance (invocation_id, policy_epoch, proposal_digest, authority_status_digest, commit_time, proposal, mechanism_digest) VALUES (?, 1, ?, ?, 100, ?, ?)",
                    ("seed-" + str(index), _digest(raw), "sha256:" + "a" * 64, raw, source))


def _retention(probe: _Experiment) -> dict[str, Any]:
    # Exercise the real configured limits. Lowering constants would only prove a
    # different implementation. Refuse insufficient local resources as UNKNOWN.
    if shutil.disk_usage(probe.directory).free < 3 * 64 * 1024**2:
        raise OSError("insufficient temporary capacity for actual ledger boundaries")
    remaining = 64 * 1024**2 - len(_proposal())
    byte_sizes = [4 * 1024**2] * (remaining // (4 * 1024**2))
    byte_sizes.append(remaining % (4 * 1024**2))
    result = {}
    for name, sizes in (("count", [len(canonical_bytes({"padding": ""}))] * 4095), ("bytes", byte_sizes)):
        selected = probe.provision("retention-" + name)
        _seed(selected, sizes)
        before = _usage(selected)
        accepted = probe.commit(selected)
        at_limit = _usage(selected)
        exhausted = probe.commit(selected, "b")
        after_exhaustion = _usage(selected)
        duplicate = probe.commit(selected)
        result[name] = {"before": before, "accepted": accepted, "at_limit": at_limit,
            "exhausted": exhausted, "after_exhaustion": after_exhaustion,
            "duplicate": duplicate, "after_duplicate": _usage(selected)}
    return result


def _integrity(probe: _Experiment) -> dict[str, Any]:
    selected = probe.provision("integrity")
    receipt = probe.commit(selected)
    original = _state(selected)
    cases = {}
    # Fixed column names only. Each mutation is restored before the next probe;
    # an invalid stored field must not become valid merely through recovery.
    for column, changed in (("proposal", _proposal("other")), ("proposal_digest", "sha256:" + "0" * 64),
                            ("policy_epoch", 2), ("commit_time", -1), ("mechanism_digest", "sha256:" + "0" * 64)):
        with closing(sqlite3.connect(selected.path)) as connection:
            previous = connection.execute("SELECT " + column + " FROM issuance WHERE invocation_id='a'").fetchone()[0]
            with connection:
                connection.execute("UPDATE issuance SET " + column + "=? WHERE invocation_id='a'", (changed,))
        corrupted = _state(selected)
        replay, recovery = probe.replay(selected, receipt), probe.recover(selected)
        after = _state(selected)
        with closing(sqlite3.connect(selected.path)) as connection:
            with connection:
                connection.execute("UPDATE issuance SET " + column + "=? WHERE invocation_id='a'", (previous,))
        cases[column] = {"corrupted": corrupted, "replay": replay, "recovery": recovery,
            "after": after, "restored": _state(selected), "restored_replay": probe.replay(selected, receipt)}
    return {"commit": receipt, "original": original, "cases": cases}


def _resources(probe: _Experiment) -> dict[str, Any]:
    selected = probe.provision("resources")
    receipt = probe.commit(selected)
    original = _state(selected)
    absent = replace(selected, path=str(probe.directory / "never-provisioned.sqlite"))
    missing = []
    for action in (lambda: probe.commit(absent), lambda: probe.replay(absent, receipt), lambda: probe.recover(absent)):
        before = Path(absent.path).exists()
        missing.append({"before_exists": before, "result": action(), "after_exists": Path(absent.path).exists()})
    invalid = []
    for variant in (replace(selected, ledger_id="different"), replace(selected, policy_domain="different"),
                    replace(selected, policy_epoch=2), {"path": selected.path}):
        invalid.append({"commit": probe.commit(variant, "b"), "replay": probe.replay(variant, receipt),
            "recovery": probe.recover(variant), "state": _state(selected)})
    return {"commit": receipt, "original": original, "missing": missing, "invalid": invalid, "final": _state(selected)}


class _InterruptedConnection:
    """Injects a fault at the COMMIT edge; `after` means the commit was durable before the fault."""

    def __init__(self, connection: sqlite3.Connection, exception: type[BaseException], after: bool) -> None:
        self.connection, self.exception, self.after = connection, exception, after

    @property
    def in_transaction(self) -> bool:
        return self.connection.in_transaction

    def execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        if sql == "COMMIT":
            if self.after:
                self.connection.execute(sql, parameters)
            raise self.exception()
        return self.connection.execute(sql, parameters)

    def close(self) -> None:
        self.connection.close()


def _observed(action: Callable[[], Any], *, exception: type[BaseException] | None = None,
        after: bool = False) -> tuple[Any, int]:
    """Run one public operation; the count is every backend connection it opened (no hidden retry)."""
    original_connect = ledger._connect
    attempts: list[bool] = []

    def connect(path: Path, *, writable: bool) -> Any:
        attempts.append(writable)
        connection = original_connect(path, writable=writable)
        return _InterruptedConnection(connection, exception, after) if exception and writable else connection

    try:
        ledger._connect = connect
        return action(), len(attempts)
    finally:
        ledger._connect = original_connect


def _recover_identifier(selected: ledger.IssuerLedgerSelection, identifier: str) -> dict[str, Any]:
    """Read-only recovery of the named invocation; _Experiment.recover is fixed to invocation "a"."""
    raw = _proposal(identifier)
    return ledger.recover_issuance_commit(raw, expected_proposal_digest=_digest(raw), invocation_id=identifier,
        selection=selected)


def _retained(state: dict[str, Any]) -> int:
    return sum(len(row[6].encode("utf-8")) for row in state["entries"])


def _ordering(probe: _Experiment) -> dict[str, Any]:
    """LEDGER-0.1: gap-free sequences; rollback consumes no sequence; post-acknowledgement loss keeps its slot."""
    selected = probe.provision("ordering")
    first = probe.commit(selected, "a")
    duplicate = probe.commit(selected, "a")
    uncertain_before, _ = _observed(lambda: probe.commit(selected, "c"), exception=sqlite3.OperationalError)
    second = probe.commit(selected, "b")
    uncertain_after, _ = _observed(lambda: probe.commit(selected, "d"), exception=sqlite3.OperationalError, after=True)
    last = probe.commit(selected, "e")
    state = _state(selected)
    return {"first": first, "duplicate": duplicate, "uncertain_before": uncertain_before, "second": second,
        "uncertain_after": uncertain_after, "last": last, "rows": state["entries"], "sequence": state["sequence"]}


def _corrections(probe: _Experiment) -> dict[str, Any]:
    """LEDGER-0.3: a different proposal for a consumed invocation is refused; only epoch metadata may advance."""
    selected = probe.provision("corrections")
    receipt = probe.commit(selected, "a")
    original = _state(selected)
    corrected = _proposal("corrected")
    commit = ledger.commit_issuance(corrected, expected_proposal_digest=_digest(corrected), invocation_id="a",
        authority_status_digest="sha256:" + "a" * 64, commit_time=100, selection=selected)
    replay = ledger.recheck_issuance_commit(canonical_bytes(receipt), proposal_bytes=corrected,
        expected_proposal_digest=_digest(corrected), selection=selected)
    recover = ledger.recover_issuance_commit(corrected, expected_proposal_digest=_digest(corrected),
        invocation_id="a", selection=selected)
    after = _state(selected)
    ledger.advance_policy_epoch(selected, new_epoch=2)
    return {"receipt": receipt, "original": original, "commit": commit, "replay": replay, "recover": recover,
        "after": after, "epoch": _state(selected)}


def _retry(probe: _Experiment) -> dict[str, Any]:
    """TRANSACTION-0.3: each public operation opens one backend connection; the busy bound is finite."""
    selected = probe.provision("retry")
    commit_precommit, pre = _observed(lambda: probe.commit(selected, "a"), exception=sqlite3.OperationalError)
    recover_precommit, pre_recovery = _observed(lambda: _recover_identifier(selected, "a"))
    commit_postcommit, post = _observed(lambda: probe.commit(selected, "b"), exception=sqlite3.OperationalError, after=True)
    recover_postcommit, post_recovery = _observed(lambda: _recover_identifier(selected, "b"))
    proposal = _proposal("b")
    recheck, replay = _observed(lambda: ledger.recheck_issuance_commit(canonical_bytes(recover_postcommit["commit"]),
        proposal_bytes=proposal, expected_proposal_digest=_digest(proposal), selection=selected))
    duplicate, duplicate_attempts = _observed(lambda: probe.commit(selected, "b"))

    def row(outcome: Any, attempts: int) -> dict[str, Any]:
        return {"outcome": outcome, "attempts": attempts}

    return {"commit_precommit": row(commit_precommit, pre), "recover_after_precommit": row(recover_precommit, pre_recovery),
        "commit_postcommit": row(commit_postcommit, post), "recover_after_postcommit": row(recover_postcommit, post_recovery),
        "recheck": row(recheck, replay), "duplicate": row(duplicate, duplicate_attempts),
        "busy_seconds": ledger.MAX_BUSY_SECONDS}


def _authorization(probe: _Experiment) -> dict[str, Any]:
    """TRANSACTION-0.1 supported part: malformed authority digests are refused before any row exists."""
    selected = probe.provision("authorization")
    before = _state(selected)
    refused = {}
    raw = _proposal("a")
    for label, value in {"absent": None, "empty": "", "uppercase": "sha256:" + "A" * 64,
                         "short": "sha256:" + "a" * 63, "wrong_algorithm": "sha1:" + "a" * 40,
                         "bytes": b"sha256:" + b"a" * 64, "padded": "sha256:" + "a" * 64 + " "}.items():
        refused[label] = ledger.commit_issuance(raw, expected_proposal_digest=_digest(raw), invocation_id="a",
            authority_status_digest=value, commit_time=100, selection=selected)
    after_refusals = _state(selected)
    # Syntactically valid but unauthenticated: retained as a status digest, never as authenticated authority.
    boundary = probe.commit(selected, "b")
    return {"before": before, "refused": refused, "after_refusals": after_refusals, "boundary": boundary,
        "final": _state(selected)}


def _accounting(probe: _Experiment) -> dict[str, Any]:
    """LEDGER-0.2 sources and sinks: every step is a full before/after persisted snapshot."""
    selected = probe.provision("accounting")
    steps = []

    def step(name: str, action: Callable[[], Any], **fault: Any) -> None:
        before = _state(selected)
        outcome, _ = _observed(action, **fault)
        steps.append({"name": name, "before": before, "outcome": outcome, "after": _state(selected)})

    step("commit-a", lambda: probe.commit(selected, "a"))
    step("duplicate-a", lambda: probe.commit(selected, "a"))
    step("precommit-c", lambda: probe.commit(selected, "c"), exception=sqlite3.OperationalError)
    step("postcommit-d", lambda: probe.commit(selected, "d"), exception=sqlite3.OperationalError, after=True)
    step("recover-d", lambda: _recover_identifier(selected, "d"))
    step("commit-e", lambda: probe.commit(selected, "e"))
    return {"steps": steps, "final": _state(selected)}


def _cancellation(probe: _Experiment) -> dict[str, Any]:
    original_connect = ledger._connect
    results = {}
    for exception in (asyncio.CancelledError, KeyboardInterrupt):
        for phase in ("before", "after"):
            name = exception.__name__ + "-" + phase
            selected = probe.provision(name)
            initial = _state(selected)

            def interrupted(path: Path, *, writable: bool) -> InterruptedConnection:
                return _InterruptedConnection(original_connect(path, writable=writable), exception, phase == "after")

            try:
                ledger._connect = interrupted
                outcome = probe.commit(selected)
            finally:
                ledger._connect = original_connect
            before_recovery = _state(selected)
            recovery = probe.recover(selected)
            results[name] = {"initial": initial, "commit": outcome, "before_recovery": before_recovery,
                "recovery": recovery, "after_recovery": _state(selected)}
    return results


def _epoch_guards(probe: _Experiment) -> dict[str, Any]:
    selected = probe.provision("epoch-guards")
    receipt = probe.commit(selected)
    original = _state(selected)
    refused = []
    for value in (1, 0, -1, True, 2**63):
        outcome = _refusal(lambda: ledger.advance_policy_epoch(selected, new_epoch=value))
        refused.append({"value": value, "outcome": outcome, "state": _state(selected)})
    ledger.advance_policy_epoch(selected, new_epoch=3)
    advanced = _state(selected)
    stale = _refusal(lambda: ledger.advance_policy_epoch(selected, new_epoch=4))
    after_stale = _state(selected)
    current = replace(selected, policy_epoch=3)
    duplicate, fresh = probe.commit(current), probe.commit(current, "b")
    return {"commit": receipt, "original": original, "refused": refused, "advanced": advanced,
        "stale": stale, "after_stale": after_stale, "duplicate": duplicate, "fresh": fresh, "final": _state(selected)}


def observe_controls(directory: Path) -> dict[str, Any]:
    """Return measurements only; independent parent predicates decide each claim."""
    probe = _Experiment(directory)
    return {"provisioning": _provisioning(probe), "retention": _retention(probe),
        "integrity": _integrity(probe), "resources": _resources(probe),
        "cancellation": _cancellation(probe), "epoch_guards": _epoch_guards(probe),
        "ordering": _ordering(probe), "corrections": _corrections(probe), "retry": _retry(probe),
        "authorization": _authorization(probe), "accounting": _accounting(probe)}
