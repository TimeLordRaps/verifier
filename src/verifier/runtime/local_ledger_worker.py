"""Fixed local ledger experiment worker for Verifier Standard (VSTD).

Only installed code runs, against fresh temporary SQLite databases. No subject
path, command, operator database, money or authority channel is accepted. Raw
observations go to the parent checker; this worker cannot issue a package PASS.
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from typing import Any


def source_pins() -> dict[str, str]:
    """Bind executable package source and the ledger's interpreted specification."""
    root = Path(__file__).resolve().parents[1]
    paths = [path for path in root.rglob("*.py") if "__pycache__" not in path.parts]
    paths.extend(root / name for name in ("standard/POLISH_INVOCATION_LEDGER.md", "standard/PACKAGE_POLISH.md"))
    return {path.relative_to(root).as_posix(): "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def observe(directory: Path) -> dict[str, Any]:
    """Exercise real public operations; injected faults occur at the backend edge."""
    import sqlite3
    from contextlib import closing
    from concurrent.futures import ThreadPoolExecutor
    from dataclasses import replace
    from verifier.core.certificate import canonical_bytes
    from verifier.runtime import polish_invocation_ledger as ledger
    from verifier.runtime.local_ledger_controls import observe_controls

    def provision(name: str) -> Any:
        selection = ledger.IssuerLedgerSelection(str(directory / (name + ".sqlite")), name, "local-check", 1)
        ledger.provision_issuance_ledger(selection)
        return selection

    def proposal(value: str) -> bytes:
        return canonical_bytes({"value": value})

    def digest(raw: bytes) -> str:
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    def commit(selection: Any, identifier: str = "a", **changes: Any) -> dict[str, Any]:
        raw = changes.pop("proposal_bytes", proposal(identifier))
        arguments = {"expected_proposal_digest": digest(raw), "invocation_id": identifier,
                     "authority_status_digest": "sha256:" + "a" * 64, "commit_time": 100,
                     "selection": selection, **changes}
        return ledger.commit_issuance(raw, **arguments)

    def rows(selection: Any) -> list[dict[str, Any]]:
        # Observe persisted state independently of the public receipt builder.
        # sqlite3's transaction context does not close its connection. Explicit
        # closure is necessary before deleting temporary databases on Windows.
        with closing(sqlite3.connect(selection.path)) as connection:
            values = connection.execute("SELECT sequence, invocation_id, policy_epoch, proposal FROM issuance ORDER BY sequence").fetchall()
        return [{"sequence": sequence, "invocation": identifier, "epoch": epoch,
                 "proposal": raw.decode("utf-8")} for sequence, identifier, epoch, raw in values]

    basic = provision("records")
    initial = rows(basic)
    first = commit(basic)
    first_rows = rows(basic)
    replay = ledger.recheck_issuance_commit(canonical_bytes(first), proposal_bytes=proposal("a"),
        expected_proposal_digest=digest(proposal("a")), selection=basic)
    wrong = [ledger.recheck_issuance_commit(canonical_bytes(first), proposal_bytes=proposal("a"),
        expected_proposal_digest=digest(proposal("a")), selection=changed)
        for changed in (replace(basic, ledger_id="different"), replace(basic, policy_domain="different"))]
    duplicate = commit(basic)
    duplicate_rows = rows(basic)
    second = commit(basic, "b")
    records = {"initial": initial, "first": first, "first_rows": first_rows, "replay": replay,
        "wrong_selection": wrong, "duplicate": duplicate, "duplicate_rows": duplicate_rows,
        "second": second, "final_rows": rows(basic)}

    precondition = provision("preconditions")
    invalid = [commit(precondition, expected_proposal_digest="sha256:" + "0" * 64),
               commit(precondition, authority_status_digest="not-a-digest"),
               commit(replace(precondition, policy_epoch=2)),
               commit(precondition, proposal_bytes=b" {} ")]
    preconditions = {"results": invalid, "rows": rows(precondition)}

    # SQLite commits can succeed before their acknowledgement is lost. The
    # caller must not infer non-consumption from UNKNOWN and blindly reissue.
    original_connect = ledger._connect

    class FaultConnection:
        def __init__(self, connection: sqlite3.Connection, after_commit: bool) -> None:
            self.connection = connection
            self.after_commit = after_commit

        @property
        def in_transaction(self) -> bool:
            return self.connection.in_transaction

        def execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Cursor:
            if sql == "COMMIT":
                if self.after_commit:
                    self.connection.execute(sql, parameters)
                raise sqlite3.OperationalError("injected commit-boundary fault")
            return self.connection.execute(sql, parameters)

        def close(self) -> None:
            self.connection.close()

    faults = {}
    for phase in ("before", "after"):
        selected = provision(phase)

        def fault_connect(path: Path, *, writable: bool) -> FaultConnection:
            return FaultConnection(original_connect(path, writable=writable), phase == "after")

        try:
            ledger._connect = fault_connect
            uncertain = commit(selected)
        finally:
            ledger._connect = original_connect
        before_recovery = rows(selected)
        recovery = ledger.recover_issuance_commit(proposal("a"), expected_proposal_digest=digest(proposal("a")),
            invocation_id="a", selection=selected)
        after_recovery = rows(selected)
        retry = commit(selected)  # A controlled probe, never automatic production retry.
        faults[phase] = {"commit": uncertain, "before_recovery": before_recovery, "recovery": recovery,
                         "after_recovery": after_recovery, "retry": retry, "final_rows": rows(selected)}

    epoch = provision("epochs")
    prior = commit(epoch)
    ledger.advance_policy_epoch(epoch, new_epoch=2)
    stale = commit(epoch, "b")
    current = replace(epoch, policy_epoch=2)
    repeated = commit(current)
    fresh = commit(current, "b")
    old_replay = ledger.recheck_issuance_commit(canonical_bytes(prior), proposal_bytes=proposal("a"),
        expected_proposal_digest=digest(proposal("a")), selection=epoch)
    epochs = {"prior": prior, "stale": stale, "repeated": repeated, "fresh": fresh,
              "old_replay": old_replay, "rows": rows(current)}
    concurrent = provision("concurrent")
    with ThreadPoolExecutor(max_workers=4) as pool:
        attempts = list(pool.map(lambda _: commit(concurrent), range(4)))
    return {"records": records, "preconditions": preconditions, "faults": faults, "epochs": epochs,
            "concurrency": {"results": attempts, "rows": rows(concurrent)},
            "controls": observe_controls(directory),
            "sqlite_version": sqlite3.sqlite_version}


def main() -> int:
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError("worker request exceeds bound")
    request = json.loads(raw)
    if type(request) is not dict or set(request) != {"schema_version", "nonce", "object_id", "object_digest", "collection_digest"}:
        raise ValueError("closed worker request required")
    if request["schema_version"] != "verifier-local-ledger-execution-request-1":
        raise ValueError("worker request version differs")
    if any(type(value) is not str or not 1 <= len(value) <= 256 for value in request.values()):
        raise ValueError("bounded worker bindings required")
    before = source_pins()
    with tempfile.TemporaryDirectory(prefix="vstd-ledger-check-") as temporary:
        directory = Path(temporary).resolve(strict=True)
        # Ignore cached subject bytecode, site customization and caller paths.
        # Only this installed worker's package root is importable as verifier.
        sys.pycache_prefix = str(directory / "empty-bytecode")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        observations = observe(directory)
    after = source_pins()
    if before != after:
        raise ValueError("worker source changed")
    result = {"schema_version": "verifier-local-ledger-execution-observations-1",
              "request": request, "source_pins": before, "observations": observations}
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
