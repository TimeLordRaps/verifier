"""Private dispatcher-protocol experiments for Verifier Standard (VSTD).

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Only fixed installed code and private ledger fixtures execute. Malformed peers
are injected at the subprocess transport edge; no subject command is accepted.
Each exchange emits an ordered transcript of parent and fixed-worker events; the
checker in worker_protocol_execution.py judges those events, not this observer.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from typing import Any


def source_pins() -> dict[str, str]:
    # Bootstrap without importing package code or possibly stale bytecode.
    root = Path(__file__).resolve().parents[1]
    paths = [path for path in root.rglob("*.py") if "__pycache__" not in path.parts]
    paths.extend(root / name for name in ("standard/POLISH_INVOCATION_LEDGER.md", "standard/PACKAGE_POLISH.md"))
    return {path.relative_to(root).as_posix(): "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def _channel_summary(record: dict[str, Any] | None) -> dict[str, Any] | None:
    """Keep a fault row's parent stream digests, lengths and truncation, but not its retained bytes.

    Injected faults can retain up to one mebibyte of parent stdout each, base64-expanded. This
    observation is itself one bounded child reply, so full retention would exceed that bound and
    the whole observation would be refused as output capacity. The checker reads only outcomes,
    transcripts and recovery from fault rows, so no verdict depends on the omitted bytes. The
    sealed digest of the complete record is kept as ``full_observation_digest``. Real exchanges
    keep their complete records because the parent re-verifies those.
    """
    if record is None:
        return None
    body = {key: value for key, value in record.items() if key != "observation_digest"}
    for key in ("stdin", "stdout", "stderr"):
        if body.get(key) is not None:
            body[key] = {name: value for name, value in body[key].items() if name != "retained_base64"}
    return {**body, "retained_streams": "OMITTED_OUTER_CHANNEL_BOUND",
            "full_observation_digest": record["observation_digest"]}


def observe() -> dict[str, Any]:
    from copy import deepcopy
    from itertools import count
    import subprocess
    from types import SimpleNamespace
    from verifier.core.namespace import NamespaceObject
    from verifier.runtime import package_execution as subject, local_ledger_execution as peer
    from verifier.runtime import local_ledger_worker as pins_module
    from verifier.runtime.tier_zero_profile import canonical_bytes

    installed = Path(subject.__file__).parents[2]
    item = NamespaceObject.create("protocol-peer", "OBJECT", {}, {})
    selection = {"object_id": item.object_id, "mechanism": peer.ADAPTER, "reason": "Fixed private protocol peer.",
        "evidence": [{"path": peer.IMPLEMENTATION, "sha256": "sha256:" + hashlib.sha256((installed / peer.IMPLEMENTATION[4:]).read_bytes()).hexdigest()}]}

    class Snapshot:
        rows = {item.object_id: {"surfaces": ["file:" + peer.IMPLEMENTATION]}}
        collection_digest = "sha256:" + "b" * 64

        def __init__(self) -> None:
            self.execution_transports: dict[tuple[str, str], dict[str, Any]] = {}

        def read(self, ref: dict[str, str]) -> bytes:
            raw = (installed / ref["path"][4:]).read_bytes()
            if ref["sha256"] != "sha256:" + hashlib.sha256(raw).hexdigest():
                raise ValueError("fixture source changed")
            return raw

    snapshot, real = Snapshot(), []
    original_run, original_pins = subprocess.run, pins_module.source_pins
    # One monotonic counter orders every event across both real exchanges.
    sequence = count()

    def record(events: list[dict[str, Any]], state: str, participant: str, **fields: Any) -> None:
        events.append({"seq": next(sequence), "state": state, "participant": participant, **fields})

    def launched(command: list[str]) -> dict[str, Any]:
        # Bind the fixed worker bytes at the moment the argv is handed to the transport.
        return {"worker_sha256": "sha256:" + hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest()}

    def capture(command: list[str], **kwargs: Any) -> Any:
        request = json.loads(kwargs["input"])
        events: list[dict[str, Any]] = []
        record(events, "CREATED_REQUEST", "parent_dispatcher")
        record(events, "LAUNCHED_FIXED_WORKER", "fixed_worker", **launched(command))
        real.append({"worker": Path(command[-1]).name, "flags": command[1:-1],
                     "interpreter_matches": command[0] == sys.executable,
                     "request": request, "environment_keys": sorted(kwargs["env"]),
                     "parameters": {name: kwargs[name] for name in ("capture_output", "timeout", "check")},
                     "transcript": events})
        return original_run(command, **kwargs)

    try:
        subprocess.run = capture
        for _ in range(2):
            reply = subject.execute_bound(snapshot, item, selection)
            row = real[-1]
            record(row["transcript"], "DECODED_BOUND_REPLY", "parent_dispatcher")
            row.update(reply=reply, reply_request=reply["request"],
                       parent_record=snapshot.execution_transports.get((item.object_id, peer.ADAPTER)))
    finally:
        subprocess.run = original_run

    faults = {}
    names = ("schema", "downgrade", "missing", "extra", "nonobject", "duplicate", "truncated", "encoding", "nonce",
             "object_id", "object_digest", "collection_digest", "timeout", "exit", "selected_source", "peer_source",
             "recapture", "at_capacity", "over_capacity")
    recovery_by_state = {"DECODED_BOUND_REPLY": "NOT_REQUIRED", "FAILED_TRANSPORT": "NO_RETRY_UNAVAILABLE",
                         "REJECTED_REPLY": "NO_RETRY_REFUSED", "NOT_LAUNCHED": "NOT_ATTEMPTED"}
    for name in names:
        calls, recaptures, response_bytes, events = [], [], [], []

        def altered_pins() -> dict[str, str]:
            recaptures.append(1)
            value = original_pins()
            return {**value, "unexpected.py": "sha256:" + "0" * 64} if len(recaptures) > 1 else value

        def unavailable(ref: dict[str, str]) -> bytes:
            raise OSError("PACKAGE_EXECUTION_SOURCE_UNAVAILABLE")

        def transport(command: list[str], **kwargs: Any) -> Any:
            calls.append(1)
            record(events, "CREATED_REQUEST", "parent_dispatcher")
            record(events, "LAUNCHED_FIXED_WORKER", "fixed_worker", **launched(command))
            if name == "timeout":
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            request = json.loads(kwargs["input"])
            body: Any = {"schema_version": peer.OBSERVATION_SCHEMA, "request": deepcopy(request),
                         "source_pins": original_pins(), "observations": {}}
            if name == "schema":
                body["schema_version"] = "different"
            elif name == "downgrade":
                body["schema_version"] = peer.OBSERVATION_SCHEMA.replace("-1", "-0")
            elif name == "missing":
                del body["observations"]
            elif name == "extra":
                body["extra"] = True
            elif name == "nonobject":
                body = []
            elif name in {"nonce", "object_id", "object_digest", "collection_digest"}:
                body["request"][name] = real[0]["request"]["nonce"] if name == "nonce" else "different"
            elif name == "peer_source":
                body["source_pins"]["unexpected.py"] = "sha256:" + "0" * 64
            elif name in {"at_capacity", "over_capacity"}:
                body["observations"] = {"padding": ""}
                body["observations"]["padding"] = "x" * (1048576 - len(canonical_bytes(body)))
            raw = canonical_bytes(body)
            if name == "over_capacity":
                raw += b" "
            elif name == "duplicate":
                raw = b'{"schema_version":"duplicate",' + raw[1:]
            elif name == "truncated":
                raw = raw[: len(raw) // 2]
            elif name == "encoding":
                raw = b"\xff"
            response_bytes.append(len(raw))
            return SimpleNamespace(returncode=1 if name == "exit" else 0, stdout=raw, stderr=b"")

        read = snapshot.read
        outcome: dict[str, Any] = {"returned": False, "exception": None, "reason": None}
        snapshot.execution_transports.clear()
        try:
            subprocess.run = transport
            if name == "recapture":
                pins_module.source_pins = altered_pins
            if name == "selected_source":
                snapshot.read = unavailable
            subject.execute_bound(snapshot, item, selection)
            outcome["returned"] = True
        except (ValueError, TypeError, KeyError, OSError, subprocess.TimeoutExpired) as exc:
            outcome.update(exception=type(exc).__name__, reason=str(exc))
        finally:
            subprocess.run, pins_module.source_pins, snapshot.read = original_run, original_pins, read
        # The terminal state is derived from the observed exception and launch count, never from the fault label.
        if outcome["returned"]:
            terminal = "DECODED_BOUND_REPLY"
        elif not calls:
            terminal = "NOT_LAUNCHED"
        elif outcome["exception"] == "TimeoutExpired" or outcome["reason"] == "PACKAGE_EXECUTION_WORKER_UNAVAILABLE":
            terminal = "FAILED_TRANSPORT"
        else:
            terminal = "REJECTED_REPLY"
        if terminal != "NOT_LAUNCHED":
            record(events, terminal, "parent_dispatcher")
        faults[name] = {**outcome, "calls": len(calls), "response_bytes": response_bytes[-1] if response_bytes else None,
                        "transcript": events, "recovery": recovery_by_state[terminal],
                        "parent_record": _channel_summary(snapshot.execution_transports.get((item.object_id, peer.ADAPTER)))}
    pins = original_pins()
    parent_name = Path(subject.__file__).name
    identities = {"parent_dispatcher": {"implementation": "runtime/" + parent_name, "sha256": pins["runtime/" + parent_name]},
                  "fixed_worker": {"implementation": "runtime/" + peer.WORKER, "sha256": pins["runtime/" + peer.WORKER]}}
    return {"real": real, "faults": faults, "identities": identities, "selection": selection,
            "item": {"object_id": item.object_id, "object_digest": item.digest},
            "collection_digest": snapshot.collection_digest}


def main() -> int:
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError("worker request exceeds bound")
    request = json.loads(raw)
    if (type(request) is not dict or set(request) != {"schema_version", "nonce", "object_id", "object_digest", "collection_digest"}
            or request["schema_version"] != "verifier-worker-protocol-request-1"
            or any(type(value) is not str or not 1 <= len(value) <= 256 for value in request.values())):
        raise ValueError("closed bounded protocol request required")
    before = source_pins()
    with tempfile.TemporaryDirectory(prefix="vstd-protocol-check-") as temporary:
        sys.pycache_prefix = str(Path(temporary) / "empty-bytecode")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        observations = observe()
    if before != source_pins():
        raise ValueError("worker source changed")
    sys.stdout.write(json.dumps({"schema_version": "verifier-worker-protocol-observations-1",
        "request": request, "source_pins": before, "observations": observations},
        sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
