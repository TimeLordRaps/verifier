"""Fixed isolated-process meter for one retained SIM transition sequence.

The process accepts data, never source code. Acronyms: central processing unit (CPU);
graphics processing unit (GPU). Thread CPU time is measured in
nanoseconds; tracemalloc's peak is traced Python allocations in bytes. Neither
is total machine utilization, energy, GPU use, or historical customer work.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import sys
import time
import tracemalloc

# `python -I` excludes the working directory and PYTHONPATH. Bind this fixed
# worker to the package tree that contains the invoked script.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from verifier.core.certificate import canonical_bytes  # noqa: E402
from verifier.domains import sim  # noqa: E402
from verifier.domains.common import Budget, same  # noqa: E402


MAX_INPUT_BYTES = 4 * 1024 * 1024


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def measure(value: dict) -> dict:
    artifact, inputs = value["artifact"], value["inputs"]
    limit, max_items = value["max_operations"], value["max_items"]
    if (type(limit) is not int or not 1 <= limit <= 100000
            or type(max_items) is not int or not 1 <= max_items <= 4096):
        raise ValueError("worker bounds differ")
    sim.evaluate("replay", artifact, inputs, Budget(limit, max_items), witness_keys={})
    program = artifact["transition"]
    states, entropy = inputs["states"], inputs["entropy"]
    budget = Budget(limit, max_items)
    steps = []
    for index, entry in enumerate(entropy):
        tracemalloc.start()
        try:
            start = time.thread_time_ns()
            following = sim.transition(program, states[index], entry, budget)
            cpu_ns = time.thread_time_ns() - start
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        same(following, states[index + 1], "metered transition differs")
        steps.append({
            "step": index, "input_state_digest": _digest(states[index]),
            "output_state_digest": _digest(following),
            "thread_cpu_ns": cpu_ns, "traced_peak_bytes": peak,
        })
    return {"method": "cpython-thread-cpu-tracemalloc-1",
            "target": "CPython " + platform.python_version(),
            "run_id": secrets.token_hex(16), "process_id": os.getpid(),
            "steps": steps}


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        return 2
    value = json.loads(raw)
    if type(value) is not dict or set(value) != {
            "artifact", "inputs", "max_operations", "max_items"}:
        return 2
    sys.stdout.buffer.write(canonical_bytes(measure(value)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise SystemExit(2)
