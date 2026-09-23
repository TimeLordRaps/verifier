"""Execution environment (ENV): retained observations, not physical attestation."""
from __future__ import annotations

import platform
import sys
from .common import Budget, Refuted, Unavailable, digest, materialize, need, number, obj, same, seq, text, unique


def collect_configuration() -> dict:
    """Capture named process observations; this collector is not independent evidence."""
    return {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
            "python_implementation": platform.python_implementation(), "python_version": platform.python_version(),
            "byteorder": sys.byteorder}


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    if artifact.get("scope") != "retained-process-observations":
        raise Unavailable("physical attestation and containment require an external qualified mechanism")
    inventory = obj(need(artifact, "files"))
    files = obj(need(inputs, "files"))
    same(sorted(inventory), sorted(files), "software inventory differs")
    if not files:
        raise Unavailable("software inventory empty")
    for name, record in files.items():
        materialize(record, budget)
        same(record["sha256"], inventory[name], "software coordinate differs")
    if check == "configuration":
        required = obj(need(artifact, "configuration"))
        if not required:
            raise Unavailable("configuration contract empty")
        same(need(inputs, "configuration"), required, "complete configuration differs")
    elif check == "resources":
        ceilings = obj(need(artifact, "ceilings"), {"wall_seconds", "memory_bytes", "threads"})
        identifiers = seq(need(artifact, "execution_ids"), budget)
        if len(identifiers) != len(set(identifiers)) or len(identifiers) < 2:
            raise Refuted("two distinct execution identities required")
        observations = unique(seq(need(inputs, "measurements"), budget), "id")
        same(sorted(observations), sorted(identifiers), "resource observation coverage differs")
        for row in observations.values():
            obj(row, set(ceilings) | {"id"})
            for key, ceiling in ceilings.items():
                if number(ceiling) <= 0 or not 0 <= number(row[key]) <= number(ceiling):
                    raise Refuted("retained resource measurement exceeds bound")
    elif check == "reproduction":
        executions = unique(seq(need(inputs, "executions"), budget), "id")
        if len(executions) < 2:
            raise Unavailable("two retained executions required")
        same(sorted(executions), sorted(need(artifact, "execution_ids")), "execution coverage differs")
        expected = obj(need(artifact, "execution"), {"executable", "input_digest", "output_digest"})
        if expected["executable"] not in inventory:
            raise Refuted("executable absent from software inventory")
        for execution in executions.values():
            obj(execution, {"id", "software_digest", "configuration_digest", "executable", "input", "output", "exit_code"})
            same(execution["software_digest"], digest(inventory), "execution software differs")
            same(execution["configuration_digest"], digest(need(artifact, "configuration")), "execution configuration differs")
            same(execution["executable"], expected["executable"], "execution program differs")
            same(digest(execution["input"]), expected["input_digest"], "execution input differs")
            same(digest(execution["output"]), expected["output_digest"], "execution output differs")
            same(execution["exit_code"], 0, "execution failed")
    return {"files": len(files), "scope": "retained-process-observations"}
